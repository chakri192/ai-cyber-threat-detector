import asyncio
import logging
import signal
import sys
import json
import os
import fcntl
import uuid
import threading
import atexit
import redis
from datetime import datetime, timezone
from faust import App
from concurrent.futures import ThreadPoolExecutor

from inference.features import extract_features
from inference.rules import evaluate_rules
from inference.models import DeepLearningEngine
from inference.correlation import IncidentCorrelator
from inference.enrichment import ThreatEnricher
from inference.schemas import validate_alert

dl_engine = DeepLearningEngine()
correlator = IncidentCorrelator()
enricher = ThreatEnricher()

logger = logging.getLogger(__name__)
BROKER_URL = os.getenv("REDPANDA_BROKERS", "soc-redpanda-cluster.prod.svc.cluster.local:9092")
# datadir explicit: Faust defaults it to a directory under the current
# working directory (CWD, /app in the container) when omitted, which
# collides with k8s/soc-deployment.yaml's readOnlyRootFilesystem: true --
# guaranteed CrashLoopBackOff on `mkdir /app/tsoc-stream-processor-data`.
# /var/lib/app is already a writable emptyDir mount on that manifest.
app = App(
    'tsoc-stream-processor',
    broker=f'kafka://{BROKER_URL}',
    datadir=os.getenv("FAUST_DATADIR", "/var/lib/app/faust"),
)
raw_traffic_topic = app.topic('raw_traffic', value_type=dict)
alerts_topic = app.topic('security_alerts', value_type=dict)
incidents_topic = app.topic("incidents")
dead_letter_topic = app.topic("dead_letter_events", value_type=dict)

# Segregate CPU and I/O ThreadPools to prevent GIL/IO resource starvation
# Right-sized thread allocations matching container resource constraints
cpu_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="cpu")  # ML Inference, Feature Extraction
io_executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="io")  # Redis Correlation
atexit.register(lambda: cpu_executor.shutdown(wait=True, cancel_futures=True))
atexit.register(lambda: io_executor.shutdown(wait=True, cancel_futures=True))
# Track submitted futures for cancellation on SIGTERM (thread-safe lock for sync and async callers)
_submitted_cpu_futures = set()
_submitted_io_futures = set()
_futures_lock = threading.Lock()

# SIGTERM handler for graceful shutdown (prevents shutdown race)
import signal

def _graceful_shutdown(signum, frame):
    with _futures_lock:
        for f in list(_submitted_cpu_futures):
            f.cancel()
        for f in list(_submitted_io_futures):
            f.cancel()
    cpu_executor.shutdown(wait=False, cancel_futures=True)
    io_executor.shutdown(wait=False, cancel_futures=True)
    raise SystemExit(0)

signal.signal(signal.SIGTERM, _graceful_shutdown)
signal.signal(signal.SIGINT, _graceful_shutdown)

class _LazySemaphore:
    def __init__(self, value: int):
        self._value = value
        self._sem = None

    def _get_sem(self):
        if self._sem is None:
            self._sem = asyncio.Semaphore(self._value)
        return self._sem

    async def __aenter__(self):
        return await self._get_sem().__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return await self._get_sem().__aexit__(exc_type, exc_val, exc_tb)

backpressure_sem = _LazySemaphore(8)
_infer_sem = _LazySemaphore(4)
# Bound concurrent inference submissions to prevent unbounded queue growth.
# The executor's internal queue caps at ~max_workers*128, but the semaphore
# provides an explicit, observable ceiling that also gates semaphore release.
_infer_pending_sem = _LazySemaphore(8)


@app.page('/healthz')
async def healthz(web, request):
    return web.json({'status': 'ok'})

@app.agent(raw_traffic_topic, concurrency=16)
async def process_traffic(stream):
    async for event in stream:
        async with backpressure_sem:
            # 1. Feature extraction (pure dictionary operations; avoids threadpool overhead/starvation)
            try:
                features = extract_features(event)
            except Exception as e:
                logger.error(f"Feature extraction failed: {e}")
                continue

            # 2. Rule evaluation
            try:
                detections = evaluate_rules(event, features)
            except Exception as e:
                logger.error(f"Rule Evaluation Error: {e}")
                detections = []

            # 3. Deep-Learning inference (CPU-bound, bounded by semaphore + input guard)
            if event.get("event_type") == "dns":
                try:
                    raw_query = event.get("query")
                    if isinstance(raw_query, str):
                        query = raw_query.strip()
                    elif isinstance(raw_query, (bytes, bytearray)):
                        query = raw_query.decode("utf-8", errors="ignore").strip()
                    elif raw_query is not None:
                        # Defend against non-string types (int, float, list, dict)
                        query = str(raw_query).strip()
                    else:
                        query = ""

                    # Pre-validate domain length before thread dispatch to prevent slow-poison starvation
                    if query and len(query) <= 253:
                        async with _infer_pending_sem:
                            async with _infer_sem:
                                infer_future = asyncio.get_running_loop().run_in_executor(
                                    cpu_executor, dl_engine.predict, dict(features), query
                                )
                                with _futures_lock:
                                    _submitted_cpu_futures.add(infer_future)
                                try:
                                    is_dga, prob, _ = await asyncio.wait_for(infer_future, timeout=5.0)
                                finally:
                                    with _futures_lock:
                                        _submitted_cpu_futures.discard(infer_future)
                            if is_dga:
                                detections.append({
                                    "threat_class": "DGA / DNS Tunnelling",
                                    "severity": "high",
                                    "confidence": prob,
                                    "rule_id": "DL_CNN_DGA"
                                })
                except asyncio.TimeoutError:
                    logger.warning("DL inference timed out for domain; skipping")
                except Exception as e:
                    logger.error(f"DL inference failed: {e}")

            # Extract or initialize distributed W3C trace context
            event_trace_id = str(event.get("trace_id") or event.get("uid") or f"trc-{uuid.uuid4().hex[:16]}")

            # 4. Emit alerts / incidents (IO-bound Redis Correlator)
            for det in detections:
                try:
                    raw_alert = {
                        "alert_id": f"ALT-{uuid.uuid4().hex[:12]}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "source_ip": str(event.get("id.orig_h") or "127.0.0.1"),
                        "destination_ip": str(event.get("id.resp_h") or "127.0.0.1"),
                        "threat_class": det.get("threat_class"),
                        "severity": det.get("severity"),
                        "confidence_score": float(det.get("confidence") or 0.9),
                        "evidence": det.get("evidence", {}),
                        "event_type": str(event.get("event_type") or "unknown"),
                        "schema_version": "1.0",
                        "model_name": str(det.get("rule_id") or "Unknown"),
                        "model_version": "1.0",
                        "mitre_tactic": det.get("mitre_tactic"),
                        "mitre_technique": det.get("mitre_technique"),
                        "trace_id": event_trace_id
                    }

                    # Resilient threat intel enrichment
                    try:
                        alert = await enricher.enrich(raw_alert)
                    except Exception as enrich_err:
                        logger.debug("Enrichment fallback: %s", enrich_err)
                        alert = raw_alert

                    # Strict alert schema validation gate
                    is_valid, schema_err = validate_alert(alert)
                    if not is_valid:
                        logger.warning("Invalid alert schema (%s); routing to DLQ", schema_err)
                        await _send_dlq_safely(event, alert, f"SchemaValidationError: {schema_err}")
                        continue

                    # Two-Phase Commit safety: publish alert to Kafka FIRST.
                    # Only mutate Redis correlation state after the write is durably
                    # persisted in the broker.  A Kafka timeout before this point
                    # routes to DLQ without touching Redis, preventing phantom
                    # incident state that can never be reconciled.
                    #
                    # force=True is load-bearing: Topic.send() called from inside
                    # an agent (as this is) with force=False (its default) does
                    # NOT publish -- it ATTACHES the message to the currently-
                    # processing event, deferred until that event's own offset
                    # commits. The await then returns almost immediately
                    # regardless of real broker state, so the timeout/DLQ
                    # handling below could never actually trigger on a slow or
                    # unreachable broker. force=True sends now and returns the
                    # real RecordMetadata acknowledgment this code already
                    # assumes it has.
                    try:
                        await asyncio.wait_for(alerts_topic.send(value=alert, force=True), timeout=3.0)
                    except asyncio.TimeoutError:
                        logger.warning("Alert Kafka publish timed out for %s; routing to DLQ (Redis NOT mutated)", alert.get("alert_id"))
                        await _send_dlq_safely(event, alert, "Timeout during alert Kafka publish")
                        continue
                    except Exception as kafka_err:
                        logger.error("Alert Kafka publish failed for %s: %s; routing to DLQ (Redis NOT mutated)", alert.get("alert_id"), kafka_err)
                        await _send_dlq_safely(event, alert, f"KafkaPublishError: {kafka_err}")
                        continue

                    # Alert is now durably in Kafka — safe to mutate Redis correlation state.
                    try:
                        io_future = asyncio.get_running_loop().run_in_executor(
                            io_executor, correlator.add_alert, alert
                        )
                        with _futures_lock:
                            _submitted_io_futures.add(io_future)
                        try:
                            incident = await asyncio.wait_for(io_future, timeout=5.0)
                        finally:
                            with _futures_lock:
                                _submitted_io_futures.discard(io_future)
                        if incident:
                            try:
                                await asyncio.wait_for(incidents_topic.send(value=incident, force=True), timeout=3.0)
                            except Exception as inc_send_err:
                                logger.error("Incident Kafka send failed for %s: %s; rolling back alert seen in Redis", incident.get("incident_id"), inc_send_err)
                                # Asynchronous rollback dispatched to io_executor to prevent event-loop blocking
                                try:
                                    await asyncio.get_running_loop().run_in_executor(
                                        io_executor, correlator.rollback_alert_seen, alert
                                    )
                                except Exception as rb_err:
                                    logger.error("Async rollback failed: %s", rb_err)
                                raise inc_send_err
                    except asyncio.TimeoutError:
                        logger.warning("Correlation/incident send timed out for %s; alert already committed to Kafka", alert.get("alert_id"))
                        # Asynchronous compensating rollback so abandoned thread results in Redis do not lock out DLQ replay
                        try:
                            await asyncio.get_running_loop().run_in_executor(
                                io_executor, correlator.rollback_alert_seen, alert
                            )
                        except Exception as rb_err:
                            logger.debug("Rollback on timeout ignored: %s", rb_err)
                        await _send_dlq_safely(event, alert, "Timeout during correlation or incident send")
                    except redis.RedisError as redis_err:
                        logger.error("Redis correlation failed for alert %s: %s; alert already committed to Kafka", alert.get("alert_id"), redis_err)
                        await _send_dlq_safely(event, alert, f"RedisUnavailable: {redis_err}")
                    except Exception as e:
                        logger.error("Processing error during correlation/incident emit: %s", e)
                        await _send_dlq_safely(event, alert, str(e))
                except Exception as det_outer_err:
                    logger.error("Detection processing loop error for %s: %s", det, det_outer_err)
                    await _send_dlq_safely(event, {"detection": str(det)}, f"DetectionLoopError: {det_outer_err}")

_raw_dlq_path = os.getenv("STREAM_DLQ_FILE_PATH", "/tmp/dlq/alerts.jsonl")  # nosec B108
_pod_name = os.getenv("POD_NAME") or os.getenv("HOSTNAME") or "default"
# Partition filename per pod to prevent inter-pod locking collisions and corruption on RWX PVCs
if "{pod}" in _raw_dlq_path:
    DLQ_FILE_PATH = _raw_dlq_path.format(pod=_pod_name)
else:
    _base_dir, _filename = os.path.split(_raw_dlq_path)
    _name, _ext = os.path.splitext(_filename)
    DLQ_FILE_PATH = os.path.join(_base_dir, f"{_name}-{_pod_name}{_ext}") if _pod_name != "default" else _raw_dlq_path

DLQ_LOCK_PATH = f"{DLQ_FILE_PATH}.lock"  # nosec B108
_dlq_file_lock = threading.Lock()

def _write_local_dlq_fallback(payload: dict):
    """POSIX flock append-only DLQ fallback with strict 0600 file permissions."""
    try:
        dlq_dir = os.path.dirname(DLQ_FILE_PATH)
        if dlq_dir:
            os.makedirs(dlq_dir, mode=0o700, exist_ok=True)
        with _dlq_file_lock:
            # We use os.open to strictly enforce 0o600 mode on file creation
            flags = os.O_CREAT | os.O_WRONLY | os.O_APPEND

            # Secure locking file
            lock_fd = os.open(DLQ_LOCK_PATH, flags, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX)

                # Secure append file
                fd = os.open(DLQ_FILE_PATH, flags, 0o600)
                try:
                    with open(fd, "a", encoding="utf-8", closefd=False) as f:
                        f.write(json.dumps(payload) + "\n")
                        f.flush()
                        os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
    except Exception as ex:
        logger.error("Local disk DLQ fallback failed: %s", ex)

async def _send_dlq_safely(event, alert, error_str):
    alert_payload = dict(alert) if isinstance(alert, dict) else alert
    if isinstance(alert_payload, dict):
        alert_payload["is_replay"] = True
    payload = {
        "original_event": event,
        "alert": alert_payload,
        "error": str(error_str),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    sent = False
    try:
        # force=True: see the comment on alerts_topic.send above -- without
        # it this "attempt" rarely reaches the broker at all, so the local-
        # disk fallback below would almost never actually trigger.
        await asyncio.wait_for(dead_letter_topic.send(value=payload, force=True), timeout=2.0)
        sent = True
    except Exception as dlq_err:
        logger.error("Kafka DLQ send failed (%s); persisting to local durable disk DLQ", dlq_err)

    if not sent:
        try:
            await asyncio.get_running_loop().run_in_executor(
                io_executor, _write_local_dlq_fallback, payload
            )
        except Exception as file_err:
            logger.error("Executor DLQ fallback failed (%s); writing directly", file_err)
            _write_local_dlq_fallback(payload)

import atexit

# Must stay ≤ K8s terminationGracePeriodSeconds (60s) to allow graceful
# in-flight correlation and DLQ-drain before SIGKILL. 45s gives a 15s margin
# for the Faust graceful-shutdown signal handler to complete before the
# atexitregistered _shutdown_executors is the final safety net.
_EXECUTOR_SHUTDOWN_TIMEOUT = 45

def _shutdown_executors():
    with _futures_lock:
        for f in list(_submitted_cpu_futures):
            f.cancel()
        for f in list(_submitted_io_futures):
            f.cancel()
    # Allow in-flight DLQ writes and correlations to drain before teardown.
    # wait=True with a bounded timeout prevents data loss from force-killed
    # futures while still respecting K8s terminationGracePeriodSeconds.
    for ex in (io_executor, cpu_executor):
        try:
            ex.shutdown(wait=True, cancel_futures=True)
        except TypeError:
            # Python < 3.9 fallback: no cancel_futures kwarg
            ex.shutdown(wait=True)

async def _on_before_shutdown(sender=None, **kwargs):
    # 1. Close async clients first while loop is active
    try:
        await enricher.close()
    except Exception as e:
        logger.error(f"Error closing threat enricher client: {e}")

    # 2. Asynchronously drain and shutdown threadpool executors without blocking the event loop
    loop = asyncio.get_running_loop()
    try:
        # Previously hardcoded to 15.0, disconnected from
        # _EXECUTOR_SHUTDOWN_TIMEOUT (45) declared above -- that constant
        # described this exact bound in its comment ("45s gives a 15s
        # margin...") but was never actually passed anywhere.
        await asyncio.wait_for(loop.run_in_executor(None, _shutdown_executors), timeout=_EXECUTOR_SHUTDOWN_TIMEOUT)
    except asyncio.TimeoutError:
        logger.warning("Executor shutdown timed out during Faust teardown; forcing cancellation")
    except Exception as e:
        logger.error("Error during async executor shutdown: %s", e)
    logger.info("Stream processor shutting down: executors and clients cleaned up")

app.on_before_shutdown.connect(_on_before_shutdown)
atexit.register(_shutdown_executors)

if __name__ == "__main__":
    app.main()
