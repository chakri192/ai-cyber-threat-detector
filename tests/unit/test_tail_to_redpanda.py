"""ingest/tail_to_redpanda.py had 0% coverage. Like ingest/simulator.py,
it constructs a real KafkaProducer at import time and exits the process
if that fails, so kafka.KafkaProducer must be patched before first
import. process_log() is exercised directly by faking the `tail -F`
subprocess (readline sequence) and the module-level producer/metrics,
rather than spawning a real tail process against a real broker.
"""
import json
from unittest.mock import MagicMock, patch

with patch("kafka.KafkaProducer", return_value=MagicMock()):
    import ingest.tail_to_redpanda as tailer


class _FakeStdout:
    """Yields the given lines, then flips the module's `running` flag to
    False and returns "" -- mirrors a real `tail -F` pipe going idle,
    but lets the test terminate the otherwise-infinite while loop."""

    def __init__(self, lines):
        self._lines = list(lines)

    def readline(self):
        if not self._lines:
            tailer.running = False
            return ""
        return self._lines.pop(0)


class _FakeProc:
    def __init__(self, lines):
        self.stdout = _FakeStdout(lines)
        self.terminated = False
        self.waited = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited = True


def _run_process_log(monkeypatch, lines, log_path):
    fake_proc = _FakeProc(lines)
    monkeypatch.setattr(tailer.subprocess, "Popen", lambda *a, **k: fake_proc)
    monkeypatch.setattr(tailer.time, "sleep", lambda s: None)

    sent = []
    fake_producer = MagicMock()
    fake_producer.send.side_effect = lambda topic, value: sent.append((topic, value))
    monkeypatch.setattr(tailer, "producer", fake_producer)

    tailer.running = True
    tailer.metrics = {"read": 0, "published": 0, "rejected": 0, "dead_lettered": 0}

    tailer.process_log(str(log_path), "conn")
    return sent, fake_proc


def test_process_log_publishes_valid_zeek_event(tmp_path, monkeypatch):
    log_path = tmp_path / "conn.log"
    log_path.write_text("")
    valid_line = json.dumps({"ts": 123.0, "id.orig_h": "10.0.0.1"})

    sent, fake_proc = _run_process_log(monkeypatch, [valid_line], log_path)

    assert tailer.metrics["read"] == 1
    assert tailer.metrics["published"] == 1
    assert tailer.metrics["rejected"] == 0
    topics = [t for t, _ in sent]
    assert topics == ["raw_traffic"]
    published_event = sent[0][1]
    assert published_event["event_type"] == "conn"
    assert published_event["sensor_id"] == tailer.SENSOR_ID
    assert fake_proc.terminated and fake_proc.waited


def test_process_log_dead_letters_invalid_json(tmp_path, monkeypatch):
    log_path = tmp_path / "conn.log"
    log_path.write_text("")

    sent, _ = _run_process_log(monkeypatch, ["not-valid-json"], log_path)

    assert tailer.metrics["rejected"] == 1
    assert tailer.metrics["dead_lettered"] == 1
    assert sent[0][0] == "dead_letter_events"
    assert sent[0][1]["raw_payload"] == "not-valid-json"


def test_process_log_dead_letters_event_missing_ts(tmp_path, monkeypatch):
    log_path = tmp_path / "conn.log"
    log_path.write_text("")
    missing_ts_line = json.dumps({"id.orig_h": "10.0.0.1"})

    sent, _ = _run_process_log(monkeypatch, [missing_ts_line], log_path)

    assert tailer.metrics["rejected"] == 1
    assert tailer.metrics["dead_lettered"] == 1
    assert sent[0][0] == "dead_letter_events"


def test_process_log_survives_a_kafka_send_failure_without_stopping_the_loop(tmp_path, monkeypatch):
    """A Kafka-side failure sending ONE line (e.g. oversized message) must
    not escape the loop and permanently stop ingestion for this log type."""
    log_path = tmp_path / "conn.log"
    log_path.write_text("")
    good_line = json.dumps({"ts": 1.0})

    fake_proc = _FakeProc([good_line])
    monkeypatch.setattr(tailer.subprocess, "Popen", lambda *a, **k: fake_proc)
    monkeypatch.setattr(tailer.time, "sleep", lambda s: None)

    fake_producer = MagicMock()
    fake_producer.send.side_effect = RuntimeError("MessageSizeTooLargeError")
    monkeypatch.setattr(tailer, "producer", fake_producer)

    tailer.running = True
    tailer.metrics = {"read": 0, "published": 0, "rejected": 0, "dead_lettered": 0}

    tailer.process_log(str(log_path), "conn")  # must not raise

    assert tailer.metrics["rejected"] == 1
    assert tailer.metrics["published"] == 0


def test_process_log_creates_missing_file_and_reaps_subprocess(tmp_path, monkeypatch):
    log_path = tmp_path / "does-not-exist-yet.log"
    assert not log_path.exists()

    _, fake_proc = _run_process_log(monkeypatch, [], log_path)

    assert log_path.exists()  # touched so `tail -F` doesn't fail
    assert fake_proc.terminated
