import contextvars
import json
import logging
import os
import uuid

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.database import Base, engine
from api import models
from api.deps import limiter, get_authenticated_db, verify_auth

# Root logger carries the structured formatter, so every module's own
# `logging.getLogger(__name__)` (api.deps, inference.*, etc.) inherits it
# via normal propagation instead of only whichever logger main.py names.
logger = logging.getLogger(__name__)


# Request-scoped, not global: contextvars are task-local, so concurrent
# requests handled on the same event loop each see only their own value --
# unlike a plain module-level variable, which every in-flight request
# would share and clobber.
_correlation_id_ctx = contextvars.ContextVar("correlation_id", default=None)
_path_ctx = contextvars.ContextVar("path", default=None)


class _RequestContextFilter(logging.Filter):
    """Stamps every log record with the current request's correlation ID
    and path, previously read via getattr(record, ..., None) from fields
    nothing ever actually set -- every line logged correlation_id/path as
    null regardless of which request triggered it."""

    def filter(self, record):
        record.correlation_id = _correlation_id_ctx.get()
        record.path = _path_ctx.get()
        return True


class StructuredLogFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "ts": self.formatTime(record),
            "level": record.levelname,
            "msg": record.getMessage(),
            "path": getattr(record, "path", None),
            "correlation_id": getattr(record, "correlation_id", None),
        })


_handler = logging.StreamHandler()
_handler.setFormatter(StructuredLogFormatter())
_handler.addFilter(_RequestContextFilter())
_root_logger = logging.getLogger()
_root_logger.addHandler(_handler)
_root_logger.setLevel(logging.INFO)

_enable_docs = os.getenv("ENABLE_DOCS", "false").lower() in ("true", "1", "yes")
app = FastAPI(
    title="T-SOC Threat Detection API",
    docs_url="/docs" if _enable_docs else None,
    redoc_url="/redoc" if _enable_docs else None,
    openapi_url="/openapi.json" if _enable_docs else None
)


@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)


from prometheus_fastapi_instrumentator import Instrumentator  # noqa: E402

Instrumentator().instrument(app).expose(app, dependencies=[Depends(verify_auth)])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins_env = os.getenv("TSOC_CORS_ORIGINS", "https://dashboard.tsoc.local")
allowed_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True if os.getenv("TSOC_CORS_STRICT") == "1" else False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID", "traceparent"],
    expose_headers=["X-Request-ID"]
)


@app.middleware("http")
async def request_tracing_middleware(request: Request, call_next):
    # W3C Trace Context & Correlation ID support
    req_id = (
        request.headers.get("X-Request-ID")
        or request.headers.get("X-Correlation-ID")
        or f"req-{uuid.uuid4().hex[:16]}"
    )
    request.state.request_id = req_id
    corr_token = _correlation_id_ctx.set(req_id)
    path_token = _path_ctx.set(request.url.path)
    try:
        response = await call_next(request)
    finally:
        _correlation_id_ctx.reset(corr_token)
        _path_ctx.reset(path_token)
    response.headers["X-Request-ID"] = req_id
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    # Do NOT leak internal Pydantic schema / field names to attacker
    return JSONResponse(status_code=422, content={"detail": "Invalid request format"})


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Invalid request format"})
    logger.error("Internal Error: %s - %s - %s", type(exc).__name__, str(exc), request.url.path)
    return JSONResponse(status_code=500, content={"message": "Internal Server Error"})


@app.get("/livez")
def livez():
    """Shallow liveness probe: verifies the process is up and serving without dependency coupling."""
    return {'status': 'alive'}


# Liveness and readiness probes are unauthenticated for Kubelet access
@app.get("/readyz")
def readyz():
    # Shallow readiness — no DB connection to prevent kubelet probe pool exhaustion
    return {'status': 'ready', 'db_probe': 'skip', 'probe': 'shallow'}


@app.get("/healthz")
def healthz():
    """Shallow health probe: verifies the HTTP listener is operational without consuming DB pool connections."""
    return {'status': 'ok'}


@app.get("/api/v1/stats")
@limiter.limit("100/minute")
def get_stats(
    request: Request,
    db=Depends(get_authenticated_db),
):
    counts = db.query(models.Alert.severity, func.count(models.Alert.id)).group_by(models.Alert.severity).all()
    severity_map = {str(sev).lower() if sev else "unknown": cnt for sev, cnt in counts}
    total = sum(severity_map.values())
    return {
        "total_alerts": total,
        "critical": severity_map.get("critical", 0),
        "high": severity_map.get("high", 0),
        "medium": severity_map.get("medium", 0),
        "low": severity_map.get("low", 0)
    }


# Alert routes live in api/routes/alerts.py, sharing this module's limiter
# and auth dependency via api.deps (see that file's docstring for why).
from api.routes.alerts import router as alerts_router  # noqa: E402
app.include_router(alerts_router)
