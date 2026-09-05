"""Shared FastAPI dependencies: trusted-proxy IP resolution, rate limiting,
authentication, and the per-request authenticated DB session.

Split out of api/main.py so api/routes/*.py can depend on the same limiter
and auth dependencies as the app itself without importing api.main (which
would create a circular import, since api.main imports the routers).
"""
import ipaddress
import logging
import os
import secrets
import urllib.parse
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError as JWTError
from slowapi import Limiter
from sqlalchemy.orm import Session

from api.auth import verify_token
from api.database import SessionLocal

logger = logging.getLogger(__name__)

# --- Trusted-proxy resolution --------------------------------------------
# Configurable trusted proxy CIDRs (defaults to loopback and standard K8s ingress subnet)
_trusted_proxies_raw = os.getenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,::1/128,10.244.0.0/16")
TRUSTED_INGRESS_NETWORKS = []
# Enforce strict allow-list; never allow 0.0.0.0/0, ::/0, or overly broad /0-/7 prefixes
for entry in _trusted_proxies_raw.split(","):
    entry = entry.strip()
    if entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            # Block overly broad networks (IPv4 < 8, IPv6 < 64) or global 0.0.0.0/0
            if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 64) or str(net) in ("0.0.0.0/0", "::/0"):
                logger.warning("Overly broad or global proxy CIDR rejected: %s (Prefix: %d)", entry, net.prefixlen)
                continue
            TRUSTED_INGRESS_NETWORKS.append(net)
        except ValueError as ex:
            logger.warning("Invalid proxy network CIDR %s: %s", entry, ex)


def _validate_ip(ip_str: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return str(addr)
    except ValueError:
        return None


def _is_trusted_proxy(ip: str) -> bool:
    # Strict allow-list only; default must not include open CIDRs
    try:
        addr = ipaddress.ip_address(ip.strip())
        for net in TRUSTED_INGRESS_NETWORKS:
            if addr in net:
                return True
        return False
    except ValueError:
        return False


# A stuffed X-Forwarded-For (thousands of comma-separated junk entries)
# costs a split() + a validation call per entry -- bounded here rather
# than processing an attacker-controlled string of unbounded size. 2048
# chars / 20 hops comfortably covers any real proxy chain (20 IPv6
# addresses alone would be under 1000 chars).
_MAX_XFF_HEADER_LEN = 2048
_MAX_XFF_HOPS = 20


def get_remote_address(request: Request) -> str:
    # Strict: never trust X-Forwarded-For / X-Real-IP unless immediate peer is verified proxy
    raw_client = request.client.host if request.client else "127.0.0.1"
    client_ip = _validate_ip(raw_client) or "127.0.0.1"
    # Only inspect proxy headers when the TCP peer is explicitly from trusted proxy list
    if _is_trusted_proxy(client_ip):
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded and len(forwarded) > _MAX_XFF_HEADER_LEN:
            forwarded = None
        if forwarded:
            # Parse right-to-left: find the first non-trusted proxy IP.
            # Only the last _MAX_XFF_HOPS entries are considered -- those
            # are the ones closest to our own trusted proxy, which is what
            # right-to-left parsing cares about first regardless of how
            # many (or how few) genuine hops precede them.
            ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()][-_MAX_XFF_HOPS:]
            valid_ips = []
            for ip in reversed(ips):
                valid = _validate_ip(ip)
                if valid:
                    valid_ips.append(valid)
                    if not _is_trusted_proxy(valid):
                        return valid
            # If all forwarded IPs are trusted proxies, return leftmost originating client
            # to isolate rate limit buckets and prevent shared ingress exhaustion DoS
            if valid_ips:
                return valid_ips[-1]
            return client_ip
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            valid = _validate_ip(real_ip)
            if valid:
                return valid
    return client_ip


# --- Rate limiter ----------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = os.getenv("REDIS_PORT", "6379")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)
REDIS_SSL = os.getenv("REDIS_SSL", "true").lower() in ("true", "1", "yes")
if REDIS_SSL and not REDIS_PASSWORD:
    raise RuntimeError("REDIS_PASSWORD required when REDIS_SSL=true")

_scheme = "rediss" if REDIS_SSL else "redis"
_auth = f":{urllib.parse.quote_plus(REDIS_PASSWORD)}@" if REDIS_PASSWORD else ""
REDIS_STORAGE_URI = os.getenv("LIMITER_STORAGE_URI", f"{_scheme}://{_auth}{REDIS_HOST}:{REDIS_PORT}/1")

try:
    # Fail-closed rate limiter: do NOT swallow errors. If Redis is unreachable,
    # reject requests or engage local fallback with explicit failure logging.
    # Enforce TLS for rate-limit storage (reject unencrypted redis://)
    if REDIS_STORAGE_URI and not REDIS_STORAGE_URI.startswith("rediss://"):
        raise RuntimeError("Redis rate limiter requires TLS (rediss://) — enforce REDIS_SSL=true")
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=REDIS_STORAGE_URI,
        swallow_errors=False
    )
except BaseException as ex:
    logger.error("CRITICAL: Redis rate limiter initialization failed: %s; using strict in-memory fail-closed limiter", ex)
    limiter = Limiter(key_func=get_remote_address, swallow_errors=False)


# --- Authentication ----------------------------------------------------------
API_KEY = os.getenv("TSOC_API_KEY")
if not API_KEY:
    raise RuntimeError("CRITICAL: TSOC_API_KEY must be configured.")

security_bearer = HTTPBearer(auto_error=False)


def _extract_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    if credentials and credentials.credentials:
        return credentials.credentials
    if request.headers.get("X-API-Key"):
        return request.headers.get("X-API-Key")
    auth_hdr = request.headers.get("Authorization")
    if auth_hdr:
        if auth_hdr.lower().startswith("bearer "):
            return auth_hdr[7:].strip()
        return auth_hdr.strip()
    return None


def _constant_time_key_match(token: str) -> bool:
    """Compare as bytes so a non-ASCII header can never raise instead of
    just failing closed (Starlette decodes headers as latin-1, so any byte
    >= 0x80 previously produced a str that secrets.compare_digest rejected
    with a TypeError instead of a 401)."""
    try:
        token_bytes = token.encode("utf-8", "surrogateescape")
        key_bytes = API_KEY.encode("utf-8")
    except Exception:
        return False
    return secrets.compare_digest(token_bytes, key_bytes)


def _authenticate(token: str) -> dict:
    """Returns a principal {"sub": ..., "scopes": [...]} for any valid
    credential, or raises 401. Two credential types are accepted:

    - the static service key (TSOC_API_KEY) — used by trusted internal
      callers such as the dashboard, which has no per-user login flow of
      its own; treated as holding every scope.
    - a JWT minted by api.auth.create_token — scoped and expiring, for any
      caller that should NOT hold blanket access. Revoked fleet-wide by
      rotating TSOC_JWT_SECRET.
    """
    if API_KEY and _constant_time_key_match(token):
        return {"sub": "service-key", "scopes": ["*"]}
    try:
        payload = verify_token(token)
    except (JWTError, RuntimeError):
        payload = None
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key / Authorization Token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return payload


def verify_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> dict:
    """Authenticate the caller without requiring a specific scope."""
    token = _extract_token(request, credentials)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key / Authorization Token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return _authenticate(token)


def require_scope(required_scope: str):
    """FastAPI dependency factory: authenticate the caller AND require the
    resulting principal to hold `required_scope` (or the service key's "*").
    Use this on routes that should reject a validly-authenticated caller
    who simply wasn't issued the right scope."""

    def _dependency(principal: dict = Depends(verify_auth)) -> dict:
        scopes = principal.get("scopes") or []
        if required_scope not in scopes and "*" not in scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Token lacks required scope: {required_scope}",
            )
        return principal

    return _dependency


def get_authenticated_db(
    _principal: dict = Depends(verify_auth)
) -> Session:
    """
    Requires authentication BEFORE allocating a database connection.
    Prevents unauthenticated request pool exhaustion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
