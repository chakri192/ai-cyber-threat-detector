# Endpoint-level smoke tests; no embedded secrets; no test code in CI.
# Env vars required for api.main to import (TSOC_API_KEY, DATABASE_URL, ...)
# are provided by tests/conftest.py before this module is collected.
import os

from fastapi.testclient import TestClient

from api.auth import create_token
from api.main import app

API_KEY = os.environ["TSOC_API_KEY"]


def test_livez():
    client = TestClient(app)
    r = client.get("/livez")
    assert r.status_code == 200
    assert r.json()["status"] == "alive"


def test_readyz():
    client = TestClient(app)
    r = client.get("/readyz")
    assert r.status_code == 200


def test_healthz():
    client = TestClient(app)
    r = client.get("/healthz")
    assert r.json()["status"] == "ok"


def test_auth_bypass_fails():
    client = TestClient(app)
    # No token should fail
    r = client.get("/api/v1/alerts")
    assert r.status_code == 401


def test_auth_static_service_key_succeeds():
    # The dashboard authenticates with the static service key, not a JWT —
    # it must keep working end-to-end through get_authenticated_db.
    with TestClient(app) as client:
        r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {API_KEY}"})
        assert r.status_code == 200
        assert r.json() == []  # empty DB, but a real 200 with a real list


def test_auth_jwt_scope():
    # A token minted with the required scope must actually decode with
    # that scope intact, and must be accepted by the scoped endpoint.
    token = create_token(scopes=["alerts:read"])
    assert isinstance(token, str) and len(token) > 0

    from api.auth import verify_token
    payload = verify_token(token)
    assert payload["scopes"] == ["alerts:read"]

    with TestClient(app) as client:
        r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


def test_auth_jwt_wrong_scope_is_rejected():
    # A validly-signed token that simply lacks the required scope must be
    # a 403, not treated as equivalent to a fully-authenticated caller.
    token = create_token(scopes=["stats:read"])
    with TestClient(app) as client:
        r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403


def test_auth_jwt_tampered_signature_is_rejected():
    token = create_token(scopes=["alerts:read"])
    tampered = token[:-4] + ("A" if token[-4] != "A" else "B") + token[-3:]
    with TestClient(app) as client:
        r = client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {tampered}"})
        assert r.status_code == 401


def test_injection_cap():
    # Cursor pagination must reject an excessive limit at the schema layer
    # (Query(..., le=100)) — a 422, not a silently-truncated or accepted value.
    with TestClient(app) as client:
        r = client.get(
            "/api/v1/alerts",
            params={"limit": 500},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        assert r.status_code == 422

        r_ok = client.get(
            "/api/v1/alerts",
            params={"limit": 100},
            headers={"Authorization": f"Bearer {API_KEY}"},
        )
        assert r_ok.status_code == 200


def test_fuzz_auth_header():
    # Malformed headers must resolve to a clean 401 — never a 500. This is
    # the regression test for the secrets.compare_digest(token, API_KEY)
    # TypeError on non-ASCII input, which previously escaped as an
    # unhandled 500 and was masked by this same test accepting 500 as
    # "fail-safe."
    client = TestClient(app)
    for bad in ["Bearer ", "Bearer invalid", "Basic dGVzdA==", ""]:
        r = client.get("/api/v1/alerts", headers={"Authorization": bad})
        assert r.status_code == 401, f"expected 401 for {bad!r}, got {r.status_code}"

    # A raw non-ASCII byte in the header (bytes, not str, to get past
    # httpx's own client-side ascii-only encoding and actually reach the
    # server — ASGI/Starlette decodes incoming header bytes as latin-1, so
    # this is what a real malicious client's raw socket request produces).
    r = client.get("/api/v1/alerts", headers={"Authorization": b"Bearer \xff\xff\xff"})
    assert r.status_code == 401, f"expected 401 for a non-ASCII header, got {r.status_code}"


def test_rate_limit_actually_returns_429_past_the_configured_threshold():
    # @limiter.limit("100/minute") on GET /api/v1/alerts was previously
    # only ever unit-tested for its key function (proxy spoofing,
    # exhaustion isolation) -- never proven to actually reject a caller
    # who exceeds it through the real endpoint. `limiter` is a
    # process-wide singleton shared with every other test in this
    # session, so its storage is reset before and after to avoid this
    # test being polluted by (or polluting) unrelated tests' request counts.
    from api.deps import limiter

    limiter.reset()
    try:
        with TestClient(app) as client:
            statuses = [
                client.get("/api/v1/alerts", headers={"Authorization": f"Bearer {API_KEY}"}).status_code
                for _ in range(105)
            ]
        assert statuses.count(200) <= 100
        assert 429 in statuses
    finally:
        limiter.reset()
