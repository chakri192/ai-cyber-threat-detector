"""Integration tests: Kafka-shaped ingestion -> real (sqlite) DB -> real
authenticated FastAPI endpoint, exercised together end-to-end.

tests/test_api_endpoints.py covers the auth boundary in isolation
(always against an empty DB); tests/unit/test_kafka_sink.py covers
process_batch's validation-before-ORM logic in isolation. Neither
previously proved that a message accepted by the ingestion pipeline is
actually the same data a caller reads back through the API, or that a
message REJECTED by the pipeline never becomes visible through it --
this file closes that gap.

tests/integration/ and tests/fixtures/ existed as empty placeholders
since an earlier remediation pass; this is the first real content in
either.
"""
import os

import pytest
from fastapi.testclient import TestClient

from api.database import SessionLocal
from api.kafka_sink import process_batch
from api.main import app
from api.models import Alert

API_KEY = os.environ["TSOC_API_KEY"]
AUTH_HEADERS = {"Authorization": f"Bearer {API_KEY}"}


@pytest.fixture(autouse=True)
def _clean_alerts_table():
    def _clear():
        db = SessionLocal()
        try:
            db.query(Alert).delete()
            db.commit()
        finally:
            db.close()

    _clear()
    yield
    _clear()


def _kafka_message(alert_id, **overrides):
    msg = {
        "alert_id": alert_id,
        "timestamp": "2026-09-06T00:00:00Z",
        "event_type": "dns",
        "threat_class": "DGA",
        "severity": "high",
        "confidence_score": 0.97,
        "source_ip": "10.0.0.5",
        "destination_ip": "8.8.8.8",
        "evidence": {"domain": "bad-example.biz"},
    }
    msg.update(overrides)
    return msg


def test_ingested_alert_is_readable_through_the_authenticated_api():
    offsets = process_batch([(_kafka_message("ALT-int-1"), "tp0", 0)])
    assert offsets == {"tp0": 1}

    with TestClient(app) as client:
        r = client.get("/api/v1/alerts", headers=AUTH_HEADERS)
        assert r.status_code == 200
        body = r.json()
        assert len(body) == 1
        assert body[0]["alert_id"] == "ALT-int-1"
        assert body[0]["threat_class"] == "DGA"
        assert body[0]["severity"] == "high"


def test_ingested_alert_is_readable_by_id():
    process_batch([(_kafka_message("ALT-int-2", threat_class="RECON_PORT_SCAN"), "tp0", 0)])

    with TestClient(app) as client:
        r = client.get("/api/v1/alerts/ALT-int-2", headers=AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json()["threat_class"] == "RECON_PORT_SCAN"

        r_missing = client.get("/api/v1/alerts/ALT-does-not-exist", headers=AUTH_HEADERS)
        assert r_missing.status_code == 404


def test_cursor_pagination_round_trip_through_the_real_endpoint():
    batch = [
        (_kafka_message(f"ALT-int-page-{i}"), "tp0", i)
        for i in range(3)
    ]
    process_batch(batch)

    with TestClient(app) as client:
        first_page = client.get(
            "/api/v1/alerts", params={"limit": 2}, headers=AUTH_HEADERS
        ).json()
        assert len(first_page) == 2
        # order_by(Alert.id.desc()): most-recently-inserted row comes first.
        assert first_page[0]["alert_id"] == "ALT-int-page-2"

        cursor = first_page[-1]["id"]
        second_page = client.get(
            "/api/v1/alerts",
            params={"limit": 2, "cursor": cursor},
            headers=AUTH_HEADERS,
        ).json()
        assert len(second_page) == 1
        assert second_page[0]["alert_id"] == "ALT-int-page-0"

        seen_ids = {a["alert_id"] for a in first_page + second_page}
        assert seen_ids == {"ALT-int-page-0", "ALT-int-page-1", "ALT-int-page-2"}


def test_a_message_the_pipeline_rejects_never_becomes_visible_through_the_api():
    # Missing every required AlertPayload field (alert_id, event_type,
    # timestamp, threat_class, severity, confidence_score, source_ip) --
    # process_batch must route it to the DLQ path, not the DB.
    bad_message = {"garbage": "not a real alert"}
    offsets = process_batch([(bad_message, "tp0", 0)])
    assert offsets == {"tp0": 1}  # offset still advances past the poison message

    with TestClient(app) as client:
        r = client.get("/api/v1/alerts", headers=AUTH_HEADERS)
        assert r.status_code == 200
        assert r.json() == []


def test_unauthenticated_caller_gets_401_even_with_real_data_present():
    process_batch([(_kafka_message("ALT-int-secret"), "tp0", 0)])

    client = TestClient(app)
    r = client.get("/api/v1/alerts")
    assert r.status_code == 401
    assert "ALT-int-secret" not in r.text


def test_reingesting_the_same_alert_id_updates_rather_than_duplicates():
    process_batch([(_kafka_message("ALT-int-dedup", severity="low"), "tp0", 0)])
    process_batch([(_kafka_message("ALT-int-dedup", severity="critical"), "tp0", 1)])

    with TestClient(app) as client:
        r = client.get("/api/v1/alerts", headers=AUTH_HEADERS)
        matches = [a for a in r.json() if a["alert_id"] == "ALT-int-dedup"]
        assert len(matches) == 1
        assert matches[0]["severity"] == "critical"
