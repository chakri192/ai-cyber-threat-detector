"""api/kafka_sink.py had 0% coverage despite carrying the mass-assignment
fix (validate every Kafka payload through AlertPayload BEFORE it ever
reaches Alert(**alert_dict), so an attacker-controlled message can't set
"id" or a SQLAlchemy internal attribute name) and the DLQ rotation/file
fallback logic. process_batch/_safe_dlq_send were previously nested
closures inside run_sink() -- only reachable through a live Kafka
consumer loop -- so they were pulled out to module level to make this
directly testable against the real (sqlite, in tests) SessionLocal.
"""
import json
from unittest.mock import MagicMock

import pytest

from api.kafka_sink import (
    _rotate_dlq_if_needed,
    _safe_dlq_send,
    process_batch,
    send_to_dlq,
    write_to_file_dlq,
)
from api.database import SessionLocal
from api.models import Alert


@pytest.fixture(autouse=True)
def _clean_alerts_table():
    db = SessionLocal()
    try:
        db.query(Alert).delete()
        db.commit()
    finally:
        db.close()
    yield


def _valid_raw_item(alert_id="ALT-test-1", **overrides):
    item = {
        "alert_id": alert_id,
        "timestamp": "2026-09-05T00:00:00Z",
        "event_type": "dns",
        "threat_class": "DGA",
        "confidence_score": 0.9,
        "severity": "high",
        "source_ip": "10.0.0.1",
        "destination_ip": "10.0.0.2",
        "evidence": {"domain": "bad.example"},
    }
    item.update(overrides)
    return item


class TestProcessBatchValidation:
    def test_valid_item_is_inserted(self):
        item = _valid_raw_item()
        offsets = process_batch([(item, "tp0", 0)])
        assert offsets == {"tp0": 1}

        db = SessionLocal()
        try:
            row = db.query(Alert).filter(Alert.alert_id == "ALT-test-1").first()
            assert row is not None
            assert row.threat_class == "DGA"
        finally:
            db.close()

    def test_mass_assignment_payload_cannot_set_primary_key_or_orm_internals(self):
        """An attacker-influenced Kafka message trying to inject "id" or a
        SQLAlchemy internal attribute name must never reach Alert(**dict) --
        AlertPayload has no such fields, so pydantic strips/rejects them
        before the ORM ever sees the payload."""
        item = _valid_raw_item(alert_id="ALT-evil-1")
        item["id"] = 999999
        item["metadata"] = "malicious-override"
        item["registry"] = "malicious-override"

        offsets = process_batch([(item, "tp0", 0)])
        assert offsets == {"tp0": 1}

        db = SessionLocal()
        try:
            row = db.query(Alert).filter(Alert.alert_id == "ALT-evil-1").first()
            assert row is not None
            assert row.id != 999999
        finally:
            db.close()

    def test_invalid_item_routes_to_dlq_and_still_advances_offset(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        monkeypatch.setattr(sink, "DLQ_PATH", str(tmp_path / "alerts.jsonl"))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(tmp_path / "alerts.jsonl.lock"))

        bad_item = {"not_a_valid_field": "whatever"}  # missing required alert_id etc.
        offsets = process_batch([(bad_item, "tp0", 5)])

        # A poisoned message must not stall the partition -- offset still advances.
        assert offsets == {"tp0": 6}
        dlq_content = (tmp_path / "alerts.jsonl").read_text()
        assert "not_a_valid_field" in dlq_content or "whatever" in dlq_content

    def test_existing_alert_is_updated_not_duplicated(self):
        process_batch([(_valid_raw_item(severity="low"), "tp0", 0)])
        process_batch([(_valid_raw_item(severity="high"), "tp0", 1)])

        db = SessionLocal()
        try:
            rows = db.query(Alert).filter(Alert.alert_id == "ALT-test-1").all()
            assert len(rows) == 1
            assert rows[0].severity == "high"
        finally:
            db.close()

    def test_evidence_dict_is_serialized_to_json_string(self):
        process_batch([(_valid_raw_item(alert_id="ALT-evidence-1"), "tp0", 0)])
        db = SessionLocal()
        try:
            row = db.query(Alert).filter(Alert.alert_id == "ALT-evidence-1").first()
            assert isinstance(row.evidence, str)
            assert json.loads(row.evidence) == {"domain": "bad.example"}
        finally:
            db.close()

    def test_db_failure_rolls_back_and_returns_no_offsets(self):
        db_mock = MagicMock()
        db_mock.query.return_value.filter.return_value.first.return_value = None
        db_mock.commit.side_effect = RuntimeError("connection lost")

        offsets = process_batch(
            [(_valid_raw_item(), "tp0", 0)],
            session_factory=lambda expire_on_commit=False: db_mock,
        )
        assert offsets == {}
        db_mock.rollback.assert_called_once()


class TestDlqHelpers:
    def test_send_to_dlq_never_raises_when_producer_is_none(self):
        send_to_dlq(None, {"alert_id": "x"}, "boom")  # must not raise

    def test_send_to_dlq_never_raises_when_producer_send_fails(self):
        producer = MagicMock()
        producer.send.side_effect = RuntimeError("broker unreachable")
        send_to_dlq(producer, {"alert_id": "x"}, "boom")  # must not raise

    def test_safe_dlq_send_falls_back_to_file_when_kafka_fails(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(dlq_path) + ".lock")

        producer = MagicMock()
        producer.send.side_effect = RuntimeError("broker unreachable")
        _safe_dlq_send(producer, "ALT-1", {"alert_id": "ALT-1"}, "some error")

        assert dlq_path.exists()
        line = json.loads(dlq_path.read_text().splitlines()[0])
        assert line["alert"] == {"alert_id": "ALT-1"}
        assert line["error"] == "some error"

    def test_write_to_file_dlq_appends_jsonl(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_LOCK_PATH", str(dlq_path) + ".lock")

        write_to_file_dlq({"alert_id": "a"}, "err-1")
        write_to_file_dlq({"alert_id": "b"}, "err-2")

        lines = dlq_path.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["error"] == "err-1"
        assert json.loads(lines[1])["error"] == "err-2"

    def test_rotate_dlq_if_needed_rotates_oversized_file(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        dlq_path.write_bytes(b"x" * (1024 * 1024))  # 1 MiB
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_MAX_SIZE_MB", 0)  # force rotation regardless of real size
        monkeypatch.setattr(sink, "DLQ_ROTATE_COUNT", 3)

        _rotate_dlq_if_needed()

        assert (tmp_path / "alerts.jsonl.1").exists()
        assert dlq_path.exists()
        assert dlq_path.read_bytes() == b""  # freshly recreated, empty

    def test_rotate_dlq_if_needed_is_a_noop_when_under_limit(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        dlq_path.write_text("small")
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_MAX_SIZE_MB", 100)

        _rotate_dlq_if_needed()

        assert dlq_path.read_text() == "small"

    def test_rotate_dlq_if_needed_never_raises_on_filesystem_error(self, tmp_path, monkeypatch):
        import api.kafka_sink as sink

        dlq_path = tmp_path / "alerts.jsonl"
        dlq_path.write_text("x")
        monkeypatch.setattr(sink, "DLQ_PATH", str(dlq_path))
        monkeypatch.setattr(sink, "DLQ_MAX_SIZE_MB", 0)
        monkeypatch.setattr(sink.os.path, "getsize", MagicMock(side_effect=OSError("disk error")))
        _rotate_dlq_if_needed()  # must not raise
