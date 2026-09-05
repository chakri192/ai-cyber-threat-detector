"""ingest/simulator.py had 0% coverage. It constructs a real KafkaProducer
at import time (connecting to REDPANDA_BROKERS, exiting the process on
failure), so kafka.KafkaProducer must be patched BEFORE the module is
first imported -- otherwise merely importing it in a test environment
with no reachable broker crashes with SystemExit.
"""
import sys
from unittest.mock import MagicMock, patch

with patch("kafka.KafkaProducer", return_value=MagicMock()):
    import ingest.simulator as simulator


def test_generate_conn_log_normal_traffic_shape():
    event = simulator.generate_conn_log(is_attack=False)
    assert event["conn_state"] == "SF"
    assert event["attack_label"] == "normal"
    assert event["event_type"] == "conn"
    assert "ja4" not in event


def test_generate_conn_log_reconnaissance_scan_shape():
    event = simulator.generate_conn_log(is_attack=True, attack_type="reconnaissance")
    assert event["conn_state"] == "S0"
    assert 1 <= event["orig_pkts"] <= 3
    assert 1 <= event["id.resp_p"] <= 1024
    assert event["attack_label"] == "reconnaissance"


def test_generate_conn_log_ddos_shape():
    event = simulator.generate_conn_log(is_attack=True, attack_type="ddos")
    assert event["conn_state"] == "REJ"
    assert event["orig_pkts"] >= 15000


def test_generate_conn_log_data_exfiltration_shape():
    event = simulator.generate_conn_log(is_attack=True, attack_type="data_exfiltration")
    assert event["orig_bytes"] >= 6_000_000
    assert event["resp_bytes"] <= 5000


def test_generate_conn_log_encrypted_malware_ja4_matches_the_calibrated_rule():
    # This exact fingerprint is what inference/rules.py's JA4 rule was
    # recalibrated against -- if either side drifts, detection silently
    # stops firing on the simulator's own demo traffic.
    event = simulator.generate_conn_log(is_attack=True, attack_type="encrypted_malware")
    assert event["ja4"] == "t13d000000_rare_fingerprint"


def test_generate_dns_log_normal_traffic():
    event = simulator.generate_dns_log(is_attack=False)
    assert event["query"] in ["google.com", "apple.com", "cloudflare.com"]
    assert event["rcode"] == 0
    assert event["rcode_name"] == "NOERROR"


def test_generate_dns_log_dga_tunnelling_shape():
    event = simulator.generate_dns_log(is_attack=True, attack_type="dga_dns_tunnelling")
    assert event["query"].endswith(".malicious-tunnel.com")
    assert event["qtype_name"] == "TXT"
    assert event["attack_label"] == "dga_dns_tunnelling"
