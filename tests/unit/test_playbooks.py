"""inference/playbooks.py sat at 20% coverage despite carrying the RFC1918
fix: a naive string-prefix check ("172.16") previously misclassified most
of the real 172.16.0.0/12 block as external while treating genuinely
public 172.160.0.0-172.169.255.255 as internal/trusted. It was replaced
with the same ipaddress-module logic inference/enrichment.py already used
correctly -- these tests exercise that boundary directly, plus the
command-injection-safe shell quoting in generate_playbook().
"""
from inference.playbooks import (
    enrich_ip_intel,
    generate_playbook,
    safe_format_string,
    sanitize_input,
)


class TestEnrichIpIntel:
    def test_empty_or_none_ip_is_trusted(self):
        assert enrich_ip_intel("")["reputation"] == "Trusted"
        assert enrich_ip_intel(None)["reputation"] == "Trusted"

    def test_rfc1918_172_block_is_trusted(self):
        # The bulk of 172.16.0.0/12 that a naive "172.16" prefix check
        # would have misclassified as external.
        result = enrich_ip_intel("172.20.5.5")
        assert result["reputation"] == "Trusted"
        assert result["country"] == "Internal / RFC1918"

    def test_public_172_range_just_outside_rfc1918_is_not_trusted(self):
        # 172.160.0.0-172.169.255.255 is genuinely public; the old
        # naive "172.16" string-prefix check misclassified it as internal.
        result = enrich_ip_intel("172.160.1.1")
        assert result["reputation"] != "Trusted"

    def test_loopback_and_link_local_are_trusted(self):
        assert enrich_ip_intel("127.0.0.1")["reputation"] == "Trusted"
        assert enrich_ip_intel("169.254.1.1")["reputation"] == "Trusted"

    def test_public_ip_gets_deterministic_non_trusted_mock_intel(self):
        first = enrich_ip_intel("8.8.8.8")
        second = enrich_ip_intel("8.8.8.8")
        assert first == second  # deterministic given the same input
        assert first["country"] != "Internal / RFC1918"
        assert first["reputation"] in ("Suspicious (Known Bulletproof Hoster)", "Neutral")

    def test_malformed_ip_falls_back_to_trusted_rather_than_crashing(self):
        result = enrich_ip_intel("not-an-ip-address")
        assert result["reputation"] == "Trusted"


class TestSanitizeInput:
    def test_none_uses_default(self):
        assert sanitize_input(None, default="fallback") == "fallback"

    def test_strips_control_chars_and_null_bytes(self):
        assert sanitize_input("abc\r\ndef\x00ghi") == "abcdefghi"

    def test_coerces_non_string_to_string(self):
        assert sanitize_input(443) == "443"


class TestSafeFormatString:
    def test_replaces_known_placeholder(self):
        assert safe_format_string("hello {name}", name="world") == "hello world"

    def test_leaves_unknown_placeholder_untouched(self):
        assert safe_format_string("hi {x}") == "hi {x}"


class TestGeneratePlaybook:
    def test_ddos_alert_maps_to_volumetric_template(self):
        playbook = generate_playbook({"threat_class": "ddos", "destination_port": 80})
        assert playbook["title"] == "Volumetric & Protocol DDoS Containment"
        assert "80" in playbook["recommended_firewall_rule"]

    def test_unknown_threat_class_falls_back_to_data_exfiltration_template(self):
        playbook = generate_playbook({"threat_class": "some-unmapped-value"})
        assert playbook["title"] == "High-Volume Unilateral Data Exfiltration Response"

    def test_shell_metacharacters_in_ip_are_quoted_not_injected(self):
        malicious_src_ip = "1.2.3.4; rm -rf /"
        playbook = generate_playbook({
            "threat_class": "BOTNET_C2_BEACONING",
            "source_ip": malicious_src_ip,
            "destination_ip": "5.6.7.8",
        })
        rule = playbook["recommended_firewall_rule"]
        # shlex.quote must wrap the malicious value so it can never be
        # interpreted as a second shell command if this string is ever
        # passed to a SOAR automation's shell execution.
        assert "; rm -rf /" not in rule or "'1.2.3.4; rm -rf /'" in rule

    def test_missing_fields_use_safe_defaults(self):
        playbook = generate_playbook({})
        assert playbook["threat_intel"]["source"]["reputation"] == "Trusted"
        assert isinstance(playbook["recommended_firewall_rule"], str)

    def test_evidence_domain_flows_into_firewall_rule(self):
        playbook = generate_playbook({
            "threat_class": "DGA",
            "evidence": {"domain": "evil-dga-domain.biz"},
        })
        assert "evil-dga-domain.biz" in playbook["recommended_firewall_rule"]
