from response.rule_generator import generate_response_rules, build_rules_bundle
from reporting.incident_report import build_incident_report


def _alert(**overrides):
    base = {
        "id": 1, "timestamp": "2026-01-01T00:00:00+00:00", "flow_id": "10.0.0.5:4000->203.0.113.9:4444_TCP",
        "src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "src_port": 4000, "dst_port": 4444, "protocol": "TCP",
        "threat_class": "Botnet_C2_Beaconing", "severity": "CRITICAL", "confidence_score": 0.92,
        "evidence": {"iat_variance": 0.0},
    }
    base.update(overrides)
    return base


def test_c2_rules_block_the_channel():
    rules = generate_response_rules(_alert())
    assert "iptables -A FORWARD -s 10.0.0.5 -d 203.0.113.9 -j DROP" in rules["iptables"]
    assert rules["suricata"].startswith("drop tcp 10.0.0.5 any -> 203.0.113.9 4444")
    assert "sid:" in rules["suricata"]


def test_ipv6_uses_ip6tables():
    rules = generate_response_rules(_alert(src_ip="2001:db8::1", dst_ip="2001:db8::2"))
    assert rules["iptables"].startswith("ip6tables")


def test_attacker_controlled_domain_cannot_inject_shell_or_rule_options():
    evil = _alert(threat_class="DGA_Domains_and_DNS_Tunneling",
                  evidence={"queried_domain": 'a$(reboot)`id`";sid:1;.evil.com'})
    rules = generate_response_rules(evil)
    for text in (rules["iptables"], rules["suricata"]):
        assert "$(" not in text and "`" not in text
    # The injected "sid:1;" option must not survive as a second rule option
    assert rules["suricata"].count("sid:") == 1
    assert "arebootidsid1.evil.com" in rules["suricata"]


def test_bundle_deduplicates_rules():
    bundle = build_rules_bundle([_alert(id=1), _alert(id=2)])
    assert bundle["iptables_sh"].count("-s 10.0.0.5 -d 203.0.113.9 -j DROP") == 1


def test_report_escapes_evidence():
    report = build_incident_report([_alert(evidence={"queried_domain": "<script>alert(1)</script>.biz"})])
    assert "<script>alert(1)" not in report
    assert "&lt;script&gt;" in report
    assert "T1071" in report
