import pytest
from models.model_registry import ThreatModelRegistry


def _syn(ts, src, dst, dport=80):
    return {"timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": 40000, "dst_port": dport,
            "protocol": "TCP", "packet_length": 60, "payload_length": 0,
            "tcp_flags": {"SYN": True, "ACK": False}, "raw_payload": b""}


def test_ddos_detection():
    registry = ThreatModelRegistry()
    # 600 half-open SYNs in 1.2 s from 200 sources -> one target
    packets = [_syn(1000.0 + i * 0.002, f"172.16.0.{i % 200}", "10.0.0.1") for i in range(600)]
    alerts = registry.evaluate_window(packets, 1000.0, 1003.0)
    ddos_alerts = [a for a in alerts if a["threat_class"] == "Volumetric_Protocol_DDoS"]
    assert len(ddos_alerts) == 1
    assert ddos_alerts[0]["confidence_score"] >= 0.90
    assert ddos_alerts[0]["flow"]["dst_ip"] == "10.0.0.1"
    assert ddos_alerts[0]["evidence"]["unique_sources"] == 200
    # Spoofed sources each send a single port: must not be mistaken for a scan
    assert not [a for a in alerts if a["threat_class"] == "Reconnaissance_Port_Scanning"]


def test_busy_server_with_completed_handshakes_is_not_ddos():
    registry = ThreatModelRegistry()
    packets = []
    for i in range(600):
        pkt = _syn(1000.0 + i * 0.002, f"10.1.0.{i % 50}", "10.0.0.1", dport=443)
        pkt["tcp_flags"] = {"ACK": True, "PSH": True}
        packets.append(pkt)
    alerts = registry.evaluate_window(packets, 1000.0, 1003.0)
    assert alerts == []


def test_beaconing_detection():
    registry = ThreatModelRegistry()
    beacon_features = {
        "packet_count": 25.0,
        "iat_mean": 5.0,
        "iat_variance": 0.002,
        "iat_cv": 0.05
    }
    alerts = registry.evaluate_flow({}, beacon_features)
    beacon_alerts = [a for a in alerts if a["threat_class"] == "Botnet_C2_Beaconing"]
    assert len(beacon_alerts) == 1
    assert beacon_alerts[0]["confidence_score"] >= 0.80


def test_dga_detection():
    registry = ThreatModelRegistry()
    dga_features = {
        "dns_entropy": 4.25,
        "dns_query_len": 45.0,
        "is_dns_suspect": 1.0
    }
    alerts = registry.evaluate_flow({}, dga_features)
    dga_alerts = [a for a in alerts if a["threat_class"] == "DGA_Domains_and_DNS_Tunneling"]
    assert len(dga_alerts) == 1
    assert dga_alerts[0]["confidence_score"] >= 0.90


def test_encrypted_malware_ja3_match():
    registry = ThreatModelRegistry()
    flow_with_ja3 = {"ja3_hash": "6734f37431670e3ab732c3f8b3799e56"}
    features = {"is_tls": 1.0}
    alerts = registry.evaluate_flow(flow_with_ja3, features)
    malware_alerts = [a for a in alerts if a["threat_class"] == "Encrypted_Malware_TLS"]
    assert len(malware_alerts) == 1
    assert malware_alerts[0]["evidence"]["matched_threat"] == "Cobalt_Strike"


def test_port_scan_detection():
    registry = ThreatModelRegistry()
    ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
    packets = [_syn(1000.0 + i * 0.05, "192.168.9.10", "10.0.0.50", dport=p) for i, p in enumerate(ports)]
    alerts = registry.evaluate_window(packets, 1000.0, 1003.0)
    scan_alerts = [a for a in alerts if a["threat_class"] == "Reconnaissance_Port_Scanning"]
    assert len(scan_alerts) == 1
    assert scan_alerts[0]["confidence_score"] >= 0.70
    assert scan_alerts[0]["evidence"]["distinct_ports_on_one_host"] == 13
    assert scan_alerts[0]["flow"]["src_ip"] == "192.168.9.10"


def test_single_connection_is_not_a_scan():
    registry = ThreatModelRegistry()
    alerts = registry.evaluate_window([_syn(1000.0, "192.168.1.5", "10.0.0.1", dport=443)], 1000.0, 1003.0)
    assert alerts == []


def test_dga_benign_domain_not_flagged():
    registry = ThreatModelRegistry()
    features = {"dns_entropy": 2.9, "dns_query_len": 13.0, "is_dns_suspect": 0.0, "dns_dga_signals": 2.0}
    alerts = registry.evaluate_flow({}, features, {"dns_query": "microsoft.com"})
    assert not [a for a in alerts if a["threat_class"] == "DGA_Domains_and_DNS_Tunneling"]


def test_encrypted_malware_clienthello_anomalies():
    registry = ThreatModelRegistry()
    implant = {"is_tls": 1.0, "tls_complete": 1.0, "tls_version": 0x0301, "cipher_count": 2.0,
               "tls_extension_count": 1.0, "tls_has_sni": 0.0, "dst_port": 4444.0}
    alerts = registry.evaluate_flow({}, implant, {"ja3_hash": "1868decfdb317f601b4ff3cf7e93db89"})
    malware = [a for a in alerts if a["threat_class"] == "Encrypted_Malware_TLS"]
    assert len(malware) == 1
    assert "no SNI (server name hidden)" in malware[0]["evidence"]["anomalies"]

    browser = {"is_tls": 1.0, "tls_complete": 1.0, "tls_version": 0x0303, "cipher_count": 15.0,
               "tls_extension_count": 9.0, "tls_has_sni": 1.0, "dst_port": 443.0}
    assert registry.evaluate_flow({}, browser, {}) == []


def test_exfiltration_detection():
    registry = ThreatModelRegistry()
    exfil_features = {
        "total_bytes": 800000.0,
        "bytes_per_second": 600000.0,
        "payload_to_header_ratio": 35.0,
        "pkt_len_mean": 1400.0
    }
    alerts = registry.evaluate_flow({}, exfil_features)
    exfil_alerts = [a for a in alerts if a["threat_class"] == "Data_Exfiltration"]
    assert len(exfil_alerts) == 1
    assert exfil_alerts[0]["confidence_score"] >= 0.85

