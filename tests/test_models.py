import pytest
from models.model_registry import ThreatModelRegistry


def test_ddos_detection():
    registry = ThreatModelRegistry()
    high_pps_features = {
        "packets_per_second": 1200.0,
        "bytes_per_second": 800000.0,
        "syn_ratio": 10.0,
        "syn_count": 200.0
    }
    alerts = registry.evaluate_flow({}, high_pps_features)
    ddos_alerts = [a for a in alerts if a["threat_class"] == "Volumetric_Protocol_DDoS"]
    assert len(ddos_alerts) == 1
    assert ddos_alerts[0]["confidence_score"] >= 0.70


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
    scan_features = {
        "syn_count": 15.0,
        "ack_count": 0.0,
        "syn_ratio": 15.0,
        "packets_per_second": 30.0
    }
    alerts = registry.evaluate_flow({}, scan_features)
    scan_alerts = [a for a in alerts if a["threat_class"] == "Reconnaissance_Port_Scanning"]
    assert len(scan_alerts) == 1
    assert scan_alerts[0]["confidence_score"] >= 0.70


def test_exfiltration_detection():
    registry = ThreatModelRegistry()
    exfil_features = {
        "total_bytes": 50000.0,
        "bytes_per_second": 60000.0,
        "payload_to_header_ratio": 35.0,
        "pkt_len_mean": 1400.0
    }
    alerts = registry.evaluate_flow({}, exfil_features)
    exfil_alerts = [a for a in alerts if a["threat_class"] == "Data_Exfiltration"]
    assert len(exfil_alerts) == 1
    assert exfil_alerts[0]["confidence_score"] >= 0.85

