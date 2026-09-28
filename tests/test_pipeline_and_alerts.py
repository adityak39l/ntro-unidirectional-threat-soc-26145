import os
import pytest
from alerts.alert_manager import AlertManager, StandardAlert
from detection.pipeline import StreamingDetectionPipeline


def test_alert_creation_and_storage(tmp_path):
    jsonl = str(tmp_path / "test_alerts.jsonl")
    db = str(tmp_path / "test_alerts.db")
    mgr = AlertManager(jsonl_path=jsonl, db_path=db, cooldown_sec=2.0)

    flow = {
        "flow_id": "192.168.1.100:5000->10.0.0.1:80_TCP",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 5000,
        "dst_port": 80,
        "protocol": "TCP"
    }
    threat = {
        "threat_class": "Volumetric_Protocol_DDoS",
        "confidence_score": 0.95,
        "evidence": {"packets_per_sec": 1500}
    }

    alert = StandardAlert.create(flow, threat)
    assert alert["severity"] == "CRITICAL"
    assert alert["confidence_score"] == 0.95

    # Publish
    assert mgr.publish_alert(alert) is True
    # Immediate duplicate should be suppressed
    assert mgr.publish_alert(alert) is False

    # Check DB
    records = mgr.get_recent_alerts(limit=10)
    assert len(records) == 1
    assert records[0]["threat_class"] == "Volumetric_Protocol_DDoS"


def test_pipeline_integration(tmp_path):
    jsonl = str(tmp_path / "pipe_alerts.jsonl")
    db = str(tmp_path / "pipe_alerts.db")
    pipeline = StreamingDetectionPipeline(alert_jsonl=jsonl, alert_db=db)

    # Ingest a series of SYN flood packets
    for i in range(100):
        pkt = {
            "timestamp": 1000.0 + (i * 0.001),
            "src_ip": "172.16.0.4",
            "dst_ip": "10.0.0.1",
            "src_port": 40000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "packet_length": 64,
            "payload_length": 0,
            "tcp_flags": {"SYN": True, "ACK": False},
            "raw_payload": b""
        }
        pipeline.process_packet(pkt)

    alerts = pipeline.flush_and_complete()
    stats = pipeline.get_stats()
    assert stats["total_packets"] == 100


ATTACK_EXPECTATIONS = {
    "ddos": "Volumetric_Protocol_DDoS",
    "beaconing": "Botnet_C2_Beaconing",
    "dga": "DGA_Domains_and_DNS_Tunneling",
    "port_scan": "Reconnaissance_Port_Scanning",
    "encrypted_malware": "Encrypted_Malware_TLS",
    "exfiltration": "Data_Exfiltration",
}


def _run_simulated(tmp_path, attack):
    from traffic_simulator.generate_traffic import generate_synthetic_pcap
    from ingestion.pcap_reader import ReadOnlyPacketReader
    pcap = str(tmp_path / f"{attack}.pcap")
    generate_synthetic_pcap(attack_type=attack, output_path=pcap)
    pipeline = StreamingDetectionPipeline(alert_jsonl=str(tmp_path / "a.jsonl"), alert_db=str(tmp_path / "a.db"), idle_timeout=2.0)
    alerts = []
    for pkt in ReadOnlyPacketReader(pcap).read_packets():
        alerts.extend(pipeline.process_packet(pkt))
    alerts.extend(pipeline.flush_and_complete())
    return alerts


@pytest.mark.parametrize("attack", list(ATTACK_EXPECTATIONS))
def test_each_simulated_attack_detected_as_its_own_class(tmp_path, attack):
    alerts = _run_simulated(tmp_path, attack)
    classes = {a["threat_class"] for a in alerts}
    assert classes == {ATTACK_EXPECTATIONS[attack]}
    # One incident, not one alert per spoofed packet
    if attack in ("ddos", "port_scan"):
        assert len(alerts) == 1


def test_benign_traffic_raises_no_alerts(tmp_path):
    assert _run_simulated(tmp_path, "benign") == []


def test_alert_timestamp_is_traffic_time(tmp_path):
    mgr = AlertManager(jsonl_path=str(tmp_path / "t.jsonl"), db_path=str(tmp_path / "t.db"))
    flow = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "last_time": 1577836800.0}  # 2020-01-01 UTC
    alert = StandardAlert.create(flow, {"threat_class": "Data_Exfiltration", "confidence_score": 0.9})
    assert alert["timestamp"].startswith("2020-01-01T00:00:00")
