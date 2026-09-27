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
