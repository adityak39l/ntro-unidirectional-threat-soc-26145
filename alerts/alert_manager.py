import os
import json
import sqlite3
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone


class StandardAlert:
    @staticmethod
    def create(flow_dict: Dict[str, Any], threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Timestamp is the traffic time of the evidence (so replayed PCAPs keep their timeline)."""
        conf = threat_info.get("confidence_score", 0.0)
        if conf >= 0.90:
            severity = "CRITICAL"
        elif conf >= 0.80:
            severity = "HIGH"
        elif conf >= 0.70:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        event_time = flow_dict.get("last_time")
        if event_time:
            ts = datetime.fromtimestamp(float(event_time), timezone.utc).isoformat()
        else:
            ts = datetime.now(timezone.utc).isoformat()

        return {
            "timestamp": ts,
            "flow_id": flow_dict.get("flow_id", "0.0.0.0:0->0.0.0.0:0_OTHER"),
            "src_ip": flow_dict.get("src_ip", "0.0.0.0"),
            "dst_ip": flow_dict.get("dst_ip", "0.0.0.0"),
            "src_port": flow_dict.get("src_port", 0),
            "dst_port": flow_dict.get("dst_port", 0),
            "protocol": flow_dict.get("protocol", "OTHER"),
            "threat_class": threat_info.get("threat_class", "UNKNOWN"),
            "severity": severity,
            "confidence_score": float(conf),
            "evidence": threat_info.get("evidence", {})
        }


class AlertManager:
    def __init__(self, jsonl_path: str = "data/alerts.jsonl", db_path: str = "data/alerts.db", cooldown_sec: float = 30.0):
        self.jsonl_path = jsonl_path
        self.db_path = db_path
        self.cooldown_sec = cooldown_sec
        self.recent_alerts: Dict[str, float] = {}

        os.makedirs(os.path.dirname(self.jsonl_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    flow_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    threat_class TEXT,
                    severity TEXT,
                    confidence_score REAL,
                    evidence TEXT
                )
            ''')
            conn.commit()

    def publish_alert(self, alert: Dict[str, Any], dedup_key: Optional[str] = None) -> bool:
        # Deduplication on traffic time, so a fast PCAP replay behaves like the live stream
        dedup_key = f"{dedup_key or alert['src_ip'] + '->' + alert['dst_ip']}_{alert['threat_class']}"
        try:
            now = datetime.fromisoformat(alert["timestamp"]).timestamp()
        except (KeyError, ValueError):
            now = time.time()
        if dedup_key in self.recent_alerts:
            if abs(now - self.recent_alerts[dedup_key]) < self.cooldown_sec:
                return False  # Suppress duplicate alert

        self.recent_alerts[dedup_key] = now

        # Append to JSONL
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + chr(10))

        # Insert to SQLite
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (timestamp, flow_id, src_ip, dst_ip, src_port, dst_port, protocol, threat_class, severity, confidence_score, evidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert["timestamp"], alert["flow_id"], alert["src_ip"], alert["dst_ip"],
                alert["src_port"], alert["dst_port"], alert["protocol"], alert["threat_class"],
                alert["severity"], alert["confidence_score"], json.dumps(alert["evidence"])
            ))
            conn.commit()

        return True

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            alerts = []
            for r in rows:
                d = dict(r)
                try:
                    d["evidence"] = json.loads(d["evidence"])
                except Exception:
                    pass
                alerts.append(d)
            return alerts
