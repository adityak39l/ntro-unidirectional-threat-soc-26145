import time
from typing import Dict, Any, List, Optional
from ingestion.flow_aggregator import FlowAggregator
from ingestion.window_manager import SlidingWindowManager
from feature_engine.feature_extractor import FeatureExtractor
from models.model_registry import ThreatModelRegistry
from alerts.alert_manager import AlertManager, StandardAlert


class StreamingDetectionPipeline:
    def __init__(
        self,
        window_size: float = 3.0,
        slide_interval: float = 1.0,
        idle_timeout: float = 15.0,
        alert_jsonl: str = "data/alerts.jsonl",
        alert_db: str = "data/alerts.db"
    ):
        self.flow_aggregator = FlowAggregator(idle_timeout=idle_timeout)
        self.window_manager = SlidingWindowManager(window_size=window_size, slide_interval=slide_interval)
        self.feature_extractor = FeatureExtractor()
        self.model_registry = ThreatModelRegistry()
        self.alert_manager = AlertManager(jsonl_path=alert_jsonl, db_path=alert_db)

        # Telemetry
        self.total_packets_processed = 0
        self.total_flows_processed = 0
        self.total_alerts_generated = 0
        self.start_time = time.time()

    def process_packet(self, pkt: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.total_packets_processed += 1
        alerts = []

        expired_flow = self.flow_aggregator.process_packet(pkt)
        if expired_flow:
            alerts.extend(self._evaluate_and_alert(expired_flow))

        # Check periodic idle flush (every 500 packets)
        if self.total_packets_processed % 500 == 0:
            flushed = self.flow_aggregator.flush_expired(pkt["timestamp"])
            for f in flushed:
                alerts.extend(self._evaluate_and_alert(f))

        return alerts

    def flush_and_complete(self) -> List[Dict[str, Any]]:
        remaining_flows = self.flow_aggregator.flush_all()
        alerts = []
        for f in remaining_flows:
            alerts.extend(self._evaluate_and_alert(f))
        return alerts

    def _evaluate_and_alert(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.total_flows_processed += 1
        features = self.feature_extractor.extract_flow_features(flow)
        detections = self.model_registry.evaluate_flow(flow, features)

        generated_alerts = []
        for d in detections:
            alert = StandardAlert.create(flow, d)
            published = self.alert_manager.publish_alert(alert)
            if published:
                self.total_alerts_generated += 1
                generated_alerts.append(alert)

        return generated_alerts

    def get_stats(self) -> Dict[str, Any]:
        elapsed = max(0.001, time.time() - self.start_time)
        return {
            "total_packets": self.total_packets_processed,
            "total_flows": self.total_flows_processed,
            "total_alerts": self.total_alerts_generated,
            "packets_per_sec": round(self.total_packets_processed / elapsed, 2),
            "flows_per_sec": round(self.total_flows_processed / elapsed, 2)
        }
