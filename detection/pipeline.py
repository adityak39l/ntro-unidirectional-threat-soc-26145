import time
from typing import Dict, Any, List
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
        self.total_windows_evaluated = 0
        self.total_alerts_generated = 0
        self.flow_inference_seconds = 0.0
        self.window_inference_seconds = 0.0
        self.start_time = time.time()

    def process_packet(self, pkt: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.total_packets_processed += 1
        alerts = []

        expired_flow = self.flow_aggregator.process_packet(pkt)
        if expired_flow:
            alerts.extend(self._evaluate_and_alert(expired_flow))

        for window_packets in self.window_manager.add_item(pkt):
            start, end = self.window_manager.last_window_bounds
            alerts.extend(self._evaluate_window(window_packets, start, end))

        # Check periodic idle flush (every 500 packets)
        if self.total_packets_processed % 500 == 0:
            flushed = self.flow_aggregator.flush_expired(pkt["timestamp"])
            for f in flushed:
                alerts.extend(self._evaluate_and_alert(f))

        return alerts

    def flush_and_complete(self) -> List[Dict[str, Any]]:
        alerts = []
        remaining_packets = self.window_manager.flush_remaining()
        if remaining_packets:
            start, end = self.window_manager.last_window_bounds
            alerts.extend(self._evaluate_window(remaining_packets, start, end))

        for f in self.flow_aggregator.flush_all():
            alerts.extend(self._evaluate_and_alert(f))
        return alerts

    def _publish(self, flow: Dict[str, Any], detection: Dict[str, Any]) -> List[Dict[str, Any]]:
        alert = StandardAlert.create(flow, detection)
        if self.alert_manager.publish_alert(alert, dedup_key=flow.get("dedup_key")):
            self.total_alerts_generated += 1
            return [alert]
        return []

    def _evaluate_and_alert(self, flow: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.total_flows_processed += 1
        t0 = time.perf_counter()
        features = self.feature_extractor.extract_flow_features(flow)
        context = self.feature_extractor.extract_context(flow)
        detections = self.model_registry.evaluate_flow(flow, features, context)
        self.flow_inference_seconds += time.perf_counter() - t0

        generated_alerts = []
        for d in detections:
            generated_alerts.extend(self._publish(flow, d))
        return generated_alerts

    def _evaluate_window(self, packets: List[Dict[str, Any]], start: float, end: float) -> List[Dict[str, Any]]:
        self.total_windows_evaluated += 1
        t0 = time.perf_counter()
        detections = self.model_registry.evaluate_window(packets, start, end)
        self.window_inference_seconds += time.perf_counter() - t0

        generated_alerts = []
        for d in detections:
            generated_alerts.extend(self._publish(d["flow"], d))
        return generated_alerts

    def get_stats(self) -> Dict[str, Any]:
        elapsed = max(0.001, time.time() - self.start_time)
        return {
            "total_packets": self.total_packets_processed,
            "total_flows": self.total_flows_processed,
            "total_windows": self.total_windows_evaluated,
            "total_alerts": self.total_alerts_generated,
            "packets_per_sec": round(self.total_packets_processed / elapsed, 2),
            "flows_per_sec": round(self.total_flows_processed / elapsed, 2),
            "avg_flow_inference_ms": round(1000 * self.flow_inference_seconds / max(1, self.total_flows_processed), 3),
            "avg_window_inference_ms": round(1000 * self.window_inference_seconds / max(1, self.total_windows_evaluated), 3),
        }
