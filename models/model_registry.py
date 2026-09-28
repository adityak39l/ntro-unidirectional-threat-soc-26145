from typing import Dict, Any, List, Optional
from feature_engine.window_features import aggregate_window
from .ddos_detector import DDoSDetector
from .beaconing_detector import BeaconingDetector
from .dga_detector import DGADetector
from .encrypted_malware_detector import EncryptedMalwareDetector
from .port_scan_detector import PortScanDetector
from .exfiltration_detector import ExfiltrationDetector


class ThreatModelRegistry:
    """Runs all 6 detectors.

    Flow-level (per 5-tuple): C2 beaconing, DGA/DNS tunneling, encrypted malware, exfiltration.
    Window-level (per host, per sliding window): DDoS fan-in, port-scan fan-out.
    """

    def __init__(self):
        self.ddos = DDoSDetector()
        self.beaconing = BeaconingDetector()
        self.dga = DGADetector()
        self.encrypted_malware = EncryptedMalwareDetector()
        self.port_scan = PortScanDetector()
        self.exfiltration = ExfiltrationDetector()

    def evaluate_flow(self, flow_dict: Dict[str, Any], features: Dict[str, float],
                      context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        context = context or {}
        ja3_hash = context.get("ja3_hash") or flow_dict.get("ja3_hash", "")
        detectors = [
            (self.beaconing, lambda d: d.predict(features)),
            (self.dga, lambda d: d.predict(features, context=context)),
            (self.encrypted_malware, lambda d: d.predict(features, ja3_hash=ja3_hash, context=context)),
            (self.exfiltration, lambda d: d.predict(features)),
        ]

        alerts = []
        for detector, call_fn in detectors:
            is_threat, confidence, evidence = call_fn(detector)
            if is_threat:
                alerts.append({
                    "threat_class": detector.NAME,
                    "confidence_score": confidence,
                    "evidence": evidence
                })
        return alerts

    def evaluate_window(self, packets: List[Dict[str, Any]], window_start: float,
                        window_end: float) -> List[Dict[str, Any]]:
        """Returns detections with a synthetic flow describing the host-level activity."""
        if not packets:
            return []
        agg = aggregate_window(packets, window_start)
        window = {"window_start": round(window_start, 3), "window_end": round(window_end, 3)}
        alerts = []

        for dst, target in agg["by_target"].items():
            is_threat, confidence, evidence = self.ddos.predict(target)
            if is_threat:
                top_src = target["top_sources"][0]
                alerts.append({
                    "flow": {
                        "flow_id": f"{top_src}:*->{dst}:{target['top_dst_port']}_{target['protocol']}",
                        "src_ip": top_src, "dst_ip": dst, "src_port": 0,
                        "dst_port": target["top_dst_port"], "protocol": target["protocol"],
                        "last_time": target["last_ts"],
                        # Top source changes between windows; one flood = one target
                        "dedup_key": f"*->{dst}",
                    },
                    "threat_class": self.ddos.NAME,
                    "confidence_score": confidence,
                    "evidence": {**evidence, **window},
                })

        for src, source in agg["by_source"].items():
            is_threat, confidence, evidence = self.port_scan.predict(source)
            if is_threat:
                vertical = source["max_ports_on_one_host"] >= source["max_hosts_on_one_port"]
                dst = source["vertical_target"] if vertical else "*"
                dst_port = 0 if vertical else source["horizontal_port"]
                alerts.append({
                    "flow": {
                        "flow_id": f"{src}:*->{dst}:{dst_port or '*'}_{source['protocol']}",
                        "src_ip": src, "dst_ip": dst, "src_port": 0,
                        "dst_port": dst_port, "protocol": source["protocol"],
                        "last_time": source["last_ts"],
                    },
                    "threat_class": self.port_scan.NAME,
                    "confidence_score": confidence,
                    "evidence": {**evidence, **window},
                })

        return alerts
