from typing import Dict, Any, List
from .ddos_detector import DDoSDetector
from .beaconing_detector import BeaconingDetector
from .dga_detector import DGADetector
from .encrypted_malware_detector import EncryptedMalwareDetector
from .port_scan_detector import PortScanDetector
from .exfiltration_detector import ExfiltrationDetector


class ThreatModelRegistry:
    def __init__(self):
        self.ddos = DDoSDetector()
        self.beaconing = BeaconingDetector()
        self.dga = DGADetector()
        self.encrypted_malware = EncryptedMalwareDetector()
        self.port_scan = PortScanDetector()
        self.exfiltration = ExfiltrationDetector()

    def evaluate_flow(self, flow_dict: Dict[str, Any], features: Dict[str, float]) -> List[Dict[str, Any]]:
        alerts = []
        detectors = [
            (self.ddos, lambda d: d.predict(features)),
            (self.beaconing, lambda d: d.predict(features)),
            (self.dga, lambda d: d.predict(features)),
            (self.encrypted_malware, lambda d: d.predict(features, ja3_hash=flow_dict.get("ja3_hash", ""))),
            (self.port_scan, lambda d: d.predict(features)),
            (self.exfiltration, lambda d: d.predict(features))
        ]

        for detector, call_fn in detectors:
            is_threat, confidence, evidence = call_fn(detector)
            if is_threat:
                alerts.append({
                    "threat_class": detector.NAME,
                    "confidence_score": confidence,
                    "evidence": evidence
                })

        return alerts
