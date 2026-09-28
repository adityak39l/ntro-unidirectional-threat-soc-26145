from typing import Dict, Any, Tuple


class PortScanDetector:
    """Window-level fan-out detector: one source probing many ports or many hosts."""
    NAME = "Reconnaissance_Port_Scanning"

    def __init__(self, min_ports: int = 10, min_hosts: int = 20, min_probe_ratio: float = 0.6):
        self.min_ports = min_ports
        self.min_hosts = min_hosts
        self.min_probe_ratio = min_probe_ratio

    def predict(self, source: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        ports = source.get("max_ports_on_one_host", 0)
        hosts = source.get("max_hosts_on_one_port", 0)
        probe_ratio = source.get("probe_ratio", 0.0)

        confidence = 0.0
        scan_type = "none"
        if probe_ratio >= self.min_probe_ratio:
            if ports >= self.min_ports:
                scan_type = "vertical (many ports, one host)"
                confidence = 0.92 if ports >= 100 else 0.85 if ports >= 25 else 0.75
            elif hosts >= self.min_hosts:
                scan_type = "horizontal (one port, many hosts)"
                confidence = 0.92 if hosts >= 100 else 0.85 if hosts >= 50 else 0.75
            if confidence and probe_ratio >= 0.9:
                confidence += 0.05

        is_threat = confidence >= 0.70
        probed = source.get("probed_ports", [])
        evidence = {
            "scan_type": scan_type,
            "distinct_ports_on_one_host": ports,
            "distinct_hosts_on_one_port": hosts,
            "probe_ratio": round(probe_ratio, 3),
            "target": source.get("vertical_target", ""),
            "sample_ports": probed[:20],
        }
        return is_threat, round(confidence, 4), evidence
