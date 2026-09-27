from typing import Dict, Any, Tuple


class PortScanDetector:
    NAME = "Reconnaissance_Port_Scanning"

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float, Dict[str, Any]]:
        pps = features.get("packets_per_second", 0.0)
        pkt_count = features.get("packet_count", 0.0)
        duration = features.get("duration", 1.0)
        syn_count = features.get("syn_count", 0.0)
        ack_count = features.get("ack_count", 0.0)

        # Fast single packet probe or SYN without ACK completion
        confidence = 0.0
        if pkt_count <= 3 and syn_count >= 1 and ack_count == 0:
            confidence = 0.85
        elif pps > 50 and syn_count > 20 and ack_count < 2:
            confidence = 0.80

        is_threat = confidence >= 0.70
        evidence = {
            "probe_packet_count": int(pkt_count),
            "syn_count": int(syn_count),
            "ack_count": int(ack_count),
            "duration_sec": round(duration, 3)
        }
        return is_threat, round(confidence, 4), evidence
