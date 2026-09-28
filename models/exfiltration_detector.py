from typing import Dict, Any, Tuple


class ExfiltrationDetector:
    NAME = "Data_Exfiltration"

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float, Dict[str, Any]]:
        tot_bytes = features.get("total_bytes", 0.0)
        bps = features.get("bytes_per_second", 0.0)
        payload_ratio = features.get("payload_to_header_ratio", 0.0)
        pkt_len_mean = features.get("pkt_len_mean", 0.0)

        confidence = 0.0
        # High volume asymmetric outbound transfer
        if tot_bytes > 5000000 and payload_ratio > 10.0:  # > 5 MB payload heavy
            confidence = 0.94
        elif tot_bytes > 1000000 and bps > 100000 and payload_ratio > 5.0:
            confidence = 0.86
        elif (tot_bytes > 25000 or bps > 40000) and payload_ratio > 15.0 and pkt_len_mean > 1000:
            # Bursty MTU-sized outbound data transfer with heavy payload ratio
            confidence = 0.89

        is_threat = confidence >= 0.70
        evidence = {
            "total_bytes": int(tot_bytes),
            "bytes_per_sec": round(bps, 2),
            "payload_ratio": round(payload_ratio, 2),
            "avg_packet_size": round(pkt_len_mean, 2)
        }
        if is_threat:
            evidence["indicators"] = [
                f"{tot_bytes / 1024:,.1f} KB pushed in one direction",
                f"payload-to-header ratio {payload_ratio:.1f} (bulk data, not control traffic)",
                f"average packet {pkt_len_mean:,.0f} B (MTU-sized frames)",
            ]
        return is_threat, round(confidence, 4), evidence
