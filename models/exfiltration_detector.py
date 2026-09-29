from typing import Dict, Any, Tuple

SERVICE_PORTS = {1080, 1433, 1521, 3128, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888}


class ExfiltrationDetector:
    NAME = "Data_Exfiltration"

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float, Dict[str, Any]]:
        tot_bytes = features.get("total_bytes", 0.0)
        bps = features.get("bytes_per_second", 0.0)
        payload_ratio = features.get("payload_to_header_ratio", 0.0)
        pkt_len_mean = features.get("pkt_len_mean", 0.0)
        # Uploads leave from a client (ephemeral) port; bulk data *from* a service port (443, 80, ...)
        # is a server answering a download, not exfiltration
        src_port = int(features.get("src_port", 50000))
        client_side = src_port >= 1024 and src_port not in SERVICE_PORTS
        # Data flowing *into* (or within) the internal network is a download / LAN copy, not exfiltration
        client_side = client_side and features.get("dst_internal", 0.0) < 0.5

        confidence = 0.0
        if not client_side:
            pass
        # High volume asymmetric outbound transfer
        elif tot_bytes > 5000000 and payload_ratio > 10.0:  # > 5 MB payload heavy
            confidence = 0.94
        elif tot_bytes > 1000000 and bps > 100000 and payload_ratio > 5.0:
            confidence = 0.86
        elif tot_bytes > 500000 and bps > 50000 and payload_ratio > 15.0 and pkt_len_mean > 1000:
            # Sub-500 KB bursts are everyday uploads (photos, forms); the model scores those shapes instead
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
