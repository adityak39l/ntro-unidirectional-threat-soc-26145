from typing import Dict, Any, Tuple


class DGADetector:
    NAME = "DGA_Domains_and_DNS_Tunneling"

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float, Dict[str, Any]]:
        entropy = features.get("dns_entropy", 0.0)
        query_len = features.get("dns_query_len", 0.0)
        is_suspect = features.get("is_dns_suspect", 0.0)

        confidence = 0.0
        if is_suspect > 0.5:
            confidence = 0.94
        elif entropy > 4.0:
            confidence = 0.88
        elif entropy > 3.6 and query_len > 25:
            confidence = 0.78
        elif entropy > 3.2 and query_len > 35:
            confidence = 0.65

        is_threat = confidence >= 0.70
        evidence = {
            "dns_entropy": round(entropy, 3),
            "dns_query_length": int(query_len),
            "is_tunnel_suspect": bool(is_suspect)
        }
        return is_threat, round(confidence, 4), evidence
