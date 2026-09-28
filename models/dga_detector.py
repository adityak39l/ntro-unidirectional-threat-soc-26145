from typing import Dict, Any, Tuple


class DGADetector:
    NAME = "DGA_Domains_and_DNS_Tunneling"

    def predict(self, features: Dict[str, float], context: Dict[str, Any] = None) -> Tuple[bool, float, Dict[str, Any]]:
        context = context or {}
        entropy = features.get("dns_entropy", 0.0)
        query_len = features.get("dns_query_len", 0.0)
        is_suspect = features.get("is_dns_suspect", 0.0)
        dga_signals = features.get("dns_dga_signals", 0.0)

        confidence = 0.0
        if is_suspect > 0.5:
            confidence = 0.94          # long high-entropy subdomains: data encoded in queries
        elif dga_signals >= 5:
            confidence = 0.94
        elif dga_signals >= 4:
            confidence = 0.88
        elif dga_signals >= 3:
            confidence = 0.78

        is_threat = confidence >= 0.70
        evidence = {
            "queried_domain": context.get("dns_query", ""),
            "label_entropy_bits": round(entropy, 3),
            "dns_query_length": int(query_len),
            "dga_indicators": context.get("dns_dga_signals", []),
            "is_tunnel_suspect": bool(is_suspect),
        }
        if is_suspect > 0.5:
            evidence["encoded_subdomain_length"] = context.get("dns_subdomain_length", 0)
            evidence["subdomain_entropy_bits"] = round(context.get("dns_subdomain_entropy", 0.0), 3)
        return is_threat, round(confidence, 4), evidence
