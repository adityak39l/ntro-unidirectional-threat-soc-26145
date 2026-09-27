import math
import re
from typing import Dict, Any, Optional

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    total = len(text)
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return float(entropy)


class DNSAnalyzer:
    VOWELS = set("aeiouAEIOU")

    @staticmethod
    def analyze_domain(domain: str) -> Dict[str, Any]:
        if not domain:
            return {
                "query_length": 0,
                "entropy": 0.0,
                "consonant_ratio": 0.0,
                "digit_ratio": 0.0,
                "subdomain_count": 0,
                "has_consecutive_consonants": False
            }

        length = len(domain)
        cleaned = re.sub(r"[^a-zA-Z0-9]", "", domain)
        clean_len = len(cleaned) or 1

        vowel_count = sum(1 for c in cleaned if c in DNSAnalyzer.VOWELS)
        consonant_count = sum(1 for c in cleaned if c.isalpha() and c not in DNSAnalyzer.VOWELS)
        digit_count = sum(1 for c in cleaned if c.isdigit())

        consonant_ratio = consonant_count / clean_len
        digit_ratio = digit_count / clean_len
        subdomains = domain.count(".")

        consecutive_consonants = bool(re.search(r"[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]{5,}", domain))

        return {
            "query_length": length,
            "entropy": calculate_entropy(domain),
            "consonant_ratio": round(consonant_ratio, 4),
            "digit_ratio": round(digit_ratio, 4),
            "subdomain_count": subdomains,
            "has_consecutive_consonants": consecutive_consonants
        }

    @staticmethod
    def parse_dns_payload(payload: bytes) -> Optional[Dict[str, Any]]:
        if not payload or not DPKT_AVAILABLE:
            return None
        try:
            dns = dpkt.dns.DNS(payload)
            query_name = ""
            query_type = "UNKNOWN"
            if dns.qd:
                q = dns.qd[0]
                query_name = q.name
                query_type = str(q.type)

            domain_features = DNSAnalyzer.analyze_domain(query_name)
            domain_features["dns_record_type"] = query_type
            domain_features["is_tunnel_suspect"] = (
                domain_features["entropy"] > 3.8 and domain_features["query_length"] > 40
            )
            return domain_features
        except Exception:
            return None
