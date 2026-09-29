import math
import re
from typing import Dict, Any, List, Optional

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Two-label public suffixes, so "ntro.gov.in" scores "ntro" rather than "gov"
TWO_LEVEL_SUFFIXES = {
    "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in", "mil.in",
    "co.uk", "ac.uk", "gov.uk", "org.uk", "com.au", "net.au", "co.jp", "com.cn", "com.br",
}
NON_SCORED_SUFFIXES = ("in-addr.arpa", "ip6.arpa", ".local")
# Cloud / CDN infrastructure whose generated hostnames (load balancers, edge nodes, hashes) look random
# by design. A SOC allowlist: extend it for the operator's own providers.
INFRA_SUFFIXES = (
    "amazonaws.com", "cloudfront.net", "akamaiedge.net", "akadns.net", "akamai.net", "akamaihd.net", "edgekey.net",
    "edgesuite.net", "fastly.net", "fastlylb.net", "cloudflare.net", "azureedge.net", "azurefd.net",
    "trafficmanager.net", "cloudapp.net", "msedge.net", "office.net", "googlevideo.com", "googleusercontent.com",
    "gvt1.com", "1e100.net", "alibabadns.com", "linode.com", "force.com", "siteforce.com", "footprint.net",
    "llnwd.net", "cdn77.org", "hwcdn.net", "services.mozilla.com",
)


def is_infrastructure(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in INFRA_SUFFIXES)
# "y" counts as a vowel: brand names like letsencrypt / symantec must not read as consonant soup
CONSONANTS = set("bcdfghjklmnpqrstvwxz")


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


def split_domain(domain: str) -> Dict[str, str]:
    labels = [l for l in domain.lower().strip(".").split(".") if l]
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        suffix_len = 2
    else:
        suffix_len = 1 if len(labels) >= 2 else 0
    registered_idx = len(labels) - suffix_len - 1
    if registered_idx < 0:
        return {"registered_label": "", "subdomain": "", "suffix": ".".join(labels)}
    return {
        "registered_label": labels[registered_idx],
        "subdomain": ".".join(labels[:registered_idx]),
        "suffix": ".".join(labels[registered_idx + 1:]),
    }


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
                "has_consecutive_consonants": False,
                "label": "",
                "label_entropy": 0.0,
                "subdomain_length": 0,
                "subdomain_entropy": 0.0,
                "max_label_length": 0,
                "hyphen_count": 0,
                "is_infrastructure": False,
                "dga_signals": [],
                "is_tunnel_suspect": False,
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

        parts = split_domain(domain)
        label = parts["registered_label"]
        label_entropy = calculate_entropy(label)
        infrastructure = is_infrastructure(domain)
        scored = not domain.lower().rstrip(".").endswith(NON_SCORED_SUFFIXES) and not infrastructure

        # DGA indicators computed on the registered label (the part malware randomises)
        dga_signals: List[str] = []
        if scored and label:
            letters = [c for c in label if c.isalpha()]
            label_consonant_ratio = (sum(1 for c in letters if c in CONSONANTS) / len(letters)) if letters else 0.0
            label_digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)
            longest_consonant_run = max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz]+", label)), default=0)
            high_entropy = label_entropy >= 3.0
            if high_entropy:
                dga_signals.append(f"high label entropy ({label_entropy:.2f} bits)")
            if len(label) >= 10:
                dga_signals.append(f"long random label ({len(label)} chars)")
            if label_consonant_ratio >= 0.80:
                dga_signals.append(f"consonant ratio {label_consonant_ratio:.2f}")
            if letters and 0.1 <= label_digit_ratio <= 0.7:
                dga_signals.append(f"letters mixed with digits ({label_digit_ratio:.0%})")
            if longest_consonant_run >= 6:
                dga_signals.append(f"{longest_consonant_run} consecutive consonants")
            # Entropy is mandatory: pronounceable-but-rare words must not trip the detector
            if not high_entropy:
                dga_signals = []

        subdomain = parts["subdomain"]
        subdomain_entropy = calculate_entropy(subdomain)
        sub_labels = [l for l in subdomain.split(".") if l]
        # Encoded payloads (base32 / base64 / hex) are long single labels of random characters. Generated
        # infrastructure names (elb-prod-2099053585, us-east-1) are hyphen-joined words and short IDs instead.
        encoded = [l for l in sub_labels if len(l) >= 25 and l.count("-") <= 1
                   and calculate_entropy(l) >= (3.8 if len(l) < 45 else 3.5)]
        is_tunnel_suspect = scored and (any(len(l) >= 30 for l in encoded) or sum(len(l) for l in encoded) >= 60)

        return {
            "query_length": length,
            "entropy": calculate_entropy(domain),
            "consonant_ratio": round(consonant_ratio, 4),
            "digit_ratio": round(digit_ratio, 4),
            "subdomain_count": subdomains,
            "has_consecutive_consonants": consecutive_consonants,
            "label": label,
            "label_entropy": round(label_entropy, 4),
            "subdomain_length": len(subdomain),
            "subdomain_entropy": round(subdomain_entropy, 4),
            "max_label_length": max((len(l) for l in domain.strip(".").split(".")), default=0),
            "hyphen_count": domain.count("-"),
            "is_infrastructure": infrastructure,
            "dga_signals": dga_signals,
            "is_tunnel_suspect": bool(is_tunnel_suspect),
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
            domain_features["query_name"] = query_name
            domain_features["dns_record_type"] = query_type
            return domain_features
        except Exception:
            return None
