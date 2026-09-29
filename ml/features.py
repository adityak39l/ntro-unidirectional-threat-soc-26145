"""Numeric feature vectors for the ML layer, with human-readable names for explanations.

Both vectors are built from outputs the rule engine already computes
(FeatureExtractor for flows, aggregate_window for hosts), so the model adds no new
parsing and cannot drift from what the rules see.
"""
import math
from typing import Any, Dict, List, Optional

COMMON_SERVICE_PORTS = {20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 137, 138, 139, 143, 161, 389, 443, 445,
                        465, 587, 636, 853, 993, 995, 1900, 3389, 5353, 8080, 8443}


def _log(x: float) -> float:
    return math.log1p(max(0.0, float(x or 0.0)))


# (name, human label shown in explanations)
FLOW_FEATURES = [
    ("log_packets", "packet count"),
    ("log_bytes", "bytes in flow"),
    ("log_duration", "flow duration"),
    ("log_pps", "packet rate"),
    ("log_bps", "byte rate"),
    ("pkt_len_mean", "mean packet size"),
    ("pkt_len_std", "packet-size spread"),
    ("pkt_len_min", "smallest packet"),
    ("pkt_len_max", "largest packet"),
    ("iat_mean", "mean inter-arrival time"),
    ("iat_cv", "timing irregularity (IAT CV)"),
    ("iat_std", "inter-arrival spread"),
    ("syn_share", "share of SYN packets"),
    ("ack_share", "share of ACK packets"),
    ("log_payload_ratio", "payload-to-header ratio"),
    ("is_dns", "DNS flow"),
    ("dns_label_entropy", "domain-label entropy"),
    ("dns_query_len", "query length"),
    ("dns_dga_signals", "DGA indicators"),
    ("dns_subdomain_len", "subdomain length"),
    ("dns_subdomain_entropy", "subdomain entropy"),
    ("dns_max_label_len", "longest domain label"),
    ("dns_hyphens", "hyphens in domain"),
    ("dns_infra", "known cloud / CDN domain"),
    ("is_tls", "TLS ClientHello seen"),
    ("tls_complete", "ClientHello fully parsed"),
    ("tls_legacy", "legacy TLS version"),
    ("tls_cipher_count", "offered cipher suites"),
    ("tls_extension_count", "TLS extensions"),
    ("tls_has_sni", "SNI present"),
    ("dst_port_common", "well-known destination port"),
    ("src_port_ephemeral", "client-side (ephemeral) source port"),
    ("is_portless", "ICMP / portless flow"),
    ("src_internal", "source inside the network"),
    ("dst_internal", "destination inside the network"),
]
FLOW_FEATURE_NAMES = [n for n, _ in FLOW_FEATURES]

HOST_FEATURES = [
    ("in_log_packets", "packets received in window"),
    ("in_log_peak_pps", "peak inbound packet rate"),
    ("in_syn_only_ratio", "half-open SYN share (inbound)"),
    ("in_udp_ratio", "UDP share (inbound)"),
    ("in_log_sources", "distinct sources"),
    ("in_source_entropy", "source-IP entropy"),
    ("out_log_packets", "packets sent in window"),
    ("out_probe_ratio", "probe share (outbound)"),
    ("out_log_ports_one_host", "ports probed on one host"),
    ("out_log_hosts_one_port", "hosts probed on one port"),
    ("out_log_targets", "distinct targets"),
]
HOST_FEATURE_NAMES = [n for n, _ in HOST_FEATURES]


def flow_vector(f: Dict[str, float]) -> List[float]:
    packets = max(1.0, f.get("packet_count", 1.0))
    dst_port, src_port = int(f.get("dst_port", 0)), int(f.get("src_port", 0))
    tls_version = f.get("tls_version", 0.0)
    return [
        _log(packets),
        _log(f.get("total_bytes", 0)),
        _log(f.get("duration", 0)),
        _log(f.get("packets_per_second", 0)),
        _log(f.get("bytes_per_second", 0)),
        f.get("pkt_len_mean", 0.0),
        f.get("pkt_len_std", 0.0),
        f.get("pkt_len_min", 0.0),
        f.get("pkt_len_max", 0.0),
        min(120.0, f.get("iat_mean", 0.0)),
        min(10.0, f.get("iat_cv", 0.0)),
        min(120.0, f.get("iat_std", 0.0)),
        f.get("syn_count", 0.0) / packets,
        f.get("ack_count", 0.0) / packets,
        _log(f.get("payload_to_header_ratio", 0.0)),
        1.0 if 53 in (dst_port, src_port) else 0.0,
        f.get("dns_entropy", 0.0),
        f.get("dns_query_len", 0.0),
        f.get("dns_dga_signals", 0.0),
        f.get("dns_subdomain_len", 0.0),
        f.get("dns_subdomain_entropy", 0.0),
        f.get("dns_max_label_len", 0.0),
        f.get("dns_hyphens", 0.0),
        f.get("dns_infra", 0.0),
        f.get("is_tls", 0.0),
        f.get("tls_complete", 0.0),
        1.0 if 0 < tls_version < 0x0303 else 0.0,
        f.get("cipher_count", 0.0),
        f.get("tls_extension_count", 0.0),
        f.get("tls_has_sni", 0.0),
        1.0 if dst_port in COMMON_SERVICE_PORTS else 0.0,
        1.0 if src_port >= 1024 and src_port not in COMMON_SERVICE_PORTS else 0.0,
        f.get("is_portless", 0.0),
        f.get("src_internal", 0.0),
        f.get("dst_internal", 0.0),
    ]


def is_host_candidate(target: Optional[Dict[str, Any]], source: Optional[Dict[str, Any]]) -> bool:
    """Hosts worth scoring in a window: busy receivers or active probers. Quiet hosts can't be a
    flood target or a scanner, and skipping them keeps window inference cheap on real captures."""
    t, s = target or {}, source or {}
    return (t.get("packets", 0) >= 50 or s.get("max_ports_on_one_host", 0) >= 5
            or s.get("max_hosts_on_one_port", 0) >= 5)


def host_vector(target: Optional[Dict[str, Any]], source: Optional[Dict[str, Any]]) -> List[float]:
    t, s = target or {}, source or {}
    return [
        _log(t.get("packets", 0)),
        _log(t.get("peak_pps", 0)),
        t.get("syn_only_ratio", 0.0),
        t.get("udp_ratio", 0.0),
        _log(t.get("unique_sources", 0)),
        t.get("source_ip_entropy", 0.0),
        _log(s.get("packets", 0)),
        s.get("probe_ratio", 0.0),
        _log(s.get("max_ports_on_one_host", 0)),
        _log(s.get("max_hosts_on_one_port", 0)),
        _log(s.get("unique_targets", 0)),
    ]
