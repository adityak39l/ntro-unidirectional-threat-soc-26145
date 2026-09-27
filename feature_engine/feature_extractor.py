import math
import numpy as np
from typing import Dict, Any, List
from .dns_analyzer import DNSAnalyzer
from .tls_fingerprint import TLSFingerprinter


class FeatureExtractor:
    def __init__(self, splt_length: int = 30):
        self.splt_length = splt_length

    def extract_flow_features(self, flow: Dict[str, Any]) -> Dict[str, float]:
        pkt_count = max(1, flow.get("packet_count", 1))
        tot_bytes = flow.get("total_bytes", 0)
        duration = max(0.0001, flow.get("duration", 0.0001))
        
        lengths = flow.get("packet_lengths", [])
        if lengths:
            len_arr = np.array(lengths)
            pkt_len_mean = float(np.mean(len_arr))
            pkt_len_std = float(np.std(len_arr))
            pkt_len_min = float(np.min(len_arr))
            pkt_len_max = float(np.max(len_arr))
        else:
            pkt_len_mean = pkt_len_std = pkt_len_min = pkt_len_max = 0.0

        iats = flow.get("inter_arrival_times", [])
        if len(iats) > 1:
            iat_arr = np.array(iats)
            iat_mean = float(np.mean(iat_arr))
            iat_std = float(np.std(iat_arr))
            iat_variance = float(np.var(iat_arr))
            iat_cv = iat_std / (iat_mean + 1e-6)
        elif len(iats) == 1:
            iat_mean = iats[0]
            iat_std = 0.0
            iat_variance = 0.0
            iat_cv = 0.0
        else:
            iat_mean = iat_std = iat_variance = iat_cv = 0.0

        pkts_per_sec = pkt_count / duration
        bytes_per_sec = tot_bytes / duration

        syn_count = flow.get("syn_count", 0)
        ack_count = flow.get("ack_count", 0)
        syn_ratio = syn_count / (ack_count + 1)

        payload_bytes = flow.get("payload_bytes", 0)
        header_bytes = max(0, tot_bytes - payload_bytes)
        payload_to_header_ratio = payload_bytes / (header_bytes + 1)

        # DNS Inspection
        dns_entropy = 0.0
        dns_query_len = 0.0
        is_dns_suspect = 0.0
        samples = flow.get("payload_samples", [])
        for payload in samples:
            dns_info = DNSAnalyzer.parse_dns_payload(payload)
            if dns_info:
                dns_entropy = max(dns_entropy, dns_info.get("entropy", 0.0))
                dns_query_len = max(dns_query_len, dns_info.get("query_length", 0))
                if dns_info.get("is_tunnel_suspect"):
                    is_dns_suspect = 1.0

        # TLS Inspection
        is_tls = 0.0
        cipher_count = 0.0
        tls_version = 0.0
        for payload in samples:
            tls_info = TLSFingerprinter.extract_ja3(payload)
            if tls_info.get("is_tls"):
                is_tls = 1.0
                cipher_count = float(tls_info.get("cipher_count", 0))
                tls_version = float(tls_info.get("tls_version", 0))
                break

        features = {
            "packet_count": float(pkt_count),
            "total_bytes": float(tot_bytes),
            "duration": float(duration),
            "packets_per_second": float(pkts_per_sec),
            "bytes_per_second": float(bytes_per_sec),
            "pkt_len_mean": float(pkt_len_mean),
            "pkt_len_std": float(pkt_len_std),
            "pkt_len_min": float(pkt_len_min),
            "pkt_len_max": float(pkt_len_max),
            "iat_mean": float(iat_mean),
            "iat_std": float(iat_std),
            "iat_variance": float(iat_variance),
            "iat_cv": float(iat_cv),
            "syn_count": float(syn_count),
            "ack_count": float(ack_count),
            "syn_ratio": float(syn_ratio),
            "payload_to_header_ratio": float(payload_to_header_ratio),
            "dns_entropy": float(dns_entropy),
            "dns_query_len": float(dns_query_len),
            "is_dns_suspect": float(is_dns_suspect),
            "is_tls": float(is_tls),
            "cipher_count": float(cipher_count),
            "tls_version": float(tls_version)
        }

        # SPLT sequence
        splt = TLSFingerprinter.extract_splt(lengths, max_packets=self.splt_length)
        for i, val in enumerate(splt):
            features[f"splt_{i}"] = float(val)

        return features
