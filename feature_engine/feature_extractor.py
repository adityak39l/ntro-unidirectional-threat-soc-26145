import numpy as np
from typing import Dict, Any, Optional, Tuple
from .dns_analyzer import DNSAnalyzer
from .tls_fingerprint import TLSFingerprinter

DNS_PORTS = {53, 5353}

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

        dns_info, tls_info = self._inspect_payloads(flow)
        dns_entropy = dns_info.get("label_entropy", 0.0) if dns_info else 0.0
        dns_query_len = float(dns_info.get("query_length", 0)) if dns_info else 0.0
        is_dns_suspect = 1.0 if dns_info and dns_info.get("is_tunnel_suspect") else 0.0
        dns_dga_signals = float(len(dns_info.get("dga_signals", []))) if dns_info else 0.0

        is_tls = 1.0 if tls_info.get("is_tls") else 0.0
        cipher_count = float(tls_info.get("cipher_count", 0))
        tls_version = float(tls_info.get("tls_version", 0))
        tls_extension_count = float(tls_info.get("extension_count", 0))
        tls_has_sni = 1.0 if tls_info.get("sni") else 0.0
        tls_complete = 1.0 if tls_info.get("complete") else 0.0

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
            "dns_dga_signals": float(dns_dga_signals),
            "is_tls": float(is_tls),
            "cipher_count": float(cipher_count),
            "tls_version": float(tls_version),
            "tls_extension_count": float(tls_extension_count),
            "tls_has_sni": float(tls_has_sni),
            "tls_complete": float(tls_complete),
            "dst_port": float(flow.get("dst_port", 0) or 0)
        }

        # SPLT sequence
        splt = TLSFingerprinter.extract_splt(lengths, max_packets=self.splt_length)
        for i, val in enumerate(splt):
            features[f"splt_{i}"] = float(val)

        return features

    def extract_context(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Non-numeric evidence (JA3, SNI, queried domain) attached to the flow for XAI."""
        dns_info, tls_info = self._inspect_payloads(flow)
        context: Dict[str, Any] = {}
        if tls_info.get("is_tls"):
            context.update({
                "ja3_hash": tls_info.get("ja3_hash", ""),
                "ja3_str": tls_info.get("ja3_str", ""),
                "sni": tls_info.get("sni", ""),
                "tls_version_name": tls_info.get("tls_version_name", ""),
            })
        if dns_info:
            context.update({
                "dns_query": dns_info.get("query_name", ""),
                "dns_label_entropy": dns_info.get("label_entropy", 0.0),
                "dns_subdomain_length": dns_info.get("subdomain_length", 0),
                "dns_subdomain_entropy": dns_info.get("subdomain_entropy", 0.0),
                "dns_dga_signals": dns_info.get("dga_signals", []),
            })
        return context

    @staticmethod
    def _inspect_payloads(flow: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        # DNS: keep the most suspicious query seen in the flow's payload samples
        dns_info = None
        if DNS_PORTS & {flow.get("src_port"), flow.get("dst_port")}:
            for payload in flow.get("payload_samples", []):
                info = DNSAnalyzer.parse_dns_payload(payload)
                if not info:
                    continue
                rank = (info["is_tunnel_suspect"], len(info["dga_signals"]), info["label_entropy"])
                if dns_info is None or rank > (dns_info["is_tunnel_suspect"], len(dns_info["dga_signals"]), dns_info["label_entropy"]):
                    dns_info = info

        tls_info: Dict[str, Any] = {}
        hello = flow.get("tls_client_hello") or b""
        candidates = [hello] if hello else flow.get("payload_samples", [])
        for payload in candidates:
            tls_info = TLSFingerprinter.extract_ja3(payload)
            if tls_info.get("is_tls"):
                break
        return dns_info, tls_info
