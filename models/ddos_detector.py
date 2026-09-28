from typing import Dict, Any, Tuple


class DDoSDetector:
    """Window-level fan-in detector: many packets converging on one target."""
    NAME = "Volumetric_Protocol_DDoS"

    def __init__(self, pps_threshold: float = 300.0, min_packets: int = 200):
        self.pps_threshold = pps_threshold
        self.min_packets = min_packets

    def predict(self, target: Dict[str, Any]) -> Tuple[bool, float, Dict[str, Any]]:
        peak_pps = target.get("peak_pps", 0)
        packets = target.get("packets", 0)
        syn_only_ratio = target.get("syn_only_ratio", 0.0)
        udp_ratio = target.get("udp_ratio", 0.0)
        unique_sources = target.get("unique_sources", 0)

        confidence = 0.0
        indicators = []
        if packets >= self.min_packets and peak_pps >= self.pps_threshold:
            confidence += 0.45
            indicators.append(f"{peak_pps} pps peak (threshold {self.pps_threshold:.0f})")
            if peak_pps >= 3 * self.pps_threshold:
                confidence += 0.15
            # Protocol signature: half-open SYNs (no ACK ever seen) or UDP flood
            if syn_only_ratio >= 0.8:
                confidence += 0.35
                indicators.append(f"{syn_only_ratio:.0%} half-open SYN packets")
            elif udp_ratio >= 0.8:
                confidence += 0.25
                indicators.append(f"{udp_ratio:.0%} UDP packets")
            if unique_sources >= 50:
                confidence += 0.15
                indicators.append(f"{unique_sources} distinct sources (distributed)")

        confidence = min(0.99, confidence)
        is_threat = confidence >= 0.70
        evidence = {
            "target": target.get("dst_ip", ""),
            "peak_packets_per_sec": peak_pps,
            "window_packets": packets,
            "syn_only_ratio": round(syn_only_ratio, 3),
            "unique_sources": unique_sources,
            "source_ip_entropy_bits": round(target.get("source_ip_entropy", 0.0), 3),
            "top_sources": target.get("top_sources", []),
            "indicators": indicators,
        }
        return is_threat, round(confidence, 4), evidence
