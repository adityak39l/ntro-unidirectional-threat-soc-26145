from typing import Dict, Any, Tuple

DISCOVERY_PORTS = {67, 68, 137, 138, 1900, 5353, 5355}


class BeaconingDetector:
    NAME = "Botnet_C2_Beaconing"

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float, Dict[str, Any]]:
        iat_var = features.get("iat_variance", 1.0)
        iat_cv = features.get("iat_cv", 1.0)
        pkt_count = features.get("packet_count", 0.0)
        iat_mean = features.get("iat_mean", 0.0)

        # C2 beacons have consistent periodicity (very low variance & low CV). Portless flows (ICMP)
        # are excluded: monitoring tools such as ping / mtr send exactly one packet per second
        # Also excluded: LAN discovery chatter (NetBIOS, SSDP, mDNS, LLMNR, DHCP) and broadcast /
        # multicast destinations, and flows with no payload, since TCP keep-alives are periodic but carry
        # no data, whereas a beacon checks in with some
        ports = {int(features.get("src_port", 0)), int(features.get("dst_port", 0))}
        confidence = 0.0
        if (features.get("is_portless", 0.0) > 0.5 or features.get("dst_broadcast", 0.0) > 0.5
                or ports & DISCOVERY_PORTS or features.get("payload_to_header_ratio", 1.0) < 0.1):
            pass
        elif pkt_count >= 5 and iat_mean > 0.5:
            if iat_var < 0.01:
                confidence = 0.92
            elif iat_var < 0.05 and iat_cv < 0.15:
                confidence = 0.82
            elif iat_var < 0.15 and iat_cv < 0.30:
                confidence = 0.65

        is_threat = confidence >= 0.70
        evidence = {
            "iat_mean_sec": round(iat_mean, 3),
            "iat_variance": round(iat_var, 5),
            "iat_cv": round(iat_cv, 4),
            "packet_count": int(pkt_count)
        }
        if is_threat:
            evidence["indicators"] = [
                f"{int(pkt_count)} check-ins at a fixed {iat_mean:.2f} s interval",
                f"interval variance {iat_var:.4f} (human-driven traffic is irregular)",
            ]
        return is_threat, round(confidence, 4), evidence
