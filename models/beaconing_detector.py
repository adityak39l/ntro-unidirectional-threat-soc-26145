from typing import Dict, Any, Tuple


class BeaconingDetector:
    NAME = "Botnet_C2_Beaconing"

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float, Dict[str, Any]]:
        iat_var = features.get("iat_variance", 1.0)
        iat_cv = features.get("iat_cv", 1.0)
        pkt_count = features.get("packet_count", 0.0)
        iat_mean = features.get("iat_mean", 0.0)

        # C2 beacons have consistent periodicity (very low variance & low CV)
        confidence = 0.0
        if pkt_count >= 5 and iat_mean > 0.5:
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
