import numpy as np
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestClassifier


class DDoSDetector:
    NAME = "Volumetric_Protocol_DDoS"

    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_trained = False

    def train(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        self.is_trained = True

    def predict(self, features: Dict[str, float]) -> Tuple[bool, float, Dict[str, Any]]:
        pps = features.get("packets_per_second", 0.0)
        bps = features.get("bytes_per_second", 0.0)
        syn_ratio = features.get("syn_ratio", 0.0)
        syn_count = features.get("syn_count", 0.0)

        # Rule + ML hybrid
        rule_score = 0.0
        if pps > 500: rule_score += 0.4
        if syn_ratio > 5.0 and syn_count > 50: rule_score += 0.5
        if bps > 500000: rule_score += 0.3

        confidence = min(0.99, rule_score)

        if self.is_trained:
            # Model prediction if available
            feat_vector = np.array([[pps, bps, syn_ratio, syn_count]])
            prob = float(self.model.predict_proba(feat_vector)[0][1])
            confidence = max(confidence, prob)

        is_threat = confidence >= 0.70
        evidence = {
            "packets_per_sec": round(pps, 2),
            "syn_ratio": round(syn_ratio, 2),
            "syn_count": int(syn_count)
        }
        return is_threat, round(confidence, 4), evidence
