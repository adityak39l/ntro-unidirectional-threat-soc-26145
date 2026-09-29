"""Random Forest layer that sits next to the rule detectors.

flow model : benign / C2 beaconing / DGA-DNS / encrypted malware / exfiltration (per 5-tuple flow)
host model : benign / DDoS target / port scanner (per host, per 3 s sliding window)

Explanations use per-prediction path contributions: walking each tree's decision
path and crediting the change in class probability at every split to the split's
feature (the Saabas method), averaged over the forest.
"""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from ml.features import FLOW_FEATURES, HOST_FEATURES

ARTIFACT_DIR = Path(__file__).resolve().parent.parent / "models" / "artifacts"
MODEL_PATH = ARTIFACT_DIR / "threat_rf.joblib"
CARD_PATH = ARTIFACT_DIR / "model_card.json"
DEFAULT_THRESHOLDS = {"flow": 0.85, "host": 0.85}


def _forest(seed: int, trees: int = 120, depth: int = 16):
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=trees, max_depth=depth, min_samples_leaf=2,
                                  class_weight="balanced_subsample", random_state=seed, n_jobs=-1)


class _Explainer:
    """Per-tree normalised node probabilities, precomputed once for fast explanations."""

    def __init__(self, forest):
        self.trees = []
        for est in forest.estimators_:
            t = est.tree_
            value = t.value[:, 0, :].astype(float)
            value /= np.clip(value.sum(axis=1, keepdims=True), 1e-12, None)
            self.trees.append((t.children_left, t.children_right, t.feature, t.threshold, value))

    def contributions(self, x: Sequence[float], class_idx: int) -> np.ndarray:
        contrib = np.zeros(len(x))
        for left, right, feature, threshold, value in self.trees:
            node = 0
            while left[node] != -1:
                f = feature[node]
                child = left[node] if x[f] <= threshold[node] else right[node]
                contrib[f] += value[child, class_idx] - value[node, class_idx]
                node = child
        return contrib / max(1, len(self.trees))


class _SmallBatchForest:
    """Pure-Python traversal for a handful of rows. sklearn's predict_proba costs ~5 ms per call in
    per-tree overhead, which dominates when a sliding window yields 1-3 candidate hosts. Inputs are
    rounded to float32 first, exactly as sklearn does before comparing against split thresholds."""

    def __init__(self, forest):
        self.trees = []
        for est in forest.estimators_:
            t = est.tree_
            value = t.value[:, 0, :].astype(float)
            value /= np.clip(value.sum(axis=1, keepdims=True), 1e-12, None)
            self.trees.append((t.children_left.tolist(), t.children_right.tolist(), t.feature.tolist(),
                               t.threshold.tolist(), value.tolist()))
        self.n_classes = len(forest.classes_)

    def predict_proba(self, rows: Sequence[Sequence[float]]) -> np.ndarray:
        out = np.zeros((len(rows), self.n_classes))
        for r, row in enumerate(rows):
            x = np.asarray(row, dtype=np.float32).tolist()
            acc = [0.0] * self.n_classes
            for left, right, feature, threshold, value in self.trees:
                node = 0
                while left[node] != -1:
                    node = left[node] if x[feature[node]] <= threshold[node] else right[node]
                leaf = value[node]
                for c in range(self.n_classes):
                    acc[c] += leaf[c]
            out[r] = acc
        return out / len(self.trees)


SMALL_BATCH = 16


class ThreatMLModel:
    def __init__(self, flow_model, host_model, thresholds: Optional[Dict[str, float]] = None,
                 meta: Optional[Dict[str, Any]] = None):
        self.flow_model = flow_model
        self.host_model = host_model
        self.thresholds = dict(DEFAULT_THRESHOLDS, **(thresholds or {}))
        self.meta = meta or {}
        self._explainers: Dict[str, _Explainer] = {}
        self._fast: Dict[int, _SmallBatchForest] = {}

    # ---------- training / persistence ----------
    @classmethod
    def train(cls, Xf, yf, Xh, yh, seed: int = 42) -> "ThreatMLModel":
        # The host model runs once per 3 s window on live traffic, so it gets a lighter forest
        flow_model, host_model = _forest(seed), _forest(seed + 1, trees=50, depth=14)
        flow_model.fit(np.asarray(Xf, dtype=float), np.asarray(yf))
        host_model.fit(np.asarray(Xh, dtype=float), np.asarray(yh))
        for m in (flow_model, host_model):
            m.n_jobs = None  # single-threaded inference: lower latency for small batches
        return cls(flow_model, host_model)

    def save(self, path: os.PathLike = MODEL_PATH):
        import joblib
        import sklearn
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.meta["sklearn_version"] = sklearn.__version__
        joblib.dump({"flow": self.flow_model, "host": self.host_model, "thresholds": self.thresholds,
                     "meta": self.meta}, path, compress=3)

    @classmethod
    def load(cls, path: os.PathLike = MODEL_PATH) -> Optional["ThreatMLModel"]:
        """Returns None when the artifact is missing or unreadable, so detection falls back to rules."""
        try:
            import joblib
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                blob = joblib.load(path)
            # A model trained on a different feature layout would mis-score every flow: refuse it
            if blob["flow"].n_features_in_ != len(FLOW_FEATURES) or blob["host"].n_features_in_ != len(HOST_FEATURES):
                return None
            return cls(blob["flow"], blob["host"], blob.get("thresholds"), blob.get("meta"))
        except Exception:
            return None

    # ---------- inference ----------
    def _predict(self, model, vectors: Sequence[Sequence[float]]) -> List[Tuple[str, float, Dict[str, float]]]:
        if len(vectors) == 0:
            return []
        if len(vectors) <= SMALL_BATCH:
            fast = self._fast.get(id(model))
            if fast is None:
                fast = self._fast[id(model)] = _SmallBatchForest(model)
            proba = fast.predict_proba(vectors)
        else:
            proba = model.predict_proba(np.asarray(vectors, dtype=float))
        classes = list(model.classes_)
        out = []
        for row in proba:
            i = int(np.argmax(row))
            out.append((classes[i], float(row[i]), {c: float(p) for c, p in zip(classes, row)}))
        return out

    def predict_flows(self, vectors):
        return self._predict(self.flow_model, vectors)

    def predict_hosts(self, vectors):
        return self._predict(self.host_model, vectors)

    def explain(self, kind: str, vector: Sequence[float], cls: str, top: int = 3) -> List[Dict[str, Any]]:
        model = self.flow_model if kind == "flow" else self.host_model
        names = FLOW_FEATURES if kind == "flow" else HOST_FEATURES
        if kind not in self._explainers:
            self._explainers[kind] = _Explainer(model)
        class_idx = list(model.classes_).index(cls)
        contrib = self._explainers[kind].contributions(vector, class_idx)
        order = np.argsort(-contrib)[:top]
        return [{"feature": names[i][1], "value": round(float(vector[i]), 3),
                 "contribution": round(float(contrib[i]), 3)} for i in order if contrib[i] > 0]

    def feature_importance(self, kind: str) -> List[Tuple[str, float]]:
        model = self.flow_model if kind == "flow" else self.host_model
        names = FLOW_FEATURES if kind == "flow" else HOST_FEATURES
        pairs = [(names[i][1], float(v)) for i, v in enumerate(model.feature_importances_)]
        return sorted(pairs, key=lambda p: -p[1])


_CACHED: Dict[str, Optional[ThreatMLModel]] = {}


def default_model() -> Optional[ThreatMLModel]:
    """Process-wide model loaded once from models/artifacts (None when absent)."""
    if "model" not in _CACHED:
        _CACHED["model"] = ThreatMLModel.load(MODEL_PATH) if MODEL_PATH.exists() else None
    return _CACHED["model"]
