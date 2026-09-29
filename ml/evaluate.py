"""Evaluation of rules vs Random Forest vs hybrid, on synthetic hold-out data and real captures."""
import os
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence

import numpy as np

from detection.pipeline import StreamingDetectionPipeline
from feature_engine.feature_extractor import FeatureExtractor
from feature_engine.window_features import aggregate_window
from ingestion.flow_aggregator import FlowAggregator
from ingestion.pcap_reader import ReadOnlyPacketReader
from ingestion.window_manager import SlidingWindowManager
from ml.features import flow_vector, host_vector, is_host_candidate
from models.model_registry import ThreatModelRegistry


def _per_class(y_true: Sequence[str], y_pred: Sequence[str], classes: Sequence[str]) -> Dict[str, Any]:
    from sklearn.metrics import precision_recall_fscore_support
    attack = [c for c in classes if c != "benign"]
    p, r, f, support = precision_recall_fscore_support(y_true, y_pred, labels=attack, zero_division=0)
    benign_total = sum(1 for t in y_true if t == "benign")
    benign_fp = sum(1 for t, q in zip(y_true, y_pred) if t == "benign" and q != "benign")
    return {
        "per_class": {c: {"precision": round(float(p[i]), 4), "recall": round(float(r[i]), 4),
                          "f1": round(float(f[i]), 4), "support": int(support[i])} for i, c in enumerate(attack)},
        "benign_false_positive_rate": round(benign_fp / max(1, benign_total), 5),
        "benign_support": benign_total,
    }


def _ml_label(pred, threshold: float) -> str:
    cls, prob, _ = pred
    return cls if cls != "benign" and prob >= threshold else "benign"


def synthetic_report(model, flow_test, host_test, flow_classes, host_classes) -> Dict[str, Any]:
    """flow_test = (X, y, raw) with raw rows (flow, features, context); host_test = (X, y, raw(target, source))."""
    rules = ThreatModelRegistry(ml_model=None)
    Xf, yf, raw_f = flow_test
    rule_f = []
    for flow, features, context in raw_f:
        fired = [(conf, cls) for cls, (hit, conf, _) in rules._flow_rules(flow, features, context).items() if hit]
        rule_f.append(max(fired)[1] if fired else "benign")
    ml_f = [_ml_label(p, model.thresholds["flow"]) for p in model.predict_flows(Xf)]
    hyb_f = [r if r != "benign" else m for r, m in zip(rule_f, ml_f)]

    Xh, yh, raw_h = host_test
    rule_h = []
    for target, source in raw_h:
        if target and rules.ddos.predict(target)[0]:
            rule_h.append(rules.ddos.NAME)
        elif source and rules.port_scan.predict(source)[0]:
            rule_h.append(rules.port_scan.NAME)
        else:
            rule_h.append("benign")
    ml_h = [_ml_label(p, model.thresholds["host"]) for p in model.predict_hosts(Xh)]
    hyb_h = [r if r != "benign" else m for r, m in zip(rule_h, ml_h)]

    report = {}
    for name, fp, hp in (("rules", rule_f, rule_h), ("ml", ml_f, ml_h), ("hybrid", hyb_f, hyb_h)):
        flow_part, host_part = _per_class(yf, fp, flow_classes), _per_class(yh, hp, host_classes)
        report[name] = {
            "per_class": {**flow_part["per_class"], **host_part["per_class"]},
            "benign_flow_false_positive_rate": flow_part["benign_false_positive_rate"],
            "benign_host_window_false_positive_rate": host_part["benign_false_positive_rate"],
        }
    report["test_size"] = {"flows": len(yf), "benign_flows": sum(1 for v in yf if v == "benign"),
                           "host_windows": len(yh), "benign_host_windows": sum(1 for v in yh if v == "benign")}
    return report


# ---------- real captures ----------

def _read_packets(path: str) -> List[Dict[str, Any]]:
    reader = ReadOnlyPacketReader(path)
    packets = list(reader.read_packets())
    packets.sort(key=lambda p: p["timestamp"])
    return packets


def score_real_benign(model, packets: Sequence[Dict[str, Any]]) -> Dict[str, np.ndarray]:
    """Highest attack-class probability the model gives each real (benign) flow and candidate host-window."""
    agg, fx, flows = FlowAggregator(), FeatureExtractor(), []
    for i, pkt in enumerate(packets, 1):
        expired = agg.process_packet(pkt)
        if expired:
            flows.append(expired)
        if i % 500 == 0:
            flows.extend(agg.flush_expired(pkt["timestamp"]))
    flows.extend(agg.flush_all())
    vectors = [flow_vector(fx.extract_flow_features(f)) for f in flows]
    flow_scores = np.array([max(v for c, v in p[2].items() if c != "benign") for p in model.predict_flows(vectors)]) \
        if vectors else np.array([])

    wm, host_vectors = SlidingWindowManager(), []
    windows = []
    for pkt in packets:
        for win in wm.add_item(pkt):
            windows.append((win, wm.last_window_bounds[0]))
    for win, start in windows:
        a = aggregate_window(win, start)
        for h in set(a["by_target"]) | set(a["by_source"]):
            t, s = a["by_target"].get(h), a["by_source"].get(h)
            if is_host_candidate(t, s):
                host_vectors.append(host_vector(t, s))
    host_scores = np.array([max(v for c, v in p[2].items() if c != "benign")
                            for p in model.predict_hosts(host_vectors)]) if host_vectors else np.array([])
    return {"flow": flow_scores, "host": host_scores, "n_flows": len(flows), "n_host_windows": len(host_vectors)}


def calibrate_thresholds(scores: Dict[str, np.ndarray], max_flow_fp_per_10k: float = 5.0,
                         max_host_fp_per_1k: float = 1.0, floor: float = 0.85) -> Dict[str, float]:
    """Smallest threshold >= floor that keeps model-only false alarms on real benign traffic under budget."""
    out = {}
    for kind, budget in (("flow", max_flow_fp_per_10k / 10_000), ("host", max_host_fp_per_1k / 1_000)):
        s = scores[kind]
        thr = floor
        if len(s):
            thr = max(floor, float(np.quantile(s, 1 - budget)) + 1e-6)
        out[kind] = round(min(0.995, thr), 4)
    return out


def run_capture(packets: Sequence[Dict[str, Any]], ml_model, label: str,
                focus_ip: Optional[str] = None) -> Dict[str, Any]:
    """Full streaming pipeline over a capture; alert counts per class and per detection source."""
    tmp = tempfile.mkdtemp(prefix="soc_eval_")
    pipe = StreamingDetectionPipeline(alert_jsonl=os.path.join(tmp, "a.jsonl"), alert_db=os.path.join(tmp, "a.db"),
                                      ml_model=ml_model)
    t0 = time.perf_counter()
    alerts = []
    for pkt in packets:
        alerts.extend(pipe.process_packet(pkt))
    alerts.extend(pipe.flush_and_complete())
    elapsed = time.perf_counter() - t0
    stats = pipe.get_stats()
    by_class: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    focus = 0
    for a in alerts:
        by_class[a["threat_class"]] = by_class.get(a["threat_class"], 0) + 1
        src = a["evidence"].get("detected_by", "Rules")
        by_source[src] = by_source.get(src, 0) + 1
        if focus_ip and focus_ip in (a["src_ip"], a["dst_ip"]):
            focus += 1
    result = {
        "capture": label, "packets": len(packets), "flows": stats["total_flows"], "alerts": len(alerts),
        "alerts_per_10k_flows": round(10_000 * len(alerts) / max(1, stats["total_flows"]), 2),
        "by_class": by_class, "by_detection_source": by_source, "seconds": round(elapsed, 1),
    }
    if focus_ip:
        result["alerts_involving_" + focus_ip] = focus
    return result
