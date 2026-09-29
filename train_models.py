"""Train, calibrate and evaluate the Random Forest layer, then write the model and its model card.

    python train_models.py                                  # synthetic training + hold-out evaluation
    python train_models.py --calibrate n12.pcap n26.pcap --benign-test n28.pcap n24.pcap
                           --real-botnet neris.pcap --botnet-ip 147.32.84.165

Real captures (e.g. CTU-13 / CTU-Normal from the Stratosphere Lab) are optional. --calibrate captures
set the model's alert thresholds on real benign traffic; --benign-test captures (different hosts and
days, never used for calibration) measure false alarms; the botnet capture shows what the full
pipeline reports on real malware traffic.
"""
import argparse
import collections
import json
import os
import time
from datetime import datetime, timezone

import numpy as np

from ml.evaluate import _read_packets, calibrate_thresholds, run_capture, score_real_benign, synthetic_report
from ml.model import CARD_PATH, MODEL_PATH, ThreatMLModel
from ml.features import FLOW_FEATURE_NAMES, HOST_FEATURE_NAMES
from ml.synthetic import FLOW_CLASSES, HOST_CLASSES, build_flow_dataset, build_host_dataset

TRAIN_SEED, TEST_SEED = 11, 99


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--flow-episodes", type=int, default=220)
    ap.add_argument("--host-episodes", type=int, default=420)
    ap.add_argument("--calibrate", nargs="*", default=[], help="real benign captures for threshold calibration")
    ap.add_argument("--benign-test", nargs="*", default=[], help="held-out real benign captures (false-alarm test)")
    ap.add_argument("--real-botnet", help="malware capture scored with rules-only and hybrid pipelines")
    ap.add_argument("--botnet-ip", help="infected host in the botnet capture")
    args = ap.parse_args()

    t0 = time.time()
    print("[1/5] building synthetic training data ...", flush=True)
    Xf, yf = build_flow_dataset(TRAIN_SEED, args.flow_episodes)
    Xh, yh = build_host_dataset(TRAIN_SEED, args.host_episodes)
    print(f"      flows {len(yf):,} {dict(collections.Counter(yf))}")
    print(f"      host-windows {len(yh):,} {dict(collections.Counter(yh))}")

    print("[2/5] training Random Forests ...", flush=True)
    model = ThreatMLModel.train(Xf, yf, Xh, yh)

    real = {}
    if args.calibrate:
        print("[3/5] calibrating thresholds on real benign traffic ...", flush=True)
        merged = {"flow": [], "host": [], "n_flows": 0, "n_host_windows": 0}
        for path in args.calibrate:
            scores = score_real_benign(model, _read_packets(path))
            for k in ("flow", "host"):
                merged[k].extend(scores[k].tolist())
            merged["n_flows"] += scores["n_flows"]
            merged["n_host_windows"] += scores["n_host_windows"]
        model.thresholds = calibrate_thresholds({k: np.asarray(merged[k]) for k in ("flow", "host")})
        print(f"      thresholds {model.thresholds} from {merged['n_flows']:,} flows / "
              f"{merged['n_host_windows']:,} candidate host-windows")
        real["benign_calibration"] = {"captures": [os.path.basename(p) for p in args.calibrate],
                                      "flows": merged["n_flows"], "candidate_host_windows": merged["n_host_windows"]}
    else:
        print("[3/5] no calibration captures given; keeping default thresholds", flush=True)
    for path in args.benign_test:
        name = os.path.basename(path)
        print(f"      scoring held-out benign capture {name} ...", flush=True)
        packets = _read_packets(path)
        real.setdefault("benign_tests", []).append({
            "capture": name,
            "rules_only": run_capture(packets, None, f"{name}, rules only"),
            "hybrid": run_capture(packets, model, f"{name}, rules + model"),
        })

    print("[4/5] evaluating on synthetic hold-out data ...", flush=True)
    flow_test = build_flow_dataset(TEST_SEED, max(40, args.flow_episodes // 3), return_raw=True)
    host_test = build_host_dataset(TEST_SEED, max(80, args.host_episodes // 3), return_raw=True)
    synthetic = synthetic_report(model, flow_test, host_test, FLOW_CLASSES, HOST_CLASSES)

    if args.real_botnet:
        print("      scoring real botnet capture ...", flush=True)
        packets = _read_packets(args.real_botnet)
        real["botnet_rules_only"] = run_capture(packets, None, "botnet, rules only", args.botnet_ip)
        real["botnet_hybrid"] = run_capture(packets, model, "botnet, rules + model", args.botnet_ip)

    print("[5/5] saving model + model card ...", flush=True)
    model.meta.update({"trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    model.save(MODEL_PATH)
    card = {
        "model": "Random Forest (scikit-learn), 2 classifiers",
        "trained_at": model.meta["trained_at"],
        "sklearn_version": model.meta.get("sklearn_version"),
        "estimators_per_forest": model.flow_model.n_estimators,
        "flow_model": {"classes": list(model.flow_model.classes_), "features": FLOW_FEATURE_NAMES,
                       "train_rows": len(yf), "train_class_counts": dict(collections.Counter(yf)),
                       "top_features": [[n, round(v, 4)] for n, v in model.feature_importance("flow")[:10]]},
        "host_model": {"classes": list(model.host_model.classes_), "features": HOST_FEATURE_NAMES,
                       "train_rows": len(yh), "train_class_counts": dict(collections.Counter(yh)),
                       "top_features": [[n, round(v, 4)] for n, v in model.feature_importance("host")[:8]]},
        "thresholds": model.thresholds,
        "synthetic_holdout": synthetic,
        "real_captures": real,
        "data": {
            "training": "synthetic labelled traffic (ml/synthetic.py, seed 11) run through the production flow and "
                        "sliding-window code; attack parameters span wider ranges than the rule thresholds",
            "holdout": "independent synthetic draw (seed 99)",
            "real": "CTU-13 captures from the Stratosphere Lab (CTU Prague), if supplied",
        },
        "limitations": [
            "Trained on synthetic traffic; real-world accuracy needs evaluation on labelled operational data.",
            "Beacons slower than the 15 s flow idle timeout are split into single-packet flows and not scored.",
            "Large legitimate uploads resemble exfiltration without destination reputation data.",
        ],
        "build_seconds": round(time.time() - t0, 1),
    }
    CARD_PATH.write_text(json.dumps(card, indent=2), encoding="utf-8")
    print(json.dumps({k: card[k] for k in ("thresholds", "synthetic_holdout", "real_captures")}, indent=1))
    print(f"done in {time.time() - t0:.0f}s -> {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
