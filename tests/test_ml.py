import json

import pytest

from ml.features import FLOW_FEATURE_NAMES, HOST_FEATURE_NAMES, flow_vector, host_vector, is_host_candidate
from ml.model import CARD_PATH, MODEL_PATH, ThreatMLModel
from ml.synthetic import FLOW_CLASSES, HOST_CLASSES, build_flow_dataset, build_host_dataset
from models.model_registry import ML_ONLY_CONFIDENCE_CAP, ThreatModelRegistry


@pytest.fixture(scope="module")
def small_model():
    Xf, yf = build_flow_dataset(seed=5, episodes=8)
    Xh, yh = build_host_dataset(seed=5, episodes=30)
    return ThreatMLModel.train(Xf, yf, Xh, yh), (Xf, yf, Xh, yh)


def test_synthetic_data_covers_every_class(small_model):
    _, (Xf, yf, Xh, yh) = small_model
    assert set(yf) == set(FLOW_CLASSES)
    assert set(yh) == set(HOST_CLASSES)
    assert all(len(row) == len(FLOW_FEATURE_NAMES) for row in Xf)
    assert all(len(row) == len(HOST_FEATURE_NAMES) for row in Xh)


def test_model_predicts_and_explains(small_model):
    model, (Xf, yf, _, _) = small_model
    idx = yf.index("Botnet_C2_Beaconing")
    cls, prob, probs = model.predict_flows([Xf[idx]])[0]
    assert abs(sum(probs.values()) - 1.0) < 1e-6 and 0 <= prob <= 1
    factors = model.explain("flow", Xf[idx], "Botnet_C2_Beaconing")
    assert factors and all(f["contribution"] > 0 for f in factors)
    assert all(isinstance(f["feature"], str) and "_" not in f["feature"] for f in factors)  # human labels


def test_small_batch_path_matches_sklearn(small_model):
    import numpy as np
    from ml.model import _SmallBatchForest
    model, (Xf, _, Xh, _) = small_model
    for forest, rows in ((model.flow_model, Xf[:12]), (model.host_model, Xh[:12])):
        expected = forest.predict_proba(np.asarray(rows, dtype=float))
        assert np.allclose(_SmallBatchForest(forest).predict_proba(rows), expected, atol=1e-9)


def test_model_round_trip_and_graceful_failure(small_model, tmp_path):
    model, (Xf, _, _, _) = small_model
    path = tmp_path / "m.joblib"
    model.save(path)
    loaded = ThreatMLModel.load(path)
    assert loaded.predict_flows(Xf[:5]) == model.predict_flows(Xf[:5])
    assert ThreatMLModel.load(tmp_path / "missing.joblib") is None
    bad = tmp_path / "bad.joblib"
    bad.write_bytes(b"not a model")
    assert ThreatMLModel.load(bad) is None


class _StubModel:
    """Deterministic stand-in for the forest, to test the hybrid logic in isolation."""
    thresholds = {"flow": 0.85, "host": 0.85}

    def __init__(self, flow_pred):
        self.flow_pred = flow_pred

    def predict_flows(self, vectors):
        return [self.flow_pred for _ in vectors]

    def predict_hosts(self, vectors):
        return [("benign", 0.99, {"benign": 0.99}) for _ in vectors]

    def explain(self, kind, vector, cls, top=3):
        return [{"feature": "timing irregularity (IAT CV)", "value": 0.2, "contribution": 0.4}]


def test_model_only_alert_is_labelled_and_capped():
    probs = {"benign": 0.03, "Botnet_C2_Beaconing": 0.97}
    registry = ThreatModelRegistry(ml_model=_StubModel(("Botnet_C2_Beaconing", 0.97, probs)))
    # Jittered beacon the rule rejects (CV too high) but the model is sure about
    features = {"packet_count": 20.0, "iat_mean": 5.0, "iat_variance": 1.5, "iat_cv": 0.25}
    alerts = registry.evaluate_flow({}, features, {})
    assert len(alerts) == 1
    ev = alerts[0]["evidence"]
    assert ev["detected_by"] == "AI model" and ev["model_probability"] == 0.97
    assert ev["model_factors"] == ["timing irregularity (IAT CV) = 0.2"]
    assert alerts[0]["confidence_score"] <= ML_ONLY_CONFIDENCE_CAP


def test_rule_alert_is_annotated_with_model_opinion():
    probs = {"benign": 0.9, "Botnet_C2_Beaconing": 0.1}
    registry = ThreatModelRegistry(ml_model=_StubModel(("benign", 0.9, probs)))
    features = {"packet_count": 25.0, "iat_mean": 5.0, "iat_variance": 0.002, "iat_cv": 0.05}
    alerts = registry.evaluate_flow({}, features, {})
    assert [a["threat_class"] for a in alerts] == ["Botnet_C2_Beaconing"]
    assert alerts[0]["evidence"]["detected_by"] == "Rules"
    assert alerts[0]["evidence"]["model_probability"] == 0.1


def test_quiet_hosts_are_not_scored():
    assert not is_host_candidate({"packets": 3}, {"max_ports_on_one_host": 1, "max_hosts_on_one_port": 1})
    assert is_host_candidate(None, {"max_ports_on_one_host": 12})
    assert len(host_vector(None, None)) == len(HOST_FEATURE_NAMES)
    assert len(flow_vector({})) == len(FLOW_FEATURE_NAMES)


def test_indian_brand_domains_are_not_dga():
    from feature_engine.dns_analyzer import DNSAnalyzer
    for domain in ("hdfcbank.com", "icicibank.com", "flipkart.com", "letsencrypt.org", "incometax.gov.in",
                   "paloaltonetworks.com", "makemytrip.com"):
        assert len(DNSAnalyzer.analyze_domain(domain)["dga_signals"]) < 3, domain


def test_truncated_capture_is_read_up_to_the_cut(tmp_path):
    from traffic_simulator.generate_traffic import generate_synthetic_pcap
    from ingestion.pcap_reader import ReadOnlyPacketReader
    full = tmp_path / "full.pcap"
    generate_synthetic_pcap("port_scan", str(full))
    data = full.read_bytes()
    cut = tmp_path / "cut.pcap"
    # Last record is a 16-byte header + 54-byte SYN; dropping 60 bytes cuts inside the record header
    cut.write_bytes(data[: len(data) - 60])
    reader = ReadOnlyPacketReader(str(cut))
    packets = list(reader.read_packets())
    assert len(packets) == 12 and reader.cut_short


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="model artifact not built")
def test_committed_model_and_card_are_consistent():
    model = ThreatMLModel.load(MODEL_PATH)
    assert model is not None
    card = json.loads(CARD_PATH.read_text(encoding="utf-8"))
    assert card["thresholds"] == model.thresholds
    syn = card["synthetic_holdout"]
    for cls, rules in syn["rules"]["per_class"].items():
        # The hybrid never loses an attack the rules alone would catch
        assert syn["hybrid"]["per_class"][cls]["recall"] >= rules["recall"] - 1e-9, cls
