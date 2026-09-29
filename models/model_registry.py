from typing import Dict, Any, List, Optional, Sequence, Tuple
from feature_engine.window_features import aggregate_window
from ml.features import flow_vector, host_vector, is_host_candidate
from .ddos_detector import DDoSDetector
from .beaconing_detector import BeaconingDetector
from .dga_detector import DGADetector
from .encrypted_malware_detector import EncryptedMalwareDetector
from .port_scan_detector import PortScanDetector
from .exfiltration_detector import ExfiltrationDetector

# An alert raised by the model alone stays below CRITICAL (0.90); rules or rule + model agreement can reach it
ML_ONLY_CONFIDENCE_CAP = 0.89


class ThreatModelRegistry:
    """Runs all 6 detectors, plus the optional Random Forest layer.

    Flow-level (per 5-tuple): C2 beaconing, DGA/DNS tunneling, encrypted malware, exfiltration.
    Window-level (per host, per sliding window): DDoS fan-in, port-scan fan-out.

    With an ML model attached, every rule alert carries the model's probability for its class,
    and the model can raise an alert on its own when its probability clears the calibrated
    threshold for a class no rule fired on.
    """

    def __init__(self, ml_model=None):
        self.ddos = DDoSDetector()
        self.beaconing = BeaconingDetector()
        self.dga = DGADetector()
        self.encrypted_malware = EncryptedMalwareDetector()
        self.port_scan = PortScanDetector()
        self.exfiltration = ExfiltrationDetector()
        self.ml = ml_model

    # ---------- flows ----------
    def _flow_rules(self, flow_dict: Dict[str, Any], features: Dict[str, float],
                    context: Dict[str, Any]) -> Dict[str, Tuple[bool, float, Dict[str, Any]]]:
        ja3_hash = context.get("ja3_hash") or flow_dict.get("ja3_hash", "")
        return {
            self.beaconing.NAME: self.beaconing.predict(features),
            self.dga.NAME: self.dga.predict(features, context=context),
            self.encrypted_malware.NAME: self.encrypted_malware.predict(features, ja3_hash=ja3_hash, context=context),
            self.exfiltration.NAME: self.exfiltration.predict(features),
        }

    def evaluate_flow(self, flow_dict: Dict[str, Any], features: Dict[str, float],
                      context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return self.evaluate_flows([(flow_dict, features, context or {})])[0]

    def evaluate_flows(self, items: Sequence[Tuple[Dict[str, Any], Dict[str, float], Dict[str, Any]]]
                       ) -> List[List[Dict[str, Any]]]:
        """Batch evaluation (one model call per batch keeps Random Forest inference cheap)."""
        rule_outputs = [self._flow_rules(flow, features, context or {}) for flow, features, context in items]
        results = []
        for outputs in rule_outputs:
            results.append([{"threat_class": cls, "confidence_score": conf, "evidence": evidence}
                            for cls, (is_threat, conf, evidence) in outputs.items() if is_threat])
        if not self.ml or not items:
            return results

        vectors = [flow_vector(features) for _, features, _ in items]
        threshold = self.ml.thresholds["flow"]
        for i, (cls, prob, probs) in enumerate(self.ml.predict_flows(vectors)):
            fired = {a["threat_class"] for a in results[i]}
            for alert in results[i]:
                p = probs.get(alert["threat_class"], 0.0)
                self._annotate(alert, p, threshold, "flow", vectors[i])
            if cls != "benign" and prob >= threshold and cls not in fired:
                evidence = dict(rule_outputs[i][cls][2])
                results[i].append(self._ml_alert(cls, prob, evidence, "flow", vectors[i]))
        return results

    # ---------- windows ----------
    def evaluate_window(self, packets: List[Dict[str, Any]], window_start: float,
                        window_end: float) -> List[Dict[str, Any]]:
        """Returns detections with a synthetic flow describing the host-level activity."""
        if not packets:
            return []
        agg = aggregate_window(packets, window_start)
        window = {"window_start": round(window_start, 3), "window_end": round(window_end, 3)}
        alerts = []

        ddos_rules = {dst: self.ddos.predict(target) for dst, target in agg["by_target"].items()}
        scan_rules = {src: self.port_scan.predict(source) for src, source in agg["by_source"].items()}
        for dst, (is_threat, confidence, evidence) in ddos_rules.items():
            if is_threat:
                alerts.append(self._ddos_alert(agg["by_target"][dst], confidence, {**evidence, **window}))
        for src, (is_threat, confidence, evidence) in scan_rules.items():
            if is_threat:
                alerts.append(self._scan_alert(agg["by_source"][src], confidence, {**evidence, **window}))

        if self.ml:
            hosts = [h for h in sorted(set(agg["by_target"]) | set(agg["by_source"]))
                     if is_host_candidate(agg["by_target"].get(h), agg["by_source"].get(h))]
            vectors = [host_vector(agg["by_target"].get(h), agg["by_source"].get(h)) for h in hosts]
            threshold = self.ml.thresholds["host"]
            by_host = {h: (v, pred) for h, v, pred in zip(hosts, vectors, self.ml.predict_hosts(vectors))}
            for alert in alerts:
                host = alert["flow"]["dst_ip"] if alert["threat_class"] == self.ddos.NAME else alert["flow"]["src_ip"]
                if host in by_host:
                    vector, (_, _, probs) = by_host[host]
                    self._annotate(alert, probs.get(alert["threat_class"], 0.0), threshold, "host", vector)
            for host, (vector, (cls, prob, _)) in by_host.items():
                if cls == self.ddos.NAME and prob >= threshold and host in agg["by_target"] \
                        and not ddos_rules[host][0]:
                    evidence = {**ddos_rules[host][2], **window}
                    alerts.append(self._ddos_alert(agg["by_target"][host], 0.0, evidence,
                                                   ml=(prob, vector)))
                elif cls == self.port_scan.NAME and prob >= threshold and host in agg["by_source"] \
                        and not scan_rules[host][0]:
                    evidence = {**scan_rules[host][2], **window}
                    alerts.append(self._scan_alert(agg["by_source"][host], 0.0, evidence, ml=(prob, vector)))
        return alerts

    # ---------- helpers ----------
    def _annotate(self, alert: Dict[str, Any], prob: float, threshold: float, kind: str, vector):
        agrees = prob >= threshold
        alert["evidence"]["detected_by"] = "Rules + AI model" if agrees else "Rules"
        alert["evidence"]["model_probability"] = round(prob, 3)
        if agrees:
            alert["evidence"]["model_factors"] = self._factors(kind, vector, alert["threat_class"])
            alert["confidence_score"] = round(min(0.99, max(alert["confidence_score"], prob)), 4)

    def _ml_alert(self, cls: str, prob: float, evidence: Dict[str, Any], kind: str, vector) -> Dict[str, Any]:
        evidence.pop("indicators", None)
        evidence.update({"detected_by": "AI model", "model_probability": round(prob, 3),
                         "model_factors": self._factors(kind, vector, cls)})
        return {"threat_class": cls, "confidence_score": round(min(ML_ONLY_CONFIDENCE_CAP, prob), 4),
                "evidence": evidence}

    def _factors(self, kind: str, vector, cls: str) -> List[str]:
        return [f"{f['feature']} = {f['value']:g}" for f in self.ml.explain(kind, vector, cls)]

    def _ddos_alert(self, target: Dict[str, Any], confidence: float, evidence: Dict[str, Any], ml=None):
        dst, top_src = target["dst_ip"], target["top_sources"][0]
        alert = {
            "flow": {
                "flow_id": f"{top_src}:*->{dst}:{target['top_dst_port']}_{target['protocol']}",
                "src_ip": top_src, "dst_ip": dst, "src_port": 0,
                "dst_port": target["top_dst_port"], "protocol": target["protocol"],
                "last_time": target["last_ts"],
                # Top source changes between windows; one flood = one target
                "dedup_key": f"*->{dst}",
            },
            "threat_class": self.ddos.NAME,
            "confidence_score": confidence,
            "evidence": evidence,
        }
        if ml:
            alert.update(self._ml_alert(self.ddos.NAME, ml[0], evidence, "host", ml[1]))
        return alert

    def _scan_alert(self, source: Dict[str, Any], confidence: float, evidence: Dict[str, Any], ml=None):
        src = source["src_ip"]
        vertical = source["max_ports_on_one_host"] >= source["max_hosts_on_one_port"]
        dst = source["vertical_target"] if vertical else "*"
        dst_port = 0 if vertical else source["horizontal_port"]
        alert = {
            "flow": {
                "flow_id": f"{src}:*->{dst}:{dst_port or '*'}_{source['protocol']}",
                "src_ip": src, "dst_ip": dst, "src_port": 0,
                "dst_port": dst_port, "protocol": source["protocol"],
                "last_time": source["last_ts"],
            },
            "threat_class": self.port_scan.NAME,
            "confidence_score": confidence,
            "evidence": evidence,
        }
        if ml:
            alert.update(self._ml_alert(self.port_scan.NAME, ml[0], evidence, "host", ml[1]))
        return alert
