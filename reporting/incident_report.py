"""Self-contained HTML incident dossier (print to PDF from any browser)."""
import json
from collections import Counter
from datetime import datetime, timezone
from html import escape
from typing import Dict, Any, List, Optional

from response.rule_generator import generate_response_rules

MITRE = {
    "Volumetric_Protocol_DDoS":      ("T1498", "Impact", "Network Denial of Service"),
    "Botnet_C2_Beaconing":           ("T1071", "Command and Control", "Application Layer Protocol"),
    "DGA_Domains_and_DNS_Tunneling": ("T1568", "Command and Control", "Dynamic Resolution"),
    "Encrypted_Malware_TLS":         ("T1573", "Command and Control", "Encrypted Channel"),
    "Reconnaissance_Port_Scanning":  ("T1046", "Discovery", "Network Service Discovery"),
    "Data_Exfiltration":             ("T1048", "Exfiltration", "Exfiltration Over Alternative Protocol"),
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

STYLE = """
body { font-family: Inter, Segoe UI, Arial, sans-serif; color: #0f172a; background: #ffffff; margin: 32px auto; max-width: 980px; padding: 0 16px; line-height: 1.45; }
h1 { font-size: 1.6rem; margin: 0 0 4px 0; } h2 { font-size: 1.15rem; margin-top: 28px; border-bottom: 2px solid #0f172a; padding-bottom: 4px; }
h3 { font-size: 1rem; margin: 18px 0 6px 0; }
.meta { color: #334155; font-size: 0.9rem; }
.banner { border: 2px solid #0f172a; padding: 6px 12px; font-weight: 700; letter-spacing: 1px; text-align: center; margin: 12px 0; font-size: 0.85rem; }
table { border-collapse: collapse; width: 100%; font-size: 0.86rem; margin: 6px 0; }
th, td { border: 1px solid #cbd5e1; padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: #f1f5f9; }
code, pre { font-family: JetBrains Mono, Consolas, monospace; font-size: 0.8rem; }
pre { background: #f8fafc; border: 1px solid #cbd5e1; padding: 8px; white-space: pre-wrap; word-break: break-all; }
.sev-CRITICAL { color: #991b1b; font-weight: 700; } .sev-HIGH { color: #9a3412; font-weight: 700; }
.sev-MEDIUM { color: #854d0e; font-weight: 700; } .sev-LOW { color: #166534; font-weight: 700; }
.incident { page-break-inside: avoid; border-top: 1px solid #cbd5e1; padding-top: 6px; }
@media print { body { margin: 0; } .incident { page-break-inside: avoid; } }
"""


def _evidence(alert: Dict[str, Any]) -> Dict[str, Any]:
    ev = alert.get("evidence", {})
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except ValueError:
            ev = {"raw": ev}
    return ev if isinstance(ev, dict) else {}


def _fmt(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return escape(", ".join(str(v) for v in value)) or "&mdash;"
    if isinstance(value, float):
        return f"{value:.4f}"
    return escape(str(value))


def build_incident_report(alerts: List[Dict[str, Any]], title: str = "Incident Forensic Report",
                          source_label: str = "", max_incidents: int = 50,
                          generated_at: Optional[datetime] = None) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    ordered = sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a.get("severity"), 9), -float(a.get("confidence_score", 0))))
    sev_counts = Counter(a.get("severity") for a in alerts)
    class_counts = Counter(a.get("threat_class") for a in alerts)
    timestamps = sorted(str(a.get("timestamp", "")) for a in alerts if a.get("timestamp"))
    sources = Counter(a.get("src_ip") for a in alerts)

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        f"<title>{escape(title)}</title><style>{STYLE}</style></head><body>",
        "<div class='banner'>RESTRICTED &mdash; FOR OFFICIAL INCIDENT-RESPONSE USE</div>",
        f"<h1>{escape(title)}</h1>",
        "<div class='meta'>Passive threat sensor for unidirectional (data-diode) IP traffic &middot; SIH 2026 PS 26145<br>",
        f"Generated: {escape(generated_at.isoformat(timespec='seconds'))}",
        f" &middot; Evidence source: {escape(source_label)}" if source_label else "",
        "</div>",

        "<h2>1. Executive summary</h2>",
        "<table><tr><th>Total alerts</th><th>Critical</th><th>High</th><th>Medium</th><th>Distinct sources</th><th>Traffic window (UTC)</th></tr>",
        f"<tr><td>{len(alerts)}</td><td>{sev_counts.get('CRITICAL', 0)}</td><td>{sev_counts.get('HIGH', 0)}</td>"
        f"<td>{sev_counts.get('MEDIUM', 0)}</td><td>{len(sources)}</td>"
        f"<td>{escape(timestamps[0]) if timestamps else '&mdash;'}<br>to {escape(timestamps[-1]) if timestamps else '&mdash;'}</td></tr></table>",

        "<h2>2. MITRE ATT&amp;CK coverage</h2>",
        "<table><tr><th>Technique</th><th>Tactic</th><th>Detected class</th><th>Alerts</th></tr>",
    ]
    for cls, count in class_counts.most_common():
        tid, tactic, name = MITRE.get(cls, ("&mdash;", "&mdash;", cls))
        parts.append(f"<tr><td>{escape(tid)} {escape(name)}</td><td>{escape(tactic)}</td><td>{escape(str(cls))}</td><td>{count}</td></tr>")
    parts.append("</table>")

    parts.append("<h2>3. Top threat sources</h2><table><tr><th>Source IP</th><th>Alerts</th><th>Threat classes</th></tr>")
    for ip, count in sources.most_common(10):
        classes = sorted({str(a.get("threat_class")) for a in alerts if a.get("src_ip") == ip})
        parts.append(f"<tr><td><code>{escape(str(ip))}</code></td><td>{count}</td><td>{escape(', '.join(classes))}</td></tr>")
    parts.append("</table>")

    shown = ordered[:max_incidents]
    parts.append(f"<h2>4. Incident details ({len(shown)} of {len(alerts)}, most severe first)</h2>")
    for i, alert in enumerate(shown, 1):
        sev = str(alert.get("severity", ""))
        ev = _evidence(alert)
        rules = generate_response_rules({**alert, "evidence": ev})
        tid = MITRE.get(alert.get("threat_class"), ("",))[0]
        parts += [
            "<div class='incident'>",
            f"<h3>{i}. <span class='sev-{escape(sev)}'>{escape(sev)}</span> &middot; {escape(str(alert.get('threat_class', '')))}"
            f"{' &middot; ' + escape(tid) if tid else ''}</h3>",
            "<table>",
            f"<tr><th>Flow</th><td><code>{escape(str(alert.get('flow_id', '')))}</code></td></tr>",
            f"<tr><th>Traffic time (UTC)</th><td>{escape(str(alert.get('timestamp', '')))}</td></tr>",
            f"<tr><th>Confidence</th><td>{float(alert.get('confidence_score', 0)) * 100:.1f}%</td></tr>",
        ]
        for key, value in ev.items():
            parts.append(f"<tr><th>{escape(key.replace('_', ' ').title())}</th><td>{_fmt(value)}</td></tr>")
        parts.append(f"<tr><th>Recommended action</th><td>{escape(rules['action'])}</td></tr></table>")
        if rules["iptables"]:
            parts.append(f"<pre>{escape(rules['iptables'])}</pre>")
        if rules["suricata"]:
            parts.append(f"<pre>{escape(rules['suricata'])}</pre>")
        parts.append("</div>")

    parts += [
        "<h2>5. Method and constraints</h2>",
        "<ul>",
        "<li>Collection is 100% passive and read-only; the sensor transmits nothing (no ACK, RST or probes).</li>",
        "<li>Encrypted traffic is assessed from ClientHello metadata (JA3, SNI, version, cipher/extension lists) and packet timing; no payload is decrypted.</li>",
        "<li>Response rules are recommendations for the downstream enforcement point and must be reviewed before deployment.</li>",
        "<li>Timestamps are the capture time of the evidence, not the time of analysis.</li>",
        "</ul></body></html>",
    ]
    return "\n".join(p for p in parts if p)
