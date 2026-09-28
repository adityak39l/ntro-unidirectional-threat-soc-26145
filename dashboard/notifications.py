"""Attack notifications: human-readable messages, toast grouping and the alarm tone."""
import io
import json
import math
import re
import struct
import wave
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Dict, Iterable, List

from dashboard.catalog import THREATS, SEVERITIES, severity

MAX_TOASTS = 6
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~])")


def md_escape(text: Any) -> str:
    """Escape Markdown so captured strings (domains, SNI) render literally, never as links."""
    return _MD_SPECIAL.sub(r"\\\1", str(text))


def human_bytes(n: float) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} GB"


def _evidence(alert: Dict[str, Any]) -> Dict[str, Any]:
    ev = alert.get("evidence") or {}
    if isinstance(ev, str):
        try:
            ev = json.loads(ev)
        except ValueError:
            ev = {}
    return ev if isinstance(ev, dict) else {}


def describe(alert: Dict[str, Any]) -> str:
    """One-line plain-text explanation of an alert, built from its evidence."""
    ev = _evidence(alert)
    cls = alert.get("threat_class", "")
    src, dst = alert.get("src_ip", "?"), alert.get("dst_ip", "?")
    port = alert.get("dst_port") or ""
    dst_sock = f"{dst}:{port}" if port else str(dst)

    if cls == "Volumetric_Protocol_DDoS":
        target = ev.get("target") or dst
        flood = "SYN flood" if float(ev.get("syn_only_ratio", 0) or 0) >= 0.8 else "Packet flood"
        return (f"{flood} on {target}: {int(ev.get('peak_packets_per_sec', 0) or 0):,} pkt/s "
                f"from {int(ev.get('unique_sources', 0) or 0):,} sources")
    if cls == "Botnet_C2_Beaconing":
        return (f"{src} beacons to {dst_sock} every {float(ev.get('iat_mean_sec', 0) or 0):.1f} s "
                f"(IAT variance {float(ev.get('iat_variance', 0) or 0):.4f})")
    if cls == "DGA_Domains_and_DNS_Tunneling":
        if ev.get("is_tunnel_suspect"):
            return (f"{src} is tunnelling data over DNS "
                    f"({int(ev.get('encoded_subdomain_length', 0) or 0)}-char encoded subdomain)")
        return f"{src} resolved algorithmic domain {ev.get('queried_domain') or '?'}"
    if cls == "Encrypted_Malware_TLS":
        family = ev.get("matched_threat")
        if family and family != "Unknown":
            return f"{src} → {dst_sock}: JA3 matches {family}"
        anomalies = ev.get("anomalies") or []
        detail = "; ".join(str(a) for a in anomalies[:2]) or "anomalous ClientHello"
        return f"Suspicious TLS {src} → {dst_sock}: {detail}"
    if cls == "Reconnaissance_Port_Scanning":
        ports = int(ev.get("distinct_ports_on_one_host", 0) or 0)
        hosts = int(ev.get("distinct_hosts_on_one_port", 0) or 0)
        if ports >= hosts:
            return f"{src} probed {ports} ports on {ev.get('target') or dst}"
        return f"{src} swept {hosts} hosts on port {port or '?'}"
    if cls == "Data_Exfiltration":
        return (f"{src} sent {human_bytes(ev.get('total_bytes', 0))} to {dst_sock} "
                f"at {human_bytes(ev.get('bytes_per_sec', 0))}/s")
    return f"{src} → {dst_sock}"


def title(alert: Dict[str, Any]) -> str:
    sev = severity(alert.get("severity", "LOW"))
    meta = THREATS.get(alert.get("threat_class", ""))
    name = f"{meta.short} ({meta.mitre_id})" if meta else str(alert.get("threat_class", "Alert"))
    return f"{sev.glyph} {sev.label} · {name}"


@dataclass(frozen=True)
class Toast:
    body: str       # Markdown (dynamic values escaped)
    icon: str
    critical: bool


def build_toasts(new_alerts: Iterable[Dict[str, Any]], max_toasts: int = MAX_TOASTS) -> List[Toast]:
    """One toast per threat class (most severe first), so a large capture can't flood the screen."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for alert in new_alerts:
        groups.setdefault(alert.get("threat_class", ""), []).append(alert)

    def worst(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        return min(alerts, key=lambda a: (severity(a.get("severity")).rank, -int(a.get("id") or 0)))

    ranked = sorted(groups.values(), key=lambda g: (severity(worst(g).get("severity")).rank, -len(g)))
    toasts = []
    for group in ranked[:max_toasts]:
        lead = worst(group)
        extra = f"  \n+{len(group) - 1} more of this type" if len(group) > 1 else ""
        meta = THREATS.get(lead.get("threat_class", ""))
        toasts.append(Toast(
            body=f"**{md_escape(title(lead))}**  \n{md_escape(describe(lead))}{extra}",
            icon=meta.icon if meta else ":material/warning:",
            critical=str(lead.get("severity")).upper() == "CRITICAL",
        ))
    return toasts


@lru_cache(maxsize=1)
def alarm_wav() -> bytes:
    """Two-tone 0.6 s alarm (880/660 Hz), generated in code so no audio asset is shipped."""
    rate, amp, fade = 22050, 0.35, int(22050 * 0.006)
    frames = bytearray()
    for freq in (880, 660, 880, 660):
        n = int(rate * 0.15)
        for i in range(n):
            env = min(1.0, i / fade, (n - 1 - i) / fade)
            frames += struct.pack("<h", int(32767 * amp * env * math.sin(2 * math.pi * freq * i / rate)))
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(bytes(frames))
    return buf.getvalue()


def severity_counts(alerts: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    counts = {level: 0 for level in SEVERITIES}
    for alert in alerts:
        level = str(alert.get("severity", "LOW")).upper()
        counts[level if level in counts else "LOW"] += 1
    return counts
