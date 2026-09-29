import os
import sys
import json
import math
import time
import random
import sqlite3
import tempfile
from contextlib import closing
from html import escape
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ── Project root ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from traffic_simulator.generate_traffic import generate_synthetic_pcap
from ingestion.pcap_reader import ReadOnlyPacketReader
from detection.pipeline import StreamingDetectionPipeline
from response.rule_generator import generate_response_rules, build_rules_bundle
from reporting.incident_report import build_incident_report
from dashboard import components as ui
from dashboard import notifications as notif
from dashboard import theme
from dashboard import workspace
from ml.model import CARD_PATH, MODEL_PATH, ThreatMLModel
from dashboard.catalog import (
    THREATS, THREAT_ORDER, SEVERITIES, SEVERITY_ORDER, KILL_CHAIN_STAGES, MITRE_TACTICS, severity, threat_short,
)

APP_VERSION = "2.0"
MAX_UPLOAD_PACKETS = 300_000
LIVE_INTERVAL_S = 12
FEED_PAGE_SIZE = 15
WORKSPACE_BASE = os.environ.get("SOC_WORKSPACE_DIR") or str(ROOT_DIR / "data" / "sessions")
TYPICAL_SEVERITY = {
    "Volumetric_Protocol_DDoS": "CRITICAL", "Botnet_C2_Beaconing": "CRITICAL",
    "DGA_Domains_and_DNS_Tunneling": "HIGH", "Encrypted_Malware_TLS": "CRITICAL",
    "Reconnaissance_Port_Scanning": "HIGH", "Data_Exfiltration": "HIGH",
}

st.set_page_config(
    page_title="AI Threat Detection · Unidirectional IP Traffic · SIH 26145",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="auto",
)

ss = st.session_state

# ══════════════════════════════════════════════════════════════════════════════
# SESSION WORKSPACE (each visitor gets private alert storage)
# ══════════════════════════════════════════════════════════════════════════════
if "workspace_id" not in ss:
    ss.workspace_id = workspace.new_workspace_id()
    workspace.cleanup_stale(WORKSPACE_BASE, keep=ss.workspace_id)
WS = workspace.open_workspace(WORKSPACE_BASE, ss.workspace_id)

ss.setdefault("sound_on", True)
ss.setdefault("pending_alarm", False)
ss.setdefault("notif_seen_id", None)       # highest alert id already toasted
ss.setdefault("notif_read_id", 0)          # highest alert id marked read in the bell
ss.setdefault("system_events", [])
ss.setdefault("data_source", {"kind": "simulated", "label": "Simulated demo traffic"})
ss.setdefault("guide_dismissed", False)
ss.setdefault("feed_page", 0)
ss.setdefault("dialog_alert", None)
ss.setdefault("live_last_ts", 0.0)
ss.setdefault("live_last", None)


# ══════════════════════════════════════════════════════════════════════════════
# DATA & PIPELINE
# ══════════════════════════════════════════════════════════════════════════════
ALERT_COLUMNS = ["id", "timestamp", "flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                 "threat_class", "severity", "confidence_score", "evidence"]


def load_alerts() -> pd.DataFrame:
    df = pd.DataFrame(columns=ALERT_COLUMNS)
    if os.path.exists(WS.db):
        try:
            with closing(sqlite3.connect(WS.db, timeout=10.0)) as conn:
                df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 5000", conn)
        except (sqlite3.Error, pd.errors.DatabaseError):
            pass

    def parse(ev):
        if isinstance(ev, dict):
            return ev
        try:
            parsed = json.loads(ev) if ev else {}
        except (TypeError, ValueError):
            parsed = {}
        return parsed if isinstance(parsed, dict) else {}

    df["evidence"] = df["evidence"].map(parse) if not df.empty else df["evidence"]
    df["confidence_score"] = pd.to_numeric(df["confidence_score"], errors="coerce").fillna(0.0)
    ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["ts"] = ts.dt.tz_convert(ui.IST).dt.tz_localize(None)
    df["short"] = df["threat_class"].map(threat_short)
    return df


def records(frame: pd.DataFrame) -> list:
    out = []
    for rec in frame.to_dict("records"):
        out.append({k: (v.item() if hasattr(v, "item") else v) for k, v in rec.items()})
    return out


@st.cache_resource(show_spinner=False)
def load_ml_model():
    """Random Forest layer shared by all sessions (None if the artifact is missing or unreadable)."""
    return ThreatMLModel.load(MODEL_PATH) if MODEL_PATH.exists() else None


@st.cache_data(show_spinner=False)
def load_model_card() -> dict:
    try:
        return json.loads(CARD_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


ML_MODEL = load_ml_model()
REAL_CAPTURE_NAMES = {
    "ctu_normal12_head.pcap": "CTU-Normal-12 (2013)",
    "ctu_normal26.pcap": "CTU-Normal-26 (2017)",
    "ctu_normal28.pcap": "Normal traffic · CTU-Normal-28 (2017)",
    "ctu_normal24_head.pcap": "Normal traffic · CTU-Normal-24 (2017, Windows host)",
}


def active_ml():
    return ML_MODEL if ss.get("ml_on", True) else None


def analyse_pcap(pcap_path: str, idle_timeout: float = 15.0, max_packets=None, on_progress=None) -> dict:
    """Runs the passive pipeline over a capture and returns ingestion + detection telemetry."""
    pipe = StreamingDetectionPipeline(alert_jsonl=WS.jsonl, alert_db=WS.db, idle_timeout=idle_timeout,
                                      ml_model=active_ml())
    reader = ReadOnlyPacketReader(pcap_path, max_packets=max_packets)
    alerts = []
    t0 = time.perf_counter()
    for pkt in reader.read_packets():
        alerts.extend(pipe.process_packet(pkt))
        if on_progress and reader.packets_parsed % 2000 == 0:
            on_progress(reader)
    alerts.extend(pipe.flush_and_complete())
    elapsed = max(1e-6, time.perf_counter() - t0)
    stats = pipe.get_stats()
    return {
        "packets": reader.packets_parsed,
        "skipped": reader.frames_skipped,
        "truncated": reader.truncated,
        "linktype": reader.linktype,
        "flows": stats["total_flows"],
        "windows": stats["total_windows"],
        "alerts": alerts,
        "elapsed": elapsed,
        "pps": reader.packets_parsed / elapsed,
        "flow_ms": stats["avg_flow_inference_ms"],
        "window_ms": stats["avg_window_inference_ms"],
    }


def run_simulation(kind: str):
    pkt_count = generate_synthetic_pcap(attack_type=kind, output_path=WS.simulated_pcap)
    result = analyse_pcap(WS.simulated_pcap, idle_timeout=2.0)
    return pkt_count, result["alerts"]


def clear_alerts() -> bool:
    try:
        if os.path.exists(WS.db):
            with closing(sqlite3.connect(WS.db, timeout=10.0)) as conn:
                conn.execute("DELETE FROM alerts")
                conn.commit()
        if os.path.exists(WS.jsonl):
            open(WS.jsonl, "w").close()
        return True
    except (OSError, sqlite3.Error):
        return False


def push_event(level: str, title: str, message: str):
    """System notification (problems, not attacks): toasted once, kept in the bell."""
    events = ss.system_events
    events.append({"id": f"sys-{time.time_ns()}", "ts": time.time(), "level": level, "title": title,
                   "message": message, "toasted": False, "read": False})
    del events[:-30]


# ══════════════════════════════════════════════════════════════════════════════
# CALLBACKS (run before the script body, so the page renders fresh data)
# ══════════════════════════════════════════════════════════════════════════════
def cb_simulate(kind: str):
    try:
        pkts, alerts = run_simulation(kind)
    except Exception as exc:  # surfaced to the operator instead of a stack trace
        push_event("error", "Simulation failed", str(exc))
        return
    if not ss.get("live_mode"):
        ss.data_source = {"kind": "simulated", "label": "Simulated demo traffic"}
    if not alerts:
        push_event("info", "Simulation finished", f"{pkts:,} packets analysed, no threats detected.")


def cb_reset():
    if clear_alerts():
        ss.feed_page = 0
        ss.dialog_alert = None
        push_event("info", "Workspace cleared", "All alerts in this session were deleted.")
    else:
        push_event("error", "Reset failed", "The alert store could not be cleared.")


def cb_open_alert(alert_id: int):
    ss.dialog_alert = int(alert_id)


def cb_close_dialog():
    ss.dialog_alert = None


def cb_toggle_sound():
    ss.sound_on = not ss.sound_on


def cb_test_alarm():
    ss.pending_alarm = True


def cb_mark_read(max_id: int):
    ss.notif_read_id = max(ss.notif_read_id, int(max_id))
    for event in ss.system_events:
        event["read"] = True


def cb_dismiss_guide():
    ss.guide_dismissed = True


def cb_clear_filters():
    for key in ("f_window", "f_sev", "f_threat", "f_ip"):
        if key in ss:
            del ss[key]
    ss.feed_page = 0


def cb_page(delta: int):
    ss.feed_page = max(0, ss.feed_page + delta)


# ══════════════════════════════════════════════════════════════════════════════
# LOAD DATA, SEED DEMO, DETECT NEW ALERTS
# ══════════════════════════════════════════════════════════════════════════════
df = load_alerts()
if df.empty and not ss.get("auto_seeded"):
    ss.auto_seeded = True
    try:
        run_simulation("all")
        df = load_alerts()
    except Exception as exc:
        push_event("error", "Demo data unavailable", str(exc))

max_id = int(df["id"].max()) if not df.empty else 0
if ss.notif_seen_id is None:
    ss.notif_seen_id = max_id  # alerts present at session start are not "new"
new_alerts = records(df[df["id"] > ss.notif_seen_id]) if not df.empty else []
ss.notif_seen_id = max(ss.notif_seen_id, max_id)

toasts = notif.build_toasts(new_alerts)
play_alarm = ss.sound_on and (ss.pending_alarm or any(t.critical for t in toasts))
ss.pending_alarm = False

for t in toasts:
    st.toast(t.body, icon=t.icon, duration="long" if t.critical else "short")
for event in ss.system_events:
    if not event["toasted"]:
        icon = {"error": ":material/error:", "warning": ":material/warning:"}.get(event["level"], ":material/info:")
        st.toast(f"**{notif.md_escape(event['title'])}**  \n{notif.md_escape(event['message'])}", icon=icon,
                 duration="long" if event["level"] == "error" else "short")
        event["toasted"] = True

if play_alarm:
    with st.container(key="alarm-audio"):
        st.audio(notif.alarm_wav(), format="audio/wav", autoplay=True)

unread_alerts = int((df["id"] > ss.notif_read_id).sum()) if not df.empty else 0
unread_events = sum(1 for e in ss.system_events if not e["read"])
unread = unread_alerts + unread_events


# ══════════════════════════════════════════════════════════════════════════════
# HEADER: brand · status · notifications · sound · theme
# ══════════════════════════════════════════════════════════════════════════════
def notification_items() -> list:
    items = []
    for rec in records(df.head(12)):
        items.append({
            "kind": "alert", "id": rec["id"], "ts": rec["ts"], "unread": rec["id"] > ss.notif_read_id,
            "glyph": severity(rec["severity"]).glyph, "color": severity(rec["severity"]).color,
            "title": notif.title(rec), "message": notif.describe(rec),
        })
    for event in ss.system_events[-8:]:
        color = {"error": SEVERITIES["CRITICAL"].color, "warning": SEVERITIES["MEDIUM"].color}.get(event["level"], "var(--accent)")
        items.append({
            "kind": "system", "id": event["id"],
            "ts": pd.Timestamp(event["ts"], unit="s", tz="UTC").tz_convert(ui.IST).tz_localize(None),
            "unread": not event["read"], "glyph": "●", "color": color,
            "title": f"System · {event['title']}", "message": event["message"],
        })
    items.sort(key=lambda i: i["ts"] if pd.notna(i["ts"]) else pd.Timestamp.min, reverse=True)
    return items[:10]


def render_notifications():
    st.html(ui.section("Notifications", f"{unread} unread · attacks and system events"))
    with st.container(horizontal=True, gap="small"):
        st.button("Mark all read", icon=":material/done_all:", key="notif_read", type="tertiary",
                  on_click=cb_mark_read, args=(max_id,), disabled=unread == 0)
        st.button("Test alarm", icon=":material/volume_up:", key="notif_test", type="tertiary",
                  on_click=cb_test_alarm, help="Plays the CRITICAL alarm once (also unlocks browser audio)")
    items = notification_items()
    if not items:
        st.html(ui.empty_state("No notifications yet."))
        return
    for item in items:
        when = item["ts"].strftime("%d %b, %H:%M:%S IST") if pd.notna(item["ts"]) else ""
        body = (f'<div class="notif{" unread" if item["unread"] else ""}" style="--sev-color:{item["color"]}">'
                f'<div class="glyph">{item["glyph"]}</div><div><div class="notif-title">{escape(item["title"])}</div>'
                f'<div class="notif-msg">{escape(item["message"])}</div><div class="notif-time">{escape(when)}</div></div></div>')
        if item["kind"] == "alert":
            with st.container(key=f"feed-notif-{item['id']}", horizontal=True, vertical_alignment="center", wrap=False):
                st.html(body)
                st.button("Open", key=f"notif_open_{item['id']}", type="tertiary", on_click=cb_open_alert,
                          args=(item["id"],))
        else:
            st.html(body)


live_on = bool(ss.get("live_mode"))
status_chip = ('<span class="chip live"><span class="dot"></span>Live monitoring</span>' if live_on
               else '<span class="chip"><span class="dot"></span>Passive monitoring</span>')
source = ss.data_source
ai_chip = ('<span class="chip ai">Hybrid: rules + AI model</span>' if active_ml()
           else '<span class="chip">Rules only</span>')
chips_html = (f'<div class="chips">{status_chip}{ai_chip}'
              f'<span class="chip">Zero return path</span>'
              f'<span class="chip source" title="{escape(source["label"])}">Data: {escape(source["label"])}</span></div>')

with st.container(key="app-header"):
    c_brand, c_ctrl = st.columns([2.7, 1.25], vertical_alignment="center", gap="medium")
    c_brand.html(
        f'<div class="brand"><div class="brand-mark">{ui.icon("shield")}</div><div class="brand-text">'
        f'<div class="brand-eyebrow">NTRO · Smart India Hackathon 2026 · Problem Statement 26145</div>'
        f'<h1 class="brand-title">AI-Based Detection of Cyber Threats in <span class="hl">Unidirectional IP Traffic</span></h1>'
        f'<div class="brand-sub">Passive threat-intelligence SOC for data-diode networks · zero return path · '
        f'zero payload decryption</div>{chips_html}</div></div>'
    )
    # Controls stay together on the right however long the heading wraps
    with c_ctrl, st.container(key="header-controls", horizontal=True, horizontal_alignment="right",
                              vertical_alignment="center", gap="small"):
        bell = st.popover(
            str(unread), icon=":material/notifications_active:" if unread else ":material/notifications:",
            type="primary" if unread else "secondary", help="Notifications", key="bell",
        )
        with bell:
            render_notifications()
        st.button(
            "Sound" if ss.sound_on else "Muted", key="sound_btn",
            icon=":material/volume_up:" if ss.sound_on else ":material/volume_off:",
            on_click=cb_toggle_sound, help="Alarm sound for CRITICAL attacks",
        )
        MODE = st.selectbox(
            "Theme", ["dark", "light"], key="theme", bind="query-params", label_visibility="collapsed",
            format_func=lambda m: {"dark": "Dark mode", "light": "Light mode"}[m], width=140,
        )

T = theme.tokens(MODE)
st.html(theme.css(MODE))


# ══════════════════════════════════════════════════════════════════════════════
# POSTURE BANNER + DEMO GUIDE
# ══════════════════════════════════════════════════════════════════════════════
sev_all = notif.severity_counts(records(df)) if not df.empty else notif.severity_counts([])
if sev_all["CRITICAL"] >= 5:
    posture = ("Critical", SEVERITIES["CRITICAL"], "var(--crit)", "var(--crit-soft)", " alert-red")
elif sev_all["CRITICAL"] >= 1 or sev_all["HIGH"] >= 5:
    posture = ("Elevated", SEVERITIES["HIGH"], "var(--high)", "var(--high-soft)", "")
elif sev_all["HIGH"] >= 1:
    posture = ("Guarded", SEVERITIES["MEDIUM"], "var(--med)", "var(--med-soft)", "")
else:
    posture = ("Nominal", SEVERITIES["LOW"], "var(--good)", "var(--good-soft)", "")
last_event = df["ts"].max() if not df.empty else None
last_event_txt = last_event.strftime("%d %b %Y, %H:%M:%S IST") if last_event is not None and pd.notna(last_event) else "—"
st.html(
    f'<div class="posture{posture[4]}" style="--posture:{posture[2]};--posture-soft:{posture[3]}">'
    f'<span class="posture-level"><span class="glyph">{posture[1].glyph}</span>Threat posture: {posture[0]}</span>'
    f'<span class="posture-stats"><b>{sev_all["CRITICAL"]}</b> critical · <b>{sev_all["HIGH"]}</b> high · '
    f'<b>{sev_all["MEDIUM"]}</b> medium · <b>{len(df)}</b> alerts in this workspace</span>'
    f'<span class="posture-time">Latest event: {escape(last_event_txt)}</span></div>'
)

if not ss.guide_dismissed:
    with st.container(key="demo-guide", horizontal=True, vertical_alignment="center"):
        st.html(
            '<div class="guide">'
            '<div class="guide-step"><div class="guide-num">1</div><div><b>Generate traffic</b>'
            '<div>Launch an attack from the sidebar, turn on live monitoring, or upload your own PCAP.</div></div></div>'
            '<div class="guide-step"><div class="guide-num">2</div><div><b>Investigate</b>'
            '<div>Open any alert for the evidence, MITRE ATT&amp;CK mapping and firewall rules.</div></div></div>'
            '<div class="guide-step"><div class="guide-num">3</div><div><b>Export</b>'
            '<div>Download iptables / Suricata rules and the incident report for formal reporting.</div></div></div>'
            '</div>'
        )
        st.button("Got it", key="guide_ok", icon=":material/close:", type="tertiary", on_click=cb_dismiss_guide)


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL FILTERS (scope every KPI, chart and table below)
# ══════════════════════════════════════════════════════════════════════════════
WINDOWS = {"All time": None, "Last 5 min": 5, "Last 15 min": 15, "Last 1 hour": 60, "Last 24 hours": 1440}
with st.container(key="filter-bar", horizontal=True, vertical_alignment="bottom", gap="small"):
    f_window = st.selectbox("Time window", list(WINDOWS), key="f_window", width=140,
                            help="Relative to the latest event, so older uploaded captures still filter correctly")
    f_sev = st.pills("Severity", SEVERITY_ORDER, selection_mode="multi", default=SEVERITY_ORDER, key="f_sev",
                     format_func=lambda s: f"{SEVERITIES[s].glyph} {SEVERITIES[s].label}")
    f_threat = st.multiselect("Threat vector", THREAT_ORDER, key="f_threat", format_func=threat_short,
                              placeholder="All six vectors", width=210)
    f_ip = st.text_input("IP address", key="f_ip", placeholder="Source or target IP", width=170,
                         icon=":material/search:")
    st.button("Clear", key="f_clear", icon=":material/filter_alt_off:", type="tertiary", on_click=cb_clear_filters)

fdf = df
if not df.empty:
    if WINDOWS.get(f_window) and pd.notna(df["ts"].max()):
        fdf = fdf[fdf["ts"] >= df["ts"].max() - pd.Timedelta(minutes=WINDOWS[f_window])]
    if f_sev:
        fdf = fdf[fdf["severity"].isin(f_sev)]
    if f_threat:
        fdf = fdf[fdf["threat_class"].isin(f_threat)]
    if f_ip:
        needle = f_ip.strip()
        fdf = fdf[fdf["src_ip"].astype(str).str.contains(needle, regex=False)
                  | fdf["dst_ip"].astype(str).str.contains(needle, regex=False)]
filtered = len(fdf) != len(df)


# ══════════════════════════════════════════════════════════════════════════════
# KPI TILES
# ══════════════════════════════════════════════════════════════════════════════
sev_view = notif.severity_counts(records(fdf)) if not fdf.empty else notif.severity_counts([])
scope_note = f"of {len(df)} in workspace" if filtered else "in current view"
st.html(ui.kpi_tiles([
    {"label": "Alerts", "value": f"{len(fdf):,}", "sub": scope_note, "icon": "bell"},
    {"label": "Critical", "value": sev_view["CRITICAL"], "sub": "■ act immediately", "icon": "report", "accent": "var(--crit)"},
    {"label": "High", "value": sev_view["HIGH"], "sub": "▲ investigate today", "icon": "warning", "accent": "var(--high)"},
    {"label": "Threat sources", "value": fdf["src_ip"].nunique() if not fdf.empty else 0, "sub": "distinct source IPs", "icon": "hub"},
    {"label": "Attack vectors", "value": f"{fdf['threat_class'].nunique() if not fdf.empty else 0} / 6", "sub": "NTRO vectors observed", "icon": "category"},
    {"label": "Avg confidence", "value": f"{fdf['confidence_score'].mean() * 100:.0f}%" if not fdf.empty else "—", "sub": "detector confidence", "icon": "target"},
]))


# ══════════════════════════════════════════════════════════════════════════════
# SHARED RENDERERS
# ══════════════════════════════════════════════════════════════════════════════
def plot(fig: go.Figure, key: str):
    st.plotly_chart(fig, theme=None, config=theme.PLOTLY_CONFIG, key=key)


def feed_row_html(rec: dict) -> str:
    meta = THREATS.get(rec["threat_class"])
    when = rec["ts"].strftime("%d %b · %H:%M:%S") if pd.notna(rec["ts"]) else "—"
    port = f":{rec['dst_port']}" if rec.get("dst_port") else ""
    name = meta.short if meta else rec["threat_class"]
    sub = f"{meta.mitre_id} · {meta.tactic}" if meta else ""
    source_tag = {"AI model": "AI", "Rules + AI model": "RULES+AI"}.get((rec.get("evidence") or {}).get("detected_by"), "")
    return (f'<div class="feed-row"><div class="time">{escape(when)}</div><div>{ui.sev_badge(rec["severity"])}</div>'
            f'<div class="threat">{escape(name)}'
            f'{f"<span class=src-tag>{source_tag}</span>" if source_tag else ""}<small>{escape(sub)}</small></div>'
            f'<div class="flow"><span class="mono">{escape(str(rec["src_ip"]))}</span> → '
            f'<span class="mono">{escape(str(rec["dst_ip"]))}{escape(port)}</span>'
            f'<br><span class="muted">{escape(notif.describe(rec))}</span></div>'
            f'<div>{ui.confidence_bar(rec["confidence_score"])}</div></div>')


def feed_rows(recs: list, prefix: str):
    for rec in recs:
        with st.container(key=f"feed-{prefix}-{rec['id']}", horizontal=True, vertical_alignment="center", wrap=False):
            st.html(feed_row_html(rec))
            st.button("Investigate", key=f"{prefix}_open_{rec['id']}", icon=":material/manage_search:",
                      on_click=cb_open_alert, args=(rec["id"],))


FEED_HEAD = ('<div class="feed-head"><div>Time (IST)</div><div>Severity</div><div>Threat vector</div>'
             '<div>Flow &amp; finding</div><div>Confidence</div></div>')


def csv_export(frame: pd.DataFrame) -> bytes:
    out = frame.drop(columns=["ts", "short"], errors="ignore").copy()
    out["evidence"] = out["evidence"].map(json.dumps)
    out.insert(1, "time_ist", frame["ts"].map(lambda v: v.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(v) else ""))
    return out.to_csv(index=False).encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════════════════════════════════════
tab_overview, tab_upload, tab_network, tab_invest, tab_lab, tab_ai, tab_reports = st.tabs([
    ":material/dashboard: Overview",
    ":material/upload_file: Analyse PCAP",
    ":material/hub: Network",
    ":material/manage_search: Investigation",
    ":material/science: Simulation lab",
    ":material/psychology: AI model",
    ":material/description: Reports",
])

EMPTY_MSG = ("No alerts match the current filters." if filtered and not df.empty
             else "No alerts yet. Launch an attack from the sidebar, turn on live monitoring or upload a PCAP.")

# ── Overview ──────────────────────────────────────────────────────────────────
with tab_overview:
    if fdf.empty:
        st.html(ui.empty_state(EMPTY_MSG))
    else:
        c1, c2 = st.columns([1.35, 1], gap="large")
        with c1:
            st.html(ui.section("Alerts by threat vector", "All six NTRO vectors, including those not observed"))
            counts = fdf["threat_class"].value_counts()
            rows = sorted(((THREATS[c].short, int(counts.get(c, 0)), THREATS[c].mitre_id) for c in THREAT_ORDER),
                          key=lambda r: r[1])
            fig = go.Figure(go.Bar(
                x=[r[1] for r in rows], y=[r[0] for r in rows], orientation="h",
                marker=dict(color=T["accent"], cornerradius=4), text=[r[1] for r in rows],
                textposition="outside", cliponaxis=False, textfont=dict(color=T["text-2"], size=12),
                customdata=[r[2] for r in rows],
                hovertemplate="<b>%{y}</b> · %{customdata}<br>%{x} alerts<extra></extra>",
            ))
            peak = max(r[1] for r in rows)
            fig.update_layout(**theme.plotly_layout(
                MODE, height=290, bargap=0.38,
                xaxis=dict(showgrid=True, rangemode="tozero", title=dict(text="Alerts"), tickformat=",d",
                           **({"dtick": 1} if peak <= 8 else {})),
                yaxis=dict(showgrid=False, tickfont=dict(color=T["text-2"], size=12)),
            ))
            plot(fig, "ov_vectors")
        with c2:
            st.html(ui.section("Severity mix", "Status colour + shape, so severity never relies on colour alone"))
            present = [s for s in SEVERITY_ORDER if sev_view[s]]
            fig = go.Figure(go.Pie(
                labels=[f"{SEVERITIES[s].glyph} {SEVERITIES[s].label}" for s in present],
                values=[sev_view[s] for s in present], hole=0.64, sort=False, direction="clockwise",
                marker=dict(colors=[SEVERITIES[s].color for s in present], line=dict(color=T["surface"], width=2)),
                textinfo="percent", textfont=dict(color=["#ffffff" if s == "CRITICAL" else "#0b1220" for s in present], size=12),
                hovertemplate="<b>%{label}</b><br>%{value} alerts (%{percent})<extra></extra>",
            ))
            fig.update_layout(**theme.plotly_layout(
                MODE, height=290, showlegend=True,
                legend=dict(orientation="v", y=0.5, yanchor="middle", x=1.02, xanchor="left"),
                annotations=[dict(text=f"<b>{len(fdf)}</b><br>alerts", x=0.5, y=0.5, showarrow=False,
                                  font=dict(size=15, color=T["text-1"]))],
            ))
            plot(fig, "ov_severity")

        st.html(ui.section("Alert timeline", "Each marker is one alert; shape and colour give severity (IST)"))
        fig = go.Figure()
        for level in SEVERITY_ORDER:
            sub = fdf[fdf["severity"] == level]
            if sub.empty:
                continue
            meta = SEVERITIES[level]
            fig.add_trace(go.Scatter(
                x=sub["ts"], y=sub["short"], mode="markers", name=meta.label,
                marker=dict(symbol=meta.plotly_symbol, size=12, color=meta.color, line=dict(width=2, color=T["surface"])),
                customdata=list(zip(sub["src_ip"], sub["dst_ip"], (sub["confidence_score"] * 100).round(0))),
                hovertemplate="<b>%{y}</b> · %{x|%H:%M:%S} IST<br>%{customdata[0]} → %{customdata[1]}"
                              "<br>Confidence %{customdata[2]}%<extra></extra>",
            ))
        t_min, t_max = fdf["ts"].min(), fdf["ts"].max()
        x_axis = dict(showgrid=False, title=dict(text="Time (IST)"), tickformat="%H:%M:%S")
        if pd.notna(t_min) and (t_max - t_min) < pd.Timedelta(seconds=60):
            # A burst of alerts spans milliseconds; pad so the axis reads as clock time
            x_axis["range"] = [t_min - pd.Timedelta(seconds=30), t_max + pd.Timedelta(seconds=30)]
        fig.update_layout(**theme.plotly_layout(
            MODE, height=300, showlegend=True,
            yaxis=dict(categoryorder="array", categoryarray=[THREATS[c].short for c in reversed(THREAT_ORDER)],
                       range=[-0.5, len(THREAT_ORDER) - 0.5], tickfont=dict(color=T["text-2"], size=12), showgrid=True),
            xaxis=x_axis,
        ))
        plot(fig, "ov_timeline")

        st.html(ui.section("Latest high-priority incidents", "Critical and high alerts, newest first"))
        urgent = records(fdf[fdf["severity"].isin(["CRITICAL", "HIGH"])].head(5))
        if urgent:
            st.html(FEED_HEAD)
            feed_rows(urgent, "ov")
        else:
            st.html(ui.empty_state("No critical or high alerts in the current view."))

        c1, c2 = st.columns([1, 1], gap="large")
        with c1:
            st.html(ui.section("Top threat sources", "Ranked by number of alerts"))
            top = []
            for ip, grp in sorted(fdf.groupby("src_ip"), key=lambda kv: -len(kv[1]))[:8]:
                tags = "".join(ui.tag(threat_short(c)) for c in sorted(
                    grp["threat_class"].unique(), key=lambda c: THREAT_ORDER.index(c) if c in THREAT_ORDER else 99))
                top.append([ip, len(grp), int((grp["severity"] == "CRITICAL").sum()), tags])
            st.html(ui.table(["Source IP", "Alerts", "Critical", "Vectors"], top, raw_html_cols=(3,),
                             num_cols=(1, 2), mono_cols=(0,)))
        with c2:
            # Table twin of the charts above (every value readable without hover or colour)
            st.html(ui.section("Vector × severity", "The charts above as a table"))
            matrix_rows = []
            for c in THREAT_ORDER:
                sub = fdf[fdf["threat_class"] == c]
                matrix_rows.append([THREATS[c].short, THREATS[c].mitre_id]
                                   + [int((sub["severity"] == s).sum()) for s in SEVERITY_ORDER[:3]] + [len(sub)])
            st.html(ui.table(["Vector", "MITRE", "■ Crit", "▲ High", "◆ Med", "Total"], matrix_rows,
                             num_cols=(2, 3, 4, 5), mono_cols=(1,)))

# ── Analyse PCAP ──────────────────────────────────────────────────────────────
with tab_upload:
    st.html(ui.section(
        "Live PCAP dissection — bring your own capture",
        f"Replayed through the same passive pipeline (5-tuple flows, 3 s sliding windows, all 6 detectors). "
        f"Ethernet, Linux-cooked, raw-IP and loopback captures; first {MAX_UPLOAD_PACKETS:,} packets; max 50 MB.",
    ))
    uploaded = st.file_uploader("PCAP / PCAPNG file", type=["pcap", "pcapng", "cap"], key="pcap_upload")
    clear_first = st.checkbox("Clear this workspace's alerts first (show only this capture)", value=True)

    if uploaded is not None and st.button("Analyse capture", type="primary", icon=":material/biotech:", key="analyse_upload"):
        suffix = os.path.splitext(uploaded.name)[1] or ".pcap"
        with tempfile.NamedTemporaryFile(suffix=suffix, dir=WS.pcap_dir, delete=False) as tmp:
            tmp.write(uploaded.getbuffer())
            tmp_path = tmp.name
        bar = st.progress(0.0, text="Reading capture …")

        def on_progress(reader):
            frac = min(1.0, reader.bytes_read / max(1, reader.file_size))
            bar.progress(frac, text=f"{reader.packets_parsed:,} packets analysed · {frac:.0%} of file")

        try:
            if clear_first:
                clear_alerts()
            result = analyse_pcap(tmp_path, max_packets=MAX_UPLOAD_PACKETS, on_progress=on_progress)
            bar.progress(1.0, text=f"Done · {result['packets']:,} packets in {result['elapsed']:.1f} s")
            summary = {k: v for k, v in result.items() if k != "alerts"}
            summary.update({
                "name": uploaded.name, "alert_count": len(result["alerts"]),
                "classes": pd.Series([a["threat_class"] for a in result["alerts"]], dtype=object).value_counts().to_dict(),
            })
            ss.upload_result = summary
            ss.data_source = {"kind": "upload", "label": uploaded.name}
            if result["packets"] == 0:
                push_event("warning", "Capture not decoded",
                           f"No IP packets in {uploaded.name} (link type {result['linktype']}, "
                           f"{result['skipped']:,} frames skipped).")
            elif result["truncated"]:
                push_event("warning", "Capture truncated",
                           f"Only the first {MAX_UPLOAD_PACKETS:,} packets of {uploaded.name} were analysed.")
            if result["packets"] and not result["alerts"]:
                push_event("info", "Capture analysed", f"No threats found in {uploaded.name}.")
        except Exception as exc:
            ss.pop("upload_result", None)
            push_event("error", "Could not parse capture", f"{uploaded.name}: {exc}")
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        st.rerun()

    res = ss.get("upload_result")
    if res:
        st.html(ui.kpi_tiles([
            {"label": "Capture", "value": f"{res['packets']:,}", "sub": f"packets · {res['name']}", "icon": "category"},
            {"label": "Flows", "value": f"{res['flows']:,}", "sub": f"{res['windows']:,} sliding windows", "icon": "hub"},
            {"label": "Alerts", "value": f"{res['alert_count']:,}", "sub": "raised by the 6 detectors", "icon": "bell",
             "accent": "var(--crit)" if res["alert_count"] else "var(--good)"},
            {"label": "Throughput", "value": f"{res['pps']:,.0f}", "sub": "packets / second", "icon": "target"},
            {"label": "Inference", "value": f"{res['flow_ms']:.2f} ms", "sub": f"per flow · {res['window_ms']:.2f} ms per window", "icon": "report"},
        ]))
        if res["classes"]:
            rows = [[THREATS[c].short if c in THREATS else c, THREATS[c].mitre_id if c in THREATS else "—", n]
                    for c, n in sorted(res["classes"].items(), key=lambda kv: -kv[1])]
            st.html(ui.table(["Threat vector", "MITRE", "Alerts"], rows, num_cols=(2,), mono_cols=(1,)))
            st.caption("Every tab (Overview, Network, Investigation, Reports) now reflects this capture.")
        elif res["packets"]:
            st.html(ui.empty_state("No threats detected in this capture by any of the six detectors."))
        if res["skipped"]:
            st.caption(f"{res['skipped']:,} non-IP frames (ARP, STP, …) were skipped.")


# ── Network ───────────────────────────────────────────────────────────────────
def topology_figure(frame: pd.DataFrame, max_nodes: int = 36) -> go.Figure:
    involvement = pd.concat([frame["src_ip"], frame["dst_ip"]]).value_counts()
    keep = set(involvement.head(max_nodes).index)
    srcs, dsts = set(frame["src_ip"]), set(frame["dst_ip"])

    def role(ip):
        return "both" if ip in srcs and ip in dsts else ("src" if ip in srcs else "dst")

    columns = {"src": [], "both": [], "dst": []}
    for ip in involvement.index:
        if ip in keep:
            columns[role(ip)].append(ip)
    x_of = {"src": 0.0, "both": 0.5, "dst": 1.0}
    pos = {}
    for col, ips in columns.items():
        for i, ip in enumerate(ips):
            pos[ip] = (x_of[col], 1.0 - (i + 0.5) / max(len(ips), 1))

    node_rank = {}
    for ip in pos:
        sub = frame[(frame["src_ip"] == ip) | (frame["dst_ip"] == ip)]
        node_rank[ip] = min(severity(s).rank for s in sub["severity"])
    size_of = {ip: 13 + min(15, 2 * int(involvement[ip])) for ip in pos}

    fig = go.Figure()
    edges = frame.groupby(["src_ip", "dst_ip"]).size().reset_index(name="n")
    peak = max(1, int(edges["n"].max())) if not edges.empty else 1
    for _, e in edges.iterrows():
        if e["src_ip"] not in pos or e["dst_ip"] not in pos:
            continue
        (x0, y0), (x1, y1) = pos[e["src_ip"]], pos[e["dst_ip"]]
        fig.add_annotation(
            x=x1, y=y1, ax=x0, ay=y0, xref="x", yref="y", axref="x", ayref="y", showarrow=True, text="",
            arrowhead=2, arrowsize=1.1, arrowwidth=1 + 2.5 * int(e["n"]) / peak, arrowcolor=T["text-3"],
            standoff=size_of[e["dst_ip"]] / 2 + 3, startstandoff=size_of[e["src_ip"]] / 2 + 2, opacity=0.8,
        )
    for level in SEVERITY_ORDER:
        meta = SEVERITIES[level]
        ips = [ip for ip in pos if node_rank[ip] == meta.rank]
        if not ips:
            continue
        fig.add_trace(go.Scatter(
            x=[pos[ip][0] for ip in ips], y=[pos[ip][1] for ip in ips], mode="markers+text",
            name=f"{meta.label} risk",
            marker=dict(symbol=meta.plotly_symbol, size=[size_of[ip] for ip in ips], color=meta.color,
                        line=dict(width=2, color=T["surface"])),
            text=ips, textfont=dict(family=theme.FONT_MONO, size=11, color=T["text-2"]),
            textposition=["middle left" if pos[ip][0] == 0 else "middle right" if pos[ip][0] == 1 else "top center"
                          for ip in ips],
            customdata=[int(involvement[ip]) for ip in ips],
            hovertemplate="<b>%{text}</b><br>%{customdata} alerts involve this host<extra></extra>",
        ))
    for label, col, x in (("Sources", "src", 0.0), ("Sources & targets", "both", 0.5), ("Targets", "dst", 1.0)):
        if columns[col]:
            fig.add_annotation(x=x, y=1.06, xref="x", yref="paper", text=f"<b>{label}</b>", showarrow=False,
                               font=dict(color=T["text-3"], size=11))
    tallest = max(len(v) for v in columns.values())
    fig.update_layout(**theme.plotly_layout(
        MODE, height=max(340, 30 * tallest + 90), showlegend=True, margin=dict(l=8, r=8, t=36, b=8),
        legend=dict(y=-0.02, yanchor="top"),
        xaxis=dict(visible=False, range=[-0.42, 1.42]), yaxis=dict(visible=False, range=[-0.04, 1.04]),
    ))
    return fig


with tab_network:
    if fdf.empty:
        st.html(ui.empty_state(EMPTY_MSG))
    else:
        st.html(ui.section("Directional attack topology",
                           "Arrows follow the traffic direction (one-way, as through the data diode) · "
                           "node shape/colour = highest severity involving the host · size = alert volume"))
        plot(topology_figure(fdf), "net_topology")

        st.html(ui.section("Heatmap — source IP × threat vector", "Top 20 sources · darker cell = more alerts"))
        top_src = fdf["src_ip"].value_counts().head(20).index.tolist()
        z = [[int(((fdf["src_ip"] == ip) & (fdf["threat_class"] == c)).sum()) for c in THREAT_ORDER] for ip in top_src]
        zmax = max(1, max(max(r) for r in z))
        fig = go.Figure(go.Heatmap(
            z=z, x=[THREATS[c].short for c in THREAT_ORDER], y=top_src, zmin=0, zmax=zmax,
            colorscale=theme.heat_colorscale(MODE), xgap=2, ygap=2,
            colorbar=dict(title=dict(text="Alerts", font=dict(color=T["text-3"], size=11)),
                          tickfont=dict(color=T["text-3"], size=10), outlinewidth=0, thickness=10,
                          tickformat=",d", **({"dtick": 1} if zmax <= 8 else {})),
            hovertemplate="<b>%{y}</b> · %{x}<br>%{z} alerts<extra></extra>",
        ))
        for yi, row in enumerate(z):
            for xi, val in enumerate(row):
                if val:
                    # The ramp runs light->dark in light mode and dark->light in dark mode
                    light_cell = (val / zmax <= 0.55) if MODE == "light" else (val / zmax > 0.55)
                    fig.add_annotation(x=THREATS[THREAT_ORDER[xi]].short, y=top_src[yi], text=str(val), showarrow=False,
                                       font=dict(size=11, color="#0b1220" if light_cell else "#ffffff"))
        fig.update_layout(**theme.plotly_layout(
            MODE, height=70 + 30 * len(top_src),
            xaxis=dict(showgrid=False, side="top", tickfont=dict(color=T["text-2"], size=11)),
            yaxis=dict(showgrid=False, autorange="reversed",
                       tickfont=dict(family=theme.FONT_MONO, color=T["text-2"], size=11)),
        ))
        plot(fig, "net_heatmap")

# ── Investigation ─────────────────────────────────────────────────────────────
with tab_invest:
    if fdf.empty:
        st.html(ui.empty_state(EMPTY_MSG))
    else:
        pages = max(1, math.ceil(len(fdf) / FEED_PAGE_SIZE))
        ss.feed_page = min(ss.feed_page, pages - 1)
        with st.container(horizontal=True, vertical_alignment="center"):
            st.html(ui.section("Alert feed", f"{len(fdf)} alerts · newest first · open one for evidence and response rules"))
            st.button("Previous", key="pg_prev", icon=":material/chevron_left:", on_click=cb_page, args=(-1,),
                      disabled=ss.feed_page == 0)
            st.html(f'<div class="muted" style="white-space:nowrap;font-size:.8rem">Page {ss.feed_page + 1} of {pages}</div>',
                    width="content")
            st.button("Next", key="pg_next", icon=":material/chevron_right:", icon_position="right", on_click=cb_page,
                      args=(1,), disabled=ss.feed_page >= pages - 1)
        st.html(FEED_HEAD)
        start = ss.feed_page * FEED_PAGE_SIZE
        feed_rows(records(fdf.iloc[start:start + FEED_PAGE_SIZE]), "inv")

        st.html(ui.section("Bulk export", "Everything in the current filtered view"))
        view_recs = records(fdf.drop(columns=["ts", "short"]))
        bundle = build_rules_bundle(view_recs)
        with st.container(horizontal=True, gap="small"):
            st.download_button("Alerts CSV", csv_export(fdf), "soc_alerts.csv", "text/csv", key="dl_csv",
                               icon=":material/table_view:", on_click="ignore")
            st.download_button("iptables script", bundle["iptables_sh"], "sih26145_block.sh", "text/x-shellscript",
                               key="dl_ipt", icon=":material/terminal:", on_click="ignore")
            st.download_button("Suricata rules", bundle["suricata_rules"], "sih26145.rules", "text/plain", key="dl_rules",
                               icon=":material/policy:", on_click="ignore")
            st.download_button("Incident report", build_incident_report(view_recs, source_label=ss.data_source["label"]),
                               "sih26145_incident_report.html", "text/html", key="dl_report",
                               icon=":material/description:", on_click="ignore",
                               help="Open the HTML file and use Print → Save as PDF")

# ── Simulation lab ────────────────────────────────────────────────────────────
with tab_lab:
    st.html(ui.section("Attack simulation laboratory",
                       "Each scenario is generated as packets and replayed through the passive pipeline — the detectors "
                       "see exactly what they would see behind a data diode."))
    for row_start in range(0, len(THREAT_ORDER), 3):
        cols = st.columns(3, gap="medium")
        for col, cls in zip(cols, THREAT_ORDER[row_start:row_start + 3]):
            meta = THREATS[cls]
            with col, st.container(key=f"lab-{meta.sim_key}"):
                st.markdown(f"**{meta.icon} {meta.label}**")
                st.html(
                    f'<div>{ui.tag(meta.mitre_id + " · " + meta.technique, "mitre")}{ui.sev_badge(TYPICAL_SEVERITY[cls])}</div>'
                    f'<div class="lab-desc">{escape(meta.description)}</div>'
                    f'<div class="lab-meta"><b>Detection:</b> {escape(meta.method)}</div>'
                    f'<div class="lab-meta"><b>Seen in the wild:</b> {escape(meta.examples)}</div>'
                )
                st.button(f"Simulate {meta.short}", key=f"lab_{meta.sim_key}", icon=":material/play_arrow:",
                          width="stretch", on_click=cb_simulate, args=(meta.sim_key,))

# ── Reports ───────────────────────────────────────────────────────────────────
with tab_ai:
    card = load_model_card()
    if not card or ML_MODEL is None:
        st.html(ui.empty_state("Model artifact not found. Train it with: python train_models.py"))
    else:
        st.html(ui.section("Hybrid detection: explainable rules + Random Forest",
                           "Rules give precise, auditable detections; the model catches variants the fixed thresholds miss. "
                           "Every alert records which of the two raised it."))
        st.html(
            '<div class="guide" style="margin-bottom:12px">'
            '<div class="guide-step"><div class="guide-num">1</div><div><b>Same features</b><div>The model reads the '
            'numbers the rules already compute: flow timing, sizes, DNS entropy, ClientHello metadata, per-host fan-in / '
            'fan-out in each 3 s window. No payload is decrypted.</div></div></div>'
            '<div class="guide-step"><div class="guide-num">2</div><div><b>Two Random Forests</b><div>A flow model '
            '(benign, C2, DGA/DNS, encrypted malware, exfiltration) and a host-window model (benign, DDoS target, '
            'scanner) together cover all six NTRO vectors.</div></div></div>'
            '<div class="guide-step"><div class="guide-num">3</div><div><b>Calibrated &amp; explained</b><div>Alert '
            'thresholds are tuned on real benign traffic; each model alert lists the features that pushed its '
            'probability up. A model-only alert is capped below Critical.</div></div></div></div>'
        )
        fm, hm = card.get("flow_model", {}), card.get("host_model", {})
        thr = card.get("thresholds", {})
        st.html(ui.kpi_tiles([
            {"label": "Model", "value": "Random Forest",
             "sub": f"{ML_MODEL.flow_model.n_estimators} + {ML_MODEL.host_model.n_estimators} trees (flow + host)", "icon": "hub"},
            {"label": "Training rows", "value": f"{fm.get('train_rows', 0) + hm.get('train_rows', 0):,}",
             "sub": f"{fm.get('train_rows', 0):,} flows · {hm.get('train_rows', 0):,} host-windows", "icon": "category"},
            {"label": "Alert threshold", "value": f"{thr.get('flow', 0):.2f} / {thr.get('host', 0):.2f}",
             "sub": "flow / host probability", "icon": "target"},
            {"label": "AI layer", "value": "On" if active_ml() else "Off", "sub": "toggle in the sidebar", "icon": "shield",
             "accent": "var(--good)" if active_ml() else "var(--low)"},
        ]))

        syn = card.get("synthetic_holdout", {})
        if syn:
            size = syn.get("test_size", {})
            st.html(ui.section("Accuracy on held-out synthetic traffic",
                               f"Independent draw never seen in training: {size.get('flows', 0):,} flows and "
                               f"{size.get('host_windows', 0):,} host-windows. Recall = share of attacks caught; "
                               "precision = share of alerts that were real."))
            rows = []
            for cls in THREAT_ORDER:
                r_, m_, h_ = (syn[k]["per_class"].get(cls, {}) for k in ("rules", "ml", "hybrid"))
                rows.append([THREATS[cls].short, THREATS[cls].mitre_id, f"{r_.get('recall', 0):.1%}",
                             f"{m_.get('recall', 0):.1%}", f"{h_.get('recall', 0):.1%}", f"{h_.get('precision', 0):.1%}",
                             f"{h_.get('support', 0):,}"])
            rows.append(["Benign flows wrongly flagged", "—",
                         f"{syn['rules']['benign_flow_false_positive_rate']:.2%}",
                         f"{syn['ml']['benign_flow_false_positive_rate']:.2%}",
                         f"{syn['hybrid']['benign_flow_false_positive_rate']:.2%}", "—", f"{size.get('benign_flows', 0):,}"])
            st.html(ui.table(["Vector", "MITRE", "Rules recall", "AI recall", "Hybrid recall", "Hybrid precision", "Test cases"],
                             rows, num_cols=(2, 3, 4, 5, 6), mono_cols=(1,)))

        real = card.get("real_captures", {})
        if real:
            calib = real.get("benign_calibration", {})
            st.html(ui.section(
                "Validation on real traffic (Stratosphere Lab, CTU Prague)",
                f"Alert thresholds were tuned on {', '.join(REAL_CAPTURE_NAMES.get(c, c) for c in calib.get('captures', [])) or '—'}. "
                "The normal-traffic rows below are other hosts and days, never used for tuning; on benign traffic every alert "
                "is a false alarm."))
            rrows = []

            def real_row(name, ro, hy, focus="—"):
                classes = ", ".join(f"{threat_short(c)} {n}" for c, n in sorted(hy["by_class"].items(), key=lambda kv: -kv[1])) or "none"
                rrows.append([name, f"{hy['packets']:,}", f"{hy['flows']:,}", f"{ro['alerts']:,}", f"{hy['alerts']:,}",
                              focus, classes])

            for test in real.get("benign_tests", []):
                real_row(REAL_CAPTURE_NAMES.get(test["capture"], test["capture"]), test["rules_only"], test["hybrid"])
            ro, hy = real.get("botnet_rules_only"), real.get("botnet_hybrid")
            if ro and hy:
                involve = next((v for k, v in hy.items() if k.startswith("alerts_involving_")), None)
                real_row("Neris botnet (CTU-13 scenario 1)", ro, hy, f"{involve:,}" if involve is not None else "—")
            st.html(ui.table(["Capture", "Packets", "Flows", "Alerts: rules only", "Alerts: hybrid",
                              "Involving infected host", "Hybrid alerts by vector"], rrows, num_cols=(1, 2, 3, 4)))

        c1, c2 = st.columns(2, gap="large")
        for col, part, title in ((c1, fm, "Flow model — most important features"),
                                 (c2, hm, "Host-window model — most important features")):
            feats = part.get("top_features", [])[:8][::-1]
            if not feats:
                continue
            with col:
                st.html(ui.section(title, "Mean decrease in impurity across the forest"))
                fig = go.Figure(go.Bar(x=[v for _, v in feats], y=[n for n, _ in feats], orientation="h",
                                       marker=dict(color=T["accent"], cornerradius=4),
                                       text=[f"{v:.2f}" for _, v in feats], textposition="outside", cliponaxis=False,
                                       textfont=dict(color=T["text-2"], size=11),
                                       hovertemplate="<b>%{y}</b><br>importance %{x:.3f}<extra></extra>"))
                fig.update_layout(**theme.plotly_layout(MODE, height=300, bargap=0.35,
                                                        xaxis=dict(showgrid=True, tickformat=".2f"),
                                                        yaxis=dict(showgrid=False, tickfont=dict(color=T["text-2"], size=11))))
                plot(fig, f"ai_importance_{title[:4]}")

        st.html(ui.section("Limitations", "Stated plainly so the numbers are read correctly"))
        st.html("<ul style='margin:0 0 0 18px;padding:0'>" + "".join(
            f"<li style='color:var(--text-2);font-size:.86rem;margin:3px 0'>{escape(item)}</li>"
            for item in card.get("limitations", []) + [
                "Synthetic accuracy shows the model generalises across attack variants; it is not a field-accuracy claim.",
                f"Model trained {card.get('trained_at', '?')} with scikit-learn {card.get('sklearn_version', '?')}; "
                "reproduce with python train_models.py."]) + "</ul>")

with tab_reports:
    detected = set(fdf["threat_class"]) if not fdf.empty else set()
    st.html(ui.section("Cyber kill chain coverage", "Lockheed Martin kill-chain stages with at least one detection in view"))
    stages = []
    for stage in KILL_CHAIN_STAGES:
        hits = [THREATS[c].short for c in THREAT_ORDER if THREATS[c].kill_chain == stage and c in detected]
        hit_html = f'<span class="hit">{escape(", ".join(hits))}</span>' if hits else '<span class="hit">—</span>'
        stages.append(f'<div class="kc{" on" if hits else ""}"><b>{escape(stage)}</b>{hit_html}</div>')
    st.html(f'<div class="killchain">{"".join(stages)}</div>')

    st.html(ui.section("MITRE ATT&CK® coverage", "Techniques this sensor detects, grouped by tactic · highlighted = observed in view"))
    cols_html = []
    for tactic in MITRE_TACTICS:
        cells = [f'<div class="tactic-h">{escape(tactic)}</div>']
        for c in THREAT_ORDER:
            meta = THREATS[c]
            if meta.tactic != tactic:
                continue
            sub = fdf[fdf["threat_class"] == c] if not fdf.empty else fdf
            if len(sub):
                stat = (f'<div class="tech-stat">{len(sub)} alerts · avg confidence</div>'
                        f'{ui.confidence_bar(sub["confidence_score"].mean())}')
            else:
                stat = '<div class="tech-stat muted">Not observed</div>'
            cells.append(f'<div class="tech {"on" if len(sub) else "off"}"><div class="tech-id">{meta.mitre_id}</div>'
                         f'<div class="tech-name">{escape(meta.technique)}</div>{stat}</div>')
        cols_html.append(f'<div>{"".join(cells)}</div>')
    st.html(f'<div class="matrix">{"".join(cols_html)}</div>')

    st.html(ui.section("Deployment & compliance", "How the sensor meets the data-diode constraints"))
    st.html(ui.table(["Parameter", "Implementation", "Constraint met"], [
        ["Collection", "100% passive, read-only ingestion (dpkt)", "Physical data diode · zero return packets"],
        ["Encrypted traffic", "ClientHello metadata: JA3, SNI, version, cipher/extension lists", "Zero payload decryption"],
        ["Detection", "6 explainable detectors: 4 per-flow + 2 per 3 s sliding window", "NTRO PS 26145 threat vectors"],
        ["Alerting", "Standard JSON schema → SQLite + JSONL, traffic-time de-duplication", "SOC audit trail"],
        ["Response", "iptables + Snort/Suricata rules exported for the downstream enforcement point",
         "No inline blocking across the diode"],
        ["Taxonomy", "MITRE ATT&CK® Enterprise + Lockheed Martin kill chain", "Threat-intel reporting standards"],
    ]))

    st.html(ui.section("Reports", "Generated from the current filtered view"))
    report_recs = records(fdf.drop(columns=["ts", "short"])) if not fdf.empty else []
    report_bundle = build_rules_bundle(report_recs)
    with st.container(horizontal=True, gap="small"):
        st.download_button("Incident report (HTML → PDF)",
                           build_incident_report(report_recs, source_label=ss.data_source["label"]),
                           "sih26145_incident_report.html", "text/html", key="rep_report", type="primary",
                           icon=":material/description:", on_click="ignore", disabled=not report_recs,
                           help="Open the file in a browser and use Print → Save as PDF")
        st.download_button("Suricata rules", report_bundle["suricata_rules"], "sih26145.rules", "text/plain",
                           key="rep_rules", icon=":material/policy:", on_click="ignore", disabled=not report_recs)
        st.download_button("iptables script", report_bundle["iptables_sh"], "sih26145_block.sh", "text/x-shellscript",
                           key="rep_ipt", icon=":material/terminal:", on_click="ignore", disabled=not report_recs)


# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR: simulator · live monitoring · workspace
# ══════════════════════════════════════════════════════════════════════════════
@st.fragment(run_every=LIVE_INTERVAL_S)
def live_monitor():
    if not ss.get("live_mode"):
        return
    now = time.time()
    # Full-page reruns also execute this fragment; only inject traffic once per interval
    if now - ss.live_last_ts >= LIVE_INTERVAL_S - 1:
        ss.live_last_ts = now
        rng = random.Random()
        kind = "benign" if rng.random() < 0.45 else rng.choice([m.sim_key for m in THREATS.values()])
        try:
            _, alerts = run_simulation(kind)
        except Exception as exc:
            push_event("error", "Live stream error", str(exc))
            alerts = []
        ss.data_source = {"kind": "live", "label": "Live traffic stream"}
        ss.live_last = {"ts": now, "kind": kind, "alerts": len(alerts)}
        if alerts:
            st.rerun(scope="app")
    last = ss.live_last
    if last:
        label = "benign traffic" if last["kind"] == "benign" else next(
            (m.short for m in THREATS.values() if m.sim_key == last["kind"]), last["kind"])
        st.caption(f"Last batch {ui.fmt_ist(last['ts'], with_date=False)} · {label} · {last['alerts']} alert(s). "
                   f"Next in ~{LIVE_INTERVAL_S} s.")


with st.sidebar:
    st.subheader("Traffic simulator")
    st.button("Launch full attack stream", type="primary", icon=":material/rocket_launch:", width="stretch",
              key="sb_all", on_click=cb_simulate, args=("all",), help="Benign traffic plus all six attack vectors")
    for cls in THREAT_ORDER:
        meta = THREATS[cls]
        st.button(f"{meta.short} · {meta.mitre_id}", icon=meta.icon, width="stretch", key=f"sb_{meta.sim_key}",
                  on_click=cb_simulate, args=(meta.sim_key,), help=meta.label)

    st.subheader("Detection engine")
    st.toggle("AI model layer (Random Forest)", key="ml_on", value=True, disabled=ML_MODEL is None,
              help="On: rules + Random Forest (hybrid). Off: rules only. Applies to the next analysis or simulation.")
    st.caption("Hybrid mode: every alert shows whether the rules, the model or both flagged it."
               if ML_MODEL else "Model artifact not found — running rules only.")

    st.subheader("Live monitoring")
    st.toggle("Stream live traffic", key="live_mode",
              help=f"Every ~{LIVE_INTERVAL_S} s a new batch of benign or attack traffic flows through the pipeline, "
                   "so notifications arrive as they would on a real sensor.")
    if ss.get("live_mode"):
        live_monitor()
    else:
        st.caption("Off. Turn on to watch alerts and notifications arrive in real time.")

    st.subheader("Workspace")
    st.html(ui.kv_table([
        ("Data", ss.data_source["label"]),
        ("Alerts", f"{len(df):,}"),
        ("Session", ss.workspace_id[:8]),
    ]))
    st.button("Reset alerts", icon=":material/restart_alt:", width="stretch", key="sb_reset", on_click=cb_reset)
    st.caption("Private to this browser session; cleared automatically after 12 h idle.")


# ══════════════════════════════════════════════════════════════════════════════
# ALERT INVESTIGATION DIALOG
# ══════════════════════════════════════════════════════════════════════════════
EVIDENCE_LABELS = {
    "peak_packets_per_sec": ("Peak rate", "{:,} pkt/s"), "window_packets": ("Packets in window", "{:,}"),
    "syn_only_ratio": ("Half-open SYN share", "{:.0%}"), "unique_sources": ("Distinct sources", "{:,}"),
    "source_ip_entropy_bits": ("Source-IP entropy", "{:.2f} bits"), "iat_mean_sec": ("Mean interval", "{:.2f} s"),
    "iat_variance": ("Interval variance", "{:.5f}"), "iat_cv": ("Coefficient of variation", "{:.3f}"),
    "label_entropy_bits": ("Label entropy", "{:.2f} bits"), "subdomain_entropy_bits": ("Subdomain entropy", "{:.2f} bits"),
    "total_bytes": ("Bytes sent", None), "bytes_per_sec": ("Egress rate", None), "payload_ratio": ("Payload : header", "{:.1f}"),
    "avg_packet_size": ("Avg packet size", "{:,.0f} B"), "probe_ratio": ("Probe share", "{:.0%}"),
    "window_start": ("Window start", None), "window_end": ("Window end", None),
    "model_probability": ("Model probability", "{:.0%}"), "detected_by": ("Detected by", None),
}
LIST_KEYS = ("indicators", "anomalies", "dga_indicators")
HIDDEN_KEYS = LIST_KEYS + ("model_factors", "model_probability", "detected_by")
MONO_KEYS = ("ja3_hash", "ja3_string", "queried_domain", "target", "top_sources", "sample_ports", "sni")


def format_evidence(key: str, value) -> str:
    if key in ("window_start", "window_end"):
        return ui.fmt_ist(value, with_date=False)
    if key == "total_bytes":
        return notif.human_bytes(value)
    if key == "bytes_per_sec":
        return notif.human_bytes(value) + "/s"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "—"
    label_fmt = EVIDENCE_LABELS.get(key)
    if label_fmt and label_fmt[1] and isinstance(value, (int, float)):
        try:
            return label_fmt[1].format(value)
        except (ValueError, TypeError):
            pass
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value) if value not in ("", None) else "—"


@st.dialog("Alert investigation", width="large", on_dismiss=cb_close_dialog)
def alert_dialog(alert_id: int):
    match = df[df["id"] == alert_id]
    if match.empty:
        st.info("This alert is no longer in the workspace.")
        return
    rec = records(match)[0]
    meta = THREATS.get(rec["threat_class"])
    ev = rec["evidence"] if isinstance(rec["evidence"], dict) else {}
    st.html(
        f'<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">{ui.sev_badge(rec["severity"])}'
        f'{ui.tag((meta.mitre_id + " · " + meta.technique) if meta else "—", "mitre")}'
        f'{ui.tag(meta.tactic if meta else "—")}<span class="muted" style="font-size:.8rem">Alert #{rec["id"]} · '
        f'{escape(ui.fmt_ist(rec["timestamp"]))}</span></div>'
        f'<div class="section-title" style="font-size:1.15rem;margin-top:10px">'
        f'{escape(meta.label if meta else str(rec["threat_class"]))}</div>'
        f'<div class="section-sub" style="font-size:.9rem">{escape(notif.describe(rec))}</div>'
    )
    c1, c2 = st.columns([1, 1.25], gap="medium")
    with c1:
        st.html(ui.section("Flow"))
        st.html(ui.kv_table([
            ("Flow ID", rec["flow_id"]), ("Source", f"{rec['src_ip']}:{rec['src_port']}"),
            ("Target", f"{rec['dst_ip']}:{rec['dst_port']}"), ("Protocol", rec["protocol"]),
            ("Confidence", f"{float(rec['confidence_score']) * 100:.1f}%"),
            ("Kill-chain stage", meta.kill_chain if meta else "—"),
        ]))
    with c2:
        st.html(ui.section("Why it was flagged"))
        detected_by = ev.get("detected_by")
        if detected_by:
            prob = ev.get("model_probability")
            st.html(f'<div class="detected-by">{ui.tag("Detected by: " + detected_by, "mitre")}'
                    + (f'<span class="muted" style="font-size:.8rem">model probability {float(prob):.0%}</span>'
                       if prob is not None else "") + "</div>")
        reasons = [str(r) for k in LIST_KEYS for r in (ev.get(k) or [])]
        if reasons:
            st.html("<ul style='margin:0 0 8px 18px;padding:0'>" + "".join(
                f"<li style='color:var(--text-1);font-size:.86rem;margin:2px 0'>{escape(r)}</li>" for r in reasons) + "</ul>")
        items = [{"key": EVIDENCE_LABELS.get(k, (k.replace("_", " ").capitalize(), None))[0],
                  "value": format_evidence(k, v), "mono": k in MONO_KEYS}
                 for k, v in ev.items() if k not in HIDDEN_KEYS]
        st.html(ui.evidence_grid(items))
        factors = ev.get("model_factors") or []
        if factors:
            st.html(ui.section("AI model — strongest factors", "Path contributions from the Random Forest for this alert")
                    + "<ul style='margin:0 0 4px 18px;padding:0'>" + "".join(
                        f"<li style='color:var(--text-1);font-size:.84rem;margin:2px 0'>{escape(str(f))}</li>" for f in factors)
                    + "</ul>")

    rules = generate_response_rules(rec)
    st.html(ui.section("Automated response playbook",
                       "For the downstream firewall / IPS — the diode-side sensor never transmits, nothing is applied automatically"))
    st.html(f'<div class="action-box"><b>Recommended action:</b> {escape(rules["action"])}</div>')
    r1, r2 = st.columns(2, gap="medium")
    with r1:
        st.caption("iptables")
        st.code(rules["iptables"] or "# no host-level rule for this alert", language=None, wrap_lines=True)
    with r2:
        st.caption("Snort 3 / Suricata")
        st.code(rules["suricata"] or "# no signature for this alert", language=None, wrap_lines=True)
    single = build_rules_bundle([rec])
    with st.container(horizontal=True, gap="small"):
        st.download_button("Incident report", build_incident_report([rec], source_label=f"Alert #{rec['id']}"),
                           f"alert_{rec['id']}_report.html", "text/html", key=f"dlg_rep_{rec['id']}",
                           icon=":material/description:", on_click="ignore")
        st.download_button("Rules (.rules)", single["suricata_rules"], f"alert_{rec['id']}.rules", "text/plain",
                           key=f"dlg_rules_{rec['id']}", icon=":material/policy:", on_click="ignore")


if ss.dialog_alert is not None:
    alert_dialog(ss.dialog_alert)

st.html(
    f'<div class="soc-footer"><span>Unidirectional Traffic Threat SOC · v{APP_VERSION} · passive sensor · zero return path'
    f'</span><span>SIH 2026 · Problem Statement 26145 · National Technical Research Organisation</span></div>'
)
