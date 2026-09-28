import os
import sys
import json
import math
import time
import sqlite3
import tempfile
from html import escape
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
from datetime import datetime

# ── Project root ──────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from traffic_simulator.generate_traffic import generate_synthetic_pcap
from ingestion.pcap_reader import ReadOnlyPacketReader
from detection.pipeline import StreamingDetectionPipeline
from response.rule_generator import generate_response_rules, build_rules_bundle
from reporting.incident_report import build_incident_report

# ── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NTRO Cyber Threat SOC | SIH 26145",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR THEME TOGGLE
# ══════════════════════════════════════════════════════════════════════════════
st.sidebar.markdown("### 🎨 Display Theme")
theme_mode = st.sidebar.radio(
    "Select Display Theme",
    ["Dark Mode 🌙 (Cyber SOC)", "Light Mode ☀️ (High Contrast Enterprise)"],
    index=0,
    help="Switch between Cyber SOC dark mode and high-contrast light mode",
    key="soc_theme_choice"
)
is_dark = "Dark Mode" in theme_mode

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & DYNAMIC THEME DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

THREAT_COLORS = {
    "Volumetric_Protocol_DDoS":       "#ef4444",
    "Botnet_C2_Beaconing":          "#f97316",
    "DGA_Domains_and_DNS_Tunneling": "#eab308",
    "Encrypted_Malware_TLS":         "#a855f7",
    "Reconnaissance_Port_Scanning":  "#06b6d4",
    "Data_Exfiltration":             "#ec4899",
}

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
}

MITRE_MAP = {
    "Volumetric_Protocol_DDoS":       {"id": "T1498", "tactic": "Impact",            "name": "Network Denial of Service"},
    "Botnet_C2_Beaconing":          {"id": "T1071", "tactic": "Command & Control", "name": "Application Layer Protocol"},
    "DGA_Domains_and_DNS_Tunneling": {"id": "T1568", "tactic": "Command & Control", "name": "Dynamic Resolution (DGA)"},
    "Encrypted_Malware_TLS":         {"id": "T1573", "tactic": "Command & Control", "name": "Encrypted Channel"},
    "Reconnaissance_Port_Scanning":  {"id": "T1046", "tactic": "Discovery",         "name": "Network Service Discovery"},
    "Data_Exfiltration":             {"id": "T1048", "tactic": "Exfiltration",      "name": "Exfiltration Over Alternative Protocol"},
}

KILL_CHAIN_STAGES = [
    ("Reconnaissance",        "Reconnaissance_Port_Scanning"),
    ("Weaponization",         None),
    ("Delivery",              "Volumetric_Protocol_DDoS"),
    ("Exploitation",          None),
    ("Installation",          "Encrypted_Malware_TLS"),
    ("Command & Control",     "Botnet_C2_Beaconing"),
    ("Actions on Objectives", "Data_Exfiltration"),
]

DB_PATH = str(ROOT_DIR / "data" / "alerts.db")
JSONL_PATH = str(ROOT_DIR / "data" / "alerts.jsonl")

# ══════════════════════════════════════════════════════════════════════════════
# THEME-SPECIFIC TOKENS & PLOTLY LAYOUT
# ══════════════════════════════════════════════════════════════════════════════

if is_dark:
    theme_css = """
    :root {
        --bg-main: #0a0e1a;
        --bg-sidebar: #0f172a;
        --bg-card: rgba(15, 23, 42, 0.92);
        --bg-card-hover: rgba(30, 41, 59, 0.95);
        --text-primary: #f8fafc;
        --text-secondary: #e2e8f0;
        --text-muted: #cbd5e1;
        --border-color: rgba(59, 130, 246, 0.28);
        --heading-color: #ffffff;
        --pill-bg: rgba(6, 78, 59, 0.75);
        --pill-text: #6ee7b7;
        --pill-border: #10b981;
        --code-bg: #1e293b;
        --code-text: #38bdf8;
        --tab-bg: #0f172a;
        --tab-text: #94a3b8;
        --tab-active-bg: #1e293b;
        --tab-active-text: #60a5fa;
        --btn-bg: #1e293b;
        --btn-text: #f8fafc;
        --btn-border: rgba(59, 130, 246, 0.35);
        --input-bg: #1e293b;
        --input-text: #f8fafc;
        --input-border: rgba(59, 130, 246, 0.3);
    }
    .soc-title {
        background: linear-gradient(135deg, #60a5fa, #a78bfa, #f472b6);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    }
    .t-green  { background: rgba(6,78,59,.75); border: 2px solid #059669; color: #6ee7b7; }
    .t-yellow { background: rgba(113,63,18,.75); border: 2px solid #d97706; color: #fde047; }
    .t-orange { background: rgba(124,45,18,.75); border: 2px solid #ea580c; color: #fdba74; }
    .t-red    { background: rgba(127,29,29,.75); border: 2px solid #dc2626; color: #fca5a5;
                 animation: pulse-red 1.5s ease-in-out infinite alternate; }
    .mitre-tag { background: rgba(59, 130, 246, 0.25) !important; color: #93c5fd !important; border: 1.5px solid #3b82f6 !important; font-weight: 700 !important; }
    .sev-crit  { background: rgba(239, 68, 68, 0.25) !important; color: #fca5a5 !important; border: 1.5px solid #ef4444 !important; font-weight: 700 !important; }
    .sev-high  { background: rgba(249, 115, 22, 0.25) !important; color: #fdba74 !important; border: 1.5px solid #f97316 !important; font-weight: 700 !important; }
    .kc-active  { background: rgba(239, 68, 68, 0.35) !important; border: 2px solid #ef4444 !important; color: #fee2e2 !important; font-weight: 800 !important; }
    .kc-inactive{ background: rgba(30, 41, 59, 0.7) !important; border: 1.5px solid rgba(148, 163, 184, 0.25) !important; color: #cbd5e1 !important; font-weight: 700 !important; }
    """
    plotly_template = "plotly_dark"
    plotly_font_color = "#f8fafc"
    plotly_grid_color = "rgba(255, 255, 255, 0.12)"
    plotly_paper_bg = "rgba(10, 14, 26, 0.5)"
    edge_color = "rgba(96, 165, 250, 0.5)"
    node_text_color = "#f8fafc"
    heatmap_colorscale = "Hot"
    kpi_colors = {
        "total": "#60a5fa",
        "crit":  "#f87171",
        "high":  "#fb923c",
        "src":   "#c084fc",
        "pkt":   "#38bdf8",
        "rate":  "#4ade80",
    }
else:
    theme_css = """
    :root {
        --bg-main: #f8fafc;
        --bg-sidebar: #ffffff;
        --bg-card: #ffffff;
        --bg-card-hover: #f1f5f9;
        --text-primary: #0f172a;
        --text-secondary: #1e293b;
        --text-muted: #334155;
        --border-color: #cbd5e1;
        --heading-color: #020617;
        --pill-bg: #dcfce7;
        --pill-text: #14532d;
        --pill-border: #16a34a;
        --code-bg: #e2e8f0;
        --code-text: #0369a1;
        --tab-bg: #f1f5f9;
        --tab-text: #475569;
        --tab-active-bg: #ffffff;
        --tab-active-text: #1d4ed8;
        --btn-bg: #ffffff;
        --btn-text: #0f172a;
        --btn-border: #cbd5e1;
        --input-bg: #ffffff;
        --input-text: #0f172a;
        --input-border: #cbd5e1;
    }
    .soc-title {
        background: linear-gradient(135deg, #1d4ed8, #6d28d9, #be185d);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
    }
    .t-green  { background: #dcfce7; border: 2px solid #16a34a; color: #14532d; }
    .t-yellow { background: #fef9c3; border: 2px solid #ca8a04; color: #713f12; }
    .t-orange { background: #ffedd5; border: 2px solid #ea580c; color: #7c2d12; }
    .t-red    { background: #fee2e2; border: 2px solid #dc2626; color: #7f1d1d;
                 animation: pulse-red 1.5s ease-in-out infinite alternate; }
    .mitre-tag { background: #eff6ff !important; color: #1e40af !important; border: 1.5px solid #93c5fd !important; font-weight: 800 !important; }
    .sev-crit  { background: #fee2e2 !important; color: #991b1b !important; border: 1.5px solid #fca5a5 !important; font-weight: 800 !important; }
    .sev-high  { background: #ffedd5 !important; color: #9a3412 !important; border: 1.5px solid #fdba74 !important; font-weight: 800 !important; }
    .kc-active  { background: #fee2e2 !important; border: 2px solid #dc2626 !important; color: #7f1d1d !important; font-weight: 800 !important; }
    .kc-inactive{ background: #f1f5f9 !important; border: 1.5px solid #cbd5e1 !important; color: #334155 !important; font-weight: 700 !important; }
    """
    plotly_template = "plotly_white"
    plotly_font_color = "#0f172a"
    plotly_grid_color = "rgba(0, 0, 0, 0.08)"
    plotly_paper_bg = "rgba(255, 255, 255, 0.8)"
    edge_color = "rgba(37, 99, 235, 0.55)"
    node_text_color = "#020617"
    heatmap_colorscale = "YlOrRd"
    kpi_colors = {
        "total": "#1d4ed8",
        "crit":  "#b91c1c",
        "high":  "#c2410c",
        "src":   "#7e22ce",
        "pkt":   "#0369a1",
        "rate":  "#15803d",
    }

def make_layout(**overrides):
    base = dict(
        template=plotly_template,
        paper_bgcolor=plotly_paper_bg,
        plot_bgcolor=plotly_paper_bg,
        font=dict(family="Inter, sans-serif", color=plotly_font_color, size=12),
        margin=dict(l=40, r=40, t=50, b=40),
        xaxis=dict(gridcolor=plotly_grid_color, color=plotly_font_color, tickfont=dict(color=plotly_font_color, size=11)),
        yaxis=dict(gridcolor=plotly_grid_color, color=plotly_font_color, tickfont=dict(color=plotly_font_color, size=11)),
    )
    for k, v in overrides.items():
        if isinstance(v, dict) and k in base and isinstance(base[k], dict):
            merged = dict(base[k])
            merged.update(v)
            base[k] = merged
        else:
            base[k] = v
    return base

PLOTLY_LAYOUT = make_layout()

# ══════════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE HIGH-CONTRAST CSS INJECTION
# ══════════════════════════════════════════════════════════════════════════════
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;800&family=Inter:wght@400;500;600;700;800&display=swap');

{theme_css}

/* ── Base App & Shell ──────────────────────── */
.main, .stApp {{
    background-color: var(--bg-main) !important;
    color: var(--text-primary) !important;
    font-family: 'Inter', sans-serif !important;
}}
section[data-testid="stSidebar"] {{
    background-color: var(--bg-sidebar) !important;
    border-right: 1.5px solid var(--border-color) !important;
}}
section[data-testid="stSidebar"] div[data-testid="stMarkdownContainer"] p,
section[data-testid="stSidebar"] div[data-testid="stMarkdownContainer"] span {{
    color: var(--text-primary) !important;
}}

::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: var(--bg-sidebar); }}
::-webkit-scrollbar-thumb {{ background: var(--border-color); border-radius: 4px; }}

/* ── Complete Typography Enforcements ──────── */
h1, h2, h3, h4, h5, h6,
.stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, .stMarkdown h5, .stMarkdown h6,
span[data-testid="stHeader"],
[data-testid="stHeading"] {{
    color: var(--heading-color) !important;
    font-weight: 800 !important;
    letter-spacing: -0.3px !important;
}}

p, span, li,
div[data-testid="stMarkdownContainer"] p,
div[data-testid="stMarkdownContainer"] span,
div[data-testid="stMarkdownContainer"] li,
div[data-testid="stText"] {{
    color: var(--text-primary) !important;
}}

/* Captions and subtext */
div[data-testid="stCaptionContainer"],
div[data-testid="stCaptionContainer"] p,
div[data-testid="stCaptionContainer"] span,
.stCaption, small {{
    color: var(--text-muted) !important;
    font-size: 0.88rem !important;
    font-weight: 600 !important;
}}

/* Form and input widget labels */
label[data-testid="stWidgetLabel"],
label[data-testid="stWidgetLabel"] p,
label[data-testid="stWidgetLabel"] span,
label[data-testid="stWidgetLabel"] div {{
    color: var(--heading-color) !important;
    font-weight: 800 !important;
    font-size: 0.92rem !important;
}}

/* ── Streamlit Tabs Styling ────────────────── */
div[data-baseweb="tab-list"] {{
    background-color: var(--tab-bg) !important;
    border-radius: 10px !important;
    padding: 6px !important;
    border: 1.5px solid var(--border-color) !important;
    gap: 6px !important;
}}
button[data-baseweb="tab"] {{
    color: var(--tab-text) !important;
    background-color: transparent !important;
    font-weight: 700 !important;
    font-size: 0.95rem !important;
    border-radius: 8px !important;
    padding: 10px 18px !important;
    border: none !important;
    transition: all .2s ease !important;
}}
button[data-baseweb="tab"] p,
button[data-baseweb="tab"] span,
button[data-baseweb="tab"] div {{
    color: var(--tab-text) !important;
    font-weight: 700 !important;
}}
button[data-baseweb="tab"][aria-selected="true"] {{
    color: var(--tab-active-text) !important;
    background-color: var(--tab-active-bg) !important;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1) !important;
}}
button[data-baseweb="tab"][aria-selected="true"] p,
button[data-baseweb="tab"][aria-selected="true"] span,
button[data-baseweb="tab"][aria-selected="true"] div {{
    color: var(--tab-active-text) !important;
    font-weight: 800 !important;
}}

/* ── Buttons (Sidebar & Main Area) ─────────── */
button[kind="secondary"],
.stButton > button {{
    background-color: var(--btn-bg) !important;
    color: var(--btn-text) !important;
    border: 1.5px solid var(--btn-border) !important;
    font-weight: 700 !important;
    border-radius: 8px !important;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06) !important;
    transition: all .2s ease !important;
}}
button[kind="secondary"]:hover,
.stButton > button:hover {{
    border-color: #3b82f6 !important;
    color: #1d4ed8 !important;
    box-shadow: 0 3px 10px rgba(59,130,246,0.15) !important;
}}
button[kind="primary"] {{
    background-color: #2563eb !important;
    color: #ffffff !important;
    border: 1.5px solid #1d4ed8 !important;
    font-weight: 800 !important;
    border-radius: 8px !important;
    box-shadow: 0 2px 8px rgba(37,99,235,0.25) !important;
}}

/* ── Input Controls (Selectbox, Multiselect, Text Input) ── */
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
div[data-baseweb="base-input"] {{
    background-color: var(--input-bg) !important;
    border: 1.5px solid var(--input-border) !important;
    color: var(--input-text) !important;
    border-radius: 8px !important;
}}
div[data-baseweb="select"] span,
div[data-baseweb="select"] div,
div[data-baseweb="input"] input {{
    color: var(--input-text) !important;
    font-weight: 600 !important;
}}
ul[data-baseweb="menu"] {{
    background-color: var(--bg-card) !important;
    border: 1.5px solid var(--border-color) !important;
    border-radius: 8px !important;
}}
li[data-baseweb="menu-item"] {{
    color: var(--text-primary) !important;
    font-weight: 600 !important;
}}
li[data-baseweb="menu-item"]:hover {{
    background-color: var(--bg-card-hover) !important;
    color: #1d4ed8 !important;
}}

/* Multiselect tag pills */
span[data-baseweb="tag"] {{
    background-color: var(--pill-bg) !important;
    border: 1px solid var(--pill-border) !important;
    border-radius: 6px !important;
}}
span[data-baseweb="tag"] span {{
    color: var(--pill-text) !important;
    font-weight: 700 !important;
}}

/* Alert / Info / Warning Callout boxes */
div[data-testid="stAlert"] {{
    background-color: var(--bg-card) !important;
    border: 1.5px solid #3b82f6 !important;
    border-radius: 10px !important;
}}
div[data-testid="stAlert"] p,
div[data-testid="stAlert"] span {{
    color: var(--text-primary) !important;
    font-weight: 600 !important;
}}

/* SVG icon colors */
svg {{
    fill: var(--text-muted) !important;
    color: var(--text-muted) !important;
}}

/* Tables and Dataframes */
div[data-testid="stDataFrame"] {{
    border: 1.5px solid var(--border-color) !important;
    border-radius: 10px !important;
    overflow: hidden !important;
}}

table {{
    color: var(--text-primary) !important;
    width: 100% !important;
    border-collapse: collapse !important;
}}
th {{
    color: var(--heading-color) !important;
    background-color: var(--bg-card-hover) !important;
    border-bottom: 2px solid var(--border-color) !important;
    font-weight: 800 !important;
    padding: 10px 14px !important;
}}
td {{
    color: var(--text-primary) !important;
    border-bottom: 1px solid var(--border-color) !important;
    padding: 10px 14px !important;
    font-weight: 500 !important;
}}
code {{
    background: var(--code-bg) !important;
    color: var(--code-text) !important;
    padding: 3px 7px !important;
    border-radius: 5px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.88em !important;
    font-weight: 700 !important;
}}

/* ── Header & Banner ───────────────────────── */
.soc-header {{ text-align: center; padding: 8px 0 4px 0; }}
.soc-title {{
    font-size: 2.2rem; font-weight: 900;
}}
.soc-sub {{
    color: var(--text-muted) !important;
    font-size: 0.92rem; font-weight: 700; letter-spacing: 0.5px; margin-top: 4px;
}}
.status-pill {{
    display: inline-block; padding: 7px 20px; border-radius: 20px;
    font-size: 0.84rem; font-weight: 800;
    font-family: 'JetBrains Mono', monospace;
    background: var(--pill-bg) !important;
    color: var(--pill-text) !important;
    border: 1.5px solid var(--pill-border) !important;
    margin: 6px 0 16px 0;
}}
.threat-banner {{
    padding: 12px 24px; border-radius: 10px; font-weight: 800;
    font-size: 0.98rem; text-align: center; letter-spacing: 1.2px;
    margin: 4px 0 18px 0;
}}
@keyframes pulse-red {{
    from {{ box-shadow: 0 0 5px rgba(239,68,68,.25); }}
    to   {{ box-shadow: 0 0 25px rgba(239,68,68,.55); }}
}}

/* ── KPI Cards ─────────────────────────────── */
.kpi-row {{ display: flex; gap: 14px; flex-wrap: wrap; margin: 8px 0 20px 0; }}
.kpi-card {{
    flex: 1; min-width: 140px;
    background: var(--bg-card) !important;
    border: 1.5px solid var(--border-color) !important;
    border-radius: 14px; padding: 18px 14px; text-align: center;
    box-shadow: 0 4px 14px rgba(0,0,0,0.06);
    transition: all .3s ease;
}}
.kpi-card:hover {{
    background: var(--bg-card-hover) !important;
    box-shadow: 0 8px 22px rgba(59,130,246,0.18);
}}
.kpi-icon {{ font-size: 1.6rem; margin-bottom: 4px; }}
.kpi-val {{
    font-size: 2.2rem; font-weight: 900;
    font-family: 'JetBrains Mono', monospace; margin: 4px 0;
}}
.kpi-lbl {{
    font-size: 0.78rem; color: var(--text-muted) !important;
    text-transform: uppercase; letter-spacing: 1px; font-weight: 800;
}}
.kc-crit {{ border-left: 5px solid #ef4444 !important; }}
.kc-high {{ border-left: 5px solid #f97316 !important; }}
.kc-total{{ border-left: 5px solid #3b82f6 !important; }}
.kc-src  {{ border-left: 5px solid #a855f7 !important; }}
.kc-pkt  {{ border-left: 5px solid #06b6d4 !important; }}
.kc-rate {{ border-left: 5px solid #22c55e !important; }}

/* ── Attack Cards in Simulation Lab ────────── */
.atk-card {{
    background: var(--bg-card) !important;
    border: 1.5px solid var(--border-color) !important;
    border-radius: 14px; padding: 20px; margin: 10px 0;
    box-shadow: 0 4px 14px rgba(0,0,0,0.06);
    transition: all .3s ease;
}}
.atk-card:hover {{
    border-color: #3b82f6 !important;
    box-shadow: 0 8px 24px rgba(59,130,246,0.16);
}}
.atk-title {{
    color: var(--heading-color) !important;
    font-size: 1.22rem; font-weight: 800; margin-bottom: 6px;
}}
.atk-desc {{
    color: var(--text-secondary) !important;
    font-size: 0.94rem; line-height: 1.5; margin: 12px 0; font-weight: 500;
}}
.atk-meta {{
    color: var(--text-primary) !important;
    font-size: 0.88rem; margin-top: 5px;
}}
.atk-meta strong {{ color: var(--heading-color) !important; font-weight: 800; }}
.atk-real {{
    color: var(--text-muted) !important;
    font-size: 0.85rem; margin-top: 5px; font-weight: 600;
}}
.atk-real strong {{ color: var(--text-primary) !important; font-weight: 800; }}

.mitre-tag {{
    display: inline-block; padding: 4px 10px; border-radius: 5px;
    font-size: 0.76rem; font-family: 'JetBrains Mono', monospace; margin-right: 6px;
}}
.sev-crit {{ display: inline-block; padding: 4px 10px; border-radius: 5px; font-size: 0.76rem; }}
.sev-high {{ display: inline-block; padding: 4px 10px; border-radius: 5px; font-size: 0.76rem; }}

/* ── Cyber Kill Chain ──────────────────────── */
.kc-pipeline {{ display: flex; gap: 10px; flex-wrap: wrap; justify-content: center; margin: 18px 0; }}
.kc-stage {{
    padding: 14px 18px; border-radius: 12px; font-size: 0.88rem;
    font-weight: 800; text-align: center; min-width: 135px;
    box-shadow: 0 3px 10px rgba(0,0,0,0.05);
}}

/* ── Forensic Evidence Cards ───────────────── */
.ev-card {{
    background: var(--bg-card) !important;
    border: 1.5px solid var(--border-color) !important;
    border-radius: 12px; padding: 18px; margin: 8px 0;
    box-shadow: 0 4px 14px rgba(0,0,0,0.06);
}}
.ev-metric {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.4rem; font-weight: 800;
    color: var(--text-primary) !important;
}}
.ev-label {{
    color: var(--text-muted) !important;
    font-size: 0.82rem; text-transform: uppercase; font-weight: 800; letter-spacing: 0.8px;
    margin-bottom: 2px;
}}
.ev-bad  {{ color: #dc2626 !important; }}
.ev-good {{ color: #16a34a !important; }}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_alert_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        with sqlite3.connect(DB_PATH, timeout=10.0) as conn:
            df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 500", conn)
        return df
    except Exception:
        return pd.DataFrame()


MAX_UPLOAD_PACKETS = 300_000


def analyse_pcap(pcap_path: str, idle_timeout: float = 15.0, max_packets=None) -> dict:
    """Runs the passive pipeline over a capture and returns ingestion + detection telemetry."""
    pipe = StreamingDetectionPipeline(alert_jsonl=JSONL_PATH, alert_db=DB_PATH, idle_timeout=idle_timeout)
    reader = ReadOnlyPacketReader(pcap_path, max_packets=max_packets)
    alerts = []
    t0 = time.perf_counter()
    for pkt in reader.read_packets():
        alerts.extend(pipe.process_packet(pkt))
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


def run_simulation(attack_name: str):
    pcap_path = str(ROOT_DIR / "data" / "pcaps" / "simulated_traffic.pcap")
    pkt_count = generate_synthetic_pcap(attack_type=attack_name, output_path=pcap_path)
    result = analyse_pcap(pcap_path, idle_timeout=2.0)
    return pkt_count, len(result["alerts"])


def alert_record(row) -> dict:
    """DB row -> alert dict with parsed evidence (for rules and reports)."""
    rec = {k: (v.item() if hasattr(v, "item") else v) for k, v in dict(row).items()}
    try:
        rec["evidence"] = json.loads(rec["evidence"]) if isinstance(rec.get("evidence"), str) else (rec.get("evidence") or {})
    except ValueError:
        rec["evidence"] = {}
    return rec


def format_evidence_value(v) -> str:
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v) if v else "—"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def reset_database():
    try:
        if os.path.exists(DB_PATH):
            with sqlite3.connect(DB_PATH, timeout=10.0) as conn:
                conn.execute("DELETE FROM alerts")
                conn.commit()
        if os.path.exists(JSONL_PATH):
            open(JSONL_PATH, "w").close()
        return True
    except Exception:
        return False


def threat_level(df):
    if df.empty:
        return "GREEN", "NOMINAL", "t-green"
    crit = len(df[df["severity"] == "CRITICAL"])
    high = len(df[df["severity"] == "HIGH"])
    if crit >= 5:
        return "RED", "CRITICAL", "t-red"
    if crit >= 1 or high >= 5:
        return "ORANGE", "ELEVATED", "t-orange"
    if high >= 1:
        return "YELLOW", "GUARDED", "t-yellow"
    return "GREEN", "NOMINAL", "t-green"

# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════

st.markdown("""
<div class="soc-header">
    <div class="soc-title">🛡️ Unidirectional IP Traffic — Threat Intelligence SOC</div>
    <div class="soc-sub">Smart India Hackathon 2026 &nbsp;|&nbsp; PS 26145 &nbsp;|&nbsp; National Technical Research Organisation (NTRO)</div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div style="text-align:center"><span class="status-pill">● DATA DIODE ENCLAVE &nbsp;—&nbsp; PASSIVE MONITORING &nbsp;|&nbsp; 100% READ-ONLY &nbsp;|&nbsp; ZERO RETURN PATH</span></div>', unsafe_allow_html=True)

# Load data and compute threat posture (auto-seed baseline threats once per session, so
# "Reset" and an uploaded capture with no findings are not refilled with simulated attacks)
df = load_alert_data()
if df.empty and not st.session_state.get("auto_seeded"):
    st.session_state["auto_seeded"] = True
    try:
        run_simulation("all")
        df = load_alert_data()
    except Exception:
        pass
_tl_color, _tl_label, _tl_css = threat_level(df)
total_alerts = len(df)
critical_count = len(df[df["severity"] == "CRITICAL"]) if not df.empty else 0
high_count = len(df[df["severity"] == "HIGH"]) if not df.empty else 0
unique_sources = df["src_ip"].nunique() if not df.empty else 0
unique_threats = df["threat_class"].nunique() if not df.empty else 0
avg_confidence = round(df["confidence_score"].mean() * 100, 1) if not df.empty else 0.0

st.markdown(f'<div class="threat-banner {_tl_css}">THREAT POSTURE: {_tl_label} &nbsp;&nbsp; {_tl_color} &nbsp;&nbsp; | &nbsp;&nbsp; {critical_count} CRITICAL &nbsp; {high_count} HIGH &nbsp; {total_alerts} TOTAL ALERTS</div>', unsafe_allow_html=True)

# KPI Row
st.markdown(f"""
<div class="kpi-row">
  <div class="kpi-card kc-total">
    <div class="kpi-icon">🚨</div>
    <div class="kpi-val" style="color: {kpi_colors['total']} !important;">{total_alerts}</div>
    <div class="kpi-lbl">Total Alerts</div>
  </div>
  <div class="kpi-card kc-crit">
    <div class="kpi-icon">☣️</div>
    <div class="kpi-val" style="color: {kpi_colors['crit']} !important;">{critical_count}</div>
    <div class="kpi-lbl">Critical</div>
  </div>
  <div class="kpi-card kc-high">
    <div class="kpi-icon">⚠️</div>
    <div class="kpi-val" style="color: {kpi_colors['high']} !important;">{high_count}</div>
    <div class="kpi-lbl">High</div>
  </div>
  <div class="kpi-card kc-src">
    <div class="kpi-icon">🌐</div>
    <div class="kpi-val" style="color: {kpi_colors['src']} !important;">{unique_sources}</div>
    <div class="kpi-lbl">Threat Sources</div>
  </div>
  <div class="kpi-card kc-pkt">
    <div class="kpi-icon">🔍</div>
    <div class="kpi-val" style="color: {kpi_colors['pkt']} !important;">{unique_threats}</div>
    <div class="kpi-lbl">Attack Types</div>
  </div>
  <div class="kpi-card kc-rate">
    <div class="kpi-icon">🎯</div>
    <div class="kpi-val" style="color: {kpi_colors['rate']} !important;">{avg_confidence}%</div>
    <div class="kpi-lbl">Avg Confidence</div>
  </div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════════

st.sidebar.markdown("---")
st.sidebar.markdown("### ⚡ Threat Simulator")
st.sidebar.caption("Inject attacks through the passive data-diode pipeline")

if st.sidebar.button("🚀 Launch Full Attack Stream (All 6)", type="primary", use_container_width=True):
    with st.spinner("Injecting 6 attack vectors through Data Diode ..."):
        pkts, alerts = run_simulation("all")
    st.sidebar.success(f"✔ {pkts} pkts → {alerts} threats detected")
    st.rerun()

st.sidebar.markdown("**Individual Vectors**")

_attacks = [
    ("🌊 DDoS SYN Flood", "ddos"),
    ("🤖 C2 Beaconing", "beaconing"),
    ("🌐 DGA Domains", "dga"),
    ("🚪 Port Scan", "port_scan"),
    ("🔒 Encrypted Malware", "encrypted_malware"),
    ("📤 Data Exfiltration", "exfiltration"),
]
for label, key in _attacks:
    if st.sidebar.button(label, key=f"sb_{key}", use_container_width=True):
        with st.spinner(f"Simulating {key} ..."):
            p, a = run_simulation(key)
        st.sidebar.success(f"{a} alerts fired!")
        st.rerun()

st.sidebar.markdown("---")
if st.sidebar.button("🗑️ Reset All Alerts", use_container_width=True):
    if reset_database():
        st.sidebar.warning("Database cleared!")
        st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════════════════════════════════════

tab1, tab_upload, tab2, tab3, tab4, tab5 = st.tabs([
    "🚨 Threat Overview",
    "📂 Analyse Your PCAP",
    "🗺️ Network Intelligence",
    "🔍 Alert Investigation",
    "🧪 Attack Simulation Lab",
    "📊 Analytics & Reports",
])

# ──────────────────────────────────────────────────────────────────────────────
# TAB 1 — Threat Overview
# ──────────────────────────────────────────────────────────────────────────────
with tab1:
    if df.empty:
        st.info("💡 No alerts yet — use the sidebar **Launch Full Attack Stream** button to inject traffic and see the AI detect threats in real-time!")
    else:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("##### Threats by Attack Classification")
            tc = df["threat_class"].value_counts().reset_index()
            tc.columns = ["Threat", "Count"]
            color_seq = [THREAT_COLORS.get(t, "#3b82f6") for t in tc["Threat"]]
            fig_bar = px.bar(tc, x="Count", y="Threat", orientation="h",
                             color="Threat", color_discrete_sequence=color_seq)
            fig_bar.update_layout(**make_layout(showlegend=False, height=330,
                                  yaxis=dict(categoryorder="total ascending", color=plotly_font_color)))
            st.plotly_chart(fig_bar, use_container_width=True)

        with c2:
            st.markdown("##### Severity Distribution")
            sv = df["severity"].value_counts().reset_index()
            sv.columns = ["Severity", "Count"]
            sev_colors = [SEVERITY_COLORS.get(s, "#3b82f6") for s in sv["Severity"]]
            fig_donut = go.Figure(data=[go.Pie(
                labels=sv["Severity"], values=sv["Count"],
                hole=0.55, marker=dict(colors=sev_colors),
                textinfo="label+percent", textfont=dict(size=13, color=plotly_font_color),
            )])
            fig_donut.update_layout(**make_layout(height=330, showlegend=False))
            st.plotly_chart(fig_donut, use_container_width=True)

        # Alert timeline
        st.markdown("##### Alert Timeline")
        tl = df.copy()
        tl["ts"] = pd.to_datetime(tl["timestamp"], errors="coerce")
        tl = tl.dropna(subset=["ts"]).sort_values("ts")
        if not tl.empty:
            fig_tl = px.scatter(tl, x="ts", y="threat_class", color="severity",
                                color_discrete_map=SEVERITY_COLORS,
                                size="confidence_score", hover_data=["src_ip", "dst_ip"],
                                size_max=14)
            fig_tl.update_layout(**make_layout(height=290, xaxis_title="Time", yaxis_title=""))
            st.plotly_chart(fig_tl, use_container_width=True)

        # Top attackers table
        st.markdown("##### Top Threat Sources")
        top = df.groupby("src_ip").agg(
            alerts=("id", "count"),
            critical=("severity", lambda s: (s == "CRITICAL").sum()),
            threats=("threat_class", "nunique"),
        ).sort_values("alerts", ascending=False).head(10).reset_index()
        top.columns = ["Source IP", "Alerts", "Critical", "Threat Types"]
        st.dataframe(top, use_container_width=True, hide_index=True)

# ──────────────────────────────────────────────────────────────────────────────
# TAB — Analyse Your PCAP (bring-your-own capture)
# ──────────────────────────────────────────────────────────────────────────────
with tab_upload:
    st.markdown("##### 📂 Live PCAP Dissection — bring your own capture")
    st.caption(
        "Upload any Wireshark / tcpdump capture. It is replayed through the same passive pipeline "
        "(5-tuple flows + 3 s sliding windows + all 6 detectors). Ethernet, Linux-cooked, raw-IP and "
        f"loopback captures are supported; the first {MAX_UPLOAD_PACKETS:,} packets are analysed."
    )
    uploaded = st.file_uploader("PCAP / PCAPNG file", type=["pcap", "pcapng", "cap"], key="pcap_upload")
    clear_first = st.checkbox("Clear existing alerts first (show only this capture's detections)", value=True)

    if uploaded is not None and st.button("🔬 Analyse Capture", type="primary", key="analyse_upload"):
        upload_dir = ROOT_DIR / "data" / "pcaps"
        os.makedirs(upload_dir, exist_ok=True)
        suffix = os.path.splitext(uploaded.name)[1] or ".pcap"
        with tempfile.NamedTemporaryFile(suffix=suffix, dir=upload_dir, delete=False) as tmp:
            tmp.write(uploaded.getbuffer())
            tmp_path = tmp.name
        try:
            if clear_first:
                reset_database()
            with st.spinner(f"Dissecting {uploaded.name} through the passive pipeline ..."):
                result = analyse_pcap(tmp_path, max_packets=MAX_UPLOAD_PACKETS)
            st.session_state["upload_result"] = {**result, "name": uploaded.name}
        except Exception as exc:
            st.session_state.pop("upload_result", None)
            st.error(f"Could not parse this capture: {exc}")
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        if "upload_result" in st.session_state:
            st.rerun()

    res = st.session_state.get("upload_result")
    if res:
        st.success(f"✔ {res['name']}: {res['packets']:,} packets → {res['flows']:,} flows → {len(res['alerts'])} alerts")
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Packets analysed", f"{res['packets']:,}")
        m2.metric("Flows", f"{res['flows']:,}")
        m3.metric("Sliding windows", f"{res['windows']:,}")
        m4.metric("Throughput", f"{res['pps']:,.0f} pkt/s")
        m5.metric("Avg inference", f"{res['flow_ms']:.2f} ms/flow")
        if res["truncated"]:
            st.warning(f"Capture is larger than {MAX_UPLOAD_PACKETS:,} packets; only the first part was analysed.")
        if res["packets"] == 0:
            st.warning(f"No IP packets could be decoded (link type {res['linktype']}, {res['skipped']:,} frames skipped).")
        elif res["skipped"]:
            st.caption(f"{res['skipped']:,} non-IP frames (ARP, STP, etc.) were skipped.")
        if res["alerts"]:
            summary = pd.DataFrame(res["alerts"]).groupby(["threat_class", "severity"]).size().reset_index(name="alerts")
            summary["MITRE"] = summary["threat_class"].map(lambda t: MITRE_MAP.get(t, {}).get("id", "-"))
            st.dataframe(summary, use_container_width=True, hide_index=True)
            st.caption("All tabs (Overview, Network, Investigation, Analytics) now reflect this capture.")
        else:
            st.info("No threats detected in this capture by any of the 6 detectors.")

# ──────────────────────────────────────────────────────────────────────────────
# TAB 2 — Network Intelligence
# ──────────────────────────────────────────────────────────────────────────────
with tab2:
    if df.empty:
        st.info("💡 Run an attack simulation first to see the network topology.")
    else:
        st.markdown("##### Network Attack Topology")
        st.caption("Nodes = IP addresses | Edges = active connections | Color = risk severity | Size = alert volume")

        # Build node data
        src_ips = df["src_ip"].unique().tolist()
        dst_ips = df["dst_ip"].unique().tolist()
        all_ips = list(dict.fromkeys(src_ips + dst_ips))
        alert_counts = df["src_ip"].value_counts().to_dict()

        ip_severity = {}
        for ip in all_ips:
            sub = df[(df["src_ip"] == ip) | (df["dst_ip"] == ip)]
            if "CRITICAL" in sub["severity"].values:
                ip_severity[ip] = "CRITICAL"
            elif "HIGH" in sub["severity"].values:
                ip_severity[ip] = "HIGH"
            elif "MEDIUM" in sub["severity"].values:
                ip_severity[ip] = "MEDIUM"
            else:
                ip_severity[ip] = "LOW"

        n = len(all_ips)
        node_x, node_y = [], []
        for i, ip in enumerate(all_ips):
            angle = 2 * math.pi * i / max(n, 1)
            r = 2.5 if ip in src_ips else 1.0
            node_x.append(r * math.cos(angle))
            node_y.append(r * math.sin(angle))

        # Edges
        conns = df.groupby(["src_ip", "dst_ip"]).size().reset_index(name="cnt")
        edge_x, edge_y = [], []
        for _, row in conns.iterrows():
            if row["src_ip"] in all_ips and row["dst_ip"] in all_ips:
                si = all_ips.index(row["src_ip"])
                di = all_ips.index(row["dst_ip"])
                edge_x.extend([node_x[si], node_x[di], None])
                edge_y.extend([node_y[si], node_y[di], None])

        sev_cmap = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
        node_colors = [sev_cmap.get(ip_severity.get(ip, "LOW"), "#22c55e") for ip in all_ips]
        node_sizes = [max(14, min(45, alert_counts.get(ip, 1) * 4)) for ip in all_ips]

        fig_net = go.Figure()
        fig_net.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines",
                                     line=dict(width=1.5, color=edge_color),
                                     hoverinfo="none"))
        fig_net.add_trace(go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            marker=dict(size=node_sizes, color=node_colors,
                        line=dict(width=2.5, color="rgba(255,255,255,0.8)" if is_dark else "rgba(15,23,42,0.6)")),
            text=all_ips, textposition="top center",
            textfont=dict(size=11, color=node_text_color, family="JetBrains Mono"),
            hovertext=[f"IP: {ip}<br>Alerts: {alert_counts.get(ip,0)}<br>Risk: {ip_severity.get(ip,'LOW')}" for ip in all_ips],
            hoverinfo="text",
        ))
        fig_net.update_layout(**make_layout(showlegend=False, height=520,
                              xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                              yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)))
        st.plotly_chart(fig_net, use_container_width=True)

        # Heatmap: Source IP x Threat
        st.markdown("##### Threat Heatmap — Source IP × Attack Type")
        hm = df.groupby(["src_ip", "threat_class"]).size().unstack(fill_value=0)
        fig_hm = px.imshow(hm, color_continuous_scale=heatmap_colorscale, aspect="auto")
        fig_hm.update_layout(**make_layout(height=350))
        st.plotly_chart(fig_hm, use_container_width=True)

# ──────────────────────────────────────────────────────────────────────────────
# TAB 3 — Alert Investigation
# ──────────────────────────────────────────────────────────────────────────────
with tab3:
    if df.empty:
        st.info("💡 No alerts to investigate yet. Launch an attack simulation first.")
    else:
        # Filters
        st.markdown("##### 🔍 Multi-Criteria Alert Filters")
        fc1, fc2, fc3 = st.columns(3)
        with fc1:
            sev_filter = st.multiselect("Severity Level", ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        with fc2:
            threat_opts = df["threat_class"].unique().tolist()
            threat_filter = st.multiselect("Threat Classification", threat_opts, default=threat_opts)
        with fc3:
            ip_search = st.text_input("Search Source IP", placeholder="e.g. 192.168.1.*")

        filtered = df[df["severity"].isin(sev_filter) & df["threat_class"].isin(threat_filter)]
        if ip_search:
            filtered = filtered[filtered["src_ip"].str.contains(ip_search.replace("*", ""), na=False)]

        st.markdown(f"##### Live Security Alert Feed &nbsp;&nbsp; ({len(filtered)} matches)")
        display_cols = ["id", "timestamp", "severity", "threat_class", "src_ip", "dst_ip", "dst_port", "confidence_score"]
        available_cols = [c for c in display_cols if c in filtered.columns]
        st.dataframe(filtered[available_cols], height=320, use_container_width=True, hide_index=True)

        # Export
        csv_data = filtered.to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Filtered Alerts as CSV", csv_data, "soc_alerts_export.csv", "text/csv")

        st.markdown("---")

        # Forensic Inspector
        st.markdown("##### 🔬 Explainable AI — Forensic Evidence Inspector")
        st.caption("Select any alert to inspect the cryptographic, statistical, and mathematical evidence generated by the AI detectors.")

        alert_ids = filtered["id"].tolist()
        if alert_ids:
            selected_id = st.selectbox("Select Alert ID to Inspect", alert_ids)
            row = filtered[filtered["id"] == selected_id].iloc[0]
            try:
                evidence = json.loads(row["evidence"]) if isinstance(row["evidence"], str) else row["evidence"]
            except Exception:
                evidence = {}

            e1, e2 = st.columns(2)
            with e1:
                st.markdown('<div class="ev-card">', unsafe_allow_html=True)
                st.markdown("#### 📋 Flow Identification")
                st.markdown(f"""
| Property | Value |
|---|---|
| **Flow ID** | `{row.get('flow_id','-')}` |
| **Timestamp (UTC)** | `{row.get('timestamp','-')}` |
| **Source Socket** | `{row.get('src_ip','-')}:{row.get('src_port','-')}` |
| **Target Socket** | `{row.get('dst_ip','-')}:{row.get('dst_port','-')}` |
| **Protocol** | `{row.get('protocol','-')}` |
| **Threat Class** | `{row.get('threat_class','-')}` |
| **Detection Confidence** | **{float(row.get('confidence_score',0))*100:.1f}%** |
| **Assigned Severity** | **{row.get('severity','-')}** |
""")
                st.markdown('</div>', unsafe_allow_html=True)

            with e2:
                st.markdown('<div class="ev-card">', unsafe_allow_html=True)
                st.markdown("#### ⚡ AI Detection Evidence")
                if isinstance(evidence, dict) and evidence:
                    # Evidence can hold attacker-controlled strings (domains, SNI): always escape
                    for k, v in evidence.items():
                        label = escape(k.replace("_", " ").title())
                        if isinstance(v, bool):
                            icon = "⚠️" if v else "—"
                            st.markdown(f'<div class="ev-label">{label}</div><div class="ev-metric">{icon} {v}</div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="ev-label">{label}</div><div class="ev-metric">{escape(format_evidence_value(v))}</div>', unsafe_allow_html=True)
                else:
                    st.json(evidence)
                st.markdown('</div>', unsafe_allow_html=True)

            # Automated response playbook for the selected alert
            st.markdown("##### 🛡️ Automated Response Playbook (SOAR)")
            st.caption("Rules for the downstream firewall / IPS on the production side. The diode-side sensor never transmits, so nothing is applied automatically.")
            rules = generate_response_rules(alert_record(row))
            st.markdown(f"**Recommended action:** {rules['action']}")
            r1, r2 = st.columns(2)
            with r1:
                st.markdown("**iptables**")
                st.code(rules["iptables"] or "# no host-level rule for this alert", language="bash")
            with r2:
                st.markdown("**Snort 3 / Suricata**")
                st.code(rules["suricata"] or "# no signature for this alert", language="text")

        st.markdown("---")
        st.markdown("##### 📦 Bulk Export (filtered alerts)")
        filtered_records = [alert_record(r) for _, r in filtered.iterrows()]
        bundle = build_rules_bundle(filtered_records)
        x1, x2, x3 = st.columns(3)
        x1.download_button("🧱 iptables script (.sh)", bundle["iptables_sh"], "sih26145_block.sh", "text/x-shellscript", use_container_width=True)
        x2.download_button("📜 Suricata rules (.rules)", bundle["suricata_rules"], "sih26145.rules", "text/plain", use_container_width=True)
        x3.download_button(
            "📄 Incident Report (HTML → PDF)",
            build_incident_report(filtered_records, source_label=f"{len(filtered_records)} filtered alerts"),
            "sih26145_incident_report.html", "text/html", use_container_width=True,
        )

# ──────────────────────────────────────────────────────────────────────────────
# TAB 4 — Attack Simulation Lab
# ──────────────────────────────────────────────────────────────────────────────
with tab4:
    st.markdown("##### 🧪 Cyber Attack Simulation Laboratory")
    st.caption("Inject specific attack vectors through the passive data-diode pipeline and observe real-time AI detection.")

    attack_defs = [
        {
            "icon": "🌊", "title": "Volumetric DDoS (SYN Flood)",
            "mitre": "T1498", "severity": "CRITICAL",
            "desc": "600 half-open SYNs at ~500 pps from ~200 spoofed bots hit one server. Each 3 s sliding window aggregates fan-in per target: peak PPS, share of half-open SYNs and source-IP entropy.",
            "method": "Sliding-window fan-in analysis (peak PPS ≥ 300, ≥ 80% half-open SYN)",
            "example": "Mirai Botnet (2016), Memcached Amplification (2018)",
            "key": "ddos",
        },
        {
            "icon": "🤖", "title": "Botnet C2 Beaconing",
            "mitre": "T1071", "severity": "HIGH",
            "desc": "Infected host sends periodic check-in signals to C2 server every 2.0 seconds with zero variance. AI detects via inter-arrival time (IAT) statistical periodicity.",
            "method": "IAT variance analysis (threshold < 0.01)",
            "example": "APT28 (Fancy Bear), Cobalt Strike Beacons",
            "key": "beaconing",
        },
        {
            "icon": "🌐", "title": "DGA Domains & DNS Tunneling",
            "mitre": "T1568", "severity": "HIGH",
            "desc": "Malware queries pseudorandom domains (e.g. vxzq981pkm.biz) and tunnels data in long base32 subdomains. Scored on the registered label: Shannon entropy, length, consonant ratio, digit mixing.",
            "method": "Entropy + consonant/digit indicators; subdomain entropy for tunneling",
            "example": "Conficker, CryptoLocker, Emotet",
            "key": "dga",
        },
        {
            "icon": "🚪", "title": "Reconnaissance Port Scan",
            "mitre": "T1046", "severity": "MEDIUM",
            "desc": "Systematic SYN probes across 13 ports (21, 22, 80, 443, 3389, etc.) to map services. Each 3 s window counts distinct ports per host and hosts per port for every source.",
            "method": "Sliding-window fan-out (≥ 10 ports or ≥ 20 hosts, probe ratio ≥ 60%)",
            "example": "Nmap SYN Scan, Masscan",
            "key": "port_scan",
        },
        {
            "icon": "🔒", "title": "Encrypted Malware (TLS Metadata)",
            "mitre": "T1573", "severity": "CRITICAL",
            "desc": "An implant opens TLS with a hand-rolled ClientHello. Without decrypting anything, the JA3 hash is checked against known C2 fingerprints, then the ClientHello is scored for legacy version, missing SNI, odd port and cipher list.",
            "method": "JA3 blocklist + ClientHello metadata anomaly scoring",
            "example": "Cobalt Strike, Emotet, TrickBot, Metasploit",
            "key": "encrypted_malware",
        },
        {
            "icon": "📤", "title": "Data Exfiltration",
            "mitre": "T1048", "severity": "CRITICAL",
            "desc": "Asymmetric outbound data burst with high payload-to-header ratio and large MTU frames. AI detects via volume ratio analysis without inspecting payload contents.",
            "method": "Asymmetric byte ratio (>15:1) + MTU frame volume bursts",
            "example": "SolarWinds (2020), Colonial Pipeline (2021)",
            "key": "exfiltration",
        },
    ]

    for i in range(0, len(attack_defs), 2):
        cols = st.columns(2)
        for j, col in enumerate(cols):
            if i + j < len(attack_defs):
                atk = attack_defs[i + j]
                with col:
                    sev_tag = "sev-crit" if atk["severity"] == "CRITICAL" else "sev-high"
                    st.markdown(f"""<div class="atk-card">
<div class="atk-title">{atk['icon']} {atk['title']}</div>
<span class="mitre-tag">MITRE {atk['mitre']}</span> <span class="{sev_tag}">{atk['severity']}</span>
<div class="atk-desc">{atk['desc']}</div>
<div class="atk-meta"><strong>Detection Method:</strong> {atk['method']}</div>
<div class="atk-real"><strong>Threat Actor Example:</strong> {atk['example']}</div>
</div>""", unsafe_allow_html=True)
                    if st.button(f"Simulate {atk['title']}", key=f"lab_{atk['key']}"):
                        with st.spinner(f"Injecting {atk['title']} ..."):
                            p, a = run_simulation(atk["key"])
                        st.success(f"{p} packets ingested → {a} alerts fired!")
                        st.rerun()

# ──────────────────────────────────────────────────────────────────────────────
# TAB 5 — Analytics & Reports
# ──────────────────────────────────────────────────────────────────────────────
with tab5:
    # Kill Chain
    st.markdown("##### ⚔️ Cyber Kill Chain — Detection Coverage")
    st.caption("Lockheed Martin Cyber Kill Chain stages mapped against active AI detections.")

    detected_classes = set(df["threat_class"].unique()) if not df.empty else set()
    kc_html = '<div class="kc-pipeline">'
    for stage_name, mapped_threat in KILL_CHAIN_STAGES:
        is_active = mapped_threat in detected_classes if mapped_threat else False
        css = "kc-active" if is_active else "kc-inactive"
        icon = "🔴" if is_active else "⚪"
        threat_label = f"<br><small style='font-weight:700;'>{mapped_threat.replace('_',' ').title()}</small>" if mapped_threat and is_active else ""
        kc_html += f'<div class="kc-stage {css}">{icon}<br><strong>{stage_name}</strong>{threat_label}</div>'
    kc_html += '</div>'
    st.markdown(kc_html, unsafe_allow_html=True)

    st.markdown("---")

    # MITRE ATT&CK Mapping
    st.markdown("##### 🎯 MITRE ATT&CK® Framework — Detected Techniques")
    if df.empty:
        st.info("No detections yet.")
    else:
        mitre_data = []
        for threat, info in MITRE_MAP.items():
            count = len(df[df["threat_class"] == threat]) if not df.empty else 0
            avg_conf = df[df["threat_class"] == threat]["confidence_score"].mean() if count > 0 else 0
            mitre_data.append({
                "Technique ID": info["id"],
                "Technique Name": info["name"],
                "Tactic": info["tactic"],
                "Alerts Count": count,
                "Avg Confidence": f"{avg_conf*100:.1f}%" if count > 0 else "-",
                "Detection Status": "🔴 ACTIVE DETECTION" if count > 0 else "⚪ Not Observed",
            })
        mitre_df = pd.DataFrame(mitre_data)
        st.dataframe(mitre_df, use_container_width=True, hide_index=True)

    st.markdown("---")

    # Radar chart of attack coverage
    if not df.empty:
        st.markdown("##### 🕸️ Threat Radar — Attack Category Confidence")
        categories = list(MITRE_MAP.keys())
        values = []
        for cat in categories:
            sub = df[df["threat_class"] == cat]
            values.append(sub["confidence_score"].mean() if not sub.empty else 0)
        categories_display = [c.replace("_", " ").title() for c in categories]

        fig_radar = go.Figure(data=go.Scatterpolar(
            r=values + [values[0]],
            theta=categories_display + [categories_display[0]],
            fill="toself",
            fillcolor="rgba(59,130,246,.25)" if is_dark else "rgba(37,99,235,.2)",
            line=dict(color="#3b82f6" if is_dark else "#1d4ed8", width=3),
            marker=dict(size=6, color="#3b82f6" if is_dark else "#1d4ed8"),
        ))
        fig_radar.update_layout(**make_layout(height=430,
                                polar=dict(
                                    bgcolor=plotly_paper_bg,
                                    radialaxis=dict(visible=True, range=[0, 1], gridcolor=plotly_grid_color, color=plotly_font_color, tickfont=dict(color=plotly_font_color, size=10)),
                                    angularaxis=dict(gridcolor=plotly_grid_color, color=plotly_font_color, tickfont=dict(color=plotly_font_color, size=11, family="Inter")),
                                )))
        st.plotly_chart(fig_radar, use_container_width=True)

    st.markdown("---")
    st.markdown("##### 🏛️ System Architecture Verification")
    st.markdown(f"""
| Parameter | Value | Standard / Compliance |
|---|---|---|
| **Architecture Enclave** | 100% Passive Read-Only | Physical Data Diode (Tx-disabled, zero return packet) |
| **Inspection Engine** | Metadata & Statistical Feature Extraction | Zero Payload Decryption (RFC 8446 compliant) |
| **Detection Suite** | 6 explainable detectors: 4 per-flow + 2 per 3 s sliding window | NTRO Problem Statement #26145 Specification |
| **Alert Schema** | Standardized JSON with Evidence & Severity | Real-time SQLite DB + JSONL Streaming Log |
| **Response** | iptables + Snort/Suricata rules exported for the downstream enforcement point | Sensor never transmits (no inline blocking across the diode) |
| **Taxonomy Alignment** | MITRE ATT&CK® Enterprise + Cyber Kill Chain | Enterprise Threat Intelligence Standards |
""")

    if not df.empty:
        st.download_button(
            "📄 Download Full Incident Report (HTML — open and Print → Save as PDF)",
            build_incident_report([alert_record(r) for _, r in df.iterrows()], source_label=f"{len(df)} alerts in SOC database"),
            "sih26145_incident_report.html", "text/html", key="report_full",
        )
