"""Design tokens for the SOC dashboard, the page CSS and the matching Plotly layout.

Both modes are defined here once. The page CSS only references CSS custom
properties, so switching mode swaps the :root block and nothing else. Plotly
cannot read CSS variables, so charts take the same tokens as hex values.
"""
from typing import Any, Dict

from dashboard.catalog import SEVERITIES
from dashboard.components import icon_css

MODES = ("dark", "light")

TOKENS: Dict[str, Dict[str, str]] = {
    "dark": {
        "scheme": "dark",
        "page": "#0b111c",
        "surface": "#121a28",
        "surface-2": "#182235",
        "surface-3": "#1f2a40",
        "border": "rgba(148, 163, 184, 0.16)",
        "border-strong": "rgba(148, 163, 184, 0.30)",
        "text-1": "#f1f5f9",
        "text-2": "#cbd5e1",
        "text-3": "#8fa0b8",
        "accent": "#3987e5",
        "accent-strong": "#6da7ec",
        "accent-soft": "rgba(57, 135, 229, 0.16)",
        "on-accent": "#ffffff",
        "grid": "#1e293b",
        "baseline": "#334155",
        "code-bg": "#0d1422",
        "code-text": "#d6e4ff",
        "shadow": "0 1px 2px rgba(0, 0, 0, 0.45), 0 8px 24px rgba(0, 0, 0, 0.28)",
        "crit-soft": "rgba(208, 59, 59, 0.16)",
        "high-soft": "rgba(236, 131, 90, 0.16)",
        "med-soft": "rgba(250, 178, 25, 0.14)",
        "low-soft": "rgba(138, 148, 166, 0.16)",
        "good": "#0ca30c",
        "good-soft": "rgba(12, 163, 12, 0.16)",
        "heat-low": "#184f95",
        "heat-high": "#86b6ef",
    },
    "light": {
        "scheme": "light",
        "page": "#f4f6fa",
        "surface": "#ffffff",
        "surface-2": "#f2f4f8",
        "surface-3": "#e9edf3",
        "border": "rgba(16, 24, 40, 0.10)",
        "border-strong": "rgba(16, 24, 40, 0.18)",
        "text-1": "#0b1220",
        "text-2": "#344054",
        "text-3": "#5d6b82",
        "accent": "#2a78d6",
        "accent-strong": "#1c5cab",
        "accent-soft": "rgba(42, 120, 214, 0.10)",
        "on-accent": "#ffffff",
        "grid": "#e6e9ef",
        "baseline": "#c7cdd8",
        "code-bg": "#f5f7fb",
        "code-text": "#1e3a5f",
        "shadow": "0 1px 2px rgba(16, 24, 40, 0.06), 0 8px 24px rgba(16, 24, 40, 0.06)",
        "crit-soft": "rgba(208, 59, 59, 0.10)",
        "high-soft": "rgba(236, 131, 90, 0.12)",
        "med-soft": "rgba(250, 178, 25, 0.14)",
        "low-soft": "rgba(138, 148, 166, 0.14)",
        "good": "#0ca30c",
        "good-soft": "rgba(12, 163, 12, 0.10)",
        "heat-low": "#cde2fb",
        "heat-high": "#104281",
    },
}

FONT_UI = "Inter, system-ui, -apple-system, 'Segoe UI', sans-serif"
FONT_MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Consolas, monospace"


def tokens(mode: str) -> Dict[str, str]:
    t = dict(TOKENS["light" if mode == "light" else "dark"])
    t.update({
        "crit": SEVERITIES["CRITICAL"].color,
        "high": SEVERITIES["HIGH"].color,
        "med": SEVERITIES["MEDIUM"].color,
        "low": SEVERITIES["LOW"].color,
    })
    return t


def _root_block(t: Dict[str, str]) -> str:
    props = "".join(f"--{k}: {v};" for k, v in t.items() if k != "scheme")
    return f":root {{ color-scheme: {t['scheme']}; {props} }}"


_STATIC_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

/* ---------- shell ---------- */
.stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {
  background: var(--page) !important; color: var(--text-1);
  font-family: Inter, system-ui, -apple-system, 'Segoe UI', sans-serif;
}
[data-testid="stHeader"] { background: transparent !important; }
[data-testid="stMainBlockContainer"] { padding-top: 2.6rem; padding-bottom: 2rem; max-width: 1480px; }
[data-testid="stSidebar"] > div:first-child { background: var(--surface) !important; }
[data-testid="stSidebar"] { border-right: 1px solid var(--border); }
[data-testid="stSidebarContent"] { padding-top: 0.4rem; }
h1, h2, h3, h4, h5, h6, [data-testid="stHeading"] * { color: var(--text-1) !important; letter-spacing: -0.01em; }
[data-testid="stMarkdownContainer"] p, [data-testid="stMarkdownContainer"] li { color: var(--text-2); }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p { color: var(--text-3) !important; }
[data-testid="stWidgetLabel"] p { color: var(--text-2) !important; font-weight: 600; font-size: 0.8rem; }
[data-testid="stMarkdownContainer"] code { background: var(--surface-2); color: var(--text-1); border-radius: 5px;
  padding: 1px 6px; font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; font-size: 0.85em; }
hr { border-color: var(--border) !important; }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-thumb { background: var(--border-strong); border-radius: 8px; }
::-webkit-scrollbar-track { background: transparent; }

/* ---------- inputs (react-aria widgets in Streamlit 1.64) ---------- */
[data-testid="stSelectbox"] [role="group"], [data-testid="stMultiSelect"] [role="group"],
[data-testid="stTextInputRootElement"], [data-testid="stNumberInputContainer"] {
  background: var(--surface) !important; border: 1px solid var(--border-strong) !important; color: var(--text-1) !important;
}
[data-testid="stSelectbox"] [role="group"]:focus-within, [data-testid="stMultiSelect"] [role="group"]:focus-within,
[data-testid="stTextInputRootElement"]:focus-within { border-color: var(--accent) !important; }
[data-testid="stSelectbox"] input, [data-testid="stMultiSelect"] input, [data-testid="stTextInputField"] {
  color: var(--text-1) !important; -webkit-text-fill-color: var(--text-1) !important;
}
[data-testid="stSelectbox"] input::placeholder, [data-testid="stMultiSelect"] input::placeholder,
[data-testid="stTextInputField"]::placeholder { color: var(--text-3) !important; -webkit-text-fill-color: var(--text-3) !important; }
[data-testid="stSelectbox"] [role="group"] svg, [data-testid="stMultiSelect"] [role="group"] svg,
[data-testid="stTextInputIcon"], [data-testid="stTextInputIcon"] * { color: var(--text-3) !important; }
[data-testid="stSelectboxVirtualDropdown"], [data-testid="stMultiSelectDropdown"], [role="listbox"] {
  background: var(--surface) !important; border-color: var(--border-strong) !important; color: var(--text-1) !important;
}
[role="listbox"] [role="option"] { color: var(--text-1) !important; background: transparent; }
[role="listbox"] [role="option"] * { color: var(--text-1) !important; }
[role="listbox"] [role="option"]:hover, [role="listbox"] [role="option"][data-focused="true"],
[role="listbox"] [role="option"][aria-selected="true"] { background: var(--surface-2) !important; }
[data-testid="stMultiSelectTagsContainer"] [role="row"] {
  background: var(--accent-soft) !important; color: var(--text-1) !important; border-color: var(--border) !important;
}
[data-testid="stMultiSelectTagsContainer"] [role="row"] * { color: var(--text-1) !important; }
[data-testid="stTooltipIcon"] svg { color: var(--text-3) !important; }
[data-testid="stCheckbox"] p { color: var(--text-2) !important; }
[data-testid="stCheckbox"] label:has(input[role="switch"]) > div:not([data-testid]) { background: var(--surface-3) !important; }
[data-testid="stCheckbox"] label:has(input[role="switch"]:checked) > div:not([data-testid]) { background: var(--accent) !important; }
[data-testid="stCheckbox"] label:has(input[role="switch"]) > div:not([data-testid]) > div { background: #ffffff !important;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.35); }

/* ---------- buttons ---------- */
[data-testid="stBaseButton-secondary"], [data-testid="stPopoverButton"] {
  background: var(--surface) !important; color: var(--text-1) !important; border: 1px solid var(--border-strong) !important;
  border-radius: 8px !important; box-shadow: none !important;
}
[data-testid="stBaseButton-secondary"]:hover, [data-testid="stPopoverButton"]:hover {
  border-color: var(--accent) !important; color: var(--accent-strong) !important;
}
[data-testid="stBaseButton-secondary"] p, [data-testid="stPopoverButton"] p { color: inherit !important; }
[data-testid="stBaseButton-primary"] {
  background: var(--accent) !important; color: var(--on-accent) !important; border: 1px solid var(--accent) !important;
  border-radius: 8px !important;
}
[data-testid="stBaseButton-primary"]:hover { background: var(--accent-strong) !important; border-color: var(--accent-strong) !important; }
[data-testid="stBaseButton-primary"] p { color: var(--on-accent) !important; }
[data-testid="stBaseButton-tertiary"] { color: var(--text-2) !important; }
[data-testid="stBaseButton-tertiary"]:hover { color: var(--accent-strong) !important; }
[data-testid="stBaseButton-tertiary"] p { color: inherit !important; }
[data-testid="stDownloadButton"] button { width: 100%; }
[data-testid="stButtonGroup"] button { background: var(--surface) !important; color: var(--text-2) !important;
  border: 1px solid var(--border-strong) !important; }
[data-testid="stButtonGroup"] button[aria-pressed="true"] { background: var(--accent-soft) !important;
  color: var(--text-1) !important; border-color: var(--accent) !important; }
[data-testid="stButtonGroup"] button p { color: inherit !important; }

/* ---------- tabs ---------- */
[data-testid="stTabs"] [role="tablist"] { gap: 4px; border-bottom: 1px solid var(--border); }
[data-testid="stTabs"] [role="tab"] { padding: 8px 12px; }
[data-testid="stTabs"] [role="tab"] p { color: var(--text-3) !important; font-weight: 600; font-size: 0.9rem; }
[data-testid="stTabs"] [role="tab"][aria-selected="true"] p { color: var(--text-1) !important; }
[data-testid="stTabs"] [role="tab"]:hover p { color: var(--text-1) !important; }
[data-baseweb="tab-highlight"] { background: var(--accent) !important; }
[data-baseweb="tab-border"] { background: var(--border) !important; }

/* ---------- native containers ---------- */
[data-testid="stAlertContainer"] { background: var(--surface-2) !important; border: 1px solid var(--border) !important; color: var(--text-1) !important; }
[data-testid="stAlertContainer"] p { color: var(--text-1) !important; }
[data-testid="stExpander"] details { background: var(--surface); border: 1px solid var(--border) !important; border-radius: 10px; }
[data-testid="stExpander"] summary p { color: var(--text-1) !important; font-weight: 600; }
[data-testid="stFileUploaderDropzone"] { background: var(--surface-2) !important; border: 1px dashed var(--border-strong) !important; }
[data-testid="stFileUploaderDropzoneInstructions"] * { color: var(--text-3) !important; }
[data-testid="stFileChip"], [data-testid="stFileChipName"] { color: var(--text-1) !important; }
[data-testid="stCode"] pre, [data-testid="stCode"] code { background: var(--code-bg) !important; color: var(--code-text) !important;
  font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace !important; font-size: 0.78rem !important; }
[data-testid="stCode"] pre { border: 1px solid var(--border); border-radius: 8px; }
[data-testid="stPopoverBody"] { background: var(--surface) !important; border: 1px solid var(--border-strong) !important;
  box-shadow: var(--shadow) !important; color: var(--text-1); }
[data-testid="stDialog"] > div { background: var(--surface) !important; color: var(--text-1) !important;
  border: 1px solid var(--border-strong) !important; box-shadow: var(--shadow) !important; }
[data-testid="stDialog"] section[role="dialog"] h2, [data-testid="stDialog"] section[role="dialog"] h2 p { color: var(--text-1) !important; }
[data-testid="stDialog"] section[role="dialog"] > button, [data-testid="stDialog"] section[role="dialog"] > button svg {
  color: var(--text-3) !important; }
[data-testid="stToast"] { background: var(--surface) !important; border: 1px solid var(--border-strong) !important;
  box-shadow: var(--shadow) !important; }
[data-testid="stToast"] p, [data-testid="stToastText"] p { color: var(--text-1) !important; font-size: 0.84rem; }
[data-testid="stToastDynamicIcon"], [data-testid="stToast"] [data-testid="stIconMaterial"] { color: var(--accent-strong) !important; }
.stApp [data-testid="stMarkdownContainer"], [data-testid="stToast"], [data-testid="stPopoverBody"], [data-testid="stDialog"],
[data-testid="stWidgetLabel"], .stApp button, .stApp input, [role="listbox"] {
  font-family: Inter, system-ui, -apple-system, 'Segoe UI', sans-serif;
}
[data-testid="stMultiSelect"] input, [data-testid="stMultiSelectTagsContainer"] { background: transparent !important; }
[data-testid="stPopoverBody"] { max-height: 72vh; overflow-y: auto; }
[data-testid="stToast"] button, [data-testid="stToast"] button * { color: var(--text-3) !important; }
[data-testid="stExpander"] summary svg, [data-testid="stExpander"] summary [data-testid="stIconMaterial"] { color: var(--text-3) !important; }
[data-testid="stSidebarCollapseButton"] *, [data-testid="stExpandSidebarButton"] * { color: var(--text-3) !important; }
[data-testid="stProgress"] p { color: var(--text-2) !important; }
[data-testid="stSpinner"] * { color: var(--text-2) !important; }
[data-testid="stSidebar"] [data-testid="stHeading"] * { font-size: 0.72rem !important; text-transform: uppercase;
  letter-spacing: 0.08em; color: var(--text-3) !important; font-weight: 700 !important; }
.st-key-alarm-audio { position: absolute !important; width: 1px !important; height: 1px !important; overflow: hidden !important;
  opacity: 0 !important; pointer-events: none !important; }

/* ---------- header ---------- */
.st-key-app-header { background: var(--surface); border: 1px solid var(--border); border-radius: 14px;
  padding: 10px 14px 10px 16px; box-shadow: var(--shadow); }
.st-key-app-header [data-testid="stSelectbox"] { min-width: 132px; }
.brand { display: flex; align-items: flex-start; gap: 14px; min-width: 0; }
.brand-mark { width: 52px; height: 52px; border-radius: 14px; display: grid; place-items: center; margin-top: 4px;
  background: var(--accent-soft); color: var(--accent-strong); flex: none; }
.brand-mark .ico { width: 30px; height: 30px; }
.brand-eyebrow { font-size: 0.7rem; font-weight: 700; letter-spacing: 0.09em; text-transform: uppercase; color: var(--accent-strong); }
h1.brand-title { font-size: 1.7rem !important; font-weight: 750 !important; color: var(--text-1) !important; line-height: 1.2;
  letter-spacing: -0.02em; margin: 4px 0 4px !important; padding: 0 !important; }
h1.brand-title .hl { color: var(--accent-strong); }
.brand-sub { font-size: 0.84rem; color: var(--text-3); margin-top: 1px; }
@media (max-width: 640px) { h1.brand-title { font-size: 1.3rem !important; } .brand-mark { display: none; } }
.chips { display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-start; margin-top: 7px; }
.brand-text { min-width: 0; }
.chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; background: var(--surface-2);
  border: 1px solid var(--border); color: var(--text-2); font-size: 0.74rem; font-weight: 600; white-space: nowrap; }
.chip .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); }
.chip.live .dot { background: var(--good); animation: soc-pulse 1.6s ease-in-out infinite; }
.chip.source { max-width: 280px; overflow: hidden; text-overflow: ellipsis; }
.chip.ai { background: var(--accent-soft); color: var(--text-1); border-color: var(--accent); }
.detected-by { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 8px; }
.src-tag { display: inline-block; margin-left: 6px; padding: 0 5px; border-radius: 4px; font-size: 0.64rem; font-weight: 700;
  letter-spacing: 0.04em; color: var(--accent-strong); border: 1px solid var(--accent); vertical-align: middle; }
@keyframes soc-pulse { 0%, 100% { box-shadow: 0 0 0 0 var(--good-soft); } 50% { box-shadow: 0 0 0 5px var(--good-soft); } }

/* ---------- posture + guide ---------- */
.posture { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 18px; margin: 12px 0 4px; padding: 10px 16px;
  border-radius: 12px; border: 1px solid var(--border); border-left: 4px solid var(--posture); background: var(--posture-soft); }
.posture-level { font-weight: 700; color: var(--text-1); font-size: 0.9rem; letter-spacing: 0.02em; }
.posture-level .glyph { color: var(--posture); margin-right: 6px; }
.posture-stats { color: var(--text-2); font-size: 0.84rem; }
.posture-stats b { color: var(--text-1); }
.posture-time { margin-left: auto; color: var(--text-3); font-size: 0.78rem; }
.posture.alert-red { animation: soc-glow 2.4s ease-in-out infinite; }
@keyframes soc-glow { 0%, 100% { box-shadow: 0 0 0 0 transparent; } 50% { box-shadow: 0 0 0 4px var(--crit-soft); } }
.guide { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; }
.guide-step { display: flex; gap: 10px; align-items: flex-start; }
.guide-num { flex: none; width: 24px; height: 24px; border-radius: 50%; background: var(--accent); color: var(--on-accent);
  font-size: 0.78rem; font-weight: 700; display: grid; place-items: center; }
.guide-step b { color: var(--text-1); font-size: 0.86rem; }
.guide-step div div { color: var(--text-3); font-size: 0.78rem; margin-top: 2px; line-height: 1.4; }
.st-key-demo-guide { background: var(--accent-soft); border: 1px solid var(--border); border-radius: 12px; padding: 12px 14px; }

/* ---------- KPI tiles ---------- */
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 6px 0 14px; }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px;
  box-shadow: var(--shadow); position: relative; overflow: hidden; }
.kpi::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--kpi-accent, var(--accent)); }
.kpi-head { display: flex; align-items: center; gap: 8px; color: var(--text-3); font-size: 0.78rem; font-weight: 600; }
.kpi-head .ico { color: var(--kpi-accent, var(--accent)); }
.kpi-value { font-size: 1.85rem; font-weight: 650; color: var(--text-1); line-height: 1.15; margin-top: 6px; }
.kpi-sub { font-size: 0.74rem; color: var(--text-3); margin-top: 2px; }

/* ---------- cards, sections, tables ---------- */
.section-title { font-size: 0.98rem; font-weight: 650; color: var(--text-1); margin: 4px 0 2px; }
.section-sub { font-size: 0.8rem; color: var(--text-3); margin-bottom: 8px; }
.soc-table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); }
table.soc-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
table.soc-table th { background: var(--surface-2); color: var(--text-3); font-size: 0.7rem; text-transform: uppercase;
  letter-spacing: 0.06em; font-weight: 700; text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; }
table.soc-table td { color: var(--text-1); padding: 9px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
table.soc-table tr:last-child td { border-bottom: none; }
table.soc-table td.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; font-size: 0.8rem; }
.muted { color: var(--text-3) !important; }
.sev { display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px; border-radius: 6px; font-size: 0.72rem;
  font-weight: 700; color: var(--text-1); background: var(--sev-soft); letter-spacing: 0.02em; white-space: nowrap; }
.sev .glyph { color: var(--sev-color); font-size: 0.78rem; }
.tag { display: inline-block; padding: 2px 7px; border-radius: 6px; font-size: 0.72rem; font-weight: 600; color: var(--text-1);
  background: var(--surface-2); border: 1px solid var(--border); margin: 0 4px 4px 0; white-space: nowrap; }
.tag.mitre { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; background: var(--accent-soft); white-space: normal; }
.conf { display: flex; align-items: center; gap: 8px; min-width: 96px; }
.conf-track { flex: 1; height: 6px; border-radius: 4px; background: var(--surface-3); overflow: hidden; }
.conf-fill { height: 100%; border-radius: 4px; background: var(--accent); }
.conf-val { font-size: 0.78rem; color: var(--text-2); font-variant-numeric: tabular-nums; min-width: 38px; text-align: right; }

/* ---------- alert feed ---------- */
.feed-head, .feed-row { display: grid; grid-template-columns: 150px 104px minmax(150px, 1.1fr) minmax(220px, 1.6fr) 130px;
  gap: 12px; align-items: center; }
.feed-head { padding: 0 12px 6px; color: var(--text-3); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700; }
.feed-row { padding: 10px 12px; background: var(--surface); border: 1px solid var(--border); border-radius: 10px; min-height: 52px; }
.feed-row .time { color: var(--text-2); font-size: 0.78rem; font-variant-numeric: tabular-nums; }
.feed-row .threat { color: var(--text-1); font-weight: 600; font-size: 0.86rem; }
.feed-row .threat small { display: block; color: var(--text-3); font-weight: 500; font-size: 0.72rem; }
.feed-row .flow { color: var(--text-2); font-size: 0.8rem; overflow: hidden; text-overflow: ellipsis; }
.feed-row .flow .mono { color: var(--text-1); }
[class*="st-key-feed-"] [data-testid="stButton"] { flex: none; }
[data-testid="stPopoverBody"] { min-width: min(420px, 92vw); max-width: 480px; }
@media (max-width: 900px) {
  .feed-head { display: none; }
  .feed-row { grid-template-columns: 1fr 1fr; }
  .feed-row .flow { grid-column: 1 / -1; }
}

/* ---------- notifications ---------- */
.notif { display: flex; gap: 10px; padding: 8px 2px; border-bottom: 1px solid var(--border); }
.notif:last-child { border-bottom: none; }
.notif .glyph { color: var(--sev-color); font-size: 0.9rem; line-height: 1.3; }
.notif-title { font-size: 0.8rem; font-weight: 700; color: var(--text-1); }
.notif-msg { font-size: 0.78rem; color: var(--text-2); margin-top: 1px; word-break: break-word; }
.notif-time { font-size: 0.7rem; color: var(--text-3); margin-top: 2px; }
.notif.unread .notif-title::after { content: "NEW"; margin-left: 6px; font-size: 0.62rem; color: var(--on-accent);
  background: var(--accent); padding: 1px 5px; border-radius: 4px; vertical-align: middle; }

/* ---------- evidence (dialog) ---------- */
.ev-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }
.ev { background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; min-width: 0; }
.ev-k { font-size: 0.7rem; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 700; }
.ev-v { font-size: 0.92rem; color: var(--text-1); font-weight: 600; margin-top: 3px; word-break: break-word; }
.ev-v.mono { font-size: 0.8rem; font-weight: 500; }
.kv { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
.kv td { padding: 6px 4px; border-bottom: 1px solid var(--border); color: var(--text-1); vertical-align: top; }
.kv td:first-child { color: var(--text-3); width: 38%; }
.action-box { background: var(--accent-soft); border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px;
  color: var(--text-1); font-size: 0.86rem; }

/* ---------- kill chain + ATT&CK matrix ---------- */
.killchain { display: flex; flex-wrap: wrap; align-items: stretch; gap: 6px; }
.kc { flex: 1 1 120px; border: 1px solid var(--border); border-radius: 10px; padding: 10px; background: var(--surface);
  text-align: center; color: var(--text-3); font-size: 0.8rem; font-weight: 600; }
.kc b { display: block; color: var(--text-2); font-size: 0.82rem; }
.kc.on { border-color: var(--crit); background: var(--crit-soft); color: var(--text-2); }
.kc.on b { color: var(--text-1); }
.kc .hit { display: block; margin-top: 4px; font-size: 0.72rem; color: var(--text-2); font-weight: 500; }
.matrix { display: grid; grid-template-columns: repeat(4, minmax(200px, 1fr)); gap: 10px; overflow-x: auto; }
.tactic-h { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.07em; color: var(--text-3); font-weight: 700;
  padding: 6px 2px; border-bottom: 2px solid var(--border-strong); margin-bottom: 8px; }
.tech { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; background: var(--surface); margin-bottom: 8px; }
.tech.on { border-color: var(--accent); background: var(--accent-soft); }
.tech-id { font-family: 'JetBrains Mono', ui-monospace, Consolas, monospace; font-size: 0.72rem; color: var(--text-3); }
.tech-name { font-size: 0.86rem; font-weight: 650; color: var(--text-1); margin: 2px 0 6px; }
.tech-stat { font-size: 0.76rem; color: var(--text-2); }
.tech.off .tech-name { color: var(--text-3); }

/* ---------- lab cards + footer ---------- */
[class*="st-key-lab-"] { background: var(--surface); border: 1px solid var(--border) !important; border-radius: 12px;
  padding: 14px 16px; box-shadow: var(--shadow); }
.lab-desc { color: var(--text-2); font-size: 0.86rem; line-height: 1.5; margin: 6px 0 8px; }
.lab-meta { color: var(--text-3); font-size: 0.78rem; margin-top: 3px; }
.lab-meta b { color: var(--text-2); }
.soc-footer { margin-top: 28px; padding-top: 12px; border-top: 1px solid var(--border); color: var(--text-3);
  font-size: 0.74rem; display: flex; flex-wrap: wrap; gap: 6px 16px; justify-content: space-between; }
.empty { border: 1px dashed var(--border-strong); border-radius: 12px; padding: 22px; text-align: center; color: var(--text-3);
  font-size: 0.88rem; background: var(--surface); }
@media (prefers-reduced-motion: reduce) { .chip.live .dot, .posture.alert-red { animation: none !important; } }
@media (max-width: 640px) {
  [data-testid="stMainBlockContainer"] { padding-left: 1rem; padding-right: 1rem; }
  .chips { justify-content: flex-start; }
  .kpi-value { font-size: 1.5rem; }
}
"""


def css(mode: str) -> str:
    return f"<style>{_root_block(tokens(mode))}{_STATIC_CSS}{icon_css()}</style>"


def plotly_layout(mode: str, **overrides: Any) -> Dict[str, Any]:
    t = tokens(mode)
    axis = dict(gridcolor=t["grid"], linecolor=t["baseline"], zeroline=False, showline=False, automargin=True,
                tickfont=dict(color=t["text-3"], size=11), title=dict(font=dict(color=t["text-3"], size=11)))
    base: Dict[str, Any] = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT_UI, color=t["text-2"], size=12),
        margin=dict(l=8, r=16, t=8, b=8),
        xaxis=dict(axis),
        yaxis=dict(axis),
        hoverlabel=dict(bgcolor=t["surface"], bordercolor=t["border-strong"],
                        font=dict(family=FONT_UI, color=t["text-1"], size=12)),
        legend=dict(font=dict(color=t["text-2"], size=11), bgcolor="rgba(0,0,0,0)",
                    orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        showlegend=False,
    )
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merged = dict(base[key])
            merged.update(value)
            base[key] = merged
        else:
            base[key] = value
    return base


def heat_colorscale(mode: str):
    t = tokens(mode)
    return [[0.0, t["surface-2"]], [0.0001, t["heat-low"]], [1.0, t["heat-high"]]]


PLOTLY_CONFIG = {"displayModeBar": False, "responsive": True}
