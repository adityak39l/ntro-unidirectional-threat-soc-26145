"""Small HTML building blocks for the dashboard. Every dynamic value is escaped."""
from datetime import datetime, timedelta, timezone
from html import escape
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import quote

from dashboard.catalog import severity

IST = timezone(timedelta(hours=5, minutes=30), "IST")

# Material Design icon paths (24x24 viewBox)
ICON_PATHS = {
    "shield": "M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z",
    "bell": "M12 22c1.1 0 2-.9 2-2h-4c0 1.1.89 2 2 2zm6-6v-5c0-3.07-1.64-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5"
            "s-1.5.67-1.5 1.5v.68C7.63 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z",
    "report": "M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3c-.72 0-1.3-.58-1.3-1.3"
              " 0-.72.58-1.3 1.3-1.3.72 0 1.3.58 1.3 1.3 0 .72-.58 1.3-1.3 1.3zm1-4.3h-2V7h2v6z",
    "warning": "M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z",
    "hub": "M17 16l-4-4V8.82C14.16 8.4 15 7.3 15 6c0-1.66-1.34-3-3-3S9 4.34 9 6c0 1.3.84 2.4 2 2.82V12l-4 4H3v5h5"
           "v-3.05l4-4.2 4 4.2V21h5v-5h-4z",
    "category": "M12 2l-5.5 9h11L12 2zm5.5 11c-2.49 0-4.5 2.01-4.5 4.5s2.01 4.5 4.5 4.5 4.5-2.01 4.5-4.5-2.01-4.5"
                "-4.5-4.5zM3 21.5h8v-8H3v8z",
    "target": "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8"
              " 8 3.59 8 8-3.59 8-8 8zm0-13c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zm0 7.5c-1.38 0-2.5-1.12"
              "-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5z",
}


def icon(name: str) -> str:
    """Icon drawn by a CSS mask (st.html strips inline <svg>, but keeps classed spans)."""
    return f'<span class="ico ico-{name}" aria-hidden="true"></span>'


def icon_css() -> str:
    rules = [".ico { display: inline-block; flex: none; width: 16px; height: 16px; background-color: currentColor;"
             " -webkit-mask: var(--ico) center / contain no-repeat; mask: var(--ico) center / contain no-repeat; }"]
    for name, path in ICON_PATHS.items():
        svg = f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><path d='{path}'/></svg>"
        rules.append(f'.ico-{name} {{ --ico: url("data:image/svg+xml;utf8,{quote(svg)}"); }}')
    return " ".join(rules)


# ---------- time ----------

def to_ist(value: Any) -> Optional[datetime]:
    """ISO timestamp / epoch / datetime -> aware datetime in IST (UTC+05:30, no DST)."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, datetime):
            dt = value
        elif isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(float(value), timezone.utc)
        else:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)


def fmt_ist(value: Any, with_date: bool = True) -> str:
    dt = to_ist(value)
    if dt is None:
        return "—"
    return dt.strftime("%d %b %Y, %H:%M:%S IST" if with_date else "%H:%M:%S IST")


# ---------- badges & small pieces ----------

def sev_badge(level: str) -> str:
    meta = severity(level)
    soft = {"CRITICAL": "crit-soft", "HIGH": "high-soft", "MEDIUM": "med-soft"}.get(str(level).upper(), "low-soft")
    return (f'<span class="sev" style="--sev-color:{meta.color};--sev-soft:var(--{soft})">'
            f'<span class="glyph">{meta.glyph}</span>{escape(meta.label.upper())}</span>')


def tag(text: str, cls: str = "") -> str:
    return f'<span class="tag {cls}">{escape(str(text))}</span>'


def confidence_bar(value: float) -> str:
    pct = max(0.0, min(1.0, float(value or 0))) * 100
    return (f'<div class="conf"><div class="conf-track"><div class="conf-fill" style="width:{pct:.0f}%"></div></div>'
            f'<span class="conf-val">{pct:.0f}%</span></div>')


def kpi_tiles(tiles: Sequence[Dict[str, Any]]) -> str:
    """tiles: {label, value, sub, icon, accent(css color)}"""
    cells = []
    for t in tiles:
        cells.append(
            f'<div class="kpi" style="--kpi-accent:{t.get("accent", "var(--accent)")}">'
            f'<div class="kpi-head">{icon(t["icon"])}{escape(t["label"])}</div>'
            f'<div class="kpi-value">{escape(str(t["value"]))}</div>'
            f'<div class="kpi-sub">{escape(t.get("sub", ""))}</div></div>'
        )
    return f'<div class="kpi-grid">{"".join(cells)}</div>'


def section(title: str, subtitle: str = "") -> str:
    sub = f'<div class="section-sub">{escape(subtitle)}</div>' if subtitle else ""
    return f'<div class="section-title">{escape(title)}</div>{sub}'


def table(columns: Sequence[str], rows: Iterable[Sequence[Any]], raw_html_cols: Iterable[int] = (),
          num_cols: Iterable[int] = (), mono_cols: Iterable[int] = ()) -> str:
    """Themed HTML table. Cells are escaped unless their column index is in raw_html_cols."""
    raw, num, mono = set(raw_html_cols), set(num_cols), set(mono_cols)
    head = "".join(f"<th>{escape(str(c))}</th>" for c in columns)
    body = []
    for row in rows:
        tds = []
        for i, cell in enumerate(row):
            content = str(cell) if i in raw else escape(str(cell))
            classes = " ".join(c for c, on in (("num", i in num), ("mono", i in mono)) if on)
            tds.append(f'<td class="{classes}">{content}</td>' if classes else f"<td>{content}</td>")
        body.append(f"<tr>{''.join(tds)}</tr>")
    return (f'<div class="soc-table-wrap"><table class="soc-table"><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def empty_state(message: str) -> str:
    return f'<div class="empty">{escape(message)}</div>'


def evidence_grid(items: List[Dict[str, Any]]) -> str:
    """items: {key, value, mono}"""
    cells = []
    for item in items:
        mono = " mono" if item.get("mono") else ""
        cells.append(f'<div class="ev"><div class="ev-k">{escape(str(item["key"]))}</div>'
                     f'<div class="ev-v{mono}">{escape(str(item["value"]))}</div></div>')
    return f'<div class="ev-grid">{"".join(cells)}</div>'


def kv_table(pairs: Sequence[Sequence[Any]], mono_values: bool = False) -> str:
    rows = "".join(
        f'<tr><td>{escape(str(k))}</td><td class="{"mono" if mono_values else ""}">{escape(str(v))}</td></tr>'
        for k, v in pairs
    )
    return f'<table class="kv">{rows}</table>'
