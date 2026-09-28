import io
import os
import time
import wave
from pathlib import Path

import pytest

from dashboard import catalog, components, notifications, theme, workspace
from detection.pipeline import StreamingDetectionPipeline
from ingestion.pcap_reader import ReadOnlyPacketReader
from models.model_registry import ThreatModelRegistry

APP_PATH = str(Path(__file__).resolve().parent.parent / "dashboard" / "app.py")


@pytest.fixture(scope="module")
def simulated_alerts(tmp_path_factory):
    from traffic_simulator.generate_traffic import generate_synthetic_pcap
    tmp = tmp_path_factory.mktemp("sim")
    pcap = str(tmp / "all.pcap")
    generate_synthetic_pcap(attack_type="all", output_path=pcap)
    pipe = StreamingDetectionPipeline(alert_jsonl=str(tmp / "a.jsonl"), alert_db=str(tmp / "a.db"), idle_timeout=2.0)
    alerts = []
    for pkt in ReadOnlyPacketReader(pcap).read_packets():
        alerts.extend(pipe.process_packet(pkt))
    alerts.extend(pipe.flush_and_complete())
    for i, alert in enumerate(alerts, 1):
        alert["id"] = i
    return alerts


def test_catalog_covers_every_detector():
    registry = ThreatModelRegistry()
    names = {d.NAME for d in (registry.ddos, registry.beaconing, registry.dga, registry.encrypted_malware,
                              registry.port_scan, registry.exfiltration)}
    assert set(catalog.THREATS) == names
    assert [catalog.SEVERITIES[s].rank for s in catalog.SEVERITY_ORDER] == [0, 1, 2, 3]
    assert len({m.plotly_symbol for m in catalog.SEVERITIES.values()}) == 4  # shape differs per severity


def test_catalog_icons_are_valid_material_icons():
    from streamlit.string_util import validate_material_icon
    for meta in catalog.THREATS.values():
        validate_material_icon(meta.icon)


def test_every_threat_gets_a_specific_message(simulated_alerts):
    expected = {
        "Volumetric_Protocol_DDoS": "pkt/s",
        "Botnet_C2_Beaconing": "beacons",
        "DGA_Domains_and_DNS_Tunneling": "domain",
        "Encrypted_Malware_TLS": "TLS",
        "Reconnaissance_Port_Scanning": "ports",
        "Data_Exfiltration": "KB",
    }
    seen = set()
    for alert in simulated_alerts:
        msg = notifications.describe(alert)
        assert expected[alert["threat_class"]] in msg, msg
        seen.add(alert["threat_class"])
    assert seen == set(expected)


def test_toasts_group_by_threat_and_put_critical_first(simulated_alerts):
    toasts = notifications.build_toasts(simulated_alerts)
    assert len(toasts) == len({a["threat_class"] for a in simulated_alerts})
    assert toasts[0].critical
    assert [t.critical for t in toasts] == sorted((t.critical for t in toasts), reverse=True)
    assert len(notifications.build_toasts(simulated_alerts * 20, max_toasts=6)) <= 6


def test_toast_escapes_markdown_from_captured_domains():
    alert = {"id": 1, "threat_class": "DGA_Domains_and_DNS_Tunneling", "severity": "HIGH", "src_ip": "10.0.0.5",
             "dst_ip": "8.8.8.8", "evidence": {"queried_domain": "[click](http://evil.example)"}}
    body = notifications.build_toasts([alert])[0].body
    assert "](" not in body
    assert "\\[click\\]" in body


def test_alarm_is_a_short_valid_wav():
    with wave.open(io.BytesIO(notifications.alarm_wav())) as w:
        assert w.getnchannels() == 1
        assert w.getframerate() == 22050
        assert 0.5 < w.getnframes() / w.getframerate() < 0.8


def test_ist_formatting():
    assert components.fmt_ist("2026-01-01T00:00:00+00:00") == "01 Jan 2026, 05:30:00 IST"
    assert components.fmt_ist(0, with_date=False) == "05:30:00 IST"
    assert components.fmt_ist("not a time") == "—"


def test_html_helpers_escape_values():
    html = components.table(["IP"], [["<img src=x onerror=alert(1)>"]])
    assert "<img" not in html and "&lt;img" in html
    assert "■" in components.sev_badge("CRITICAL")
    css = components.icon_css()
    assert "data:image/svg+xml" in css and "<svg" not in css


def test_theme_css_defines_both_modes():
    dark, light = theme.css("dark"), theme.css("light")
    assert "--page: #0b111c" in dark and "--page: #f4f6fa" in light
    layout = theme.plotly_layout("light", height=200, xaxis=dict(title=dict(text="x")))
    assert layout["height"] == 200 and layout["xaxis"]["automargin"] is True


def test_workspaces_are_isolated_and_stale_ones_pruned(tmp_path):
    a = workspace.open_workspace(str(tmp_path))
    b = workspace.open_workspace(str(tmp_path))
    assert a.db != b.db and os.path.isdir(a.pcap_dir)
    assert workspace.open_workspace(str(tmp_path), "../../etc").id != "../../etc"
    old = time.time() - 48 * 3600
    os.utime(a.root, (old, old))
    assert workspace.cleanup_stale(str(tmp_path), max_age_hours=12, keep=b.id) == 1
    assert not os.path.exists(a.root) and os.path.exists(b.root)


def test_dashboard_renders_in_both_themes_and_notifies(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("SOC_WORKSPACE_DIR", str(tmp_path))
    at = AppTest.from_file(APP_PATH, default_timeout=180)
    at.run()
    assert not at.exception
    assert len(at.tabs) == 6
    at.selectbox(key="theme").set_value("light").run()
    assert not at.exception
    at.button(key="sb_ddos").click().run()
    assert not at.exception
    assert any("DDoS" in t.value for t in at.toast)
    assert at.get("audio"), "CRITICAL alert should render the alarm"
