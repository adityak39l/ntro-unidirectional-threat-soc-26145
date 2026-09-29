# 🛡️ AI-Based Threat Intelligence SOC for Unidirectional IP Traffic
### Smart India Hackathon 2026 | Problem Statement ID: 26145
**Organization:** National Technical Research Organisation (NTRO)  
**Domain:** Defense, Critical Information Infrastructure (CII), Cybersecurity  
**Theme:** Blockchain & Cybersecurity  

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Production--Ready-success.svg)]()
[![Tests](https://img.shields.io/badge/Tests-60%2F60%20Passed-brightgreen.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/Taxonomy-MITRE%20ATT%26CK%C2%AE-orange.svg)](https://attack.mitre.org/)
[![Architecture](https://img.shields.io/badge/Compliance-Hardware%20Data%20Diode%20(Zero--Tx)-red.svg)]()

**🔴 Live dashboard:** https://adityak39l-ntro-unidirectional-threat-soc-2-dashboardapp-p1v8yi.streamlit.app/

---

## 📌 Executive Summary

Critical national enclaves — including **Nuclear Power Plants (BARC/NPCIL), Military Command Centers, Naval Warships, and Power Grids** — isolate their networks using **Hardware Data Diodes**. In these enclaves, the physical transmission line (Tx) is severed or disabled, enforcing strictly **unidirectional traffic** (data flows in, zero packets return).

Standard security tools (**Wireshark, Snort, Suricata, Zeek, Palo Alto firewalls**) fail in these environments because they require bidirectional TCP handshakes, return packets, or active probing. Furthermore, high-security enclaves legally prohibit sharing TLS private keys, ruling out traditional payload decryption.

This system provides a **100% passive, read-only AI streaming threat detection appliance** capable of detecting and classifying threats in real time without returning any packets and without decrypting payloads.

---

## 🎯 6 Mandated Threat Vectors (NTRO Scope)

| # | Threat Vector | MITRE ATT&CK ID | Detection Algorithm & Proof | Severity |
|---|---|---|---|---|
| 1 | **Volumetric & Protocol DDoS** | **T1498** (Network DoS) | Per-target fan-in in each 3 s sliding window: peak PPS (≥300), share of half-open SYNs, source-IP entropy | **CRITICAL** |
| 2 | **Botnet C2 Beaconing** | **T1071** (App Layer Protocol) | Inter-Arrival Time (IAT) variance ($\sigma^2 < 0.01$) on payload-carrying TCP/UDP flows (ICMP, keep-alives and LAN discovery excluded) | **HIGH** |
| 3 | **DGA Domains & DNS Tunneling** | **T1568** (Dynamic Resolution) | Shannon entropy of the registered label + length, consonant ratio, digit mixing; high-entropy long subdomains for tunneling | **HIGH** |
| 4 | **Encrypted Malware (TLS Metadata)** | **T1573** (Encrypted Channel) | JA3 blocklist match, then ClientHello anomaly scoring (legacy version, no SNI, odd port, cipher/extension count) | **CRITICAL** |
| 5 | **Reconnaissance Port Scanning** | **T1046** (Network Discovery) | Per-source fan-out in each 3 s window: distinct ports per host (≥10) or hosts per port (≥20) | **HIGH** |
| 6 | **Data Exfiltration** | **T1048** (Exfiltration Over Protocol) | Client-side egress to an external host: bulk MTU-sized bursts (≥ 500 KB) or sustained paced uploads (AI layer); downloads and LAN copies excluded | **CRITICAL** |

---

## 🏗️ System Architecture

```
[ Unidirectional Raw Traffic (PCAP / Passive Optical TAP) ]
                   │
                   ▼ (100% Read-Only, 0 Return Packets)
┌─────────────────────────────────────────────────────────────┐
│ 1. PASSIVE STREAMING INGESTION LAYER                        │
│    - dpkt/Scapy stateless packet sniffer                    │
│    - Synthetic Half-Connection Flow Aggregator (5-tuple)    │
│    - Temporal Sliding Window Manager (3s window, 1s slide)  │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. ZERO-DECRYPTION MATHEMATICAL FEATURE ENGINE              │
│    - Shannon Entropy & Consonant Ratio (DNS DGA)            │
│    - JA3 Cryptographic Fingerprint & SPLT Vectors (TLS)     │
│    - Inter-Arrival Time (IAT) Variance (C2 Beaconing)       │
│    - Asymmetric Packet & Byte Ratios (Exfiltration/DDoS)    │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. HYBRID DETECTION CORE (rules + AI)                       │
│    - 4 per-flow detectors (C2, DGA/DNS, TLS, exfiltration)  │
│    - 2 sliding-window detectors (DDoS fan-in, scan fan-out) │
│    - Random Forest layer: flow model + host-window model,   │
│      thresholds calibrated on real CTU traffic, explained   │
│    - Unified Model Registry evaluating all 6 vectors        │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. SOC AUDIT & ALERTING ENGINE                              │
│    - Standardized JSON Alert Schema + SQLite DB + JSONL log │
│    - MITRE ATT&CK Mapping & Lockheed Martin Kill Chain      │
│    - iptables / Suricata response rules + incident report   │
│    - Enterprise SOC Dashboard (Light & Dark Mode)           │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔬 Mathematical & Cryptographic Formulations

### 1. Shannon Entropy Formula (Domain Generation Algorithms)
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
- Normal human domains (`google.com`, `github.com`): $H < 3.2$
- DGA pseudorandom malware domains (`vxzq981pkm.biz`): $H > 4.0$

### 2. JA3 Cryptographic Fingerprinting (Encrypted Malware)
Extracts Client Hello parameters (GREASE values removed, per the JA3 spec):
$$\text{JA3} = \text{MD5}(\text{TLSVersion, Ciphers, Extensions, EllipticCurves, PointFormats})$$
Matches against known threat actor profiles (Cobalt Strike, Emotet, TrickBot, Metasploit) without decrypting payloads. Implants with an unknown JA3 are still scored on ClientHello metadata: legacy TLS version, missing SNI, non-standard port, tiny cipher list, few extensions.

### 3. IAT Statistical Variance (C2 Beaconing)
$$\sigma^2 = \frac{1}{N}\sum_{i=1}^{N}(t_i - \bar{t})^2$$
Automated malware beacons trigger deterministic pulses with variance tending toward 0 ($\sigma^2 < 0.01$).

---

## 🤖 AI Layer: Rules + Random Forest (Hybrid)

The rule detectors stay the first line: precise and auditable. Next to them runs a trained **Random Forest** layer (scikit-learn):

* **Flow model** (120 trees, 35 features): benign / C2 beaconing / DGA-DNS / encrypted malware / exfiltration.
* **Host-window model** (50 trees, 11 features): benign / DDoS target / port scanner, scored per host in every 3 s window.
* It reads the same numbers the rules compute (timing, sizes, DNS label statistics, ClientHello metadata, fan-in / fan-out, traffic direction). **No payload is decrypted.**
* Every alert records who raised it: `Rules`, `AI model` or `Rules + AI model`. It also carries the model probability and the **features that pushed it up** (per-prediction path contributions through the forest). An alert raised by the model alone is capped below *Critical*.
* The sidebar toggle switches the layer off for a rules-only comparison. The dashboard's **AI model** tab shows the model card below.

**Training data:** labelled traffic generated in `ml/synthetic.py` and run through the production flow and sliding-window code. Attack parameters span wider ranges than the rule thresholds (jittered beacons, low-and-slow exfiltration, UDP floods, slow and horizontal scans, hex / base32 / base64 tunnels). Benign traffic includes hard negatives: legacy-TLS browsers, app heartbeats, TCP keep-alives, `ping`/`mtr`, BitTorrent downloads, LAN copies, uploads, cloud / CDN hostnames and long brand names.

**Held-out synthetic test** (independent draw, never used in training):

| Vector | Rules recall | AI recall | **Hybrid recall** | Hybrid precision |
|---|---|---|---|---|
| C2 beaconing (T1071) | 62.8% | 98.1% | **99.2%** | 99.6% |
| DGA / DNS tunneling (T1568) | 79.7% | 96.6% | **96.6%** | 98.2% |
| Encrypted malware (T1573) | 67.1% | 100% | **100%** | 100% |
| Data exfiltration (T1048) | 53.0% | 100% | **100%** | 100% |
| Port scanning (T1046) | 88.9% | 97.2% | **100%** | 88.7% |
| DDoS (T1498) | 51.3% | 62.8% | **72.4%** | 84.3% |

**Real traffic** (public captures from the Stratosphere Lab, CTU Prague). The model's alert thresholds were calibrated on CTU-Normal-12 and CTU-Normal-26. The two normal captures below are other hosts and days that were never used for calibration, so every alert on them is a false alarm:

| Capture | Flows | Alerts, rules only | Alerts, hybrid |
|---|---|---|---|
| CTU-Normal-28 (2017) | 25,559 | 0 | 3 (AI, DGA) |
| CTU-Normal-24 (2017, Windows host, first 200 MB) | 15,608 | 0 | 2 (AI, DGA) |
| Neris botnet, CTU-13 scenario 1 | 33,053 | 336 | **347**: the model adds 11 port-scan alerts the rules missed |

Validating on real traffic also exposed rule false alarms, which are now fixed. Examples: `ping`/`mtr` replies read as C2 beacons, BitTorrent downloads and LAN copies read as exfiltration, and cloud load-balancer hostnames read as DNS tunnels. **Before these fixes the rules raised 116 false alarms on the two held-out captures; now they raise none.**

Reproduce with `python train_models.py` (synthetic only). Add real captures with `--calibrate …`, `--benign-test …` and `--real-botnet … --botnet-ip …`. The model and its card are committed in `models/artifacts/`.

**Limitations.** The model is trained on synthetic traffic, so the synthetic scores show that it generalises across attack variants; they are not a field-accuracy claim. Beacons slower than the 15 s flow idle timeout are not scored. Large legitimate uploads resemble exfiltration without destination reputation data.

---

## 🖥️ Enterprise SOC Dashboard

The dashboard provides a real-time Security Operations Center interface:
* **Header:** status chips (passive / live monitoring, zero return path, current data source), a **🔔 notification centre** with unread count, an alarm **sound toggle** and a **Dark / Light mode dropdown** (the choice is kept in the URL, e.g. `?theme=Light+mode`, so a shared link opens in the same theme).
* **🚨 Attack notifications:** every new detection raises a toast for its NTRO threat type (DDoS, C2 beaconing, DGA / DNS tunneling, encrypted malware, port scan, exfiltration) with the evidence in one line, e.g. *“SYN flood on 10.0.0.1: 500 pkt/s from 186 sources”*. Toasts are grouped per threat type so a large capture cannot flood the screen. **CRITICAL** attacks also play a short alarm (generated in code; mute button in the header). System problems — an unreadable or truncated capture, a failed simulation — are notified the same way.
* **📡 Live monitoring:** a sidebar toggle streams a new batch of benign or attack traffic through the pipeline every ~12 s, so alerts and notifications arrive as they would on a real sensor.
* **🔎 Global filters:** time window, severity, threat vector and IP search in one row; every KPI, chart and table follows the same slice.
* **Overview:** threat-posture banner, KPI tiles, alerts per vector (all six shown, including zero), severity mix, alert timeline in **IST**, latest high-priority incidents and a vector × severity table (the table twin of the charts).
* **📂 Analyse PCAP:** upload any Wireshark / tcpdump capture (.pcap / .pcapng; Ethernet, Linux-cooked, raw-IP or loopback) with a live progress bar; every tab then reflects that capture.
* **Network:** directional topology (sources → targets, one-way arrows as through the data diode) and a source × vector heatmap.
* **Investigation:** paginated alert feed; **Investigate** opens a dialog with the flow, *why it was flagged*, the evidence, MITRE mapping, a recommended action, iptables + Snort 3/Suricata rules (for the downstream enforcement point) and a per-alert report. Bulk export: CSV, `.sh`, `.rules`, incident report (HTML → PDF).
* **Simulation lab & Reports:** one card per NTRO vector with its detection method; kill-chain coverage, a MITRE ATT&CK® matrix grouped by tactic with average confidence, and the data-diode compliance table.
* **Private workspaces:** each browser session of the hosted demo has its own alert store, so judges using the live link at the same time never see or reset each other's data (idle workspaces are removed after 12 h).
* **Accessibility:** severity is always encoded by shape as well as colour (■ critical, ▲ high, ◆ medium, ● low), charts use a single-hue scale for counts, and the layout adapts to phone width.

---

## ⚡ Quickstart & Installation

### 1. Prerequisites
- Python 3.12+
- Git

### 2. Clone and Setup Environment
```bash
# Clone the repository
git clone https://github.com/adityak39l/ntro-unidirectional-threat-soc-26145.git
cd ntro-unidirectional-threat-soc-26145

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Run Automated Tests
Verify all 60 unit and integration tests across features, ingestion, models, the ML layer, pipeline, response rules, reporting and the dashboard (includes an end-to-end check that each simulated attack is detected as its own class and benign traffic raises no alert):
```bash
pytest tests/ -v
```

### 4. Execute Streaming Pipeline Benchmark
Generate the synthetic benign + 6-attack capture, then run the end-to-end ingestion and detection engine on it (or pass your own capture path):
```bash
python traffic_simulator/generate_traffic.py
python run_pipeline.py
python run_pipeline.py path/to/your_capture.pcap
```

### 5. Launch the SOC Dashboard
Start the Streamlit interface:
```bash
streamlit run dashboard/app.py
```
Open **`http://localhost:8501`** in your browser.

---

## 📁 Repository Structure

```text
├── alerts/               # Alert schema, SQLite DB & JSONL logging
│   └── alert_manager.py  # StandardAlert schema & deduplication logic
├── dashboard/            # Real-time Streamlit SOC interface
│   ├── app.py            # 6-tab SOC dashboard (Streamlit + Plotly)
│   ├── catalog.py        # Threat-vector & severity metadata (MITRE, icons)
│   ├── notifications.py  # Alert messages, toast grouping, alarm tone
│   ├── theme.py          # Dark / light design tokens, CSS, chart layout
│   ├── components.py     # Escaped HTML building blocks, IST time
│   └── workspace.py      # Per-session private alert stores
├── data/                 # Captured PCAPs and alert databases (git-ignored)
├── detection/            # Pipeline orchestration
│   └── pipeline.py       # StreamingDetectionPipeline: flows + 3 s sliding windows
├── docs/                 # Architectural documentation
│   └── architecture.md   # Deep-dive system architecture specification
├── feature_engine/       # Zero-decryption feature extraction
│   ├── dns_analyzer.py   # Shannon entropy & DGA domain scoring
│   ├── feature_extractor.py # Statistical flow metrics & SPLT extractor
│   ├── tls_fingerprint.py# ClientHello parser, JA3 hash & SPLT vectorization
│   └── window_features.py# Per-window host fan-in / fan-out aggregates
├── ingestion/            # Passive read-only data ingestion
│   ├── flow_aggregator.py# 5-tuple unidirectional flow tracker
│   ├── pcap_reader.py    # dpkt read-only packet reader
│   ├── stream_listener.py# Live traffic streaming simulator
│   └── window_manager.py # Temporal sliding window engine
├── models/               # Hybrid AI threat detection suite
│   ├── beaconing_detector.py # Botnet C2 IAT variance detector
│   ├── ddos_detector.py  # Volumetric DDoS detector
│   ├── dga_detector.py   # DGA & DNS tunneling detector
│   ├── encrypted_malware_detector.py # JA3 fingerprint matching
│   ├── exfiltration_detector.py # Asymmetric egress burst detector
│   ├── port_scan_detector.py # Port fan-out anomaly detector
│   ├── model_registry.py # Unified evaluator: 6 rule detectors + Random Forest layer
│   └── artifacts/        # Trained model (threat_rf.joblib) + model_card.json
├── ml/                   # Random Forest layer
│   ├── features.py       # Flow / host-window feature vectors + human-readable names
│   ├── synthetic.py      # Labelled training traffic (attack variants + hard negatives)
│   ├── model.py          # Training, inference, explanations, save / load
│   └── evaluate.py       # Rules vs AI vs hybrid; calibration on real captures
├── presentation/         # SIH presentation resources & judge defense guide
│   ├── judge_qa_guide.md # Anticipated judge questions & technical answers
│   └── sih_presentation_slides.md # 7-slide deck content
├── reporting/            # Printable HTML incident report
├── response/             # iptables & Snort/Suricata rule generation (SOAR)
├── tests/                # Automated pytest verification suite
│   ├── test_features.py  # Entropy, DNS, JA3, SPLT tests
│   ├── test_ingestion.py # Flow aggregation & sliding window tests
│   ├── test_models.py    # Detection tests for all 6 models
│   ├── test_dashboard.py # Dashboard helpers + headless app smoke test
│   ├── test_ml.py        # ML layer: training, explanations, hybrid logic, artifact checks
│   ├── test_pipeline_and_alerts.py # Pipeline integration + end-to-end attack tests
│   └── test_response_and_report.py # Rule generation & report escaping tests
├── train_models.py       # Train + calibrate + evaluate the model, write the model card
├── traffic_simulator/    # Synthetic traffic generation
│   └── generate_traffic.py # Generates benign + 6 attack PCAP profiles
├── config.yaml           # Global system configuration
├── requirements.txt      # Dependency specifications
└── run_pipeline.py       # CLI runner & performance benchmark
```

---

## 📊 Benchmark & Performance Verification

| Metric | Measured Value | Standard Required |
|---|---|---|
| **Test Suite** | **60/60 Passed** | 100% Pass |
| **Detection on simulated attacks** | **6/6 vectors, each as its own class; 0 alerts on benign mix** | No cross-class false positives |
| **End-to-end throughput** | **~20,100 pkt/s rules only · ~15,200 pkt/s hybrid** (single Python core, CTU-13 Neris capture, 322,248 packets) | Continuous streaming |
| **False alarms on real normal traffic** | **0 (rules) · 1.2 per 10k flows (hybrid)** on 41,167 held-out CTU flows | Low alert fatigue |
| **Packet Return Policy** | **0 packets transmitted** | Strictly 100% passive |
| **Payload Decryption** | **0 bytes decrypted** | Metadata & cryptographic analysis |

Throughput was measured on a laptop over the public CTU-13 Neris capture. False-alarm rates come from CTU-Normal-28 and CTU-Normal-24, which were never used for tuning. See the AI layer section for detection results.

---

## 📜 Compliance & Ethics
Built strictly in accordance with **NTRO SIH 2026 Problem Statement #26145** specifications, adhering to Indian Critical Information Infrastructure (CII) protection mandates, NCIIPC guidelines, and RFC 8446 privacy constraints.
