# 🛡️ AI-Based Threat Intelligence SOC for Unidirectional IP Traffic
### Smart India Hackathon 2026 | Problem Statement ID: 26145
**Organization:** National Technical Research Organisation (NTRO)  
**Domain:** Defense, Critical Information Infrastructure (CII), Cybersecurity  
**Theme:** Blockchain & Cybersecurity  

[![Python](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Production--Ready-success.svg)]()
[![Tests](https://img.shields.io/badge/Tests-15%2F15%20Passed-brightgreen.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/Taxonomy-MITRE%20ATT%26CK%C2%AE-orange.svg)](https://attack.mitre.org/)
[![Architecture](https://img.shields.io/badge/Compliance-Hardware%20Data%20Diode%20(Zero--Tx)-red.svg)]()

---

## 📌 Executive Summary

Critical national enclaves — including **Nuclear Power Plants (BARC/NPCIL), Military Command Centers, Naval Warships, and Power Grids** — isolate their networks using **Hardware Data Diodes**. In these enclaves, the physical transmission line (Tx) is severed or disabled, enforcing strictly **unidirectional traffic** (data flows in, zero packets return).

Standard security tools (**Wireshark, Snort, Suricata, Zeek, Palo Alto firewalls**) fail in these environments because they require bidirectional TCP handshakes, return packets, or active probing. Furthermore, high-security enclaves legally prohibit sharing TLS private keys, ruling out traditional payload decryption.

This system provides a **100% passive, read-only AI streaming threat detection appliance** capable of detecting and classifying threats in real time without returning any packets and without decrypting payloads.

---

## 🎯 6 Mandated Threat Vectors (NTRO Scope)

| # | Threat Vector | MITRE ATT&CK ID | Detection Algorithm & Proof | Severity |
|---|---|---|---|---|
| 1 | **Volumetric & Protocol DDoS** | **T1498** (Network DoS) | PPS threshold (>500) & SYN/ACK asymmetry ratio | **CRITICAL** |
| 2 | **Botnet C2 Beaconing** | **T1071** (App Layer Protocol) | Inter-Arrival Time (IAT) variance analysis ($\sigma^2 < 0.01$) | **HIGH** |
| 3 | **DGA Domains & DNS Tunneling** | **T1568** (Dynamic Resolution) | Claude Shannon Information Entropy ($H > 4.0$) + consonant ratio | **HIGH** |
| 4 | **Encrypted Malware (TLS Metadata)** | **T1573** (Encrypted Channel) | JA3 hash signature matching & TLS Client Hello metadata | **CRITICAL** |
| 5 | **Reconnaissance Port Scanning** | **T1046** (Network Discovery) | Destination port fan-out anomaly detection | **MEDIUM** |
| 6 | **Data Exfiltration** | **T1048** (Exfiltration Over Protocol) | Asymmetric outbound byte ratio & MTU-burst volume analysis | **CRITICAL** |

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
│ 3. HYBRID AI/ML ENSEMBLE DETECTION CORE                    │
│    - Deterministic heuristic rule filters                   │
│    - Machine Learning Classifiers (Random Forest / XGBoost) │
│    - Unified Model Registry evaluating all 6 vectors        │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. SOC AUDIT & ALERTING ENGINE                              │
│    - Standardized JSON Alert Schema + SQLite DB + JSONL log │
│    - MITRE ATT&CK Mapping & Lockheed Martin Kill Chain      │
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
Extracts Client Hello parameters:
$$\text{JA3} = \text{MD5}(\text{TLSVersion, Ciphers, Extensions, EllipticCurves, PointFormats})$$
Matches against known threat actor profiles (Cobalt Strike, Emotet, TrickBot, Metasploit) without decrypting payloads.

### 3. IAT Statistical Variance (C2 Beaconing)
$$\sigma^2 = \frac{1}{N}\sum_{i=1}^{N}(t_i - \bar{t})^2$$
Automated malware beacons trigger deterministic pulses with variance tending toward 0 ($\sigma^2 < 0.01$).

---

## 🖥️ Enterprise SOC Dashboard

The dashboard provides a real-time Security Operations Center interface:
* **🚨 Threat Overview:** Dynamic DEFCON-style Threat Posture banner (GREEN/YELLOW/ORANGE/RED with glowing pulse), 6 KPI cards, Plotly threat distribution bar chart, severity donut chart, interactive attack timeline, and top 10 threat sources table.
* **🗺️ Network Intelligence:** Interactive Network Attack Topology Graph (IP nodes, connection lines, risk colors, size based on alert frequency) and Source IP × Attack Heatmap.
* **🔍 Alert Investigation:** Dynamic multi-criteria filters (Severity, Threat Class, IP search), clean alert feed, one-click CSV export, and Explainable AI Forensic Inspector displaying cryptographic proofs.
* **🧪 Attack Simulation Lab:** Interactive launcher cards for all 6 threat vectors with MITRE ATT&CK technique IDs, severity tags, algorithmic descriptions, and real-world threat actor examples.
* **📊 Analytics & Reports:** Lockheed Martin Cyber Kill Chain coverage pipeline with active detection highlights, MITRE ATT&CK® Enterprise Matrix, Threat Radar chart, and Data Diode compliance verification.
* **🎨 Dual Display Theme:** High-contrast Dark Mode (Cyber SOC) and High-Contrast Light Mode (Enterprise) with WCAG AAA accessibility standards.

---

## ⚡ Quickstart & Installation

### 1. Prerequisites
- Python 3.12+
- Git

### 2. Clone and Setup Environment
```bash
# Clone the repository
git clone https://github.com/<your-username>/ntro-unidirectional-threat-soc.git
cd ntro-unidirectional-threat-soc

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
Verify all 15 unit and integration tests across features, ingestion, models, and pipeline:
```bash
pytest tests/ -v
```

### 4. Execute Streaming Pipeline Benchmark
Run the end-to-end ingestion and detection engine on synthetic unidirectional traffic:
```bash
python run_pipeline.py
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
│   └── app.py            # 5-tab dashboard with Plotly & dual themes
├── data/                 # Captured PCAPs and alert databases (git-ignored)
├── detection/            # Pipeline orchestration
│   └── pipeline.py       # StreamingDetectionPipeline with sliding windows
├── docs/                 # Architectural documentation
│   └── architecture.md   # Deep-dive system architecture specification
├── feature_engine/       # Zero-decryption feature extraction
│   ├── dns_analyzer.py   # Shannon entropy & DGA domain scoring
│   ├── feature_extractor.py # Statistical flow metrics & SPLT extractor
│   └── tls_fingerprint.py# JA3 hash extraction & SPLT vectorization
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
│   └── model_registry.py # Unified evaluator for all 6 detectors
├── presentation/         # SIH presentation resources & judge defense guide
│   ├── judge_qa_guide.md # Anticipated judge questions & technical answers
│   └── sih_presentation_slides.md # 7-slide deck content
├── tests/                # Automated pytest verification suite
│   ├── test_features.py  # Entropy, DNS, JA3, SPLT tests
│   ├── test_ingestion.py # Flow aggregation & sliding window tests
│   ├── test_models.py    # Detection tests for all 6 models
│   └── test_pipeline_and_alerts.py # Pipeline integration tests
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
| **Test Suite Coverage** | **15/15 Passed (100%)** | 100% Pass |
| **Ingestion Latency** | **< 10ms per window** | Sub-second real-time |
| **Pipeline Throughput** | **~135 packets/sec** (single core) | Continuous streaming |
| **Packet Return Policy** | **0 packets transmitted** | Strictly 100% passive |
| **Payload Decryption** | **0 bytes decrypted** | Metadata & cryptographic analysis |

---

## 📜 Compliance & Ethics
Built strictly in accordance with **NTRO SIH 2026 Problem Statement #26145** specifications, adhering to Indian Critical Information Infrastructure (CII) protection mandates, NCIIPC guidelines, and RFC 8446 privacy constraints.
