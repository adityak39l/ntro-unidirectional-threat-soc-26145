# System Architecture & Technical Specifications
## Problem Statement ID: 26145 | Organization: NTRO
## AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

---

## 1. Executive Summary & Operational Context
In high-security military, intelligence, and critical national infrastructure networks (nuclear reactors, power grid SCADA, naval communications), monitoring networks are isolated using **Hardware Data Diodes**. Data diodes physically enforce unidirectional traffic flow (TX photodiode to RX photodetector), guaranteeing that a compromise in the monitoring enclave cannot pivot back into the core production network.

### The Engineering Challenge
The detection system operates under strict physical and protocol constraints:
1. **Zero Transmit (Tx) Capability:** The monitoring system can never send TCP ACKs, SYN-ACKs, ICMP probes, or DNS replies.
2. **Zero Inline Blocking:** The detection engine cannot push inline iptables/firewall drop rules across the diode.
3. **Zero Payload Decryption:** All TLS 1.3 / QUIC encrypted payload contents are indecipherable without private keys.
4. **Streaming Bounded Latency:** Traffic must be evaluated in near real-time sliding windows (< 50ms per flow batch).

---

## 2. Multi-Layer Pipeline Architecture

```
                       [ PRODUCTION CORE NETWORK ]
                                    │
                         Hardware Data Diode / TAP
                                    ▼ (Unidirectional Stream)
┌─────────────────────────────────────────────────────────────────────────────┐
│                       MONITORING ENCLAVE (READ-ONLY)                        │
│                                                                             │
│  [ Layer 1: Ingestion Engine ]                                              │
│  ├─ Passive PCAP/Ring Buffer (dpkt / AF_PACKET zero-copy)                   │
│  ├─ 5-Tuple Stateful Flow Aggregator (Idle: 15s, Active: 120s)              │
│  └─ Sliding Window Manager (3s Window, 1s Slide)                            │
│                                   │                                         │
│                                   ▼                                         │
│  [ Layer 2: Feature Engineering Engine ]                                    │
│  ├─ Statistical Flow Dynamics (PPS, BPS, Packet Length Moments)             │
│  ├─ DNS Cryptographic Entropy & N-gram Anomaly Analyzer                    │
│  ├─ TLS Metadata & JA3/JA4 Fingerprinter (Client Hello Inspection)         │
│  └─ Sequence of Packet Lengths and Times (SPLT Vectorizer)                  │
│                                   │                                         │
│                                   ▼                                         │
│  [ Layer 3: AI/ML Threat Detection Engine ]                                 │
│  ├─ Volumetric & Protocol DDoS Classifier (XGBoost / Random Forest)         │
│  ├─ Botnet C2 Beaconing Detector (Periodicity & IAT Variance Profiler)      │
│  ├─ DGA & DNS Tunneling Detector (Shannon Entropy + Token Length Heuristic) │
│  ├─ Encrypted Malware Detector (JA3 Signature Match + SPLT Anomaly)         │
│  ├─ Reconnaissance & Port Scan Detector (Fan-out Anomaly Isolation)         │
│  └─ Data Exfiltration Detector (Asymmetric Forward/Backward Ratio)         │
│                                   │                                         │
│                                   ▼                                         │
│  [ Layer 4: Alerting & SOC Intelligence Dashboard ]                         │
│  ├─ Standardized Alert JSON Schema                                          │
│  ├─ SQLite Telemetry Store & Alert Deduplication Engine                     │
│  └─ Real-Time Streamlit SOC Visual Interface                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Vector Detection Mechanisms

### A. Volumetric / Protocol DDoS
- **Signals:** Abrupt surge in Packets-per-Second (PPS > 500), high SYN-to-ACK ratio (> 5.0), source IP entropy dispersal.
- **Model:** Random Forest / Gradient Boosted Trees trained on flow dynamics.

### B. Botnet C2 Beaconing
- **Signals:** Mathematical periodicity in Inter-Arrival Times (IAT). Legitimate human browsing shows high variance (Poisson arrival); C2 malware shows tight clustering with near-zero variance ($\sigma^2 < 0.01$) and low coefficient of variation ($CV < 0.15$).

### C. DGA Domains & DNS Tunneling
- **Signals:** Shannon entropy $H(X) = -\sum P(x) \log_2 P(x) > 3.8$, excessive domain length (> 35 chars), consecutive consonant sequences, and abnormal TXT/NULL query types.

### D. Encrypted Malware (TLS/QUIC)
- **Signals:** Extraction of TLS Client Hello parameters without decryption. MD5 hash of TLS version, cipher suites, and extensions creates JA3 fingerprint, matched against known threat actors (Cobalt Strike, Emotet).

### E. Reconnaissance & Port Scanning
- **Signals:** Single source IP targeting multiple sequential ports in rapid succession with uncompleted TCP handshakes (SYN with no ACK).

### F. Data Exfiltration
- **Signals:** Asymmetric outbound payload bytes exceeding baseline ratios ($> 10\times$ header bytes) to non-standard external ports.