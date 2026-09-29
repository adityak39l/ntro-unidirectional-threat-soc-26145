# NTRO Cybersecurity Expert Q&A Guide
## Key Technical Questions & Strategic Winning Answers

---

### Q1: "In a real data diode setup, you only receive traffic and can never reply. How does your TCP flow tracking work if you don't see bidirectional ACKs?"
**Winning Answer:**
"Our flow aggregator does not depend on bidirectional TCP handshake completion. We track unidirectional flows keyed by the 5-tuple. For metrics like SYN-ACK ratios, in a unidirectional link mirroring internal-to-external traffic, the complete absence of return ACKs is itself an expected operational baseline. We measure anomalous distributions—such as thousands of half-open SYNs without established flow duration—which accurately isolates SYN flooding from normal browsing."

---

### Q2: "If malware authors randomize their TLS cipher suites to evade JA3, how does your system detect encrypted malware?"
**Winning Answer:**
"JA3 hash matching is our first-tier signature layer. For zero-day or randomized TLS evasion, we employ our second layer: SPLT (Sequence of Packet Lengths and Times) and inter-arrival time (IAT) variance. Even if an attacker scrambles their cipher order, the fundamental communication semantics of C2 check-ins—small payload handshake, periodic poll, and asymmetric byte ratio—generate distinct behavioral anomalies (IAT periodicity, asymmetric egress) that our behavioural detectors flag without needing payload inspection. Even with an unknown JA3, the ClientHello itself is scored: legacy TLS version, missing SNI, non-standard port and an unusually small cipher list are each explained in the alert evidence."

---

### Q3: "How does your pipeline ensure near real-time bounded latency instead of batch processing?"
**Winning Answer:**
"We implement a sliding temporal window manager (3-second window with 1-second slide). Instead of accumulating large PCAPs, packets are immediately ingested into in-memory flow state tables. When an active timeout (120s) or idle timeout (15s) fires, the flow's feature vector is evaluated by the per-flow detectors (measured ~0.08 ms per flow). Every time the window slides, host-level fan-in (DDoS) and fan-out (port scan) are computed for that window (~0.8 ms per window). End-to-end the pipeline sustains ~20,000 packets/sec with rules only and ~15,000 packets/sec with the AI layer, on a single Python core (measured on the public CTU-13 Neris capture)."

---

### Q4: "How does your system prevent alert fatigue in a high-throughput SOC?"
**Winning Answer:**
"We implement two critical mechanisms:
1. **Dynamic Deduplication Cooldown:** Identical threats between the same source and destination are suppressed within a configurable 30-second window.
2. **Confidence-Weighted Severity Classification:** Alerts are assigned severity (LOW, MEDIUM, HIGH, CRITICAL) based on statistical confidence scores and multiple corroborating evidence features, allowing analysts to prioritize actionable high-confidence incidents."

---

### Q5: "Where is the AI? Is it only rules, and was it tested on real traffic?"
**Winning Answer:**
"It is a hybrid. The rule detectors give precise, explainable alerts. Next to them run two trained Random Forests: a flow model for C2, DGA/DNS, encrypted malware and exfiltration, and a host-window model for DDoS and scanning. Every alert shows whether the rules, the model or both raised it, the model's probability, and the features that drove the decision.
- On held-out test traffic, the hybrid catches 97-100% of C2, DGA, encrypted-malware, exfiltration and scan variants, where the rules alone catch 53-89%.
- We tuned the model's thresholds on two public normal-traffic captures from CTU Prague, then tested on two other captures (about 41,000 flows). The rules raise zero false alarms there, and the hybrid about one per 10,000 flows.
- On the real Neris botnet capture, the model found 11 port scans that the rules missed.
- The training data is synthetic, so we present those scores as generalisation to attack variants, not field accuracy. The model card in the dashboard states this."

### Q6: "What did testing on real traffic change?"
**Winning Answer:**
"It exposed and fixed false alarms that synthetic tests never showed. `ping` and `mtr` replies looked like C2 beacons. BitTorrent downloads and LAN copies looked like exfiltration. Cloud load-balancer hostnames looked like DNS tunnels. On the held-out captures the rules went from 116 false alarms to none."
