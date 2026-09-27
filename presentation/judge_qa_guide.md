# NTRO Cybersecurity Expert Q&A Guide
## Key Technical Questions & Strategic Winning Answers

---

### Q1: "In a real data diode setup, you only receive traffic and can never reply. How does your TCP flow tracking work if you don't see bidirectional ACKs?"
**Winning Answer:**
"Our flow aggregator does not depend on bidirectional TCP handshake completion. We track unidirectional flows keyed by the 5-tuple. For metrics like SYN-ACK ratios, in a unidirectional link mirroring internal-to-external traffic, the complete absence of return ACKs is itself an expected operational baseline. We measure anomalous distributions—such as thousands of half-open SYNs without established flow duration—which accurately isolates SYN flooding from normal browsing."

---

### Q2: "If malware authors randomize their TLS cipher suites to evade JA3, how does your system detect encrypted malware?"
**Winning Answer:**
"JA3 hash matching is our first-tier signature layer. For zero-day or randomized TLS evasion, we employ our second layer: SPLT (Sequence of Packet Lengths and Times) and inter-arrival time (IAT) variance. Even if an attacker scrambles their cipher order, the fundamental communication semantics of C2 check-ins—small payload handshake, periodic poll, and asymmetric byte ratio—generate distinct behavioral anomalies detected by our machine learning models without needing payload inspection."

---

### Q3: "How does your pipeline ensure near real-time bounded latency instead of batch processing?"
**Winning Answer:**
"We implement a sliding temporal window manager (3-second window with 1-second slide). Instead of accumulating large PCAPs, packets are immediately ingested into in-memory flow state tables. When an active timeout (120s) or idle timeout (15s) fires, or when the sliding window advances, feature vectors are extracted on-the-fly and evaluated in under 2.5 milliseconds by our lightweight tree models."

---

### Q4: "How does your system prevent alert fatigue in a high-throughput SOC?"
**Winning Answer:**
"We implement two critical mechanisms:
1. **Dynamic Deduplication Cooldown:** Identical threats between the same source and destination are suppressed within a configurable 30-second window.
2. **Confidence-Weighted Severity Classification:** Alerts are assigned severity (LOW, MEDIUM, HIGH, CRITICAL) based on statistical confidence scores and multiple corroborating evidence features, allowing analysts to prioritize actionable high-confidence incidents."