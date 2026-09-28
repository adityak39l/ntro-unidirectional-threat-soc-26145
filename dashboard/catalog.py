"""Static metadata for the six NTRO threat vectors and the four severity levels.

Single source of truth for labels, icons, MITRE ATT&CK mapping and severity
encoding used by every dashboard view, notification and toast.
"""
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class ThreatMeta:
    label: str          # full display name
    short: str          # compact name for axes, toasts and chips
    icon: str           # Streamlit material icon
    mitre_id: str
    technique: str
    tactic: str
    kill_chain: str     # Lockheed Martin Cyber Kill Chain stage
    description: str
    method: str
    examples: str
    sim_key: str        # attack_type understood by the traffic simulator


THREATS: Dict[str, ThreatMeta] = {
    "Volumetric_Protocol_DDoS": ThreatMeta(
        label="Volumetric & protocol DDoS", short="DDoS", icon=":material/waves:",
        mitre_id="T1498", technique="Network Denial of Service", tactic="Impact",
        kill_chain="Actions on Objectives",
        description="600 half-open SYNs at ~500 pkt/s from ~200 spoofed bots converge on one server. "
                    "Every 3 s sliding window aggregates fan-in per target: peak packet rate, share of "
                    "half-open SYNs and source-IP entropy.",
        method="Sliding-window fan-in (peak ≥ 300 pkt/s, ≥ 80% half-open SYN)",
        examples="Mirai botnet (2016), Memcached amplification (2018)",
        sim_key="ddos",
    ),
    "Botnet_C2_Beaconing": ThreatMeta(
        label="Botnet C2 beaconing", short="C2 beaconing", icon=":material/settings_input_antenna:",
        mitre_id="T1071", technique="Application Layer Protocol", tactic="Command and Control",
        kill_chain="Command & Control",
        description="An infected host checks in with its command server every 2.0 s. Machine-timed "
                    "check-ins have near-zero inter-arrival-time variance, unlike human traffic.",
        method="Inter-arrival-time periodicity (variance < 0.01, CV < 0.15)",
        examples="APT28 (Fancy Bear), Cobalt Strike beacons",
        sim_key="beaconing",
    ),
    "DGA_Domains_and_DNS_Tunneling": ThreatMeta(
        label="DGA domains & DNS tunneling", short="DGA / DNS", icon=":material/dns:",
        mitre_id="T1568", technique="Dynamic Resolution", tactic="Command and Control",
        kill_chain="Command & Control",
        description="Malware resolves pseudo-random domains (e.g. vxzq981pkm.biz) and tunnels data "
                    "inside long base32 subdomains. Scored on the registered label: entropy, length, "
                    "consonant ratio and digit mixing.",
        method="Label entropy + consonant/digit indicators; subdomain entropy for tunneling",
        examples="Conficker, CryptoLocker, Emotet; iodine / dnscat2 tunnels",
        sim_key="dga",
    ),
    "Encrypted_Malware_TLS": ThreatMeta(
        label="Encrypted malware (TLS metadata)", short="Encrypted malware", icon=":material/lock:",
        mitre_id="T1573", technique="Encrypted Channel", tactic="Command and Control",
        kill_chain="Installation",
        description="An implant opens TLS with a hand-rolled ClientHello. Without decrypting anything, "
                    "the JA3 fingerprint is matched against known C2 tooling, then the ClientHello is "
                    "scored for legacy version, missing SNI, odd port and cipher list.",
        method="JA3 blocklist + ClientHello metadata anomaly scoring",
        examples="Cobalt Strike, Emotet, TrickBot, Metasploit",
        sim_key="encrypted_malware",
    ),
    "Reconnaissance_Port_Scanning": ThreatMeta(
        label="Reconnaissance port scanning", short="Port scan", icon=":material/radar:",
        mitre_id="T1046", technique="Network Service Discovery", tactic="Discovery",
        kill_chain="Reconnaissance",
        description="One host sends SYN probes to 13 service ports (21, 22, 80, 443, 3389, ...) to map "
                    "the network. Each 3 s window counts distinct ports per host and hosts per port "
                    "for every source.",
        method="Sliding-window fan-out (≥ 10 ports or ≥ 20 hosts, probe ratio ≥ 60%)",
        examples="Nmap SYN scan, Masscan",
        sim_key="port_scan",
    ),
    "Data_Exfiltration": ThreatMeta(
        label="Data exfiltration", short="Exfiltration", icon=":material/cloud_upload:",
        mitre_id="T1048", technique="Exfiltration Over Alternative Protocol", tactic="Exfiltration",
        kill_chain="Actions on Objectives",
        description="A compromised host pushes a burst of MTU-sized packets to an external server. "
                    "Detected from the payload-to-header ratio and egress volume, without reading "
                    "the payload.",
        method="Asymmetric byte ratio + MTU-sized egress bursts",
        examples="SolarWinds (2020), Colonial Pipeline (2021)",
        sim_key="exfiltration",
    ),
}

THREAT_ORDER: List[str] = list(THREATS)


@dataclass(frozen=True)
class SeverityMeta:
    label: str
    glyph: str           # shape carries severity for colour-blind readers
    plotly_symbol: str
    color: str           # status palette (fixed across themes)
    rank: int


SEVERITIES: Dict[str, SeverityMeta] = {
    "CRITICAL": SeverityMeta("Critical", "■", "square", "#d03b3b", 0),
    "HIGH": SeverityMeta("High", "▲", "triangle-up", "#ec835a", 1),
    "MEDIUM": SeverityMeta("Medium", "◆", "diamond", "#fab219", 2),
    "LOW": SeverityMeta("Low", "●", "circle", "#8a94a6", 3),
}
SEVERITY_ORDER: List[str] = list(SEVERITIES)

KILL_CHAIN_STAGES: List[str] = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives",
]

MITRE_TACTICS: List[str] = ["Discovery", "Command and Control", "Exfiltration", "Impact"]


def threat_short(threat_class: str) -> str:
    meta = THREATS.get(threat_class)
    return meta.short if meta else str(threat_class).replace("_", " ")


def severity(level: str) -> SeverityMeta:
    return SEVERITIES.get(str(level).upper(), SEVERITIES["LOW"])
