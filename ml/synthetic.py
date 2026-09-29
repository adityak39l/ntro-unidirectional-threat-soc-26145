"""Labelled synthetic traffic for training and testing the ML layer.

Packets are produced directly in the pipeline's packet-dict format (no scapy), then
turned into flows and sliding windows by the *same* ingestion and feature code the
live pipeline uses, so training and serving see identical features.

Attack parameters deliberately span a wider range than the hand-written rule
thresholds (jittered beacons, slower floods, smaller exfiltration, slow scans), and
benign traffic includes hard negatives (legacy-TLS browsers, app heartbeats, busy
servers, bulk downloads, browsers opening many connections).
"""
import random
import socket
import string
from typing import Any, Dict, List, Tuple

import dpkt

from feature_engine.feature_extractor import FeatureExtractor
from feature_engine.tls_fingerprint import build_client_hello
from feature_engine.window_features import aggregate_window
from ingestion.flow_aggregator import FlowAggregator
from ingestion.window_manager import SlidingWindowManager
from ml.features import flow_vector, host_vector, is_host_candidate

TCP_HDR, UDP_HDR = 54, 42  # Ethernet + IPv4 + TCP/UDP headers

FLOW_CLASSES = ["benign", "Botnet_C2_Beaconing", "DGA_Domains_and_DNS_Tunneling", "Encrypted_Malware_TLS",
                "Data_Exfiltration"]
HOST_CLASSES = ["benign", "Volumetric_Protocol_DDoS", "Reconnaissance_Port_Scanning"]

BENIGN_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.in", "microsoft.com", "apple.com",
    "github.com", "stackoverflow.com", "linkedin.com", "twitter.com", "instagram.com", "whatsapp.net",
    "cloudflare.com", "akamaiedge.net", "googleusercontent.com", "gstatic.com", "office365.com", "outlook.com",
    "live.com", "bing.com", "yahoo.com", "reddit.com", "netflix.com", "spotify.com", "zoom.us", "slack.com",
    "dropbox.com", "adobe.com", "mozilla.org", "ubuntu.com", "python.org", "pypi.org", "npmjs.com",
    "docker.io", "nic.in", "gov.in", "sbi.co.in", "irctc.co.in", "flipkart.com", "paytm.com", "hdfcbank.com",
    "ndtv.com", "timesofindia.com", "thehindu.com", "isro.gov.in", "drdo.gov.in", "cdn.jsdelivr.net",
    "fonts.googleapis.com", "doubleclick.net", "windowsupdate.com", "digicert.com", "letsencrypt.org",
]
SUBDOMAINS = ["", "www.", "api.", "cdn.", "mail.", "static.", "login.", "img.", "m.", "update.", "edge-2."]
MODERN_CIPHERS = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014,
                  0x009C, 0x009D, 0x002F, 0x0035, 0xC009, 0xC00A, 0x0033, 0x0039, 0x000A]
GREASE = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA]
C2_PORTS = [4444, 1337, 6667, 8080, 8081, 443, 80, 8443, 9001, 31337, 2222, 5555]
MALWARE_TLS_PORTS = [443, 443, 4444, 8443, 8080, 9443, 1443, 6667, 2222, 7443]
EXFIL_PORTS = [443, 80, 21, 8080, 22, 993, 4443]
ENGLISH_WORDS = ["kick", "starter", "admissions", "media", "hydra", "platform", "cloud", "market", "place", "travel",
                 "trip", "book", "news", "daily", "express", "health", "care", "bank", "money", "smart", "learn", "online",
                 "shop", "store", "world", "india", "digital", "tech", "solutions", "services", "global", "network",
                 "power", "green", "energy", "home", "office", "school", "college", "univ", "research", "science",
                 "photo", "video", "music", "game", "sports", "cricket", "food", "kitchen", "recipes", "weather",
                 "insurance", "finance", "career", "jobs", "portal", "express", "times", "herald", "channel", "mit"]
INFRA_WORDS = ["api", "edge", "prod", "log", "metrics", "shield", "pipeline", "user", "sync", "lb", "cdn", "static",
               "auth", "beacon", "track", "ads", "analytics", "content", "media", "push", "gateway", "match", "rtb",
               "img", "video", "balrog", "aus5", "normandy", "koala", "persoo", "euirl", "external", "public"]


class ScenarioBuilder:
    def __init__(self, rng: random.Random, t0: float = 1_700_000_000.0):
        self.rng = rng
        self.t0 = t0
        self.packets: List[Dict[str, Any]] = []
        self.flow_labels: Dict[Tuple, str] = {}
        self.host_labels: List[Tuple[str, str, float, float]] = []
        self._port = rng.randint(20000, 40000)

    # ---------- primitives ----------
    def ephemeral(self) -> int:
        self._port += self.rng.randint(1, 7)
        if self._port > 65000:
            self._port = 20000 + self.rng.randint(0, 999)
        return self._port

    def private_ip(self) -> str:
        r = self.rng
        return r.choice([f"10.{r.randint(0, 40)}.{r.randint(0, 255)}.{r.randint(2, 254)}",
                         f"192.168.{r.randint(0, 20)}.{r.randint(2, 254)}",
                         f"172.{r.randint(16, 31)}.{r.randint(0, 255)}.{r.randint(2, 254)}"])

    def public_ip(self) -> str:
        r = self.rng
        while True:
            a = r.randint(11, 223)
            if a not in (10, 100, 127, 169, 172, 192):
                return f"{a}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(1, 254)}"

    def pkt(self, ts, src, dst, sport, dport, proto="TCP", payload=b"", flags=None, size=None):
        hdr = TCP_HDR if proto == "TCP" else UDP_HDR
        payload_len = len(payload) if size is None else max(0, size - hdr)
        self.packets.append({
            "timestamp": ts, "src_ip": src, "dst_ip": dst, "src_port": sport, "dst_port": dport,
            "protocol": proto, "packet_length": hdr + payload_len, "payload_length": payload_len,
            "tcp_flags": flags if flags is not None else ({"ACK": True, "PSH": True} if proto == "TCP" else {}),
            "raw_payload": payload,
        })

    def label(self, src, dst, sport, dport, proto, cls):
        self.flow_labels[(src, dst, sport, dport, proto)] = cls

    def human_gaps(self, n, mean=0.35):
        return [min(8.0, self.rng.lognormvariate(0, 1.0) * mean) for _ in range(n)]

    # ---------- payloads ----------
    def dns_query(self, name: str) -> bytes:
        return bytes(dpkt.dns.DNS(id=self.rng.randint(0, 65535), op=0x0100,
                                  qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)]))

    def dns_response(self, name: str) -> bytes:
        answers = [dpkt.dns.DNS.RR(name=name, type=1, cls=1, ttl=300, rdata=socket.inet_aton(self.public_ip()))
                   for _ in range(self.rng.randint(1, 4))]
        return bytes(dpkt.dns.DNS(id=self.rng.randint(0, 65535), op=0x8180,
                                  qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)], an=answers))

    def benign_hello(self, sni: str, legacy: bool = False) -> bytes:
        r = self.rng
        ciphers = r.sample(MODERN_CIPHERS, r.randint(12, 18))
        if r.random() < 0.7:
            ciphers.insert(0, r.choice(GREASE))
        if legacy:
            ciphers += [0x0004, 0x0005, 0x000A, 0x0016, 0x0013, 0x0066][: r.randint(3, 6)]
        exts = {23: b"", 65281: b"\x00", 35: b""}
        if not legacy:
            exts.update({16: b"\x00\x0c\x02h2\x08http/1.1", 13: b"\x00\x04\x04\x03\x08\x04",
                         43: b"\x04\x03\x04\x03\x03", 45: b"\x01\x01", 51: bytes(r.randint(36, 40))})
        return build_client_hello(ciphers, extensions=exts, sni=sni, groups=[29, 23, 24],
                                  point_formats=[0], client_version=0x0301 if legacy else 0x0303)

    def benign_domain(self) -> str:
        roll = self.rng.random()
        if roll < 0.3:
            return self.infra_hostname()
        if roll < 0.45:
            # Long single-label brands (kickstarter, mitadmissions, mediahydraplatform): wordy, not random
            r = self.rng
            words = "".join(r.choice(ENGLISH_WORDS) for _ in range(r.randint(2, 3)))
            prefix = r.choice(["", "", "", "q1", "my", "go", "the"])
            return r.choice(SUBDOMAINS) + prefix + words + r.choice([".com", ".org", ".net", ".in", ".co.in", ".io"])
        return self.rng.choice(SUBDOMAINS) + self.rng.choice(BENIGN_DOMAINS)

    def infra_hostname(self) -> str:
        # Machine-generated but benign names seen in real traffic: load balancers, CDN edges, hashes
        r = self.rng
        w = lambda: r.choice(INFRA_WORDS)
        digits = lambda n: "".join(r.choice(string.digits) for _ in range(n))
        alnum = lambda n: "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(n))
        region = r.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-south-1", "eu-central-1"])
        return r.choice([
            f"{w()}-{w()}-{w()}-{digits(10)}.{region}.elb.amazonaws.com",
            f"dualstack.{w()}-{w()}-{alnum(12)}-{digits(9)}.{region}.elb.amazonaws.com",
            f"{''.join(r.choice('0123456789abcdef') for _ in range(33))}.profile.{w()}{digits(2)}.cloudfront.net",
            f"d{alnum(13)}.cloudfront.net",
            f"e{digits(4)}.{r.choice(['a', 'b', 'dscg', 'dsce'])}.akamaiedge.net",
            f"{w()}-{w()}.{w()}.akadns.net",
            f"r{r.randint(1, 9)}---sn-{alnum(8)}.googlevideo.com",
            f"{w()}-{alnum(4)}.r53-{r.randint(1, 9)}.services.mozilla.com",
            f"{w()}.{w()}.{r.choice(BENIGN_DOMAINS)}.cdn.cloudflare.net",
            f"{w()}{r.randint(1, 60)}-{w()}.{r.choice(['azureedge.net', 'trafficmanager.net', 'fastly.net'])}",
            f"{w()}-{w()}-{digits(6)}.{r.choice(BENIGN_DOMAINS)}",
        ])

    # ---------- benign scenarios ----------
    def dns_lookup(self, t, client, resolver):
        sport, name = self.ephemeral(), self.benign_domain()
        self.pkt(t, client, resolver, sport, 53, "UDP", self.dns_query(name))
        self.pkt(t + self.rng.uniform(0.005, 0.08), resolver, client, 53, sport, "UDP", self.dns_response(name))
        self.label(client, resolver, sport, 53, "UDP", "benign")
        self.label(resolver, client, 53, sport, "UDP", "benign")

    def https_session(self, t, client, server, legacy=False, port=443):
        r, sport = self.rng, self.ephemeral()
        self.pkt(t, client, server, sport, port, flags={"SYN": True})
        t += r.uniform(0.01, 0.2)
        self.pkt(t, client, server, sport, port, payload=self.benign_hello(self.benign_domain(), legacy))
        for gap in self.human_gaps(r.randint(3, 40)):
            t += gap
            self.pkt(t, client, server, sport, port, size=r.randint(66, 900))
        # server -> client: responses / downloads (ingress bulk data is a hard negative for exfiltration)
        ts = t - r.uniform(0, 1)
        for _ in range(r.randint(5, 250)):
            ts += r.expovariate(1 / 0.01)
            self.pkt(ts, server, client, port, sport, size=r.choice([1514, 1514, 1514, r.randint(200, 1514)]))
        self.label(client, server, sport, port, "TCP", "benign")
        self.label(server, client, port, sport, "TCP", "benign")

    def http_download(self, t, client, server):
        r, sport = self.rng, self.ephemeral()
        self.pkt(t, client, server, sport, 80, payload=b"GET / HTTP/1.1\r\nHost: " + self.benign_domain().encode())
        for _ in range(r.randint(3, 20)):
            t += r.uniform(0.05, 1.5)
            self.pkt(t, client, server, sport, 80, size=r.randint(66, 120))
        ts = t
        for _ in range(r.randint(20, 400)):
            ts += r.expovariate(1 / 0.004)
            self.pkt(ts, server, client, 80, sport, size=1514)
        self.label(client, server, sport, 80, "TCP", "benign")
        self.label(server, client, 80, sport, "TCP", "benign")

    def ssh_typing(self, t, client, server):
        r, sport = self.rng, self.ephemeral()
        for gap in self.human_gaps(r.randint(10, 80), mean=0.25):
            t += gap
            self.pkt(t, client, server, sport, 22, size=r.choice([90, 106, 122, 138]))
        self.label(client, server, sport, 22, "TCP", "benign")

    def app_heartbeat(self, t, client, server):
        # Periodic but human-scheduled traffic (chat, push, telemetry): regular-ish with real jitter
        r, sport = self.rng, self.ephemeral()
        port = r.choice([443, 5222, 1883, 8883, 5228])
        interval, jitter = r.uniform(3, 12), r.uniform(0.25, 0.6)
        for i in range(r.randint(6, 25)):
            t += max(0.2, r.gauss(interval, interval * jitter))
            self.pkt(t, client, server, sport, port, size=r.randint(80, 400))
        self.label(client, server, sport, port, "TCP", "benign")

    def monitoring_pings(self, t, client):
        # ping / mtr: one echo reply per second from each hop — perfectly periodic, entirely benign
        r = self.rng
        for hop in [self.public_ip() for _ in range(r.randint(1, 8))] + [self.private_ip()]:
            ts = t + r.uniform(0, 1)
            for _ in range(r.randint(20, 120)):
                ts += r.gauss(1.0, r.uniform(0.002, 0.12))
                self.pkt(ts, hop, client, 0, 0, "ICMP", size=r.choice([74, 98, 110]))
            self.label(hop, client, 0, 0, "ICMP", "benign")

    def p2p_download(self, t, client):
        # BitTorrent-style ingress: external peers push MTU-sized data to a high local port
        r = self.rng
        for _ in range(r.randint(1, 4)):
            peer, sport, dport = self.public_ip(), r.randint(1025, 65000), r.randint(1025, 65000)
            proto = r.choice(["TCP", "TCP", "UDP"])
            ts = t + r.uniform(0, 5)
            for _ in range(r.randint(50, 600)):
                ts += r.expovariate(1 / 0.01)
                self.pkt(ts, peer, client, sport, dport, proto, size=r.randint(1100, 1514))
            self.label(peer, client, sport, dport, proto, "benign")

    def web_upload(self, t, client, server):
        # Photo / document / form upload: a short burst of full-size segments (20-400 KB)
        r, sport = self.rng, self.ephemeral()
        self.pkt(t, client, server, sport, 443, payload=self.benign_hello(self.benign_domain()))
        for _ in range(r.randint(15, 280)):
            t += r.expovariate(1 / 0.003)
            self.pkt(t, client, server, sport, 443, size=r.randint(1200, 1514))
        self.label(client, server, sport, 443, "TCP", "benign")

    def tcp_keepalive(self, t, client, server):
        # Idle TLS connection held open by the OS: exactly periodic, but zero-payload segments
        r, sport = self.rng, self.ephemeral()
        interval = r.uniform(5, 14)
        ts = t
        for _ in range(r.randint(8, 20)):
            ts += r.gauss(interval, interval * 0.001)
            self.pkt(ts, client, server, sport, 443, flags={"ACK": True}, size=54)
            self.pkt(ts + r.uniform(0.01, 0.2), server, client, 443, sport, flags={"ACK": True}, size=54)
        self.label(client, server, sport, 443, "TCP", "benign")
        self.label(server, client, 443, sport, "TCP", "benign")

    def lan_discovery(self, t, client):
        # NetBIOS / SSDP / mDNS announcements to broadcast or multicast, a few per second
        r = self.rng
        dst, port = r.choice([(client.rsplit(".", 1)[0] + ".255", 137), ("239.255.255.250", 1900),
                              ("224.0.0.251", 5353), (client.rsplit(".", 1)[0] + ".255", 138)])
        ts = t
        for _ in range(r.randint(5, 12)):
            ts += r.gauss(0.8, 0.01)
            self.pkt(ts, client, dst, port, port, "UDP", size=r.randint(90, 300))
        self.label(client, dst, port, port, "UDP", "benign")

    def lan_copy(self, t, client):
        # SCP / SMB copy between two internal hosts
        r, sport, port = self.rng, self.ephemeral(), self.rng.choice([22, 445, 2049])
        server = self.private_ip()
        for _ in range(r.randint(100, 800)):
            t += r.expovariate(1 / 0.002)
            self.pkt(t, client, server, sport, port, size=r.randint(1300, 1514))
        self.label(client, server, sport, port, "TCP", "benign")

    def busy_server(self, t, server, duration):
        # Many established clients: high packet rate but full handshakes / data, not a flood
        r = self.rng
        for _ in range(r.randint(20, 120)):
            client, sport = self.private_ip() if r.random() < 0.5 else self.public_ip(), self.ephemeral()
            ts = t + r.uniform(0, duration)
            for _ in range(r.randint(3, 30)):
                ts += r.expovariate(1 / 0.05)
                self.pkt(ts, client, server, sport, 443, size=r.randint(66, 1200))
            self.label(client, server, sport, 443, "TCP", "benign")

    def browser_fanout(self, t, client):
        # A page load opens many connections at once; each carries data, unlike scan probes
        r = self.rng
        for _ in range(r.randint(8, 40)):
            server, sport = self.public_ip(), self.ephemeral()
            ts = t + r.uniform(0, 2.5)
            self.pkt(ts, client, server, sport, 443, flags={"SYN": True})
            self.pkt(ts + 0.03, client, server, sport, 443, payload=self.benign_hello(self.benign_domain()))
            for _ in range(r.randint(2, 12)):
                ts += r.uniform(0.01, 0.4)
                self.pkt(ts, client, server, sport, 443, size=r.randint(66, 700))
            self.label(client, server, sport, 443, "TCP", "benign")

    # ---------- flow-level attacks ----------
    def c2_beacon(self, t, client, c2):
        r, sport, port = self.rng, self.ephemeral(), self.rng.choice(C2_PORTS)
        interval, jitter = r.uniform(0.8, 12), r.choice([0.0, 0.0, r.uniform(0, 0.08), r.uniform(0.08, 0.2)])
        size = r.randint(70, 260)
        n = r.randint(6, max(7, int(110 / interval)))
        for _ in range(n):
            t += max(0.1, r.gauss(interval, interval * jitter))
            self.pkt(t, client, c2, sport, port, size=size + r.randint(0, 12))
        self.label(client, c2, sport, port, "TCP", "Botnet_C2_Beaconing")

    def dga_query(self, t, client, resolver):
        r = self.rng
        kind = r.choice(["random", "consonant", "hex", "tunnel32", "tunnelhex", "tunnel64"])
        tld = r.choice([".com", ".net", ".org", ".biz", ".info", ".xyz", ".top", ".ru", ".club", ".cc"])
        if kind == "random":
            name = "".join(r.choice(string.ascii_lowercase + string.digits) for _ in range(r.randint(10, 22))) + tld
        elif kind == "consonant":
            name = "".join(r.choice("bcdfghjklmnpqrstvwxz" + "aeiou" * (r.random() < 0.3) + "0123456789")
                           for _ in range(r.randint(9, 18))) + tld
        elif kind == "hex":
            name = "".join(r.choice("0123456789abcdef") for _ in range(r.randint(12, 32))) + tld
        else:
            alphabet = {"tunnel32": "abcdefghijklmnopqrstuvwxyz234567", "tunnelhex": "0123456789abcdef",
                        "tunnel64": string.ascii_letters + string.digits + "-_"}[kind]
            labels = ["".join(r.choice(alphabet) for _ in range(r.randint(20, 60))) for _ in range(r.randint(1, 3))]
            base = r.choice(["t.exfil-c2", "ns1.cdn-sync", "d.tunnelsvc", "api.telemetrics"]) + tld
            name = ".".join(labels + [base])
        sport = self.ephemeral()
        self.pkt(t, client, resolver, sport, 53, "UDP", self.dns_query(name))
        self.label(client, resolver, sport, 53, "UDP", "DGA_Domains_and_DNS_Tunneling")

    def tls_implant(self, t, client, server):
        r, sport, port = self.rng, self.ephemeral(), self.rng.choice(MALWARE_TLS_PORTS)
        # At least two ClientHello anomalies so the sample is not indistinguishable from a browser
        anomalies = r.sample(["legacy", "few_ciphers", "no_sni", "few_ext", "odd_port"], r.randint(2, 5))
        version = r.choice([0x0301, 0x0302]) if "legacy" in anomalies else 0x0303
        ciphers = r.sample(MODERN_CIPHERS, r.randint(1, 4) if "few_ciphers" in anomalies else r.randint(8, 16))
        exts = {65281: b"\x00"} if "few_ext" in anomalies else {23: b"", 65281: b"\x00", 35: b"", 13: b"\x00\x02\x04\x01",
                                                                     10: b"\x00\x02\x00\x17"}
        sni = "" if "no_sni" in anomalies else r.choice(["update-srv.com", "cdn-static.net", self.benign_domain()])
        if "odd_port" in anomalies and port == 443:
            port = r.choice([4444, 8443, 9443, 7443])
        hello = build_client_hello(ciphers, extensions=exts, sni=sni, client_version=version)
        self.pkt(t, client, server, sport, port, payload=hello)
        for _ in range(r.randint(4, 30)):
            t += r.uniform(0.05, 3)
            self.pkt(t, client, server, sport, port, size=r.randint(80, 700))
        self.label(client, server, sport, port, "TCP", "Encrypted_Malware_TLS")

    def exfiltration(self, t, client, server):
        r, sport, port = self.rng, self.ephemeral(), self.rng.choice(EXFIL_PORTS)
        if r.random() < 0.35:  # low and slow: sustained paced egress over minutes (100-500 KB)
            n, size, gap = r.randint(150, 500), (600, 1100), (0.2, 0.8)
        else:  # bulk: 0.5-5 MB in a burst
            n, size, gap = r.randint(400, 3000), (1100, 1514), (0.0005, 0.01)
        for _ in range(n):
            t += r.uniform(*gap)
            self.pkt(t, client, server, sport, port, size=r.randint(*size))
        self.label(client, server, sport, port, "TCP", "Data_Exfiltration")

    # ---------- host-level attacks (labelled by host and time span) ----------
    def ddos(self, t, target):
        r = self.rng
        rate, duration = r.uniform(120, 1500), r.uniform(1.0, 3.0)
        udp = r.random() < 0.3
        bots = [self.public_ip() for _ in range(r.choice([1, r.randint(5, 40), r.randint(40, 300)]))]
        port = r.choice([80, 443, 53, 8080]) if not udp else r.choice([53, 123, 80, 1900])
        ts, end = t, t + duration
        while ts < end:
            ts += r.expovariate(rate)
            src = r.choice(bots)
            if udp:
                self.pkt(ts, src, target, r.randint(1024, 65535), port, "UDP", size=r.randint(60, 600))
            else:
                self.pkt(ts, src, target, r.randint(1024, 65535), port, flags={"SYN": True}, size=60)
        self.host_labels.append((target, "Volumetric_Protocol_DDoS", t, end))

    def port_scan(self, t, scanner):
        r = self.rng
        kind = r.choice(["vertical", "vertical", "horizontal", "slow"])
        udp = r.random() < 0.2
        proto = "UDP" if udp else "TCP"
        flags = {} if udp else {"SYN": True}
        if kind == "horizontal":
            port, hosts = r.choice([22, 445, 3389, 23, 80, 5900]), [self.private_ip() for _ in range(r.randint(20, 120))]
            span = r.uniform(0.5, 2.5)
            for host in hosts:
                self.pkt(t + r.uniform(0, span), scanner, host, self.ephemeral(), port, proto, flags=flags, size=60)
        else:
            target = self.private_ip()
            count = r.randint(10, 300) if kind == "vertical" else r.randint(10, 18)
            span = r.uniform(0.3, 2.5) if kind == "vertical" else r.uniform(2.0, 2.8)
            for port in r.sample(range(1, 10000), count):
                self.pkt(t + r.uniform(0, span), scanner, target, self.ephemeral(), port, proto, flags=flags, size=60)
        self.host_labels.append((scanner, "Reconnaissance_Port_Scanning", t, t + 3.0))


# ---------- dataset builders ----------

def _flows_from_packets(packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Same flow cutting as the live pipeline (idle 15 s, active 120 s, idle sweep every 500 packets)."""
    agg, flows = FlowAggregator(), []
    for i, pkt in enumerate(sorted(packets, key=lambda p: p["timestamp"]), 1):
        expired = agg.process_packet(pkt)
        if expired:
            flows.append(expired)
        if i % 500 == 0:
            flows.extend(agg.flush_expired(pkt["timestamp"]))
    flows.extend(agg.flush_all())
    return flows


def build_flow_dataset(seed: int, episodes: int = 60, return_raw: bool = False):
    """X, y (and, with return_raw, the (flow, features, context) behind each row for rule scoring)."""
    rng, fx = random.Random(seed), FeatureExtractor()
    X, y, raw = [], [], []
    for ep in range(episodes):
        b = ScenarioBuilder(rng, t0=1_700_000_000.0 + ep * 10_000)
        t = b.t0
        clients = [b.private_ip() for _ in range(rng.randint(3, 8))]
        resolver = rng.choice(["8.8.8.8", "1.1.1.1", b.private_ip()])
        for _ in range(rng.randint(40, 70)):
            c, when = rng.choice(clients), t + rng.uniform(0, 200)
            kind = rng.random()
            if kind < 0.35:
                b.dns_lookup(when, c, resolver)
            elif kind < 0.62:
                b.https_session(when, c, b.public_ip(), legacy=rng.random() < 0.2)
            elif kind < 0.67:
                b.http_download(when, c, b.public_ip())
            elif kind < 0.72:
                b.web_upload(when, c, b.public_ip())
            elif kind < 0.78:
                b.ssh_typing(when, c, b.public_ip())
            elif kind < 0.86:
                b.app_heartbeat(when, c, b.public_ip())
            elif kind < 0.89:
                b.monitoring_pings(when, c)
            elif kind < 0.92:
                b.p2p_download(when, c)
            elif kind < 0.94:
                b.lan_copy(when, c)
            elif kind < 0.97:
                b.tcp_keepalive(when, c, b.public_ip())
            else:
                b.lan_discovery(when, c)
        for _ in range(rng.randint(12, 20)):
            c, when = rng.choice(clients), t + rng.uniform(0, 200)
            attack = rng.choice(["c2", "dga", "dga", "tls", "exfil"])
            if attack == "c2":
                b.c2_beacon(when, c, b.public_ip())
            elif attack == "dga":
                b.dga_query(when, c, resolver)
            elif attack == "tls":
                b.tls_implant(when, c, b.public_ip())
            else:
                b.exfiltration(when, c, b.public_ip())
        for flow in _flows_from_packets(b.packets):
            key = (flow["src_ip"], flow["dst_ip"], flow["src_port"], flow["dst_port"], flow["protocol"])
            label = b.flow_labels.get(key)
            if label is None:
                continue
            features = fx.extract_flow_features(flow)
            X.append(flow_vector(features))
            y.append(label)
            if return_raw:
                raw.append((flow, features, fx.extract_context(flow)))
    return (X, y, raw) if return_raw else (X, y)


def build_host_dataset(seed: int, episodes: int = 160, return_raw: bool = False):
    """X, y (and, with return_raw, the (target, source) window aggregates behind each row)."""
    rng = random.Random(seed)
    X, y, raw = [], [], []
    for ep in range(episodes):
        b = ScenarioBuilder(rng, t0=1_700_000_000.0 + ep * 10_000)
        t, duration = b.t0, 9.0
        clients = [b.private_ip() for _ in range(rng.randint(3, 10))]
        servers = [b.public_ip() for _ in range(rng.randint(2, 5))]
        for s in servers:
            if rng.random() < 0.6:
                b.busy_server(t, s, duration)
        for c in clients:
            if rng.random() < 0.5:
                b.browser_fanout(t + rng.uniform(0, 6), c)
            for _ in range(rng.randint(2, 6)):
                b.https_session(t + rng.uniform(0, duration), c, rng.choice(servers))
        roll = rng.random()
        if roll < 0.4:
            b.ddos(t + rng.uniform(1, 5), rng.choice(servers))
        elif roll < 0.8:
            b.port_scan(t + rng.uniform(1, 5), b.private_ip())
        packets = sorted(b.packets, key=lambda p: p["timestamp"])
        wm = SlidingWindowManager()
        windows = []
        for pkt in packets:
            for win in wm.add_item(pkt):
                windows.append((win, wm.last_window_bounds))
        rest = wm.flush_remaining()
        if rest:
            windows.append((rest, wm.last_window_bounds))
        for win, (start, end) in windows:
            agg = aggregate_window(win, start)
            for host in sorted(set(agg["by_target"]) | set(agg["by_source"])):
                label = "benign"
                for ip, cls, t_start, t_end in b.host_labels:
                    # A window that only grazes the attack edge carries too little of it to be a label
                    if ip == host and min(end, t_end) - max(start, t_start) >= 0.8:
                        label = cls
                target, source = agg["by_target"].get(host), agg["by_source"].get(host)
                # Same candidate filter as serving; benign candidates are the hard negatives
                if not is_host_candidate(target, source):
                    continue
                X.append(host_vector(target, source))
                y.append(label)
                if return_raw:
                    raw.append((target, source))
    return (X, y, raw) if return_raw else (X, y)
