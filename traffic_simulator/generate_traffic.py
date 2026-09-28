import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from feature_engine.tls_fingerprint import build_client_hello

try:
    from scapy.all import wrpcap, Ether, IP, TCP, UDP, DNS, DNSQR, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Browser-like ClientHello: TLS 1.2 handshake version, GREASE, SNI, modern AEAD suites
BENIGN_CIPHERS = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
                  0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035]
BENIGN_EXTENSIONS = {23: b"", 65281: b"\x00", 35: b"", 16: b"\x00\x0c\x02h2\x08http/1.1",
                     13: b"\x00\x08\x04\x03\x08\x04\x04\x01\x05\x03", 43: b"\x06\x03\x04\x03\x03\x03\x02"}


def benign_client_hello(sni: str) -> bytes:
    return build_client_hello(BENIGN_CIPHERS, extensions=BENIGN_EXTENSIONS, sni=sni,
                              groups=[0x1A1A, 29, 23, 24], point_formats=[0])


def implant_client_hello() -> bytes:
    # Legacy TLS 1.0 handshake, two suites, no SNI, one extension: typical of hand-rolled C2 stagers
    return build_client_hello([0xC02F, 0xC030], extensions={65281: b"\x00"}, client_version=0x0301)


def generate_synthetic_pcap(attack_type: str = "all", output_path: str = "data/pcaps/simulated_traffic.pcap"):
    if not SCAPY_AVAILABLE:
        print("Scapy is required to generate synthetic PCAP files.")
        return 0

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = []
    base_time = time.time()
    rand_id = random.randint(10, 99)

    # 1. Benign Traffic (baseline normal activity)
    if attack_type in ["all", "benign"]:
        benign_domains = ["google.com", "github.com", "microsoft.com", "wikipedia.org", "cloudflare.com"]
        for i in range(20):
            t = base_time + (i * 0.1)
            dom = random.choice(benign_domains)
            dns_pkt = Ether()/IP(src=f"192.168.1.{rand_id}", dst="8.8.8.8")/UDP(sport=random.randint(40000, 60000), dport=53)/DNS(rd=1, qd=DNSQR(qname=dom))
            dns_pkt.time = t
            packets.append(dns_pkt)

        # Normal HTTPS sessions: ClientHello with SNI then irregular (human-driven) data packets
        benign_sites = ["www.google.com", "github.com", "www.wikipedia.org", "ntro.gov.in", "www.cloudflare.com"]
        for k, site in enumerate(benign_sites):
            sport = random.randint(40000, 60000)
            dst = f"142.250.{k}.{random.randint(1, 254)}"
            t = base_time + 0.05 + k * 0.3
            hello = Ether()/IP(src=f"192.168.1.{rand_id}", dst=dst)/TCP(sport=sport, dport=443, flags="PA")/Raw(load=benign_client_hello(site))
            hello.time = t
            packets.append(hello)
            for _ in range(10):
                t += random.expovariate(1 / 0.4)
                data = Ether()/IP(src=f"192.168.1.{rand_id}", dst=dst)/TCP(sport=sport, dport=443, flags="PA")/Raw(load=b"\x17\x03\x03" + os.urandom(random.randint(40, 900)))
                data.time = t
                packets.append(data)

    # 2. Volumetric DDoS (SYN Flood) — T1498: ~500 pps of half-open SYNs from ~200 spoofed bots
    if attack_type in ["all", "ddos"]:
        ddos_start = base_time + 1.0
        bots = [f"172.16.{random.randint(1, 10)}.{random.randint(1, 254)}" for _ in range(200)]
        for i in range(600):
            t = ddos_start + (i * 0.002)
            src_ip = random.choice(bots)
            syn_pkt = Ether()/IP(src=src_ip, dst="10.0.0.1")/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
            syn_pkt.time = t
            packets.append(syn_pkt)

    # 3. Botnet C2 Beaconing (Strict Periodicity) — T1071
    if attack_type in ["all", "beaconing"]:
        beacon_start = base_time + 2.0
        c2_ip = f"198.51.100.{rand_id}"
        for i in range(10):
            t = beacon_start + (i * 2.0)
            c2_pkt = Ether()/IP(src=f"192.168.1.{rand_id}", dst=c2_ip)/TCP(sport=48922, dport=4444, flags="PA")/Raw(load=b"\x00\x01BEACON_CHECKIN_CMD")
            c2_pkt.time = t
            packets.append(c2_pkt)

    # 4. DGA Domains & DNS Tunneling — T1568
    if attack_type in ["all", "dga"]:
        dga_start = base_time + 3.0
        dga_samples = [
            f"vxzq{random.randint(100,999)}pkm.biz",
            f"qweasd{random.randint(1000,9999)}rty.info",
            f"mnbv{random.randint(100,999)}lkjh.org",
            f"d8f3k{random.randint(10,99)}mzpw0qka.net",
            f"xt7m{random.randint(100,999)}bvnq.xyz",
            f"kp9w{random.randint(10,99)}zjlm4h.club",
        ]
        for i, dga in enumerate(dga_samples):
            t = dga_start + (i * 0.2)
            pkt = Ether()/IP(src=f"192.168.2.{rand_id}", dst="8.8.8.8")/UDP(sport=random.randint(40000, 60000), dport=53)/DNS(rd=1, qd=DNSQR(qname=dga))
            pkt.time = t
            packets.append(pkt)

        # DNS tunneling: stolen data base32-encoded into long subdomain labels
        tunnel_host = f"192.168.2.{rand_id + 1}"
        for i in range(3):
            chunk = "".join(random.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(48))
            t = dga_start + 1.5 + (i * 0.3)
            pkt = Ether()/IP(src=tunnel_host, dst="8.8.4.4")/UDP(sport=random.randint(40000, 60000), dport=53)/DNS(rd=1, qd=DNSQR(qname=f"{chunk}.{i}.t.exfil-c2.net"))
            pkt.time = t
            packets.append(pkt)

    # 5. Port Scanning (Reconnaissance) — T1046
    if attack_type in ["all", "port_scan"]:
        scan_start = base_time + 4.0
        target_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
        for i, port in enumerate(target_ports):
            t = scan_start + (i * 0.05)
            scan_pkt = Ether()/IP(src=f"192.168.9.{rand_id}", dst="10.0.0.50")/TCP(sport=38291, dport=port, flags="S")
            scan_pkt.time = t
            packets.append(scan_pkt)

    # 6. Encrypted Malware (TLS metadata anomaly) — T1573
    if attack_type in ["all", "encrypted_malware"]:
        mal_start = base_time + 5.0
        suspicious_ports = [4444, 8443, 9443, 1443, 6667]
        mal_sport = random.randint(40000, 60000)
        mal_dport = random.choice(suspicious_ports)
        for i in range(15):
            payload = implant_client_hello() if i == 0 else b"\x17\x03\x01" + os.urandom(100)
            t = mal_start + (i * 0.4)
            mal_pkt = Ether()/IP(src=f"192.168.1.{rand_id}", dst=f"203.0.113.{rand_id}")/TCP(sport=mal_sport, dport=mal_dport, flags="PA")/Raw(load=payload)
            mal_pkt.time = t
            packets.append(mal_pkt)

    # 7. Data Exfiltration (large asymmetric outbound) — T1048
    if attack_type in ["all", "exfiltration"]:
        exfil_start = base_time + 6.0
        exfil_dst = f"198.51.100.{random.randint(1, 50)}"
        exfil_sport = random.randint(40000, 60000)
        for i in range(35):
            t = exfil_start + (i * 0.05)
            large_payload = os.urandom(1400)
            exfil_pkt = Ether()/IP(src=f"192.168.1.{rand_id}", dst=exfil_dst)/TCP(sport=exfil_sport, dport=443, flags="PA")/Raw(load=large_payload)
            exfil_pkt.time = t
            packets.append(exfil_pkt)

    packets.sort(key=lambda p: float(p.time))
    wrpcap(output_path, packets)
    return len(packets)


if __name__ == "__main__":
    count = generate_synthetic_pcap()
    print(f"Generated {count} packets.")
