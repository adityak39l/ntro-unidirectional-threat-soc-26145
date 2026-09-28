import os
import socket
from typing import Generator, Dict, Any, Optional

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

# Link-layer types seen in real-world captures (tcpdump -i any, tun/VPN, loopback)
LINKTYPE_ETHERNET = 1
LINKTYPE_NULL = 0
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
LINKTYPE_RAW_IP = {12, 14, 101, 228, 229}


def inet_to_str(inet: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except Exception:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except Exception:
            return "0.0.0.0"


class ReadOnlyPacketReader:
    def __init__(self, filepath: str, max_packets: Optional[int] = None):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        self.filepath = filepath
        self.max_packets = max_packets
        self.linktype = LINKTYPE_ETHERNET
        # Ingestion telemetry, populated while reading
        self.frames_read = 0
        self.packets_parsed = 0
        self.frames_skipped = 0
        self.truncated = False

    def read_packets(self) -> Generator[Dict[str, Any], None, None]:
        if not DPKT_AVAILABLE:
            raise RuntimeError("dpkt library is required for passive packet reading.")

        with open(self.filepath, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            try:
                self.linktype = pcap.datalink()
            except Exception:
                self.linktype = LINKTYPE_ETHERNET

            for ts, buf in pcap:
                if self.max_packets is not None and self.packets_parsed >= self.max_packets:
                    self.truncated = True
                    break
                self.frames_read += 1
                pkt = self._parse_packet(ts, buf)
                if pkt:
                    self.packets_parsed += 1
                    yield pkt
                else:
                    self.frames_skipped += 1

    def _decode_network_layer(self, buf: bytes):
        lt = self.linktype
        if lt == LINKTYPE_ETHERNET:
            return dpkt.ethernet.Ethernet(buf).data
        if lt == LINKTYPE_LINUX_SLL:
            return dpkt.sll.SLL(buf).data
        if lt == LINKTYPE_LINUX_SLL2:
            return dpkt.sll2.SLL2(buf).data
        if lt in (LINKTYPE_NULL, LINKTYPE_LOOP):
            return dpkt.loopback.Loopback(buf).data
        if lt in LINKTYPE_RAW_IP:
            version = buf[0] >> 4 if buf else 0
            if version == 4:
                return dpkt.ip.IP(buf)
            if version == 6:
                return dpkt.ip6.IP6(buf)
        return None

    def _parse_packet(self, ts: float, buf: bytes) -> Optional[Dict[str, Any]]:
        try:
            ip = self._decode_network_layer(buf)
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return None

            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            proto_name = "OTHER"
            src_port = 0
            dst_port = 0
            tcp_flags = {}
            raw_payload = b""

            if isinstance(ip.data, dpkt.tcp.TCP):
                proto_name = "TCP"
                src_port = ip.data.sport
                dst_port = ip.data.dport
                flags = ip.data.flags
                tcp_flags = {
                    "SYN": bool(flags & dpkt.tcp.TH_SYN),
                    "ACK": bool(flags & dpkt.tcp.TH_ACK),
                    "FIN": bool(flags & dpkt.tcp.TH_FIN),
                    "RST": bool(flags & dpkt.tcp.TH_RST),
                    "PSH": bool(flags & dpkt.tcp.TH_PUSH),
                    "URG": bool(flags & dpkt.tcp.TH_URG),
                }
                raw_payload = bytes(ip.data.data)
            elif isinstance(ip.data, dpkt.udp.UDP):
                proto_name = "UDP"
                src_port = ip.data.sport
                dst_port = ip.data.dport
                raw_payload = bytes(ip.data.data)
            elif isinstance(ip.data, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                proto_name = "ICMP"

            return {
                "timestamp": float(ts),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto_name,
                "packet_length": len(buf),
                # Application-layer bytes only (excludes L2/L3/L4 headers)
                "payload_length": len(raw_payload),
                "tcp_flags": tcp_flags,
                "raw_payload": raw_payload
            }
        except Exception:
            return None
