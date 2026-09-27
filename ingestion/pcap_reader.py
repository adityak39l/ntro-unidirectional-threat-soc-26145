import os
import socket
from typing import Generator, Dict, Any, Optional

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

def inet_to_str(inet: bytes) -> str:
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except Exception:
        try:
            return socket.inet_ntop(socket.AF_INET6, inet)
        except Exception:
            return "0.0.0.0"

class ReadOnlyPacketReader:
    def __init__(self, filepath: str):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        self.filepath = filepath

    def read_packets(self) -> Generator[Dict[str, Any], None, None]:
        if not DPKT_AVAILABLE:
            raise RuntimeError("dpkt library is required for passive packet reading.")

        with open(self.filepath, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except Exception:
                f.seek(0)
                pcap = dpkt.pcapng.Reader(f)

            for ts, buf in pcap:
                pkt = self._parse_packet(ts, buf)
                if pkt:
                    yield pkt

    def _parse_packet(self, ts: float, buf: bytes) -> Optional[Dict[str, Any]]:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return None

            src_ip = inet_to_str(ip.src)
            dst_ip = inet_to_str(ip.dst)
            proto_name = "OTHER"
            src_port = 0
            dst_port = 0
            tcp_flags = {}
            payload_len = len(ip.data)
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
            elif isinstance(ip.data, dpkt.icmp.ICMP):
                proto_name = "ICMP"

            return {
                "timestamp": float(ts),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto_name,
                "packet_length": len(buf),
                "payload_length": payload_len,
                "tcp_flags": tcp_flags,
                "raw_payload": raw_payload
            }
        except Exception:
            return None
