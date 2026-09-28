from typing import Dict, Tuple, List, Optional, Any

# A TLS ClientHello fits in one record; cap what we keep per flow
MAX_CLIENT_HELLO_BYTES = 16384


def looks_like_client_hello(payload: bytes) -> bool:
    # TLS record type 0x16 (handshake), major version 3, handshake type 1 (ClientHello)
    return len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01


class NetworkFlow:
    def __init__(self, key: Tuple, first_packet: Dict[str, Any]):
        self.key = key
        self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol = key
        self.start_time = first_packet["timestamp"]
        self.last_time = first_packet["timestamp"]
        
        self.packet_count = 0
        self.total_bytes = 0
        self.payload_bytes = 0
        self.packet_lengths: List[int] = []
        self.inter_arrival_times: List[float] = []
        
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.payload_samples: List[bytes] = []
        self.tls_client_hello: bytes = b""

        self.add_packet(first_packet)

    def add_packet(self, pkt: Dict[str, Any]):
        current_ts = pkt["timestamp"]
        if self.packet_count > 0:
            iat = max(0.0, current_ts - self.last_time)
            self.inter_arrival_times.append(iat)

        self.last_time = max(self.last_time, current_ts)
        self.packet_count += 1
        self.total_bytes += pkt["packet_length"]
        self.payload_bytes += pkt["payload_length"]
        self.packet_lengths.append(pkt["packet_length"])

        flags = pkt.get("tcp_flags", {})
        if flags.get("SYN"): self.syn_count += 1
        if flags.get("ACK"): self.ack_count += 1
        if flags.get("FIN"): self.fin_count += 1
        if flags.get("RST"): self.rst_count += 1
        if flags.get("PSH"): self.psh_count += 1

        raw = pkt.get("raw_payload")
        if raw:
            if len(self.payload_samples) < 5:
                self.payload_samples.append(raw[:512])
            if not self.tls_client_hello and looks_like_client_hello(raw):
                self.tls_client_hello = raw[:MAX_CLIENT_HELLO_BYTES]

    @property
    def duration(self) -> float:
        return max(0.0, self.last_time - self.start_time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}_{self.protocol}",
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "last_time": self.last_time,
            "duration": self.duration,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "payload_bytes": self.payload_bytes,
            "packet_lengths": self.packet_lengths,
            "inter_arrival_times": self.inter_arrival_times,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "psh_count": self.psh_count,
            "payload_samples": self.payload_samples,
            "tls_client_hello": self.tls_client_hello
        }

class FlowAggregator:
    def __init__(self, idle_timeout: float = 15.0, active_timeout: float = 120.0):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.active_flows: Dict[Tuple, NetworkFlow] = {}

    def process_packet(self, pkt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key = (pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"], pkt["protocol"])
        expired_flow = None

        if key in self.active_flows:
            flow = self.active_flows[key]
            if (pkt["timestamp"] - flow.start_time) >= self.active_timeout:
                expired_flow = flow.to_dict()
                self.active_flows[key] = NetworkFlow(key, pkt)
            else:
                flow.add_packet(pkt)
        else:
            self.active_flows[key] = NetworkFlow(key, pkt)

        return expired_flow

    def flush_expired(self, current_time: float) -> List[Dict[str, Any]]:
        flushed = []
        keys_to_remove = []
        for key, flow in self.active_flows.items():
            if (current_time - flow.last_time) >= self.idle_timeout:
                flushed.append(flow.to_dict())
                keys_to_remove.append(key)

        for k in keys_to_remove:
            del self.active_flows[k]

        return flushed

    def flush_all(self) -> List[Dict[str, Any]]:
        flushed = [flow.to_dict() for flow in self.active_flows.values()]
        self.active_flows.clear()
        return flushed
