import pytest
from ingestion.flow_aggregator import FlowAggregator, NetworkFlow
from ingestion.window_manager import SlidingWindowManager

def test_network_flow_creation():
    pkt = {
        "timestamp": 1000.0,
        "src_ip": "192.168.1.10",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 80,
        "protocol": "TCP",
        "packet_length": 64,
        "payload_length": 0,
        "tcp_flags": {"SYN": True, "ACK": False},
        "raw_payload": b""
    }
    key = ("192.168.1.10", "10.0.0.1", 54321, 80, "TCP")
    flow = NetworkFlow(key, pkt)
    
    assert flow.packet_count == 1
    assert flow.syn_count == 1
    assert flow.total_bytes == 64
    assert flow.duration == 0.0

def test_flow_aggregation_and_iat():
    aggregator = FlowAggregator(idle_timeout=5.0, active_timeout=30.0)
    
    pkt1 = {
        "timestamp": 100.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "192.168.1.1",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_length": 100,
        "payload_length": 50,
        "tcp_flags": {"SYN": True},
        "raw_payload": b"hello"
    }
    pkt2 = {
        "timestamp": 100.5,
        "src_ip": "10.0.0.5",
        "dst_ip": "192.168.1.1",
        "src_port": 12345,
        "dst_port": 443,
        "protocol": "TCP",
        "packet_length": 200,
        "payload_length": 150,
        "tcp_flags": {"ACK": True},
        "raw_payload": b"world"
    }
    
    aggregator.process_packet(pkt1)
    aggregator.process_packet(pkt2)
    
    flows = aggregator.flush_all()
    assert len(flows) == 1
    flow_dict = flows[0]
    assert flow_dict["packet_count"] == 2
    assert flow_dict["total_bytes"] == 300
    assert len(flow_dict["inter_arrival_times"]) == 1
    assert flow_dict["inter_arrival_times"][0] == 0.5

def test_sliding_window_manager():
    wm = SlidingWindowManager(window_size=3.0, slide_interval=1.0)
    
    slices = []
    items = [
        {"timestamp": 1.0, "data": "pkt1"},
        {"timestamp": 2.0, "data": "pkt2"},
        {"timestamp": 4.5, "data": "pkt3"},
    ]
    for item in items:
        for s in wm.add_item(item):
            slices.append(s)
            
    assert len(slices) >= 1
    assert len(slices[0]) == 2


def test_sliding_window_skips_idle_gaps():
    wm = SlidingWindowManager(window_size=3.0, slide_interval=1.0)
    slices = []
    for ts in (1.0, 2.0, 3600.0, 3605.0):
        slices.extend(wm.add_item({"timestamp": ts}))
    # A packet belongs to up to 3 overlapping windows (3 s / 1 s slide); the hour-long
    # gap must not produce ~3600 empty windows
    assert all(slices)
    assert len(slices) <= 6


def _write_pcap(path, linktype, frames):
    import dpkt
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=linktype)
        for ts, buf in frames:
            writer.writepkt(buf, ts=ts)


def _tcp_syn_ip(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02"):
    import dpkt
    tcp = dpkt.tcp.TCP(sport=1234, dport=80, flags=dpkt.tcp.TH_SYN)
    ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
    ip.len = len(ip)
    return ip


def test_pcap_reader_handles_raw_ip_and_linux_cooked(tmp_path):
    import dpkt
    from ingestion.pcap_reader import ReadOnlyPacketReader

    raw_path = str(tmp_path / "raw.pcap")
    _write_pcap(raw_path, 101, [(1.0, bytes(_tcp_syn_ip()))])
    pkts = list(ReadOnlyPacketReader(raw_path).read_packets())
    assert len(pkts) == 1 and pkts[0]["dst_port"] == 80 and pkts[0]["tcp_flags"]["SYN"]

    sll = dpkt.sll.SLL(type=0, hrd=1, hlen=6, hdr=b"\x00" * 8, ethtype=0x0800, data=_tcp_syn_ip())
    sll_path = str(tmp_path / "sll.pcap")
    _write_pcap(sll_path, 113, [(1.0, bytes(sll))])
    pkts = list(ReadOnlyPacketReader(sll_path).read_packets())
    assert len(pkts) == 1 and pkts[0]["src_ip"] == "10.0.0.1"


def test_pcap_reader_respects_packet_cap(tmp_path):
    import dpkt
    from ingestion.pcap_reader import ReadOnlyPacketReader
    eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6, type=0x0800, data=_tcp_syn_ip())
    path = str(tmp_path / "eth.pcap")
    _write_pcap(path, 1, [(float(i), bytes(eth)) for i in range(10)])
    reader = ReadOnlyPacketReader(path, max_packets=4)
    assert len(list(reader.read_packets())) == 4
    assert reader.truncated is True
