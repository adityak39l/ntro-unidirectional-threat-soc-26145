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
