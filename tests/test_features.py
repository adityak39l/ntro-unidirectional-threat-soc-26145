import pytest
from feature_engine.dns_analyzer import DNSAnalyzer, calculate_entropy
from feature_engine.tls_fingerprint import TLSFingerprinter
from feature_engine.feature_extractor import FeatureExtractor


def test_shannon_entropy():
    assert calculate_entropy("") == 0.0
    # Repeating string has low entropy
    assert calculate_entropy("aaaaaaa") == 0.0
    # Random DGA-like string has high entropy (> 3.5)
    random_str = "x8f7z9q1v3k2m4"
    assert calculate_entropy(random_str) > 3.0


def test_dns_domain_analysis():
    normal_domain = "google.com"
    res1 = DNSAnalyzer.analyze_domain(normal_domain)
    assert res1["query_length"] == len(normal_domain)
    assert res1["has_consecutive_consonants"] is False

    dga_domain = "vxzqplmktrfdsa992.biz"
    res2 = DNSAnalyzer.analyze_domain(dga_domain)
    assert res2["entropy"] > res1["entropy"]
    assert res2["has_consecutive_consonants"] is True


def test_splt_extraction():
    lengths = [100, 200, 300]
    splt = TLSFingerprinter.extract_splt(lengths, max_packets=5)
    assert len(splt) == 5
    assert splt[:3] == [100, 200, 300]
    assert splt[3:] == [0, 0]


def test_feature_extractor_pipeline():
    flow = {
        "flow_id": "192.168.1.1:1234->10.0.0.1:80_TCP",
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "duration": 2.0,
        "packet_count": 10,
        "total_bytes": 1000,
        "payload_bytes": 600,
        "packet_lengths": [100] * 10,
        "inter_arrival_times": [0.2] * 9,
        "syn_count": 1,
        "ack_count": 9,
        "payload_samples": []
    }
    
    extractor = FeatureExtractor(splt_length=10)
    features = extractor.extract_flow_features(flow)

    assert "packet_count" in features
    assert features["packet_count"] == 10.0
    assert features["packets_per_second"] == 5.0
    assert features["iat_variance"] == 0.0
    assert "splt_0" in features
    assert features["splt_0"] == 100.0
