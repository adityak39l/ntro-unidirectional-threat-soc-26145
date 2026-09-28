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


def test_ja3_from_clienthello_filters_grease():
    from feature_engine.tls_fingerprint import build_client_hello
    hello = build_client_hello(
        [0x0A0A, 0x1301, 0xC02F], extensions={23: b"", 0x2A2A: b""}, sni="example.org",
        groups=[0x1A1A, 29, 23], point_formats=[0],
    )
    info = TLSFingerprinter.extract_ja3(hello)
    assert info["is_tls"] and info["complete"]
    assert info["sni"] == "example.org"
    # version, ciphers, extensions (SNI, groups, point formats, 23), curves, point formats; GREASE removed
    assert info["ja3_str"] == "771,4865-49199,0-10-11-23,29-23,0"
    import hashlib
    assert info["ja3_hash"] == hashlib.md5(info["ja3_str"].encode()).hexdigest()


def test_truncated_clienthello_is_tls_but_incomplete():
    from feature_engine.tls_fingerprint import build_client_hello
    hello = build_client_hello([0x1301, 0x1302], extensions={23: b""}, sni="example.org")
    info = TLSFingerprinter.extract_ja3(hello[:-10])
    assert info["is_tls"] is True
    assert info["complete"] is False
    assert info["ja3_hash"] == ""


def test_dga_scoring_separates_benign_and_generated_domains():
    benign = ["google.com", "microsoft.com", "stackoverflow.com", "cloudflare.com", "ntro.gov.in",
              "googleusercontent.com", "strengths.com", "d1a2b3c4e5f6.cloudfront.net"]
    generated = ["vxzq123pkm.biz", "qweasd1234rty.info", "mnbv123lkjh.org", "kp9w12zjlm4h.club"]
    for d in benign:
        assert len(DNSAnalyzer.analyze_domain(d)["dga_signals"]) < 3, d
    for d in generated:
        assert len(DNSAnalyzer.analyze_domain(d)["dga_signals"]) >= 3, d


def test_dns_tunnel_subdomain_detected():
    res = DNSAnalyzer.analyze_domain("mzxw6ytboi2dsnrzgq3tmnzygu4tsmjrgiztinjwg4.t.exfil-c2.net")
    assert res["is_tunnel_suspect"] is True
    assert DNSAnalyzer.analyze_domain("www.wikipedia.org")["is_tunnel_suspect"] is False
