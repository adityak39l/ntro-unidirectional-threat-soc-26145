import math
from collections import Counter, defaultdict
from typing import Dict, Any, List


def _shannon(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def _is_probe(pkt: Dict[str, Any]) -> bool:
    # A packet that opens a conversation without carrying data: SYN-only, empty UDP, or ICMP
    flags = pkt.get("tcp_flags") or {}
    if pkt["protocol"] == "TCP":
        return bool(flags.get("SYN")) and not flags.get("ACK")
    if pkt["protocol"] == "UDP":
        return pkt.get("payload_length", 0) == 0
    return pkt["protocol"] == "ICMP"


def aggregate_window(packets: List[Dict[str, Any]], window_start: float) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Host-level aggregates for one sliding window.

    by_target: fan-in to each destination (DDoS view)
    by_source: fan-out from each source (reconnaissance view)
    """
    targets: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "packets": 0, "bytes": 0, "syn_only": 0, "udp": 0,
        "sources": Counter(), "dst_ports": Counter(), "protocols": Counter(), "per_second": Counter(),
        "first_ts": float("inf"), "last_ts": 0.0,
    })
    sources: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "packets": 0, "probes": 0, "targets": set(), "host_ports": defaultdict(set), "port_hosts": defaultdict(set),
        "protocols": Counter(), "first_ts": float("inf"), "last_ts": 0.0,
    })

    for pkt in packets:
        ts = pkt["timestamp"]
        flags = pkt.get("tcp_flags") or {}
        dst, src = pkt["dst_ip"], pkt["src_ip"]

        t = targets[dst]
        t["packets"] += 1
        t["bytes"] += pkt.get("packet_length", 0)
        if flags.get("SYN") and not flags.get("ACK"):
            t["syn_only"] += 1
        if pkt["protocol"] == "UDP":
            t["udp"] += 1
        t["sources"][src] += 1
        t["dst_ports"][pkt.get("dst_port", 0)] += 1
        t["protocols"][pkt["protocol"]] += 1
        t["per_second"][int(ts - window_start)] += 1
        t["first_ts"] = min(t["first_ts"], ts)
        t["last_ts"] = max(t["last_ts"], ts)

        s = sources[src]
        s["packets"] += 1
        if _is_probe(pkt):
            s["probes"] += 1
            s["host_ports"][dst].add(pkt.get("dst_port", 0))
            s["port_hosts"][pkt.get("dst_port", 0)].add(dst)
        s["targets"].add(dst)
        s["protocols"][pkt["protocol"]] += 1
        s["first_ts"] = min(s["first_ts"], ts)
        s["last_ts"] = max(s["last_ts"], ts)

    by_target = {}
    for dst, t in targets.items():
        n = t["packets"]
        by_target[dst] = {
            "dst_ip": dst,
            "packets": n,
            "bytes": t["bytes"],
            "peak_pps": max(t["per_second"].values()),
            "syn_only_ratio": t["syn_only"] / n,
            "udp_ratio": t["udp"] / n,
            "unique_sources": len(t["sources"]),
            "source_ip_entropy": _shannon(t["sources"]),
            "top_sources": [ip for ip, _ in t["sources"].most_common(5)],
            "top_dst_port": t["dst_ports"].most_common(1)[0][0],
            "protocol": t["protocols"].most_common(1)[0][0],
            "first_ts": t["first_ts"],
            "last_ts": t["last_ts"],
        }

    by_source = {}
    for src, s in sources.items():
        n = s["packets"]
        vertical_host, vertical_ports = max(s["host_ports"].items(), key=lambda kv: len(kv[1]), default=("", set()))
        horizontal_port, horizontal_hosts = max(s["port_hosts"].items(), key=lambda kv: len(kv[1]), default=(0, set()))
        by_source[src] = {
            "src_ip": src,
            "packets": n,
            "probe_ratio": s["probes"] / n,
            "unique_targets": len(s["targets"]),
            "max_ports_on_one_host": len(vertical_ports),
            "vertical_target": vertical_host,
            "probed_ports": sorted(vertical_ports),
            "max_hosts_on_one_port": len(horizontal_hosts),
            "horizontal_port": horizontal_port,
            "protocol": s["protocols"].most_common(1)[0][0],
            "first_ts": s["first_ts"],
            "last_ts": s["last_ts"],
        }

    return {"by_target": by_target, "by_source": by_source}
