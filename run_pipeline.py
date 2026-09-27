import os
import sys
import time
from ingestion.pcap_reader import ReadOnlyPacketReader
from detection.pipeline import StreamingDetectionPipeline


def main():
    pcap_path = "data/pcaps/simulated_traffic.pcap"
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]

    if not os.path.exists(pcap_path):
        print(f"Error: PCAP not found: {pcap_path}")
        return

    print("=" * 60)
    print("AI-BASED DETECTION OF CYBER THREATS IN UNIDIRECTIONAL IP TRAFFIC")
    print("NTRO | SIH Problem Statement ID: 26145")
    print("=" * 60)
    print(f"[*] Ingesting Passive Traffic Stream from: {pcap_path}")

    pipeline = StreamingDetectionPipeline(
        alert_jsonl="data/alerts.jsonl",
        alert_db="data/alerts.db"
    )
    reader = ReadOnlyPacketReader(pcap_path)

    start_time = time.time()
    packet_count = 0

    for pkt in reader.read_packets():
        packet_count += 1
        alerts = pipeline.process_packet(pkt)
        for a in alerts:
            print(f"[!] ALERT: [{a['severity']}] {a['threat_class']} | Src: {a['src_ip']} -> Dst: {a['dst_ip']} | Conf: {a['confidence_score']:.2f}")

    # Flush final remaining flows
    final_alerts = pipeline.flush_and_complete()
    for a in final_alerts:
        print(f"[!] ALERT: [{a['severity']}] {a['threat_class']} | Src: {a['src_ip']} -> Dst: {a['dst_ip']} | Conf: {a['confidence_score']:.2f}")

    elapsed = max(0.001, time.time() - start_time)
    stats = pipeline.get_stats()

    print("\n" + "=" * 60)
    print("STREAMING INFERENCE SUMMARY & BENCHMARKS")
    print("=" * 60)
    print(f"Total Packets Ingested:    {packet_count}")
    print(f"Total Flows Tracked:       {stats['total_flows']}")
    print(f"Total Threat Alerts Fired: {stats['total_alerts']}")
    print(f"Elapsed Processing Time:   {elapsed:.3f} seconds")
    print(f"Throughput (Packets/sec):  {packet_count / elapsed:.2f} pkts/sec")
    print(f"Throughput (Flows/sec):    {stats['total_flows'] / elapsed:.2f} flows/sec")
    print("Alerts written to:         data/alerts.jsonl & data/alerts.db")
    print("=" * 60)


if __name__ == "__main__":
    main()