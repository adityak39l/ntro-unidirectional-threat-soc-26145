import time
from typing import Generator, Dict, Any
from ingestion.pcap_reader import ReadOnlyPacketReader

class TrafficStreamSimulator:
    def __init__(self, pcap_path: str, real_time_speed: float = 1.0):
        self.reader = ReadOnlyPacketReader(pcap_path)
        self.speed = real_time_speed

    def stream(self) -> Generator[Dict[str, Any], None, None]:
        prev_ts = None
        for pkt in self.reader.read_packets():
            if prev_ts is not None and self.speed > 0:
                delta = pkt["timestamp"] - prev_ts
                if 0 < delta < 2.0:
                    time.sleep(delta / self.speed)
            prev_ts = pkt["timestamp"]
            yield pkt
