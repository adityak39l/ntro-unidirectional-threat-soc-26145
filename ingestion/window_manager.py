from typing import List, Dict, Any, Generator

class SlidingWindowManager:
    def __init__(self, window_size: float = 3.0, slide_interval: float = 1.0):
        self.window_size = window_size
        self.slide_interval = slide_interval
        self.current_window_start: float = 0.0
        self.buffer: List[Dict[str, Any]] = []

    def add_item(self, item: Dict[str, Any]) -> Generator[List[Dict[str, Any]], None, None]:
        ts = item.get("timestamp") or item.get("last_time") or 0.0
        if not self.current_window_start:
            self.current_window_start = ts

        self.buffer.append(item)

        while ts >= (self.current_window_start + self.window_size):
            window_end = self.current_window_start + self.window_size
            window_slice = [
                x for x in self.buffer
                if (x.get("timestamp") or x.get("last_time") or 0.0) >= self.current_window_start
                and (x.get("timestamp") or x.get("last_time") or 0.0) < window_end
            ]
            yield window_slice

            self.current_window_start += self.slide_interval
            self.buffer = [
                x for x in self.buffer
                if (x.get("timestamp") or x.get("last_time") or 0.0) >= self.current_window_start
            ]

    def flush_remaining(self) -> List[Dict[str, Any]]:
        remaining = list(self.buffer)
        self.buffer.clear()
        return remaining
