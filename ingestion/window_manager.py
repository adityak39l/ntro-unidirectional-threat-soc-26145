import math
from typing import List, Dict, Any, Generator, Optional, Tuple


def _item_ts(item: Dict[str, Any]) -> float:
    return item.get("timestamp") or item.get("last_time") or 0.0


class SlidingWindowManager:
    def __init__(self, window_size: float = 3.0, slide_interval: float = 1.0):
        self.window_size = window_size
        self.slide_interval = slide_interval
        self.current_window_start: Optional[float] = None
        self.buffer: List[Dict[str, Any]] = []
        # (start, end) of the window most recently yielded by add_item
        self.last_window_bounds: Tuple[float, float] = (0.0, 0.0)

    def add_item(self, item: Dict[str, Any]) -> Generator[List[Dict[str, Any]], None, None]:
        ts = _item_ts(item)
        if self.current_window_start is None:
            self.current_window_start = ts

        self.buffer.append(item)

        while ts >= (self.current_window_start + self.window_size):
            window_end = self.current_window_start + self.window_size
            window_slice = [
                x for x in self.buffer
                if self.current_window_start <= _item_ts(x) < window_end
            ]
            if window_slice:
                self.last_window_bounds = (self.current_window_start, window_end)
                yield window_slice

            next_start = self.current_window_start + self.slide_interval
            self.buffer = [x for x in self.buffer if _item_ts(x) >= next_start]

            # Skip over idle gaps in the capture instead of emitting empty windows
            earliest = min(_item_ts(x) for x in self.buffer)
            gap = earliest - self.window_size - next_start
            if gap >= 0:
                next_start += (math.floor(gap / self.slide_interval) + 1) * self.slide_interval
            self.current_window_start = next_start

    def flush_remaining(self) -> List[Dict[str, Any]]:
        start = self.current_window_start or 0.0
        self.last_window_bounds = (start, start + self.window_size)
        remaining = list(self.buffer)
        self.buffer.clear()
        return remaining
