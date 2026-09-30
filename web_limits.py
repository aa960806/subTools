"""Single-worker rate budget for expensive authenticated operations."""
from collections import deque
import math
import threading
import time


class RequestBudget:
    def __init__(self, limit, window=60):
        self.limit, self.window = limit, window
        self.hits = deque()
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            now = time.monotonic()
            while self.hits and self.hits[0] <= now - self.window:
                self.hits.popleft()
            if len(self.hits) >= self.limit:
                return max(1, math.ceil(self.hits[0] + self.window - now))
            self.hits.append(now)
            return 0
