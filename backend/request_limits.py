"""Bounded per-peer request admission for a single-process deployment."""
import threading
import time
from collections import deque


class PeerLimiter:
    def __init__(self, limit=30, window=60, capacity=2048):
        self.limit, self.window, self.capacity = limit, window, capacity
        self.entries, self.lock = {}, threading.Lock()

    def allow(self, peer, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            for key in list(self.entries):
                queue = self.entries[key]
                while queue and queue[0] <= now-self.window: queue.popleft()
                if not queue: del self.entries[key]
            if peer not in self.entries:
                if len(self.entries) >= self.capacity: return False
                self.entries[peer] = deque()
            queue = self.entries[peer]
            if len(queue) >= self.limit: return False
            queue.append(now)
            return True

    def reset(self):
        with self.lock: self.entries.clear()
