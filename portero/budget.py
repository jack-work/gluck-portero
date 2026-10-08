#!/usr/bin/env python3
"""Keyed request budgets: a sliding window per key, with bounded memory.

A budget keyed by the empty string is a whole-endpoint flood ceiling. A budget
keyed by a nonce spends against one invite and nothing else, so one caller
cannot exhaust another's allowance.

Keys are only ever created for inputs the caller has already proven something
about, because an unbounded key space is itself a denial of service. `max_keys`
is the hard backstop: least-recently-used keys are evicted past it.
"""

import threading
import time
from collections import OrderedDict, deque


class Budget:
    def __init__(self, limit, window, max_keys=4096):
        self.limit = int(limit)
        self.window = float(window)
        self.max_keys = int(max_keys)
        self._lock = threading.Lock()
        self._keys = OrderedDict()
        self._last_sweep = None

    def spend(self, key="", now=None):
        """Charge one request. True if it is within budget."""
        now = float(now if now is not None else time.monotonic())
        cutoff = now - self.window
        with self._lock:
            if self._last_sweep is None or now - self._last_sweep >= self.window:
                self._sweep(cutoff)
                self._last_sweep = now
            hits = self._keys.get(key)
            if hits is None:
                hits = deque()
                self._keys[key] = hits
            self._keys.move_to_end(key)
            while hits and hits[0] < cutoff:
                hits.popleft()
            allowed = len(hits) < self.limit
            if allowed:
                hits.append(now)
            if not hits:
                del self._keys[key]
            while len(self._keys) > self.max_keys:
                self._keys.popitem(last=False)
            return allowed

    def _sweep(self, cutoff):
        for key in [k for k, hits in self._keys.items() if not hits or hits[-1] < cutoff]:
            del self._keys[key]

    def spent(self, key=""):
        with self._lock:
            return len(self._keys.get(key, ()))

    def reset(self):
        with self._lock:
            self._keys.clear()

    def keys_held(self):
        with self._lock:
            return len(self._keys)
