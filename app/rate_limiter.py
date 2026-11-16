# Copyright Yahoo, Licensed under the terms of the Apache 2.0 license. See LICENSE for terms.

"""In-process sliding-window rate limiter (CWE-770).

Deliberately dependency-free. slowapi/limits key on the socket peer address by
default, and behind the platform's edge proxy -> SSO gateway -> pod-local reverse proxy chain
the peer is ALWAYS the proxy's loopback address — every caller would collapse into one
shared bucket keyed on the wrong identity. Callers key this limiter with
``app.audit.client_ip()`` (right-indexed X-Forwarded-For), the platform's
established anti-spoof client identity.

The sidecar is a single-process, single-replica deployment, so process-local
state is authoritative. If the deployment model ever becomes multi-replica,
this must move to shared state.
"""
import threading
import time
from collections import deque
from typing import Deque, Dict, Optional, Tuple

# Bound the key map so a caller rotating identities cannot grow memory without
# limit. On the production chain the right-indexed XFF extraction already makes
# key spoofing ineffective; this is defence in depth for dev / port-forward
# paths where the header is client-controlled.
_MAX_KEYS = 10_000


class SlidingWindowRateLimiter:
    """At most ``limit`` events per ``window_seconds``, per key (true sliding window)."""

    def __init__(self, limit: int, window_seconds: float = 60.0):
        if limit < 1:
            raise ValueError("limit must be >= 1")
        self.limit = int(limit)
        self.window_seconds = float(window_seconds)
        self._events: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str, now: Optional[float] = None) -> Tuple[bool, float]:
        """Record-and-check one request for ``key``.

        Returns ``(allowed, retry_after_seconds)``; ``retry_after_seconds`` is
        0.0 when allowed. A denied request is NOT recorded, so rejected traffic
        cannot extend its own penalty window.
        """
        if now is None:
            now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            events = self._events.get(key)
            if events is None:
                if len(self._events) >= _MAX_KEYS:
                    self._prune(cutoff)
                    if len(self._events) >= _MAX_KEYS:
                        # Saturated key map (key-churn abuse): fail CLOSED for
                        # brand-new keys — refusing is the safe posture for a
                        # limiter that exists to bound resource consumption.
                        return False, self.window_seconds
                events = deque()
                self._events[key] = events
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False, max(events[0] - cutoff, 0.0)
            events.append(now)
            return True, 0.0

    def _prune(self, cutoff: float) -> None:
        """Drop keys with no in-window events. Called with the lock held."""
        stale = [k for k, q in self._events.items() if not q or q[-1] <= cutoff]
        for k in stale:
            del self._events[k]
