"""Simple async token-bucket rate limiter (per-source instances)."""
from __future__ import annotations

import asyncio
import time


class TokenBucket:
    def __init__(self, rps: float, burst: float | None = None) -> None:
        self.rps = max(rps, 0.01)
        self.capacity = burst if burst is not None else max(self.rps, 1.0)
        self.tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rps)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                deficit = 1.0 - self.tokens
                wait = deficit / self.rps
                await asyncio.sleep(wait)
