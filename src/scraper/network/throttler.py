"""Per-domain concurrency and pacing."""

from __future__ import annotations

import asyncio
import random
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Dict
from urllib.parse import urlparse

from scraper.network.policy import normalize_host


@dataclass
class _DomainState:
    semaphore: asyncio.Semaphore
    next_allowed_at: float = 0.0


class DomainThrottler:
    """Limit concurrent requests per domain and space sequential requests.

    Pacing happens while holding the *per-domain* semaphore only.  Callers
    acquire the global fetch semaphore after entering :meth:`limit`, so pacing
    never consumes a global fetch slot.
    """

    def __init__(
        self,
        max_concurrent: int = 1,
        min_interval: float = 0.0,
        jitter: float = 0.75,
    ) -> None:
        self._max_concurrent = max(1, max_concurrent)
        self._min_interval = max(0.0, min_interval)
        self._jitter = max(0.0, jitter)
        self._states: Dict[str, _DomainState] = {}

    def _state(self, url: str) -> _DomainState:
        domain = normalize_host(urlparse(url).hostname) or "unknown"
        state = self._states.get(domain)
        if state is None:
            state = _DomainState(asyncio.Semaphore(self._max_concurrent))
            self._states[domain] = state
        return state

    def get_semaphore(self, url: str) -> asyncio.Semaphore:
        """Compatibility helper returning the per-domain semaphore."""
        return self._state(url).semaphore

    @asynccontextmanager
    async def limit(self, url: str) -> AsyncIterator[None]:
        state = self._state(url)
        async with state.semaphore:
            delay = state.next_allowed_at - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                yield
            finally:
                state.next_allowed_at = (
                    time.monotonic()
                    + self._min_interval
                    + random.uniform(0.0, self._jitter)
                )
