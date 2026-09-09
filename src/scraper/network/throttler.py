import asyncio
from collections import defaultdict
from typing import Dict
from urllib.parse import urlparse
from scraper.parsers.url import normalize_hostname


class DomainThrottler:
    """Manages per-domain concurrency locks to prevent HTTP 429 rate limits."""

    def __init__(self, max_concurrent: int = 1):
        self._max_concurrent = max_concurrent
        self._semaphores: Dict[str, asyncio.Semaphore] = defaultdict(
            lambda: asyncio.Semaphore(self._max_concurrent)
        )

    def get_semaphore(self, url: str) -> asyncio.Semaphore:
        domain = normalize_hostname(urlparse(url).hostname) or "unknown"
        return self._semaphores[domain]