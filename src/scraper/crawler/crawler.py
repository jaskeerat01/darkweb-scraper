import asyncio
import logging
import random
from typing import List, Tuple
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup

from scraper.config import CONFIG, Config
from scraper.core.exceptions import RetryableFetchError
from scraper.network.session import fetch_full_page
from scraper.network.throttler import DomainThrottler
from scraper.parsers.dom import extract_page_links, get_soup
from scraper.parsers.heuristics import looks_like_html, score_page_url
from scraper.parsers.url import (
    is_allowed_page_url,
    normalize_hostname,
    normalize_page_url,
    redact_url,
)

logger = logging.getLogger("scraper")


class CrawlerEngine:
    """Manage priority frontier crawling and depth-constrained link extraction."""

    def __init__(
        self,
        throttler: DomainThrottler,
        config: Config | None = None,
    ) -> None:
        self._throttler = throttler
        self._config = config or CONFIG

    async def fetch_with_semaphore(
        self,
        url: str,
        fetch_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
    ) -> str | None:
        """Fetch with per-domain pacing, global back-pressure, and retries."""
        cfg = self._config
        async with self._throttler.limit(url):
            for attempt in range(cfg.fetch_retries + 1):
                try:
                    async with fetch_sem:
                        return await fetch_full_page(url, session, config=cfg)
                except RetryableFetchError as exc:
                    if attempt >= cfg.fetch_retries:
                        logger.warning(
                            "Giving up on transient response for %s after %d attempts",
                            redact_url(url, cfg),
                            attempt + 1,
                        )
                        return None
                    delay = (
                        exc.retry_after
                        if exc.retry_after is not None
                        else cfg.fetch_backoff_base * (2**attempt)
                    )
                    delay += random.uniform(0.0, 1.0)
                    logger.info(
                        "Transient response for %s; retrying in %.1fs",
                        redact_url(url, cfg),
                        delay,
                    )
                    await asyncio.sleep(delay)
        return None

    async def discover_site_pages(
        self,
        start_url: str,
        fetch_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
    ) -> List[Tuple[str, str, BeautifulSoup]]:
        cfg = self._config
        start_url = normalize_page_url(start_url)
        if not start_url:
            return []

        max_pages = max(1, cfg.max_pages_per_site)
        max_depth = max(0, cfg.page_discovery_depth)
        allow_external = cfg.follow_external_links
        max_external = cfg.max_external_links_per_site

        seen = {start_url}
        frontier = [(score_page_url(start_url, "index"), start_url, 0)]
        fetched: List[Tuple[str, str, BeautifulSoup]] = []
        external_used = 0

        while frontier and len(fetched) < max_pages:
            frontier.sort(key=lambda item: item[0], reverse=True)
            batch: list[tuple[str, int]] = []
            while frontier and len(batch) < min(
                max_pages - len(fetched), cfg.max_links_per_page
            ):
                _score, candidate, depth = frontier.pop(0)
                if depth <= max_depth:
                    batch.append((candidate, depth))
            if not batch:
                break

            async def fetch_candidate(candidate: str, depth: int):
                return candidate, depth, await self.fetch_with_semaphore(
                    candidate, fetch_sem, session
                )

            results = await asyncio.gather(
                *(fetch_candidate(candidate, depth) for candidate, depth in batch),
                return_exceptions=True,
            )

            next_candidates: list[tuple[int, str, int]] = []
            for item in results:
                if isinstance(item, BaseException):
                    continue
                page_url, depth, raw_html = item
                if not raw_html or not looks_like_html(raw_html):
                    continue

                soup = await asyncio.to_thread(get_soup, raw_html)
                fetched.append((page_url, raw_html, soup))
                if depth >= max_depth:
                    continue

                current_host = normalize_hostname(urlparse(page_url).hostname)
                links = await asyncio.to_thread(
                    extract_page_links, soup, page_url, False, cfg
                )

                for link, anchor_text in links:
                    if link in seen or not is_allowed_page_url(link, cfg):
                        continue
                    link_host = normalize_hostname(urlparse(link).hostname)
                    is_same = link_host == current_host
                    if not is_same and not allow_external:
                        continue
                    link_score = score_page_url(link, anchor_text)
                    if link_score < cfg.min_link_score:
                        continue
                    if not is_same:
                        if link_score < max(cfg.min_link_score, 10):
                            continue
                        if external_used >= max_external:
                            continue
                        external_used += 1

                    seen.add(link)
                    next_candidates.append((link_score, link, depth + 1))

            frontier.extend(next_candidates)
            frontier.sort(key=lambda item: item[0], reverse=True)
            frontier = frontier[: max_pages * 5]

        fetched.sort(key=lambda item: score_page_url(item[0]), reverse=True)
        return fetched[:max_pages]
