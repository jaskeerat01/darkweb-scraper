import asyncio
import logging
import random
from typing import List, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import aiohttp

from scraper.config import CONFIG
from scraper.parsers.dom import get_soup, extract_page_links
from scraper.parsers.heuristics import score_page_url, looks_like_html
from scraper.parsers.url import normalize_hostname, normalize_page_url, is_allowed_page_url
from scraper.network.session import fetch_full_page
from scraper.network.throttler import DomainThrottler

logger = logging.getLogger("scraper")


class CrawlerEngine:
    """Manages priority frontier crawling and depth-constrained link extraction."""

    def __init__(self, throttler: DomainThrottler, config=CONFIG):
        self._throttler = throttler
        self._config = config

    async def fetch_with_semaphore(
        self,
        url: str,
        fetch_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession
    ):
        domain_sem = self._throttler.get_semaphore(url)
        async with fetch_sem:
            async with domain_sem:
                await asyncio.sleep(random.uniform(1.0, 3.0))
                return await fetch_full_page(url, session)

    async def discover_site_pages(
        self,
        start_url: str,
        fetch_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession
    ) -> List[Tuple[str, str, BeautifulSoup]]:
        start_url = normalize_page_url(start_url)
        if not start_url:
            return []

        max_pages = max(1, self._config.max_pages_per_site)
        max_depth = max(0, self._config.page_discovery_depth)
        allow_external = self._config.follow_external_links
        max_external = self._config.max_external_links_per_site

        seen = {start_url}
        frontier = [(score_page_url(start_url, "index"), start_url, 0)]
        fetched: List[Tuple[str, str, BeautifulSoup]] = []
        external_used = 0

        while frontier and len(fetched) < max_pages:
            frontier.sort(key=lambda x: x[0], reverse=True)
            batch = []
            while frontier and len(batch) < min(max_pages - len(fetched), self._config.max_links_per_page):
                _s, u, d = frontier.pop(0)
                if d <= max_depth:
                    batch.append((u, d))
            if not batch:
                break

            async def fetch_candidate(u: str, d: int):
                return u, d, await self.fetch_with_semaphore(u, fetch_sem, session)

            results = await asyncio.gather(
                *(fetch_candidate(u, d) for u, d in batch),
                return_exceptions=True
            )

            next_candidates: List[Tuple[int, str, int]] = []
            for item in results:
                if isinstance(item, BaseException):
                    continue
                u, d, raw_html = item
                if not raw_html or not looks_like_html(raw_html):
                    continue

                soup = await asyncio.to_thread(get_soup, raw_html)
                fetched.append((u, raw_html, soup))
                if d >= max_depth:
                    continue

                current_host = normalize_hostname(urlparse(u).hostname)
                extracted_links = await asyncio.to_thread(extract_page_links, soup, u, False)

                for link, anchor_text in extracted_links:
                    if link in seen or not is_allowed_page_url(link):
                        continue
                    link_host = normalize_hostname(urlparse(link).hostname)
                    is_same = link_host == current_host
                    if not is_same and not allow_external:
                        continue
                    link_score = score_page_url(link, anchor_text)
                    if link_score < self._config.min_link_score:
                        continue
                    if not is_same:
                        if link_score < max(self._config.min_link_score, 10):
                            continue
                        if external_used >= max_external:
                            continue
                        external_used += 1

                    seen.add(link)
                    next_candidates.append((link_score, link, d + 1))

            frontier.extend(next_candidates)
            frontier.sort(key=lambda x: x[0], reverse=True)
            frontier = frontier[:max_pages * 5]

        fetched.sort(key=lambda x: score_page_url(x[0]), reverse=True)
        return fetched[:max_pages]