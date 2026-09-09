import asyncio
import hashlib
import logging
import random
from datetime import datetime, timezone
from typing import Optional, Set
from bs4 import BeautifulSoup
import aiohttp

from scraper.config import CONFIG
from scraper.crawler.crawler import CrawlerEngine
from scraper.intel.ioc import extract_iocs, extract_contact_links
from scraper.intel.llm import filter_and_summarize, get_llm
from scraper.notifications.telegram import telegram_queue
from scraper.parsers.dom import get_soup, clean_text_for_hash, extract_post_description
from scraper.parsers.heuristics import looks_like_error_page
from scraper.parsers.url import redact_url
from scraper.storage.repositories import AlertRepository, SiteRepository

logger = logging.getLogger("scraper")


class PageProcessor:
    """Coordinates parsing, deduplication, LLM filtering, and alert creation."""

    def __init__(self, crawler_engine: CrawlerEngine):
        self.crawler = crawler_engine

    async def process_page(
        self,
        site: dict,
        page_url: str,
        fetch_sem: asyncio.Semaphore,
        llm_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
        cached_html: Optional[str] = None,
        cached_soup: Optional[BeautifulSoup] = None,
        seen_hashes: Optional[Set[str]] = None,
        seen_lock: Optional[asyncio.Lock] = None
    ) -> bool:
        try:
            raw_html = cached_html
            soup = cached_soup
            if raw_html is None:
                raw_html = await self.crawler.fetch_with_semaphore(page_url, fetch_sem, session)
                if not raw_html:
                    return False
                soup = await asyncio.to_thread(get_soup, raw_html)

            description = await asyncio.to_thread(extract_post_description, soup)
            if looks_like_error_page(description):
                logger.info(f"Skipped error/challenge page: {redact_url(page_url)}")
                return False

            clean_text = await asyncio.to_thread(clean_text_for_hash, soup)
            content_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()

            if seen_hashes is not None and seen_lock is not None:
                async with seen_lock:
                    if content_hash in seen_hashes:
                        return False
                    seen_hashes.add(content_hash)

            if CONFIG.require_relevance:
                has_keywords = any(k.lower() in clean_text.lower() for k in CONFIG.keywords)
                iocs_found = await asyncio.to_thread(extract_iocs, clean_text)

                if CONFIG.llm_prefilter_keywords and not has_keywords and not iocs_found:
                    return False

                async with llm_sem:
                    filtered = await asyncio.to_thread(
                        filter_and_summarize, description, site["name"], site["group_name"]
                    )
                if not filtered.get("is_relevant", False):
                    return False
            else:
                iocs = await asyncio.to_thread(extract_iocs, description)
                summary = ""
                if CONFIG.summarize_alerts and get_llm() is not None:
                    async with llm_sem:
                        result = await asyncio.to_thread(
                            filter_and_summarize, description, site["name"], site["group_name"]
                        )
                    summary = result.get("summary", "")
                    for v in result.get("iocs", []):
                        if v not in iocs:
                            iocs.append(v)
                filtered = {
                    "is_relevant": True,
                    "category": "all",
                    "threat_group": site["group_name"] or "unknown",
                    "summary": summary,
                    "entities": [],
                    "iocs": iocs,
                }

            contact_iocs = await asyncio.to_thread(extract_contact_links, soup)
            if contact_iocs:
                merged = list(filtered.get("iocs") or [])
                for v in contact_iocs:
                    if v not in merged:
                        merged.append(v)
                filtered["iocs"] = merged

            is_new = await asyncio.to_thread(
                AlertRepository.save_if_new,
                site["name"],
                page_url,
                site["group_name"],
                description,
                content_hash,
                filtered.get("category", "other"),
                filtered.get("entities", []),
                filtered.get("iocs", [])
            )
            if not is_new:
                return False

            payload = {
                "source_name": site["name"],
                "source_url": page_url,
                "group_name": filtered.get("threat_group") or site["group_name"] or "unknown",
                "category": filtered.get("category", "other"),
                "summary": filtered.get("summary", ""),
                "entities": filtered.get("entities", []),
                "iocs": filtered.get("iocs", []),
                "hash": content_hash[:8],
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            await telegram_queue.put(payload)
            return True

        except Exception as e:
            logger.error(f"process_page error for {redact_url(page_url)}: {type(e).__name__}")
            return False

    async def process_site(
        self,
        site: dict,
        fetch_sem: asyncio.Semaphore,
        llm_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession
    ) -> int:
        url = site["url"]
        try:
            await asyncio.to_thread(SiteRepository.mark_scrape_attempt, url)

            seen_hashes: Set[str] = set()
            seen_lock = asyncio.Lock()

            if CONFIG.page_discovery_enabled:
                pages = await self.crawler.discover_site_pages(url, fetch_sem, session)
            else:
                pages = [(url, None, None)]

            tasks = [
                self.process_page(
                    site, page_url, fetch_sem, llm_sem, session,
                    cached_html=cached_html, cached_soup=cached_soup,
                    seen_hashes=seen_hashes, seen_lock=seen_lock
                )
                for page_url, cached_html, cached_soup in pages
            ]
            if not tasks:
                return 0

            results = await asyncio.gather(*tasks, return_exceptions=True)
            new_alerts = sum(1 for r in results if r is True)
            await asyncio.sleep(random.uniform(1, 3))
            return new_alerts
        except Exception as e:
            logger.error(f"process_site error for {redact_url(url)}: {type(e).__name__}")
            return 0