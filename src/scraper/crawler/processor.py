import asyncio
import hashlib
import logging
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional, Sequence, Set

import aiohttp
from bs4 import BeautifulSoup

from scraper.config import CONFIG, Config
from scraper.crawler.crawler import CrawlerEngine
from scraper.intel.ioc import extract_contact_links, extract_iocs
from scraper.intel.llm import PROMPT_VERSION, model_identity
from scraper.intel.llm import cache_key as llm_cache_key
from scraper.intel.llm import filter_and_summarize
from scraper.intel.taxonomy import derive_category, derive_severity
from scraper.network.policy import host_from_url, network_label
from scraper.notifications.telegram import enqueue_alert
from scraper.parsers.dom import clean_text_for_hash, extract_post_description, get_soup
from scraper.parsers.heuristics import looks_like_error_page
from scraper.parsers.url import redact_url
from scraper.storage.models import LLMResult
from scraper.storage.repositories import (
    AlertRepository,
    LLMCacheRepository,
    SiteRepository,
)

logger = logging.getLogger("scraper")


@lru_cache(maxsize=32)
def _keyword_patterns(keywords: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    return tuple(
        re.compile(rf"(?<!\w){re.escape(keyword.lower())}(?!\w)", re.IGNORECASE)
        for keyword in keywords
        if keyword.strip()
    )


class PageProcessor:
    """Coordinate parsing, deduplication, LLM filtering, and alert creation."""

    def __init__(
        self,
        crawler_engine: CrawlerEngine,
        config: Config | None = None,
        db_path: str | None = None,
    ) -> None:
        self.crawler = crawler_engine
        self._config = config or CONFIG
        self._db_path = db_path

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
        seen_lock: Optional[asyncio.Lock] = None,
    ) -> bool:
        cfg = self._config
        try:
            raw_html = cached_html
            soup = cached_soup
            if raw_html is None:
                raw_html = await self.crawler.fetch_with_semaphore(
                    page_url, fetch_sem, session
                )
                if not raw_html:
                    return False
                soup = await asyncio.to_thread(get_soup, raw_html)

            if soup is None:
                return False

            description = await asyncio.to_thread(
                extract_post_description, soup, cfg
            )
            if looks_like_error_page(description):
                logger.info("Skipped error/challenge page: %s", redact_url(page_url, cfg))
                return False

            clean_text = await asyncio.to_thread(clean_text_for_hash, soup)
            content_hash = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()

            if seen_hashes is not None and seen_lock is not None:
                async with seen_lock:
                    if content_hash in seen_hashes:
                        return False
                    seen_hashes.add(content_hash)

            # Cheap indexed check before any inference work.
            already_seen = await asyncio.to_thread(
                AlertRepository.exists,
                page_url,
                content_hash,
                self._db_path,
                config=cfg,
            )
            if already_seen:
                return False

            text_lower = clean_text.lower()
            has_keywords = any(
                pattern.search(text_lower)
                for pattern in _keyword_patterns(tuple(cfg.keywords))
            )
            page_iocs = await asyncio.to_thread(extract_iocs, clean_text)

            if cfg.require_relevance:
                if cfg.llm_prefilter_keywords and not has_keywords and not page_iocs:
                    return False

                filtered = await self._classify(
                    description,
                    site,
                    content_hash,
                    page_iocs,
                    llm_sem,
                )
                if not filtered.get("is_relevant", False):
                    return False
            else:
                filtered = {
                    "is_relevant": True,
                    "category": derive_category(description),
                    "severity": derive_severity(
                        derive_category(description), description
                    ),
                    "threat_group": site.get("group_name") or "unknown",
                    "summary": "",
                    "entities": [],
                    "iocs": list(page_iocs),
                }
                if cfg.summarize_alerts:
                    summarized = await self._classify(
                        description,
                        site,
                        content_hash,
                        page_iocs,
                        llm_sem,
                    )
                    filtered["summary"] = summarized.get("summary", "")
                    merged = list(filtered.get("iocs") or [])
                    for value in summarized.get("iocs", []):
                        if value not in merged:
                            merged.append(value)
                    filtered["iocs"] = merged

            contact_iocs = await asyncio.to_thread(extract_contact_links, soup)
            if contact_iocs:
                merged = list(filtered.get("iocs") or [])
                for value in contact_iocs:
                    if value not in merged:
                        merged.append(value)
                filtered["iocs"] = merged

            category = derive_category(description, filtered.get("category"))
            severity = filtered.get("severity") or derive_severity(category, description)
            summary = str(filtered.get("summary") or "")[:20000]

            source_host = host_from_url(page_url)
            is_new = await asyncio.to_thread(
                AlertRepository.save_if_new,
                site["name"],
                page_url,
                site.get("group_name") or "unknown",
                description,
                content_hash,
                category,
                filtered.get("entities", []),
                filtered.get("iocs", []),
                summary,
                severity,
                self._db_path,
                config=cfg,
            )
            if not is_new:
                return False

            payload = {
                "source_name": site["name"],
                "source_url": page_url,
                "group_name": filtered.get("threat_group")
                or site.get("group_name")
                or "unknown",
                "category": category,
                "severity": severity,
                "summary": summary,
                "entities": filtered.get("entities", []),
                "iocs": filtered.get("iocs", []),
                "hash": content_hash[:8],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "network": network_label(source_host),
            }
            enqueue_alert(payload)
            return True

        except Exception as exc:
            logger.error(
                "process_page error for %s: %s",
                redact_url(page_url, self._config),
                type(exc).__name__,
            )
            logger.debug("process_page traceback", exc_info=True)
            return False

    async def _classify(
        self,
        description: str,
        site: dict,
        content_hash: str,
        page_iocs: Sequence[str],
        llm_sem: asyncio.Semaphore,
    ) -> LLMResult:
        cfg = self._config
        cache_id = llm_cache_key(content_hash, cfg)

        if cfg.llm_cache_enabled:
            cached = await asyncio.to_thread(
                LLMCacheRepository.get,
                cache_id,
                self._db_path,
                config=cfg,
            )
            if cached is not None:
                return {
                    "is_relevant": bool(cached["is_relevant"]),
                    "category": str(cached["category"]),
                    "severity": str(cached["severity"]),
                    "threat_group": site.get("group_name") or "unknown",
                    "summary": str(cached["summary"]),
                    "entities": [],
                    "iocs": list(cached["iocs"]),
                }

        async with llm_sem:
            result = await asyncio.to_thread(
                filter_and_summarize,
                description,
                site["name"],
                site.get("group_name") or "unknown",
                iocs=page_iocs,
                config=cfg,
            )

        if cfg.llm_cache_enabled and not result.get("degraded"):
            await asyncio.to_thread(
                LLMCacheRepository.save,
                cache_id,
                model_identity(cfg),
                PROMPT_VERSION,
                bool(result.get("is_relevant", False)),
                str(result.get("category", "other")),
                str(result.get("severity", "low")),
                str(result.get("summary", "")),
                list(result.get("iocs", [])),
                self._db_path,
                config=cfg,
            )
        return result

    async def process_site(
        self,
        site: dict,
        fetch_sem: asyncio.Semaphore,
        llm_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
    ) -> int:
        url = site["url"]
        try:
            await asyncio.to_thread(
                SiteRepository.mark_scrape_attempt,
                url,
                self._db_path,
                config=self._config,
            )
            return await asyncio.wait_for(
                self._process_site_inner(site, fetch_sem, llm_sem, session),
                timeout=self._config.site_budget_seconds,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Site budget exceeded for %s (%ss)",
                redact_url(url, self._config),
                self._config.site_budget_seconds,
            )
            return 0
        except Exception as exc:
            logger.error(
                "process_site error for %s: %s",
                redact_url(url, self._config),
                type(exc).__name__,
            )
            logger.debug("process_site traceback", exc_info=True)
            return 0

    async def _process_site_inner(
        self,
        site: dict,
        fetch_sem: asyncio.Semaphore,
        llm_sem: asyncio.Semaphore,
        session: aiohttp.ClientSession,
    ) -> int:
        cfg = self._config
        url = site["url"]
        seen_hashes: Set[str] = set()
        seen_lock = asyncio.Lock()

        if cfg.page_discovery_enabled:
            pages = await self.crawler.discover_site_pages(url, fetch_sem, session)
        else:
            pages = [(url, None, None)]

        tasks = [
            self.process_page(
                site,
                page_url,
                fetch_sem,
                llm_sem,
                session,
                cached_html=cached_html,
                cached_soup=cached_soup,
                seen_hashes=seen_hashes,
                seen_lock=seen_lock,
            )
            for page_url, cached_html, cached_soup in pages
        ]
        if not tasks:
            return 0

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for result in results if result is True)
