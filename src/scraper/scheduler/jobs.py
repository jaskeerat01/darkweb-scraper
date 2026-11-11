import asyncio
import logging
import time

import aiohttp

from scraper.config import CONFIG, Config
from scraper.crawler.crawler import CrawlerEngine
from scraper.crawler.processor import PageProcessor
from scraper.network.policy import is_allowed_target_url
from scraper.network.session import build_tor_connector, check_site_live
from scraper.network.throttler import DomainThrottler
from scraper.network.tor import tor_manager
from scraper.parsers.url import redact_url
from scraper.storage.repositories import AlertRepository, SiteRepository
from scraper.storage.seed import seed_sites_from_csv

logger = logging.getLogger("scraper")


def _build_processor(config: Config) -> PageProcessor:
    throttler = DomainThrottler(
        config.max_fetches_per_domain,
        min_interval=config.domain_min_interval,
    )
    return PageProcessor(CrawlerEngine(throttler, config=config), config=config)


async def health_check_job(config: Config | None = None) -> None:
    """Validate the availability of tracked targets through the Tor proxy."""
    cfg = config or CONFIG
    logger.info("=" * 60)
    logger.info("Starting health check cycle...")
    await tor_manager.renew_circuit(cfg)

    sites = await asyncio.to_thread(SiteRepository.get_all_sites, config=cfg)
    if not sites:
        logger.warning("No sites in database.")
        return

    allowed = []
    skipped = 0
    for site in sites:
        if is_allowed_target_url(site["url"], cfg):
            allowed.append(site)
        else:
            skipped += 1

    if skipped:
        logger.warning("Skipped %d targets rejected by the current scope policy.", skipped)
    if not allowed:
        logger.warning("No in-scope sites to check.")
        return

    total = len(allowed)
    connector = build_tor_connector(config=cfg)
    if connector is None:
        return

    timeout = aiohttp.ClientTimeout(total=cfg.health_timeout)
    async with aiohttp.ClientSession(
        connector=connector, trust_env=False, timeout=timeout
    ) as session:
        sem = asyncio.Semaphore(max(1, cfg.max_parallel_health))
        counts = {"up": 0, "down": 0, "checked": 0}
        lock = asyncio.Lock()

        async def check_one(site: dict) -> None:
            url = site["url"]
            async with sem:
                alive, status_code, error = await check_site_live(
                    url, session, config=cfg
                )
                await asyncio.to_thread(
                    SiteRepository.update_health,
                    url,
                    alive,
                    status_code,
                    error,
                    config=cfg,
                )
                async with lock:
                    counts["up" if alive else "down"] += 1
                    counts["checked"] += 1
                    checked = counts["checked"]
                    if alive:
                        logger.info(
                            "[%d/%d] UP   %s (status=%s)",
                            checked,
                            total,
                            redact_url(url, cfg),
                            status_code,
                        )
                    if checked % 50 == 0 or checked == total:
                        logger.info(
                            "Health progress: %d/%d | Up: %d | Down: %d",
                            checked,
                            total,
                            counts["up"],
                            counts["down"],
                        )
                await asyncio.sleep(0.15)

        await asyncio.gather(*(check_one(site) for site in allowed), return_exceptions=True)

    logger.info(
        "Health check complete. Up: %d, Down: %d, Total: %d",
        counts["up"],
        counts["down"],
        total,
    )
    logger.info("=" * 60)


async def scrape_job(config: Config | None = None) -> None:
    """Run a recursive discovery and scraping cycle across in-scope sites."""
    cfg = config or CONFIG
    logger.info("=" * 60)
    logger.info("Starting scrape cycle...")
    await tor_manager.renew_circuit(cfg)

    live_sites = await asyncio.to_thread(SiteRepository.get_live_sites, config=cfg)
    live_sites = [site for site in live_sites if is_allowed_target_url(site["url"], cfg)]
    if not live_sites:
        logger.warning("No live in-scope sites to scrape. Waiting for next health check.")
        return

    total = len(live_sites)
    logger.info(
        "Scraping %d live sites in parallel. sites=%d, fetches=%d, llm_workers=%d, "
        "domain_throttle=%d, budget=%ds",
        total,
        cfg.max_parallel_sites,
        cfg.max_parallel_fetches,
        cfg.max_llm_workers,
        cfg.max_fetches_per_domain,
        cfg.scrape_cycle_budget_seconds,
    )

    connector = build_tor_connector(limit=cfg.max_parallel_fetches * 2, config=cfg)
    if connector is None:
        return

    processor = _build_processor(cfg)
    timeout = aiohttp.ClientTimeout(total=cfg.request_timeout)
    async with aiohttp.ClientSession(
        connector=connector, trust_env=False, timeout=timeout
    ) as tor_session:
        fetch_sem = asyncio.Semaphore(max(1, cfg.max_parallel_fetches))
        llm_sem = asyncio.Semaphore(max(1, cfg.max_llm_workers))
        site_sem = asyncio.Semaphore(max(1, cfg.max_parallel_sites))
        deadline = time.monotonic() + cfg.scrape_cycle_budget_seconds

        completed = 0
        alert_count = 0
        skipped = 0
        lock = asyncio.Lock()

        async def bounded_process(site: dict) -> None:
            nonlocal completed, alert_count, skipped
            if time.monotonic() >= deadline:
                async with lock:
                    skipped += 1
                return
            async with site_sem:
                if time.monotonic() >= deadline:
                    async with lock:
                        skipped += 1
                    return
                new_alerts = await processor.process_site(
                    site, fetch_sem, llm_sem, tor_session
                )
            async with lock:
                completed += 1
                alert_count += max(0, int(new_alerts or 0))
                if completed % 10 == 0 or completed == total:
                    logger.info("Scrape progress: %d/%d sites", completed, total)

        await asyncio.gather(
            *(bounded_process(site) for site in live_sites), return_exceptions=True
        )

    logger.info(
        "Scrape cycle completed. New alerts: %d | processed: %d | skipped: %d",
        alert_count,
        completed,
        skipped,
    )
    logger.info("=" * 60)


async def cleanup_job(config: Config | None = None) -> None:
    """Prune expired alerts and LLM cache entries."""
    cfg = config or CONFIG
    deleted = await asyncio.to_thread(
        AlertRepository.cleanup_old,
        cfg.data_retention_days,
        cfg.llm_cache_days,
        config=cfg,
    )
    if deleted:
        logger.info(
            "Cleaned up %d alerts older than %d days.",
            deleted,
            cfg.data_retention_days,
        )


async def sync_csv_job(config: Config | None = None) -> None:
    await asyncio.to_thread(seed_sites_from_csv, config=config or CONFIG)
