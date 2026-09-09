import asyncio
import logging
import random
import aiohttp

from scraper.config import CONFIG
from scraper.crawler.crawler import CrawlerEngine
from scraper.crawler.processor import PageProcessor
from scraper.network.session import build_tor_connector, check_site_live
from scraper.network.throttler import DomainThrottler
from scraper.network.tor import tor_manager
from scraper.parsers.url import redact_url
from scraper.storage.repositories import AlertRepository, SiteRepository
from scraper.storage.seed import seed_sites_from_csv

logger = logging.getLogger("scraper")

_throttler = DomainThrottler(CONFIG.max_fetches_per_domain)
_crawler = CrawlerEngine(_throttler)
_processor = PageProcessor(_crawler)


async def health_check_job():
    """Validates the availability of tracked onion services through the Tor proxy."""
    logger.info("=" * 60)
    logger.info("Starting health check cycle...")
    await tor_manager.renew_circuit()

    sites = await asyncio.to_thread(SiteRepository.get_all_sites)
    total = len(sites)
    if total == 0:
        logger.warning("No sites in database.")
        return

    connector = build_tor_connector()
    if connector is None:
        return

    timeout = aiohttp.ClientTimeout(total=CONFIG.health_timeout)
    async with aiohttp.ClientSession(connector=connector, trust_env=False, timeout=timeout) as session:
        sem = asyncio.Semaphore(max(1, CONFIG.max_parallel_health))
        up_count = 0
        down_count = 0
        checked = 0
        lock = asyncio.Lock()

        async def check_one(url: str):
            nonlocal up_count, down_count, checked
            async with sem:
                alive, status_code, error = await check_site_live(url, session)
                await asyncio.to_thread(SiteRepository.update_health, url, alive, status_code, error)
                async with lock:
                    if alive:
                        up_count += 1
                        logger.info(f"[{checked + 1}/{total}] UP   {redact_url(url)} (status={status_code})")
                    else:
                        down_count += 1
                    checked += 1
                    if checked % 50 == 0 or checked == total:
                        logger.info(f"Health progress: {checked}/{total} | Up: {up_count} | Down: {down_count}")
                await asyncio.sleep(random.uniform(0.1, 0.3))

        await asyncio.gather(*(check_one(r["url"]) for r in sites), return_exceptions=True)

    logger.info(f"Health check complete. Up: {up_count}, Down: {down_count}, Total: {total}")
    logger.info("=" * 60)


async def scrape_job():
    """Runs a recursive discovery and scraping cycle across online sites."""
    logger.info("=" * 60)
    logger.info("Starting scrape cycle...")
    await tor_manager.renew_circuit()

    live_sites = await asyncio.to_thread(SiteRepository.get_live_sites)
    if not live_sites:
        logger.warning("No live sites to scrape. Waiting for next health check.")
        return

    total = len(live_sites)
    logger.info(
        f"Scraping {total} live sites in parallel. "
        f"sites={CONFIG.max_parallel_sites}, fetches={CONFIG.max_parallel_fetches}, "
        f"llm_workers={CONFIG.max_llm_workers}, domain_throttle={CONFIG.max_fetches_per_domain}"
    )

    connector = build_tor_connector(limit=CONFIG.max_parallel_fetches * 2)
    if connector is None:
        return

    timeout = aiohttp.ClientTimeout(total=CONFIG.request_timeout)
    async with aiohttp.ClientSession(connector=connector, trust_env=False, timeout=timeout) as tor_session:
        fetch_sem = asyncio.Semaphore(max(1, CONFIG.max_parallel_fetches))
        llm_sem = asyncio.Semaphore(max(1, CONFIG.max_llm_workers))
        site_sem = asyncio.Semaphore(max(1, CONFIG.max_parallel_sites))

        completed = 0
        alert_count = 0
        lock = asyncio.Lock()

        async def bounded_process(site: dict):
            nonlocal completed, alert_count
            async with site_sem:
                new_alerts = await _processor.process_site(site, fetch_sem, llm_sem, tor_session)
            async with lock:
                completed += 1
                alert_count += max(0, int(new_alerts or 0))
                if completed % 10 == 0 or completed == total:
                    logger.info(f"Scrape progress: {completed}/{total} sites")

        await asyncio.gather(*(bounded_process(s) for s in live_sites), return_exceptions=True)

    logger.info(f"Scrape cycle completed. New alerts: {alert_count}")
    logger.info("=" * 60)


async def cleanup_job():
    """Prunes expired alerts to maintain database performance and bounded storage."""
    deleted = await asyncio.to_thread(AlertRepository.cleanup_old, CONFIG.data_retention_days)
    if deleted:
        logger.info(f"Cleaned up {deleted} alerts older than {CONFIG.data_retention_days} days.")


async def sync_csv_job():
    await asyncio.to_thread(seed_sites_from_csv)