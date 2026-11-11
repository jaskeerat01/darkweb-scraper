import asyncio
import signal
from datetime import datetime, timedelta, timezone
from functools import partial

import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from scraper.config import CONFIG
from scraper.core.logging import setup_logging
from scraper.network.tor import tor_manager
from scraper.notifications.telegram import supervise_telegram_worker
from scraper.scheduler.jobs import (
    cleanup_job,
    health_check_job,
    scrape_job,
    sync_csv_job,
)
from scraper.storage.db import init_db
from scraper.storage.seed import seed_sites_from_csv

logger = setup_logging()


async def main() -> None:
    init_db(config=CONFIG)
    seed_sites_from_csv(config=CONFIG)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    scheduler = AsyncIOScheduler(
        job_defaults={
            "coalesce": True,
            "misfire_grace_time": 3600,
        }
    )

    async with aiohttp.ClientSession(trust_env=False) as telegram_session:
        worker_task = asyncio.create_task(
            supervise_telegram_worker(telegram_session, stop_event, CONFIG),
            name="telegram-worker",
        )

        scheduler.add_job(
            partial(health_check_job, CONFIG),
            trigger=IntervalTrigger(minutes=CONFIG.health_interval_minutes),
            id="health_check",
            replace_existing=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=10),
        )
        scheduler.add_job(
            partial(scrape_job, CONFIG),
            trigger=IntervalTrigger(minutes=CONFIG.scrape_interval_minutes),
            id="scraper",
            replace_existing=True,
            max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5),
        )
        scheduler.add_job(
            partial(cleanup_job, CONFIG),
            trigger=CronTrigger(hour=0, minute=0),
            id="cleanup",
            replace_existing=True,
            max_instances=1,
        )
        scheduler.add_job(
            partial(sync_csv_job, CONFIG),
            trigger=IntervalTrigger(minutes=CONFIG.health_interval_minutes),
            id="seed_sync",
            replace_existing=True,
            max_instances=1,
        )
        scheduler.add_job(
            partial(tor_manager.renew_circuit, CONFIG),
            trigger=IntervalTrigger(minutes=CONFIG.tor_renew_interval_minutes),
            id="tor_renew",
            replace_existing=True,
            max_instances=1,
        )

        scheduler.start()
        logger.info(
            "Scheduler started. Health check: every %sm, scrape cycle: every %sm, "
            "retention: %sd.",
            CONFIG.health_interval_minutes,
            CONFIG.scrape_interval_minutes,
            CONFIG.data_retention_days,
        )
        if CONFIG.allow_clearnet_targets and not CONFIG.clearnet_enabled:
            logger.warning(
                "Clearnet targets are enabled but no scope is configured. Set "
                "CLEARNET_ALLOWED_DOMAINS or CLEARNET_ALLOW_ANY=true."
            )

        try:
            await stop_event.wait()
        finally:
            logger.info("Shutting down daemon...")
            stop_event.set()
            scheduler.shutdown(wait=False)
            worker_task.cancel()
            try:
                await asyncio.wait_for(worker_task, timeout=5)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass


def run() -> None:
    """Synchronous console-script entrypoint."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
