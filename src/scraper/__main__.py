import argparse
import asyncio
from datetime import datetime, timezone, timedelta
import aiohttp
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from scraper.config import CONFIG
from scraper.core.logging import setup_logging
from scraper.network.tor import tor_manager
from scraper.notifications.telegram import telegram_worker, telegram_queue
from scraper.scheduler.jobs import health_check_job, scrape_job, cleanup_job, sync_csv_job
from scraper.storage.db import init_db
from scraper.storage.seed import seed_sites_from_csv

logger = setup_logging()


async def run_once():
    """Runs a single health check and scraping pass across target sites, then exits."""
    init_db()
    seed_sites_from_csv()

    async with aiohttp.ClientSession(trust_env=False) as tg_session:
        tg_worker_task = asyncio.create_task(telegram_worker(tg_session))

        logger.info("Executing single health check cycle...")
        await health_check_job()

        logger.info("Executing single scrape cycle...")
        await scrape_job()

        if not telegram_queue.empty():
            logger.info("Flushing pending Telegram notifications...")
            await telegram_queue.join()

        tg_worker_task.cancel()

    logger.info("Single execution completed successfully.")


async def run_daemon():
    """Runs continuous scheduled scraping and health check cycles."""
    init_db()
    seed_sites_from_csv()

    scheduler = AsyncIOScheduler(job_defaults={
        "coalesce": True,
        "misfire_grace_time": 3600,
    })

    async with aiohttp.ClientSession(trust_env=False) as tg_session:
        tg_worker_task = asyncio.create_task(telegram_worker(tg_session))

        scheduler.add_job(
            health_check_job,
            trigger=IntervalTrigger(minutes=CONFIG.health_interval_minutes),
            id="health_check", replace_existing=True, max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(seconds=10)
        )
        scheduler.add_job(
            scrape_job,
            trigger=IntervalTrigger(minutes=CONFIG.scrape_interval_minutes),
            id="scraper", replace_existing=True, max_instances=1,
            next_run_time=datetime.now(timezone.utc) + timedelta(minutes=5)
        )
        scheduler.add_job(
            cleanup_job,
            trigger=CronTrigger(hour=0, minute=0),
            id="cleanup", replace_existing=True, max_instances=1
        )
        scheduler.add_job(
            sync_csv_job,
            trigger=IntervalTrigger(minutes=CONFIG.health_interval_minutes),
            id="seed_sync", replace_existing=True, max_instances=1
        )
        scheduler.add_job(
            tor_manager.renew_circuit,
            trigger=IntervalTrigger(minutes=15),
            id="tor_renew", replace_existing=True, max_instances=1
        )

        scheduler.start()
        logger.info(
            f"Scheduler started. Health check: every {CONFIG.health_interval_minutes}m, "
            f"scrape cycle: every {CONFIG.scrape_interval_minutes}m. "
            f"Retention period: {CONFIG.data_retention_days}d."
        )

        try:
            while True:
                await asyncio.sleep(3600)
        except (KeyboardInterrupt, SystemExit):
            logger.info("Shutting down daemon...")
            scheduler.shutdown()
            tg_worker_task.cancel()


def parse_args():
    parser = argparse.ArgumentParser(description="Dark Web Threat Intelligence Engine")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single health check and scraping cycle, then exit"
    )
    return parser.parse_args()


async def main():
    args = parse_args()
    if args.once:
        await run_once()
    else:
        await run_daemon()


if __name__ == "__main__":
    asyncio.run(main())