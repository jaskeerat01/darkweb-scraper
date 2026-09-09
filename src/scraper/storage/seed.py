import csv
import logging
import os
from datetime import datetime, timezone

from scraper.config import CONFIG
from scraper.parsers.url import is_onion_url, sanitize_url_for_storage
from scraper.storage.db import get_db_connection

logger = logging.getLogger("scraper")


def seed_sites_from_csv():
    """Loads target onion services from the seed CSV file into the database."""
    if not os.path.exists(CONFIG.csv_path):
        logger.error(f"CSV not found: {CONFIG.csv_path}")
        return

    skip_keywords = [
        "seized", "captcha", "just a moment", "cloudflare",
        "bot detection", "parking page", "for sale", "attention required",
        "domain is for sale", "buy this domain"
    ]

    inserted = 0
    now = int(datetime.now(timezone.utc).timestamp())
    conn = get_db_connection()
    c = conn.cursor()

    try:
        with open(CONFIG.csv_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = (row.get("URL") or "").strip()
                name = (row.get("Name") or "Unknown").strip()
                csv_status = (row.get("Status") or "").strip().lower()
                title = (row.get("PageTitle") or "").lower()

                if not url or any(k in title for k in skip_keywords):
                    continue
                if not url.startswith(("http://", "https://")):
                    url = f"http://{url}"

                url = sanitize_url_for_storage(url)
                if not CONFIG.allow_clearnet_targets and not is_onion_url(url):
                    continue

                initial_status = "up" if csv_status == "online" else "down"
                try:
                    c.execute(
                        "INSERT INTO sites (url, name, group_name, status, last_check, consecutive_failures, window_start) "
                        "VALUES (?, ?, ?, ?, ?, 0, ?) "
                        "ON CONFLICT(url) DO UPDATE SET name = excluded.name, group_name = excluded.group_name",
                        (url, name, name, initial_status, now, now)
                    )
                    inserted += 1
                except Exception:
                    pass

        conn.commit()
        logger.info(f"Seeded/synced {inserted} sites from CSV.")
    finally:
        conn.close()