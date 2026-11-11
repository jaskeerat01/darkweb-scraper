"""Seed/synchronise targets from the configured CSV file."""

from __future__ import annotations

import csv
import logging
from datetime import datetime, timezone

from scraper.config import CONFIG, Config
from scraper.network.policy import is_allowed_target_url, target_kind
from scraper.parsers.url import is_onion_url, redact_url, sanitize_url_for_storage
from scraper.storage.db import db_connection

logger = logging.getLogger("scraper")

_SKIP_TITLE_KEYWORDS = (
    "seized",
    "captcha",
    "just a moment",
    "cloudflare",
    "bot detection",
    "parking page",
    "for sale",
    "attention required",
    "domain is for sale",
    "buy this domain",
)


def seed_sites_from_csv(
    csv_path: str | None = None,
    db_path: str | None = None,
    *,
    config: Config | None = None,
) -> int:
    """Load targets from CSV into SQLite and return the number upserted.

    Clearnet rows are skipped unless the target policy allows them.  Existing
    rows are updated in place; removal only happens when ``SEED_REMOVE_MISSING``
    is explicitly enabled.
    """
    cfg = config or CONFIG
    source = csv_path or cfg.csv_path

    try:
        handle = open(source, mode="r", encoding="utf-8-sig")
    except OSError as exc:
        logger.error("CSV not found or unreadable: %s (%s)", source, type(exc).__name__)
        return 0

    now = int(datetime.now(timezone.utc).timestamp())
    upserted = 0
    skipped_clearnet = 0
    skipped_invalid = 0
    seen_urls: set[str] = set()

    with handle, db_connection(db_path, config=cfg) as conn:
        reader = csv.DictReader(handle)
        for row in reader:
            raw_url = (row.get("URL") or "").strip()
            name = (row.get("Name") or "Unknown").strip() or "Unknown"
            csv_status = (row.get("Status") or "").strip().lower()
            title = (row.get("PageTitle") or "").lower()

            if not raw_url or any(keyword in title for keyword in _SKIP_TITLE_KEYWORDS):
                skipped_invalid += 1
                continue
            if not raw_url.startswith(("http://", "https://")):
                raw_url = f"http://{raw_url}"

            url = sanitize_url_for_storage(raw_url)
            if not url or not is_allowed_target_url(url, cfg):
                if is_onion_url(url):
                    skipped_invalid += 1
                else:
                    skipped_clearnet += 1
                continue

            kind = target_kind(url)
            initial_status = "up" if csv_status == "online" else "down"
            seen_urls.add(url)
            try:
                conn.execute(
                    """
                    INSERT INTO sites
                        (url, name, group_name, target_type, status, last_check,
                         consecutive_failures, window_start)
                    VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                    ON CONFLICT(url) DO UPDATE SET
                        name = excluded.name,
                        group_name = excluded.group_name,
                        target_type = excluded.target_type
                    """,
                    (
                        url,
                        name,
                        name,
                        kind.value if kind else "onion",
                        initial_status,
                        now,
                        now,
                    ),
                )
                upserted += 1
            except Exception:
                logger.warning(
                    "Failed to upsert target %s",
                    redact_url(url, cfg),
                    exc_info=True,
                )

        if cfg.seed_remove_missing and seen_urls:
            placeholders = ",".join("?" for _ in seen_urls)
            conn.execute(
                f"DELETE FROM sites WHERE url NOT IN ({placeholders})",
                tuple(seen_urls),
            )

        conn.commit()

    logger.info(
        "Seeded/synced %d targets from CSV (skipped %d clearnet, %d invalid).",
        upserted,
        skipped_clearnet,
        skipped_invalid,
    )
    if cfg.allow_clearnet_targets and not cfg.clearnet_enabled:
        logger.warning(
            "ALLOW_CLEARNET_TARGETS is enabled but neither CLEARNET_ALLOWED_DOMAINS "
            "nor CLEARNET_ALLOW_ANY is configured; clearnet targets are skipped."
        )
    return upserted
