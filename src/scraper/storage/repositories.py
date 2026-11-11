"""Data access for tracked sites, alerts, and the local LLM cache."""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from scraper.config import CONFIG, Config
from scraper.network.policy import host_from_url
from scraper.storage.db import db_connection

logger = logging.getLogger("scraper")


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


class SiteRepository:
    """Data access layer for tracked targets and their health metrics."""

    @staticmethod
    def get_all_sites(
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> list[dict[str, Any]]:
        with db_connection(db_path, config=config) as conn:
            rows = conn.execute(
                "SELECT url, name, target_type FROM sites ORDER BY url"
            ).fetchall()
            return [dict(row) for row in rows]

    @staticmethod
    def get_live_sites(
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> list[dict[str, Any]]:
        with db_connection(db_path, config=config) as conn:
            rows = conn.execute(
                """
                SELECT url, name, group_name, target_type
                FROM sites
                WHERE status = 'up'
                ORDER BY last_scrape ASC NULLS FIRST
                """
            ).fetchall()
            return [dict(row) for row in rows]

    @staticmethod
    def mark_scrape_attempt(
        url: str,
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> None:
        with db_connection(db_path, config=config) as conn:
            conn.execute(
                "UPDATE sites SET last_scrape = ? WHERE url = ?", (_now(), url)
            )
            conn.commit()

    @staticmethod
    def update_health(
        url: str,
        alive: bool,
        status_code: int | None,
        error: str | None,
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> None:
        cfg = config or CONFIG
        now = _now()
        with db_connection(db_path, config=cfg) as conn:
            row = conn.execute(
                """
                SELECT status, consecutive_failures, check_count, up_count,
                       last_up, window_start
                FROM sites WHERE url = ?
                """,
                (url,),
            ).fetchone()
            if row is None:
                return

            old_status = row["status"]
            failures = row["consecutive_failures"] or 0
            check_count = row["check_count"] or 0
            up_count = row["up_count"] or 0
            window_start = row["window_start"]

            if window_start is None or now - window_start >= 30 * 86400:
                check_count = 0
                up_count = 0
                window_start = now
            check_count += 1

            if alive:
                new_status = "up"
                failures = 0
                up_count += 1
                last_up = now
                error = None
            else:
                failures += 1
                last_up = row["last_up"]
                new_status = (
                    "down"
                    if failures >= cfg.max_failures_before_down
                    else old_status
                )

            uptime_30 = (
                round((up_count / check_count) * 100, 2) if check_count else 0.0
            )

            conn.execute(
                """
                UPDATE sites
                SET status = ?, last_check = ?, last_up = ?,
                    consecutive_failures = ?, check_count = ?, up_count = ?,
                    uptime_30 = ?, last_error = ?, window_start = ?
                WHERE url = ?
                """,
                (
                    new_status,
                    now,
                    last_up,
                    failures,
                    check_count,
                    up_count,
                    uptime_30,
                    error,
                    window_start,
                    url,
                ),
            )
            conn.commit()


class AlertRepository:
    """Data access layer for captured threat intelligence alerts."""

    @staticmethod
    def exists(
        source_url: str,
        content_hash: str,
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> bool:
        """Return True when this URL or content hash was already stored.

        Called before LLM inference so repeated pages do not consume CPU.
        """
        source_host = host_from_url(str(source_url))
        with db_connection(db_path, config=config) as conn:
            row = conn.execute(
                """
                SELECT 1 FROM alerts
                WHERE source_host = ?
                  AND (content_hash = ? OR source_url = ?)
                LIMIT 1
                """,
                (source_host, content_hash, source_url),
            ).fetchone()
            return row is not None

    @staticmethod
    def save_if_new(
        source_name: str,
        source_url: str,
        group_name: str,
        description: str,
        content_hash: str,
        category: str,
        entities: list[str],
        iocs: list[str],
        summary: str = "",
        severity: str = "low",
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> bool:
        source_host = host_from_url(str(source_url))
        timestamp = _now()
        source_url_decoded = unquote(source_url)

        with db_connection(db_path, config=config) as conn:
            try:
                # Preserve the historical URL-based duplicate check. The unique
                # (host, hash) constraint is the final guard.
                row = conn.execute(
                    "SELECT 1 FROM alerts WHERE source_host = ? AND source_url = ? LIMIT 1",
                    (source_host, source_url),
                ).fetchone()
                if row is not None:
                    return False

                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO alerts
                        (source_name, source_url, source_url_decoded, source_host,
                         group_name, content_hash, description, summary, category,
                         severity, entities, iocs, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        source_name,
                        source_url,
                        source_url_decoded,
                        source_host,
                        group_name,
                        content_hash,
                        description,
                        summary,
                        category,
                        severity,
                        json.dumps(entities, ensure_ascii=False),
                        json.dumps(iocs, ensure_ascii=False),
                        timestamp,
                    ),
                )
                conn.commit()
                if cursor.rowcount == 0:
                    return False
                logger.info(
                    "New alert saved for %s (hash: %s...)", source_name, content_hash[:8]
                )
                return True
            except sqlite3.IntegrityError:
                logger.debug("Duplicate alert ignored for %s", source_name)
                return False
            except sqlite3.Error:
                logger.exception("Failed to save alert for %s", source_name)
                return False

    @staticmethod
    def cleanup_old(
        retention_days: int | None = None,
        cache_days: int | None = None,
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> int:
        cfg = config or CONFIG
        retention = retention_days if retention_days is not None else cfg.data_retention_days
        cache_retention = cache_days if cache_days is not None else cfg.llm_cache_days
        cutoff = int(
            (datetime.now(timezone.utc) - timedelta(days=retention)).timestamp()
        )
        cache_cutoff = int(
            (datetime.now(timezone.utc) - timedelta(days=cache_retention)).timestamp()
        )

        with db_connection(db_path, config=cfg) as conn:
            cursor = conn.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            deleted = cursor.rowcount
            conn.execute("DELETE FROM llm_cache WHERE created_at < ?", (cache_cutoff,))
            conn.commit()
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            except sqlite3.Error:
                pass
            return deleted


class LLMCacheRepository:
    """Persistent cache for local inference keyed by content + model version."""

    @staticmethod
    def get(
        cache_key: str,
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> dict[str, Any] | None:
        with db_connection(db_path, config=config) as conn:
            row = conn.execute(
                """
                SELECT is_relevant, category, severity, summary, iocs
                FROM llm_cache WHERE cache_key = ?
                """,
                (cache_key,),
            ).fetchone()
            if row is None:
                return None
            try:
                iocs = json.loads(row["iocs"]) if row["iocs"] else []
            except (TypeError, json.JSONDecodeError):
                iocs = []
            return {
                "is_relevant": bool(row["is_relevant"]),
                "category": row["category"] or "other",
                "severity": row["severity"] or "low",
                "summary": row["summary"] or "",
                "iocs": iocs if isinstance(iocs, list) else [],
            }

    @staticmethod
    def save(
        cache_key: str,
        model: str,
        prompt_version: int,
        is_relevant: bool,
        category: str,
        severity: str,
        summary: str,
        iocs: list[str],
        db_path: str | Path | None = None,
        *,
        config: Config | None = None,
    ) -> None:
        with db_connection(db_path, config=config) as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO llm_cache
                        (cache_key, model, prompt_version, is_relevant, category,
                         severity, summary, iocs, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cache_key) DO UPDATE SET
                        model = excluded.model,
                        prompt_version = excluded.prompt_version,
                        is_relevant = excluded.is_relevant,
                        category = excluded.category,
                        severity = excluded.severity,
                        summary = excluded.summary,
                        iocs = excluded.iocs,
                        created_at = excluded.created_at
                    """,
                    (
                        cache_key,
                        model,
                        prompt_version,
                        int(is_relevant),
                        category,
                        severity,
                        summary,
                        json.dumps(iocs, ensure_ascii=False),
                        _now(),
                    ),
                )
                conn.commit()
            except sqlite3.Error:
                logger.debug("Failed to store LLM cache entry", exc_info=True)
