import json
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, unquote

from scraper.config import CONFIG
from scraper.parsers.url import normalize_hostname
from scraper.storage.db import get_db_connection

logger = logging.getLogger("scraper")


class SiteRepository:
    """Data access layer for tracked onion services and their health metrics."""

    @staticmethod
    def get_all_sites() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        rows = [dict(r) for r in conn.execute("SELECT url FROM sites ORDER BY url").fetchall()]
        conn.close()
        return rows

    @staticmethod
    def get_live_sites() -> List[Dict[str, Any]]:
        conn = get_db_connection()
        rows = [dict(r) for r in conn.execute("""
            SELECT url, name, group_name
            FROM sites
            WHERE status = 'up'
            ORDER BY last_scrape ASC NULLS FIRST
        """).fetchall()]
        conn.close()
        return rows

    @staticmethod
    def mark_scrape_attempt(url: str):
        now = int(datetime.now(timezone.utc).timestamp())
        conn = get_db_connection()
        conn.execute("UPDATE sites SET last_scrape = ? WHERE url = ?", (now, url))
        conn.commit()
        conn.close()

    @staticmethod
    def update_health(url: str, alive: bool, status_code: Optional[int], error: Optional[str]):
        now = int(datetime.now(timezone.utc).timestamp())
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT status, consecutive_failures, check_count, up_count, last_up, window_start
            FROM sites WHERE url = ?
        """, (url,))
        row = c.fetchone()
        if not row:
            conn.close()
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
            new_status = "down" if failures >= CONFIG.max_failures_before_down else old_status

        uptime_30 = round((up_count / check_count) * 100, 2) if check_count > 0 else 0

        c.execute("""
            UPDATE sites
            SET status = ?, last_check = ?, last_up = ?,
                consecutive_failures = ?, check_count = ?, up_count = ?,
                uptime_30 = ?, last_error = ?, window_start = ?
            WHERE url = ?
        """, (new_status, now, last_up, failures, check_count, up_count, uptime_30, error, window_start, url))
        conn.commit()
        conn.close()


class AlertRepository:
    """Data access layer for captured threat intelligence alerts."""

    @staticmethod
    def save_if_new(
        source_name: str,
        source_url: str,
        group_name: str,
        description: str,
        content_hash: str,
        category: str,
        entities: List[str],
        iocs: List[str]
    ) -> bool:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            source_host = normalize_hostname(urlparse(str(source_url)).hostname)

            c.execute("SELECT id FROM alerts WHERE source_host = ? AND source_url = ?", (source_host, source_url))
            if c.fetchone():
                return False

            c.execute("SELECT id FROM alerts WHERE source_host = ? AND content_hash = ?", (source_host, content_hash))
            if c.fetchone():
                return False

            timestamp = int(datetime.now(timezone.utc).timestamp())
            source_url_decoded = unquote(source_url)
            c.execute(
                """
                INSERT INTO alerts
                    (source_name, source_url, source_url_decoded, source_host, group_name, content_hash,
                     description, category, entities, iocs, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_name,
                    source_url,
                    source_url_decoded,
                    source_host,
                    group_name,
                    content_hash,
                    description,
                    category,
                    json.dumps(entities, ensure_ascii=False),
                    json.dumps(iocs, ensure_ascii=False),
                    timestamp
                )
            )
            conn.commit()
            logger.info(f"New alert saved for {source_name} (hash: {content_hash[:8]}...)")
            return True
        except Exception as e:
            logger.debug(f"Save alert ignored/failed: {e}")
            return False
        finally:
            conn.close()

    @staticmethod
    def cleanup_old(retention_days: int = CONFIG.data_retention_days) -> int:
        conn = get_db_connection()
        try:
            c = conn.cursor()
            cutoff = int((datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp())
            c.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
            deleted = c.rowcount
            conn.commit()
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            except Exception:
                pass
            return deleted
        finally:
            conn.close()