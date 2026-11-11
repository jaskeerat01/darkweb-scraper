"""SQLite connection helpers and additive schema migrations."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import quote, urlparse

from scraper.config import CONFIG, Config
from scraper.intel.taxonomy import derive_category, derive_severity

SCHEMA_VERSION = 3


def _resolve_db_path(db_path: str | Path | None, config: Config | None = None) -> Path:
    value = db_path if db_path is not None else (config or CONFIG).db_path
    return Path(value)


def _is_onion_url(url: str) -> bool:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".").endswith(".onion")
    except ValueError:
        return False


def _connect(
    path: Path,
    *,
    read_only: bool = False,
    cache_kib: int | None = None,
) -> sqlite3.Connection:
    if read_only:
        if not path.exists():
            raise FileNotFoundError(str(path))
        try:
            uri = f"file:{quote(str(path))}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        except sqlite3.OperationalError:
            # WAL databases can require a writable -shm file. Fall back to a
            # normal handle, then enforce logical read-only mode.
            conn = sqlite3.connect(str(path), timeout=5.0)
            conn.execute("PRAGMA query_only=ON;")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA query_only=ON;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute(f"PRAGMA cache_size = -{cache_kib or 4096};")
        return conn

    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA secure_delete=ON;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute(f"PRAGMA cache_size = -{cache_kib or 64000};")
    conn.execute("PRAGMA mmap_size = 268435456;")
    return conn


def get_db_connection(
    db_path: str | Path | None = None,
    *,
    config: Config | None = None,
) -> sqlite3.Connection:
    """Create a configured read/write SQLite connection.

    Callers own the returned connection and must close it.  New code should
    prefer :func:`db_connection`, which closes it automatically.
    """
    return _connect(_resolve_db_path(db_path, config))


@contextmanager
def db_connection(
    db_path: str | Path | None = None,
    *,
    read_only: bool = False,
    config: Config | None = None,
    cache_kib: int | None = None,
) -> Iterator[sqlite3.Connection]:
    conn = _connect(
        _resolve_db_path(db_path, config),
        read_only=read_only,
        cache_kib=cache_kib,
    )
    try:
        yield conn
    finally:
        conn.close()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {str(row["name"]) for row in rows}


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
        (table,),
    ).fetchone()
    return row is not None


def _ensure_column(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sites (
            url TEXT PRIMARY KEY,
            name TEXT,
            group_name TEXT,
            target_type TEXT NOT NULL DEFAULT 'onion',
            status TEXT DEFAULT 'unknown',
            last_check INTEGER,
            last_up INTEGER,
            last_scrape INTEGER,
            consecutive_failures INTEGER DEFAULT 0,
            uptime_30 REAL DEFAULT 0,
            check_count INTEGER DEFAULT 0,
            up_count INTEGER DEFAULT 0,
            last_error TEXT,
            window_start INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT,
            source_url TEXT,
            source_url_decoded TEXT,
            source_host TEXT,
            group_name TEXT,
            content_hash TEXT,
            description TEXT,
            summary TEXT,
            category TEXT,
            severity TEXT,
            entities TEXT,
            iocs TEXT,
            timestamp INTEGER,
            UNIQUE (source_host, content_hash)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS llm_cache (
            cache_key TEXT PRIMARY KEY,
            model TEXT,
            prompt_version INTEGER,
            is_relevant INTEGER,
            category TEXT,
            severity TEXT,
            summary TEXT,
            iocs TEXT,
            created_at INTEGER
        )
        """
    )


def _create_indexes(conn: sqlite3.Connection) -> None:
    statements = (
        "CREATE INDEX IF NOT EXISTS idx_alerts_hash ON alerts (content_hash)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_host_url ON alerts (source_host, source_url)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_host_hash ON alerts (source_host, content_hash)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_category_ts ON alerts (category, timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_source_ts ON alerts (source_name, timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity_ts ON alerts (severity, timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_sites_status ON sites (status)",
        "CREATE INDEX IF NOT EXISTS idx_sites_type ON sites (target_type)",
        "CREATE INDEX IF NOT EXISTS idx_llm_cache_created ON llm_cache (created_at)",
    )
    for statement in statements:
        conn.execute(statement)


def _migrate(conn: sqlite3.Connection) -> None:
    _ensure_column(conn, "sites", "target_type", "TEXT NOT NULL DEFAULT 'onion'")
    _ensure_column(conn, "alerts", "summary", "TEXT")
    _ensure_column(conn, "alerts", "severity", "TEXT")

    # Backfill target types once for legacy rows. ALTER TABLE fills the default
    # value, so recompute every row from its URL rather than trusting the default.
    rows = conn.execute("SELECT url FROM sites").fetchall()
    for row in rows:
        kind = "onion" if _is_onion_url(row["url"]) else "clearnet"
        conn.execute(
            "UPDATE sites SET target_type = ? WHERE url = ? AND target_type IS NOT ?",
            (kind, row["url"], kind),
        )

    # Backfill category/severity for legacy alerts in bounded batches.
    while True:
        batch = conn.execute(
            """
            SELECT id, description, category
            FROM alerts
            WHERE severity IS NULL OR severity = ''
            LIMIT 500
            """
        ).fetchall()
        if not batch:
            break
        for row in batch:
            text = row["description"] or ""
            category = derive_category(text, row["category"])
            severity = derive_severity(category, text)
            conn.execute(
                "UPDATE alerts SET category = ?, severity = ? WHERE id = ?",
                (category, severity, row["id"]),
            )
        conn.commit()

    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def init_db(
    db_path: str | Path | None = None,
    *,
    config: Config | None = None,
) -> None:
    """Create or migrate the schema, then lock down database file modes."""
    path = _resolve_db_path(db_path, config)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = _connect(path)
    try:
        _create_schema(conn)
        _migrate(conn)
        _create_indexes(conn)
        conn.commit()
    finally:
        conn.close()

    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{path}{suffix}")
        try:
            if candidate.exists():
                os.chmod(candidate, 0o600)
        except OSError:
            continue


__all__ = [
    "SCHEMA_VERSION",
    "db_connection",
    "get_db_connection",
    "init_db",
]
