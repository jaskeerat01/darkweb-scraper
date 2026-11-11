import os
import sqlite3

import pytest

from scraper.storage.db import SCHEMA_VERSION, db_connection, init_db
from scraper.storage.repositories import (
    AlertRepository,
    LLMCacheRepository,
)


def _columns(conn, table):
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def test_init_db_creates_schema_and_is_idempotent(temp_db):
    init_db(str(temp_db))
    with sqlite3.connect(temp_db) as conn:
        conn.row_factory = sqlite3.Row
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        assert {"summary", "severity"} <= _columns(conn, "alerts")
        assert "target_type" in _columns(conn, "sites")
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='llm_cache'"
        ).fetchone()


def test_database_permissions_are_private(temp_db):
    mode = os.stat(temp_db).st_mode & 0o777
    assert mode == 0o600


def test_migrates_legacy_schema(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE sites (
            url TEXT PRIMARY KEY, name TEXT, group_name TEXT, status TEXT,
            last_check INTEGER, last_up INTEGER, last_scrape INTEGER,
            consecutive_failures INTEGER DEFAULT 0, uptime_30 REAL DEFAULT 0,
            check_count INTEGER DEFAULT 0, up_count INTEGER DEFAULT 0,
            last_error TEXT, window_start INTEGER
        );
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, source_name TEXT,
            source_url TEXT, source_url_decoded TEXT, source_host TEXT,
            group_name TEXT, content_hash TEXT, description TEXT,
            category TEXT, entities TEXT, iocs TEXT, timestamp INTEGER,
            UNIQUE (source_host, content_hash)
        );
        INSERT INTO sites (url) VALUES ('http://legacy.onion/');
        INSERT INTO alerts
            (source_name, source_url, source_host, content_hash, description,
             category, entities, iocs, timestamp)
        VALUES ('legacy', 'http://legacy.onion/thread-1', 'legacy.onion',
                'hash', 'LockBit ransomware leak of customer records',
                'other', '[]', '[]', 1700000000);
        """
    )
    conn.commit()
    conn.close()

    init_db(str(path))
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        alert = conn.execute("SELECT * FROM alerts").fetchone()
        assert alert["severity"] == "high"
        assert alert["category"] == "ransomware"
        site = conn.execute("SELECT * FROM sites").fetchone()
        assert site["target_type"] == "onion"


def test_read_only_connection_rejects_writes(temp_db):
    with db_connection(temp_db, read_only=True) as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO alerts (source_name) VALUES ('x')")


def test_alert_repository_deduplicates_and_persists_summary(temp_db):
    first = AlertRepository.save_if_new(
        "source",
        "http://abc.onion/thread-1",
        "group",
        "description",
        "a" * 64,
        "data_leak",
        [],
        ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
        "summary text",
        "high",
        temp_db,
    )
    assert first is True
    assert AlertRepository.exists("http://abc.onion/thread-1", "a" * 64, temp_db)

    second = AlertRepository.save_if_new(
        "source",
        "http://abc.onion/thread-1",
        "group",
        "description",
        "a" * 64,
        "data_leak",
        [],
        [],
        "summary text",
        "high",
        temp_db,
    )
    assert second is False

    with sqlite3.connect(temp_db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT summary, severity FROM alerts").fetchone()
        assert row["summary"] == "summary text"
        assert row["severity"] == "high"


def test_llm_cache_round_trip(temp_db):
    key = "cache-key"
    LLMCacheRepository.save(
        key,
        "model",
        1,
        True,
        "ransomware",
        "high",
        "summary",
        ["ioc"],
        temp_db,
    )
    cached = LLMCacheRepository.get(key, temp_db)
    assert cached is not None
    assert cached["category"] == "ransomware"
    assert cached["iocs"] == ["ioc"]


def test_cleanup_removes_old_alerts_and_cache(temp_db):
    AlertRepository.save_if_new(
        "s",
        "http://abc.onion/x",
        "g",
        "d",
        "b" * 64,
        "other",
        [],
        [],
        "",
        "low",
        temp_db,
    )
    with db_connection(temp_db) as conn:
        conn.execute("UPDATE alerts SET timestamp = 0")
        conn.commit()
    assert AlertRepository.cleanup_old(30, 7, temp_db) == 1
