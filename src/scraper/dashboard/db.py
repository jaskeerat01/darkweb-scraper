"""Read-only SQLite access for the dashboard."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from urllib.parse import quote


class DatabaseUnavailable(RuntimeError):
    """Raised when the alerts database does not exist or has no schema."""


def _connect(path: Path) -> sqlite3.Connection:
    if not path.exists():
        raise DatabaseUnavailable("database file is missing")

    try:
        uri = f"file:{quote(str(path))}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=2.0)
    except sqlite3.OperationalError:
        # WAL shared-memory files may require a writable handle; enforce
        # logical read-only mode instead.
        conn = sqlite3.connect(str(path), timeout=2.0)
        conn.execute("PRAGMA query_only=ON;")

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON;")
    conn.execute("PRAGMA busy_timeout=2000;")
    conn.execute("PRAGMA temp_store=MEMORY;")
    conn.execute("PRAGMA cache_size=-2048;")
    return conn


def _has_alerts_table(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alerts' LIMIT 1"
    ).fetchone()
    return row is not None


@contextmanager
def read_only_connection(path: Path) -> Iterator[sqlite3.Connection]:
    conn = _connect(path)
    try:
        if not _has_alerts_table(conn):
            raise DatabaseUnavailable("alerts table is missing")
        yield conn
    finally:
        conn.close()


def database_status(path: Path) -> tuple[bool, str]:
    """Return ``(available, reason)`` without creating or migrating anything."""
    try:
        with read_only_connection(path):
            return True, "ok"
    except DatabaseUnavailable as exc:
        return False, str(exc)
    except sqlite3.Error:
        return False, "database error"


def query_only_guard(path: Path) -> None:
    """Raise if the dashboard connection can write.

    Used by tests to guarantee the read-only contract.
    """
    with read_only_connection(path) as conn:
        try:
            conn.execute("CREATE TABLE __dashboard_write_probe (id INTEGER)")
        except sqlite3.OperationalError:
            return
        raise AssertionError("dashboard database connection accepted a write")
