import os
import sqlite3
from pathlib import Path
from scraper.config import CONFIG


def get_db_connection() -> sqlite3.Connection:
    """Creates a configured SQLite connection with WAL mode and memory PRAGMAs."""
    db_path = Path(CONFIG.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA secure_delete=ON;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA cache_size = -64000;")
        conn.execute("PRAGMA mmap_size = 268435456;")
    except sqlite3.Error:
        pass
    return conn


def init_db():
    """Applies file permission locks and creates the base schema."""
    for ext in ("", "-wal", "-shm"):
        p = f"{CONFIG.db_path}{ext}"
        try:
            if os.path.exists(p):
                os.chmod(p, 0o600)
        except OSError:
            pass

    conn = get_db_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS sites (
            url TEXT PRIMARY KEY,
            name TEXT,
            group_name TEXT,
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
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT,
            source_url TEXT,
            source_url_decoded TEXT,
            source_host TEXT,
            group_name TEXT,
            content_hash TEXT,
            description TEXT,
            category TEXT,
            entities TEXT,
            iocs TEXT,
            timestamp INTEGER,
            UNIQUE (source_host, content_hash)
        )
    """)

    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_hash ON alerts (content_hash)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_host_url ON alerts (source_host, source_url)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_host_hash ON alerts (source_host, content_hash)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_sites_status ON sites (status)")

    conn.commit()
    conn.close()