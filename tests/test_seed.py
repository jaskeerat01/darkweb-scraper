import csv

from scraper.config import Config
from scraper.storage.db import db_connection, init_db
from scraper.storage.seed import seed_sites_from_csv


def _write_csv(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "Name",
                "Type",
                "URL",
                "Status",
                "LastScrape",
                "Uptime30",
                "PageTitle",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def test_clearnet_rows_are_skipped_by_default(tmp_path):
    db = tmp_path / "alerts.db"
    csv_path = tmp_path / "sites.csv"
    _write_csv(
        csv_path,
        [
            {"Name": "onion", "Type": "onion", "URL": "http://abc.onion/"},
            {"Name": "clear", "Type": "clearnet", "URL": "https://example.com/"},
        ],
    )
    config = Config(db_path=str(db), csv_path=str(csv_path))
    init_db(config=config)
    assert seed_sites_from_csv(config=config) == 1

    with db_connection(db, config=config) as conn:
        rows = conn.execute("SELECT url, target_type FROM sites").fetchall()
        assert len(rows) == 1
        assert rows[0]["target_type"] == "onion"


def test_clearnet_rows_are_ingested_when_allowlisted(tmp_path):
    db = tmp_path / "alerts.db"
    csv_path = tmp_path / "sites.csv"
    _write_csv(
        csv_path,
        [
            {"Name": "clear", "Type": "clearnet", "URL": "https://example.com/"},
            {"Name": "other", "Type": "clearnet", "URL": "https://other.net/"},
        ],
    )
    config = Config(
        db_path=str(db),
        csv_path=str(csv_path),
        allow_clearnet_targets=True,
        clearnet_allowed_domains=("example.com",),
    )
    init_db(config=config)
    assert seed_sites_from_csv(config=config) == 1

    with db_connection(db, config=config) as conn:
        row = conn.execute("SELECT url, target_type FROM sites").fetchone()
        assert row["url"] == "https://example.com/"
        assert row["target_type"] == "clearnet"
