import asyncio
import sqlite3

import pytest

from scraper.config import Config
from scraper.crawler.processor import PageProcessor
from scraper.storage.db import init_db
from scraper.parsers.dom import get_soup


class DummyCrawler:
    def __init__(self):
        self.fetches = 0

    async def fetch_with_semaphore(self, *args, **kwargs):
        self.fetches += 1
        return None


@pytest.mark.asyncio
async def test_process_page_persists_summary_and_deduplicates(
    tmp_path, sample_forum_html, monkeypatch
):
    db = tmp_path / "alerts.db"
    config = Config(
        db_path=str(db),
        llm_cache_enabled=False,
        llm_prefilter_keywords=False,
        require_relevance=True,
        gguf_model_path=str(tmp_path / "missing.gguf"),
    )
    init_db(config=config)
    soup = get_soup(sample_forum_html)
    calls = {"count": 0}

    def fake_filter(text, source_name, group_hint, *, iocs=None, config=None):
        calls["count"] += 1
        return {
            "is_relevant": True,
            "category": "data_leak",
            "severity": "high",
            "threat_group": group_hint,
            "summary": "Acme customer database leaked.",
            "entities": [],
            "iocs": list(iocs or []),
        }

    monkeypatch.setattr(
        "scraper.crawler.processor.filter_and_summarize", fake_filter
    )
    queued = []
    monkeypatch.setattr(
        "scraper.crawler.processor.enqueue_alert", lambda payload: queued.append(payload)
    )

    processor = PageProcessor(DummyCrawler(), config=config)
    site = {"name": "BreachForums", "group_name": "BreachForums", "url": "http://abc.onion/"}
    fetch_sem = asyncio.Semaphore(1)
    llm_sem = asyncio.Semaphore(1)

    first = await processor.process_page(
        site,
        "http://abc.onion/thread-1",
        fetch_sem,
        llm_sem,
        session=None,
        cached_html=sample_forum_html,
        cached_soup=soup,
    )
    assert first is True
    assert calls["count"] == 1
    assert queued and queued[0]["severity"] == "high"

    second = await processor.process_page(
        site,
        "http://abc.onion/thread-1",
        fetch_sem,
        llm_sem,
        session=None,
        cached_html=sample_forum_html,
        cached_soup=soup,
    )
    assert second is False
    assert calls["count"] == 1

    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT summary, category, severity FROM alerts"
        ).fetchone()
        assert row["summary"] == "Acme customer database leaked."
        assert row["category"] == "data_leak"
        assert row["severity"] == "high"


@pytest.mark.asyncio
async def test_prefilter_skips_irrelevant_pages(
    tmp_path, sample_forum_html, monkeypatch
):
    db = tmp_path / "alerts.db"
    config = Config(
        db_path=str(db),
        llm_cache_enabled=False,
        llm_prefilter_keywords=True,
        keywords=("unmatched-term",),
        require_relevance=True,
    )
    init_db(config=config)
    soup = get_soup("<html><body><div id='posts'><div class='post'><div class='post_body'>hello world</div></div></div></body></html>")

    called = {"count": 0}

    def fake_filter(*args, **kwargs):
        called["count"] += 1
        return {"is_relevant": True}

    monkeypatch.setattr(
        "scraper.crawler.processor.filter_and_summarize", fake_filter
    )
    processor = PageProcessor(DummyCrawler(), config=config)
    result = await processor.process_page(
        {"name": "x", "group_name": "x", "url": "http://abc.onion/"},
        "http://abc.onion/thread-1",
        asyncio.Semaphore(1),
        asyncio.Semaphore(1),
        session=None,
        cached_html="<html></html>",
        cached_soup=soup,
    )
    assert result is False
    assert called["count"] == 0
