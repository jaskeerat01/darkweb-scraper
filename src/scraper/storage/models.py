"""Shared typed records used across the pipeline and dashboard tests."""

from __future__ import annotations

from typing import Literal, TypedDict

Severity = Literal["high", "medium", "low"]
Network = Literal["onion", "clearnet"]


class SiteRow(TypedDict, total=False):
    url: str
    name: str
    group_name: str
    status: str
    target_type: str
    last_check: int | None
    last_up: int | None
    last_scrape: int | None
    consecutive_failures: int
    uptime_30: float
    check_count: int
    up_count: int
    last_error: str | None
    window_start: int | None


class AlertRow(TypedDict, total=False):
    id: int
    source_name: str
    source_url: str
    source_host: str
    group_name: str
    content_hash: str
    description: str
    summary: str
    category: str
    severity: Severity
    entities: str
    iocs: str
    timestamp: int
    network: Network


class AlertPayload(TypedDict, total=False):
    source_name: str
    source_url: str
    group_name: str
    category: str
    severity: Severity
    summary: str
    entities: list[str]
    iocs: list[str]
    hash: str
    timestamp: str
    network: Network


class LLMResult(TypedDict, total=False):
    is_relevant: bool
    category: str
    severity: Severity
    threat_group: str
    summary: str
    entities: list[str]
    iocs: list[str]
    error: str
    degraded: bool


class SiteHealth(TypedDict):
    status: str
    count: int
    average_uptime: float


class Stats(TypedDict):
    total: int
    today: int
    last_24h: int
    high_7d: int
    onion: int
    clearnet: int
    sites_up: int
    sites_down: int
    sites_unknown: int
    top_categories: list[dict[str, object]]
