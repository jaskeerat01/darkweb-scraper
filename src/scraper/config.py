"""Environment-backed configuration with validation.

The module keeps the historical ``CONFIG`` singleton for compatibility, but all
values are now parsed and validated by :meth:`Config.from_env`.  Tests and new
call sites can inject a configuration object instead of mutating ``os.environ``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from dotenv import load_dotenv

from scraper.core.exceptions import ConfigError

load_dotenv()

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off", ""}


def _env_bool(
    env: Mapping[str, str],
    name: str,
    default: bool = False,
) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be a boolean (true/false), got {raw!r}")


def _env_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        value = default
    else:
        try:
            value = int(raw.strip())
        except ValueError as exc:
            raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc

    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be <= {maximum}, got {value}")
    return value


def _env_float(
    env: Mapping[str, str],
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        value = default
    else:
        try:
            value = float(raw.strip())
        except ValueError as exc:
            raise ConfigError(f"{name} must be a number, got {raw!r}") from exc

    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be <= {maximum}, got {value}")
    return value


def _env_list(
    env: Mapping[str, str],
    name: str,
    default: Sequence[str] = (),
) -> tuple[str, ...]:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return tuple(default)
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _env_ports(env: Mapping[str, str], name: str, default: Sequence[int]) -> frozenset[int]:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return frozenset(default)

    ports: set[int] = set()
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError as exc:
            raise ConfigError(f"{name} contains a non-integer port: {token!r}") from exc
        if not 1 <= port <= 65535:
            raise ConfigError(f"{name} contains an invalid port: {port}")
        ports.add(port)
    if not ports:
        raise ConfigError(f"{name} must contain at least one port")
    return frozenset(ports)


def _env_path(env: Mapping[str, str], name: str, default: str) -> str:
    raw = env.get(name, default)
    return raw.strip() if raw.strip() else default


@dataclass(frozen=True, slots=True)
class Config:
    """Validated runtime configuration for the scraper and scheduler."""

    # Tor Networking & Control
    tor_host: str = "127.0.0.1"
    tor_socks_port: int = 9050
    tor_control_port: int = 9051
    tor_control_password: str | None = None
    tor_newnym_min_interval: int = 10
    tor_renew_interval_minutes: int = 30

    # Job Intervals (minutes)
    scrape_interval_minutes: int = 120
    health_interval_minutes: int = 30

    # Local LLM Parameters
    gguf_model_path: str = "models/qwen2.5-1.5b-instruct-q4_k_m.gguf"
    llm_context: int = 4096
    llm_threads: int = 4
    llm_gpu_layers: int = 0
    llm_flash_attn: bool = False
    llm_temperature: float = 0.1
    llm_prefilter_keywords: bool = True
    llm_max_tokens: int = 512
    llm_fail_open: bool = True
    llm_cache_enabled: bool = True
    llm_cache_days: int = 30

    # Threat Intelligence Keywords
    keywords: tuple[str, ...] = (
        "data breach",
        "exploit",
        "crypto",
        "leak",
        "0day",
        "ransomware",
        "victim",
    )

    # Persistence & Input Paths
    db_path: str = "data/alerts.db"
    csv_path: str = "data/forum_sites.csv"

    # HTTP & Timeout Safeguards
    max_response_bytes: int = 5 * 1024 * 1024
    health_timeout: int = 15
    request_timeout: int = 60
    max_failures_before_down: int = 2

    # Fetch behaviour
    fetch_retries: int = 2
    fetch_backoff_base: float = 2.0
    domain_min_interval: float = 2.0

    # Retention
    data_retention_days: int = 500

    # Concurrency Controls
    max_parallel_sites: int = 3
    max_parallel_fetches: int = 3
    max_parallel_health: int = 6
    max_llm_workers: int = 1
    max_fetches_per_domain: int = 1

    # Cycle budgets (seconds)
    scrape_cycle_budget_seconds: int = 3600
    site_budget_seconds: int = 600

    # Recursive Crawler Discovery
    page_discovery_enabled: bool = True
    max_pages_per_site: int = 50
    page_discovery_depth: int = 2
    max_links_per_page: int = 25
    min_link_score: int = -10
    follow_external_links: bool = False
    max_external_links_per_site: int = 2

    # Clearnet targets (always fetched through the Tor SOCKS proxy)
    allow_clearnet_targets: bool = False
    clearnet_allowed_domains: tuple[str, ...] = ()
    clearnet_allow_any: bool = False
    clearnet_allowed_ports: frozenset[int] = field(
        default_factory=lambda: frozenset({80, 443})
    )
    clearnet_require_https: bool = False
    clearnet_max_redirects: int = 3

    # Forum & Thread Parsing Policy
    require_relevance: bool = True
    first_page_only: bool = True
    first_post_only: bool = True
    summarize_alerts: bool = True

    # Seed synchronisation
    seed_remove_missing: bool = False

    # OPSEC & Dispatch
    redact_urls_in_logs: bool = False
    include_source_url_in_alerts: bool = True
    telegram_token: str | None = None
    telegram_chat_id: str | None = None
    telegram_proxy: str | None = None
    telegram_queue_size: int = 500

    def __post_init__(self) -> None:
        if self.clearnet_require_https and 80 in self.clearnet_allowed_ports:
            # Not an error: https-only simply rejects http before the port check.
            pass
        if self.max_llm_workers < 1:
            raise ConfigError("MAX_LLM_WORKERS must be >= 1")
        if self.tor_newnym_min_interval < 0:
            raise ConfigError("TOR_NEWNYM_MIN_INTERVAL must be >= 0")
        if self.data_retention_days < 1:
            raise ConfigError("DATA_RETENTION_DAYS must be >= 1")
        if self.max_response_bytes < 1024:
            raise ConfigError("MAX_RESPONSE_BYTES must be >= 1024")

    @property
    def clearnet_enabled(self) -> bool:
        """True only when clearnet is enabled *and* an explicit scope exists."""
        if not self.allow_clearnet_targets:
            return False
        return bool(self.clearnet_allowed_domains) or self.clearnet_allow_any

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_token and self.telegram_chat_id)

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        load_dotenv_file: bool = False,
    ) -> "Config":
        """Build a validated config from a mapping (defaults to ``os.environ``)."""
        if load_dotenv_file:
            load_dotenv()
        values = os.environ if env is None else env

        def text(name: str, default: str = "") -> str:
            raw = values.get(name)
            return default if raw is None else raw.strip()

        return cls(
            tor_host=text("TOR_HOST", "127.0.0.1"),
            tor_socks_port=_env_int(values, "TOR_SOCKS_PORT", 9050, minimum=1, maximum=65535),
            tor_control_port=_env_int(
                values, "TOR_CONTROL_PORT", 9051, minimum=1, maximum=65535
            ),
            tor_control_password=text("TOR_CONTROL_PASSWORD") or None,
            tor_newnym_min_interval=_env_int(
                values, "TOR_NEWNYM_MIN_INTERVAL", 10, minimum=0, maximum=3600
            ),
            tor_renew_interval_minutes=_env_int(
                values, "TOR_RENEW_INTERVAL_MINUTES", 30, minimum=1, maximum=1440
            ),
            scrape_interval_minutes=_env_int(
                values, "SCRAPE_INTERVAL_MINUTES", 120, minimum=1, maximum=10080
            ),
            health_interval_minutes=_env_int(
                values, "HEALTH_INTERVAL_MINUTES", 30, minimum=1, maximum=10080
            ),
            gguf_model_path=_env_path(
                values,
                "GGUF_MODEL_PATH",
                "models/qwen2.5-1.5b-instruct-q4_k_m.gguf",
            ),
            llm_context=_env_int(values, "LLM_CONTEXT", 4096, minimum=512, maximum=32768),
            llm_threads=_env_int(values, "LLM_THREADS", 4, minimum=1, maximum=64),
            llm_gpu_layers=_env_int(values, "LLM_GPU_LAYERS", 0, minimum=0, maximum=256),
            llm_flash_attn=_env_bool(values, "LLM_FLASH_ATTN", False),
            llm_temperature=_env_float(
                values, "LLM_TEMPERATURE", 0.1, minimum=0.0, maximum=2.0
            ),
            llm_prefilter_keywords=_env_bool(values, "LLM_PREFILTER_KEYWORDS", True),
            llm_max_tokens=_env_int(
                values, "LLM_MAX_TOKENS", 512, minimum=32, maximum=4096
            ),
            llm_fail_open=_env_bool(values, "LLM_FAIL_OPEN", True),
            llm_cache_enabled=_env_bool(values, "LLM_CACHE_ENABLED", True),
            llm_cache_days=_env_int(values, "LLM_CACHE_DAYS", 30, minimum=1, maximum=3650),
            keywords=_env_list(
                values,
                "KEYWORDS",
                (
                    "data breach",
                    "exploit",
                    "crypto",
                    "leak",
                    "0day",
                    "ransomware",
                    "victim",
                ),
            ),
            db_path=_env_path(values, "DB_PATH", "data/alerts.db"),
            csv_path=_env_path(values, "CSV_PATH", "data/forum_sites.csv"),
            max_response_bytes=_env_int(
                values, "MAX_RESPONSE_BYTES", 5 * 1024 * 1024, minimum=1024
            ),
            health_timeout=_env_int(values, "HEALTH_TIMEOUT", 15, minimum=1, maximum=300),
            request_timeout=_env_int(values, "REQUEST_TIMEOUT", 60, minimum=1, maximum=600),
            max_failures_before_down=_env_int(
                values, "MAX_FAILURES", 2, minimum=1, maximum=100
            ),
            fetch_retries=_env_int(values, "FETCH_RETRIES", 2, minimum=0, maximum=10),
            fetch_backoff_base=_env_float(
                values, "FETCH_BACKOFF_BASE", 2.0, minimum=0.0, maximum=60.0
            ),
            domain_min_interval=_env_float(
                values, "DOMAIN_MIN_INTERVAL", 2.0, minimum=0.0, maximum=120.0
            ),
            data_retention_days=_env_int(
                values, "DATA_RETENTION_DAYS", 500, minimum=1, maximum=36500
            ),
            max_parallel_sites=_env_int(
                values, "MAX_PARALLEL_SITES", 3, minimum=1, maximum=64
            ),
            max_parallel_fetches=_env_int(
                values, "MAX_PARALLEL_FETCHES", 3, minimum=1, maximum=64
            ),
            max_parallel_health=_env_int(
                values, "MAX_PARALLEL_HEALTH", 6, minimum=1, maximum=64
            ),
            max_llm_workers=_env_int(values, "MAX_LLM_WORKERS", 1, minimum=1, maximum=8),
            max_fetches_per_domain=_env_int(
                values, "MAX_FETCHES_PER_DOMAIN", 1, minimum=1, maximum=16
            ),
            scrape_cycle_budget_seconds=_env_int(
                values, "SCRAPE_CYCLE_BUDGET_SECONDS", 3600, minimum=60, maximum=86400
            ),
            site_budget_seconds=_env_int(
                values, "SITE_BUDGET_SECONDS", 600, minimum=30, maximum=86400
            ),
            page_discovery_enabled=_env_bool(values, "PAGE_DISCOVERY_ENABLED", True),
            max_pages_per_site=_env_int(
                values, "MAX_PAGES_PER_SITE", 50, minimum=1, maximum=1000
            ),
            page_discovery_depth=_env_int(
                values, "PAGE_DISCOVERY_DEPTH", 2, minimum=0, maximum=10
            ),
            max_links_per_page=_env_int(
                values, "MAX_LINKS_PER_PAGE", 25, minimum=1, maximum=500
            ),
            min_link_score=_env_int(values, "MIN_LINK_SCORE", -10, minimum=-1000, maximum=1000),
            follow_external_links=_env_bool(values, "FOLLOW_EXTERNAL_LINKS", False),
            max_external_links_per_site=_env_int(
                values, "MAX_EXTERNAL_LINKS_PER_SITE", 2, minimum=0, maximum=100
            ),
            allow_clearnet_targets=_env_bool(values, "ALLOW_CLEARNET_TARGETS", False),
            clearnet_allowed_domains=_env_list(values, "CLEARNET_ALLOWED_DOMAINS", ()),
            clearnet_allow_any=_env_bool(values, "CLEARNET_ALLOW_ANY", False),
            clearnet_allowed_ports=_env_ports(
                values, "CLEARNET_ALLOWED_PORTS", (80, 443)
            ),
            clearnet_require_https=_env_bool(values, "CLEARNET_REQUIRE_HTTPS", False),
            clearnet_max_redirects=_env_int(
                values, "CLEARNET_MAX_REDIRECTS", 3, minimum=0, maximum=10
            ),
            require_relevance=_env_bool(values, "REQUIRE_RELEVANCE", True),
            first_page_only=_env_bool(values, "THREAD_FIRST_PAGE_ONLY", True),
            first_post_only=_env_bool(values, "FIRST_POST_ONLY", True),
            summarize_alerts=_env_bool(values, "SUMMARIZE_ALERTS", True),
            seed_remove_missing=_env_bool(values, "SEED_REMOVE_MISSING", False),
            redact_urls_in_logs=_env_bool(values, "REDACT_URLS_IN_LOGS", False),
            include_source_url_in_alerts=_env_bool(
                values, "INCLUDE_SOURCE_URL_IN_ALERTS", True
            ),
            telegram_token=text("TELEGRAM_BOT_TOKEN") or None,
            telegram_chat_id=text("TELEGRAM_CHAT_ID") or None,
            telegram_proxy=text("TELEGRAM_PROXY") or None,
            telegram_queue_size=_env_int(
                values, "TELEGRAM_QUEUE_SIZE", 500, minimum=10, maximum=100000
            ),
        )


CONFIG = Config.from_env()


def default_db_path(config: Config | None = None) -> Path:
    """Return the configured SQLite path as a :class:`Path`."""
    return Path((config or CONFIG).db_path)
