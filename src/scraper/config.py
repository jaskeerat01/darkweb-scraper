import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv

load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _parse_list_env(name: str, default: List[str]) -> List[str]:
    val = os.getenv(name)
    if not val:
        return default
    return [item.strip() for item in val.split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    # Tor Networking & Control
    tor_host: str = os.getenv("TOR_HOST", "127.0.0.1")
    tor_socks_port: int = int(os.getenv("TOR_SOCKS_PORT", "9050"))
    tor_control_port: int = int(os.getenv("TOR_CONTROL_PORT", "9051"))
    tor_control_password: Optional[str] = os.getenv("TOR_CONTROL_PASSWORD")
    tor_newnym_min_interval: int = int(os.getenv("TOR_NEWNYM_MIN_INTERVAL", "10"))

    # Job Intervals (minutes)
    scrape_interval_minutes: int = int(os.getenv("SCRAPE_INTERVAL_MINUTES", "120"))
    health_interval_minutes: int = int(os.getenv("HEALTH_INTERVAL_MINUTES", "30"))

    # Local LLM Parameters
    gguf_model_path: str = os.getenv(
        "GGUF_MODEL_PATH",
        str(Path("models/qwen2.5-1.5b-instruct-q4_k_m.gguf") if Path("models").exists() else Path("qwen2.5-1.5b-instruct-q4_k_m.gguf"))
    )
    llm_context: int = int(os.getenv("LLM_CONTEXT", "4096"))
    llm_threads: int = int(os.getenv("LLM_THREADS", "4"))
    llm_gpu_layers: int = int(os.getenv("LLM_GPU_LAYERS", "0"))
    llm_flash_attn: bool = _env_bool("LLM_FLASH_ATTN", False)
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))
    llm_prefilter_keywords: bool = _env_bool("LLM_PREFILTER_KEYWORDS", True)

    # Threat Intelligence Keywords
    keywords: List[str] = field(default_factory=lambda: _parse_list_env(
        "KEYWORDS",
        ["data breach", "exploit", "crypto", "leak", "0day", "ransomware", "victim"]
    ))

    # Persistence & Input Paths
    db_path: str = os.getenv(
        "DB_PATH",
        str(Path("data/alerts.db") if Path("data").exists() else Path("alerts.db"))
    )
    csv_path: str = os.getenv(
        "CSV_PATH",
        str(Path("data/forum_sites.csv") if Path("data/forum_sites.csv").exists() else Path("forum_sites.csv"))
    )

    # HTTP & Timeout Safeguards
    max_response_bytes: int = int(os.getenv("MAX_RESPONSE_BYTES", str(5 * 1024 * 1024)))
    health_timeout: int = int(os.getenv("HEALTH_TIMEOUT", "15"))
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "60"))
    max_failures_before_down: int = int(os.getenv("MAX_FAILURES", "2"))

    # Retention
    data_retention_days: int = int(os.getenv("DATA_RETENTION_DAYS", "500"))

    # Concurrency Controls
    max_parallel_sites: int = int(os.getenv("MAX_PARALLEL_SITES", "6"))
    max_parallel_fetches: int = int(os.getenv("MAX_PARALLEL_FETCHES", "8"))
    max_parallel_health: int = int(os.getenv("MAX_PARALLEL_HEALTH", "12"))
    max_llm_workers: int = int(os.getenv("MAX_LLM_WORKERS", "1"))
    max_fetches_per_domain: int = int(os.getenv("MAX_FETCHES_PER_DOMAIN", "1"))

    # Recursive Crawler Discovery
    page_discovery_enabled: bool = _env_bool("PAGE_DISCOVERY_ENABLED", True)
    max_pages_per_site: int = int(os.getenv("MAX_PAGES_PER_SITE", "5"))
    page_discovery_depth: int = int(os.getenv("PAGE_DISCOVERY_DEPTH", "2"))
    max_links_per_page: int = int(os.getenv("MAX_LINKS_PER_PAGE", "25"))
    min_link_score: int = int(os.getenv("MIN_LINK_SCORE", "-10"))
    follow_external_links: bool = _env_bool("FOLLOW_EXTERNAL_LINKS", False)
    max_external_links_per_site: int = int(os.getenv("MAX_EXTERNAL_LINKS_PER_SITE", "2"))

    # Forum & Thread Parsing Policy
    require_relevance: bool = _env_bool("REQUIRE_RELEVANCE", True)
    first_page_only: bool = _env_bool("THREAD_FIRST_PAGE_ONLY", True)
    first_post_only: bool = _env_bool("FIRST_POST_ONLY", True)
    summarize_alerts: bool = _env_bool("SUMMARIZE_ALERTS", True)

    # OPSEC & Dispatch
    allow_clearnet_targets: bool = _env_bool("ALLOW_CLEARNET_TARGETS", False)
    redact_urls_in_logs: bool = _env_bool("REDACT_URLS_IN_LOGS", False)
    include_source_url_in_alerts: bool = _env_bool("INCLUDE_SOURCE_URL_IN_ALERTS", True)
    telegram_token: Optional[str] = os.getenv("TELEGRAM_BOT_TOKEN")
    telegram_chat_id: Optional[str] = os.getenv("TELEGRAM_CHAT_ID")
    telegram_proxy: Optional[str] = os.getenv("TELEGRAM_PROXY") or None


CONFIG = Config()