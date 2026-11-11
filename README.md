# Dark Web Threat Intelligence Engine

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Tor Network](https://img.shields.io/badge/Tor-SOCKS5-7D4698?style=for-the-badge&logo=tor-browser&logoColor=white)](https://www.torproject.org/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Local LLM](https://img.shields.io/badge/LLM-Qwen2.5_GGUF-614385?style=for-the-badge&logo=huggingface&logoColor=white)](https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF)
[![Dashboard](https://img.shields.io/badge/Dashboard-read--only-0a0a0a?style=for-the-badge)](http://127.0.0.1:8787)

An automated threat intelligence collector and monitoring system for Tor hidden services and, optionally, allowlisted clearnet targets. It crawls configured sites through Tor, filters relevant security posts, extracts indicators of compromise (IOCs), generates summaries with a local language model, stores findings in SQLite, delivers Telegram alerts, and serves a local read-only dashboard.

---

## Key Features

- **Tor-only transport:** every target request goes through the local SOCKS5 proxy with remote DNS (`rdns=True`). There is no direct-egress path for targets.
- **Onion and optional clearnet targets:** clearnet crawling is disabled by default and, when enabled, is constrained by an allowlist, port policy, private-host rejection, and per-hop redirect validation.
- **Keyword pre-filtering:** custom keywords from `KEYWORDS` screen page text before inference.
- **Local LLM intelligence:** `llama-cpp-python` with a quantized Qwen2.5 model. No cloud LLM dependency.
- **Persistent inference cache:** repeated content is not re-inferred across sites or cycles.
- **IOC extraction:** BTC, ETH, XMR, LTC, BCH, Telegram/Tox/Keybase handles, email addresses, PGP blocks, hashes, and onion URLs.
- **Deduplication:** in-memory per-site hashes, an indexed pre-inference check, and a SQLite unique constraint.
- **Circuit rotation:** Stem control-port `NEWNYM` at a configurable interval.
- **Retention:** bounded alert and LLM-cache retention with WAL checkpointing.
- **Telegram alerts:** bounded queue, supervised worker, rate-limit backoff, and token redaction.
- **Read-only dashboard:** local FastAPI + server-rendered Jinja + vanilla JS. Black, monochrome, monospaced, no CDN and no telemetry.

---

## Architecture

```
.env / environment
        |
        v
Config.from_env()  (validated, typed)
        |
        v
main.py -> scraper.__main__:main
        |-- init_db() / seed_sites_from_csv()
        |-- supervised Telegram worker (bounded queue)
        |-- AsyncIOScheduler
        |     |-- health_check_job -> Tor NEWNYM -> check_site_live()
        |     |-- scrape_job       -> Tor NEWNYM -> PageProcessor.process_site()
        |     |     |-- CrawlerEngine.discover_site_pages()
        |     |     |     |-- fetch_full_page() via Tor SOCKS5
        |     |     |-- process_page()
        |     |           |-- parse -> hash -> DB dedupe
        |     |           |-- keyword/IOC pre-filter
        |     |           |-- LLM cache -> local inference
        |     |           |-- AlertRepository.save_if_new()
        |     |           |-- enqueue Telegram notification
        |     |-- cleanup_job       -> retention + cache pruning
        |     |-- sync_csv_job      -> target upsert
        |     \-- tor_renew         -> NEWNYM interval
        |
        v
SQLite WAL (sites, alerts, llm_cache)
        ^
        |
Dashboard (separate read-only process, localhost by default)
```

---

## System Requirements

- Ubuntu 22.04+, Debian 11+, or a compatible Linux distribution
- Python 3.10+
- Root or `sudo` for `install.sh` (Tor, packages, firewall, systemd)
- 4 GB RAM minimum for CPU inference with the 1.5B Q4 model; 8 GB recommended
- At least 5 GB free disk space
- Optional NVIDIA GPU with CUDA for `llama-cpp-python` offloading

---

## Installation

```bash
git clone https://github.com/jaskeerat01/darkweb-scraper.git
cd darkweb-scraper
chmod +x install.sh
sudo ./install.sh
```

The installer:

1. Installs Tor, build tools, Python headers, and `uv`.
2. Configures `/etc/tor/torrc` with SOCKS `9050` and authenticated control `9051`, both bound to `127.0.0.1`.
3. Validates the Tor circuit against `check.torproject.org`.
4. Hardens the host with UFW (deny inbound, allow loopback and SSH).
5. Creates `.venv` and installs the application and dashboard dependencies.
6. Downloads and verifies the Qwen2.5 GGUF model.
7. Writes a `0600` `.env` and seeds `data/forum_sites.csv`.
8. Runs the test suite.
9. Optionally registers the scraper and dashboard systemd services.
10. Optionally configures clearnet targets and dashboard authentication.

The Tor control password is generated but **not printed**; it is stored in `.env` (mode `0600`). The dashboard token, if enabled, is stored in `/etc/darkweb-dashboard.env` (mode `0600`).

---

## Configuration

All runtime settings live in `.env`. Start from `.env.example`.

### Tor and scheduling

```env
TOR_HOST=127.0.0.1
TOR_SOCKS_PORT=9050
TOR_CONTROL_PORT=9051
TOR_CONTROL_PASSWORD=change-me
TOR_NEWNYM_MIN_INTERVAL=10
TOR_RENEW_INTERVAL_MINUTES=30

SCRAPE_INTERVAL_MINUTES=120
HEALTH_INTERVAL_MINUTES=30
```

### Local LLM

```env
GGUF_MODEL_PATH=models/qwen2.5-1.5b-instruct-q4_k_m.gguf
LLM_CONTEXT=4096
LLM_THREADS=4
LLM_GPU_LAYERS=0
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=512
LLM_FAIL_OPEN=true
LLM_CACHE_ENABLED=true
LLM_CACHE_DAYS=30
LLM_PREFILTER_KEYWORDS=true
KEYWORDS=data breach,exploit,crypto,leak,0day,ransomware,victim
```

`LLM_FAIL_OPEN=true` preserves the historical behaviour: if the model is unavailable, keyword/IOC-matched pages are still stored as degraded alerts. Set it to `false` for stricter filtering.

### Concurrency and pacing

```env
MAX_PARALLEL_SITES=3
MAX_PARALLEL_FETCHES=3
MAX_PARALLEL_HEALTH=6
MAX_LLM_WORKERS=1
MAX_FETCHES_PER_DOMAIN=1
DOMAIN_MIN_INTERVAL=2.0
FETCH_RETRIES=2
FETCH_BACKOFF_BASE=2.0
SCRAPE_CYCLE_BUDGET_SECONDS=3600
SITE_BUDGET_SECONDS=600
```

`MAX_LLM_WORKERS` is validated but local inference is serialized by a process-wide lock because a single llama.cpp instance is not safe for concurrent calls.

### Crawling and retention

```env
PAGE_DISCOVERY_ENABLED=true
MAX_PAGES_PER_SITE=50
PAGE_DISCOVERY_DEPTH=2
MAX_LINKS_PER_PAGE=25
MIN_LINK_SCORE=-10
FOLLOW_EXTERNAL_LINKS=false
MAX_EXTERNAL_LINKS_PER_SITE=2
REQUIRE_RELEVANCE=true
THREAD_FIRST_PAGE_ONLY=true
FIRST_POST_ONLY=true
SUMMARIZE_ALERTS=true

DB_PATH=data/alerts.db
CSV_PATH=data/forum_sites.csv
DATA_RETENTION_DAYS=500
SEED_REMOVE_MISSING=false
```

### Clearnet targets (through Tor)

Clearnet is **off by default**. When enabled, every target request still goes through the same Tor SOCKS5 proxy; the scraper never opens a direct connection to a clearnet target.

```env
ALLOW_CLEARNET_TARGETS=false
CLEARNET_ALLOWED_DOMAINS=
CLEARNET_ALLOW_ANY=false
CLEARNET_ALLOWED_PORTS=80,443
CLEARNET_REQUIRE_HTTPS=false
CLEARNET_MAX_REDIRECTS=3
```

Rules:

- If `CLEARNET_ALLOWED_DOMAINS` is set, only those domains and their subdomains are allowed.
- If no allowlist is set, `CLEARNET_ALLOW_ANY=true` must be set explicitly; otherwise clearnet targets are skipped with a warning.
- Private, loopback, link-local, single-label, and reserved addresses are always rejected.
- Embedded credentials (`user:pass@`) are rejected.
- Non-HTTP(S) schemes and ports outside `CLEARNET_ALLOWED_PORTS` are rejected.
- Redirects are validated hop by hop. An onion → clearnet redirect is blocked when clearnet is disabled.
- `CLEARNET_REQUIRE_HTTPS=true` rejects plain HTTP, which is readable and modifiable by an exit node.

### Telegram

```env
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
TELEGRAM_PROXY=
TELEGRAM_QUEUE_SIZE=500
```

The queue is bounded. If Telegram is down and the queue is full, the notification is dropped but the alert remains in SQLite and the dashboard.

---

## Managing Targets

Targets live in `data/forum_sites.csv`:

```csv
Name,Type,URL,Status,LastScrape,Uptime30,PageTitle
BreachForums,onion,http://breached4wtyw5fb45zj7sggnoazgv3aohme2zftkrndhvo76d5q5uad.onion,online,08-14-26,97,BreachForums
Example Security,clearnet,https://example.com/security,online,08-14-26,97,Example Security
```

- `Type` is a hint; the actual network is inferred from the URL.
- Clearnet rows are ingested only when the target policy allows them.
- Existing rows are updated by name/group/type. Rows removed from the CSV are only deleted when `SEED_REMOVE_MISSING=true`.

---

## Running the Scraper

```bash
source .venv/bin/activate
python -m scraper
# or
./main.py
```

With systemd:

```bash
sudo systemctl status darkweb-scraper
sudo journalctl -u darkweb-scraper -f
sudo systemctl restart darkweb-scraper
```

The process handles `SIGINT`/`SIGTERM`, stops the scheduler, and cancels the Telegram worker cleanly.

---

## Running the Dashboard

```bash
source .venv/bin/activate

# default: http://127.0.0.1:8787
python -m scraper.dashboard

# or with the installed console script
darkweb-dashboard
```

Options:

```bash
python -m scraper.dashboard --host 127.0.0.1 --port 8787 --db data/alerts.db
```

With systemd:

```bash
sudo systemctl status darkweb-dashboard
sudo journalctl -u darkweb-dashboard -f
```

Access from another machine through an SSH tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 user@host
# then open http://127.0.0.1:8787 locally
```

### Dashboard security model

- Default bind is `127.0.0.1:8787`.
- Binding to a non-loopback address without `DASHBOARD_AUTH_TOKEN` is refused.
- Optional token login issues a signed, `HttpOnly`, `SameSite=Strict` cookie (12 h).
- Login attempts are rate-limited in memory.
- Strict CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, and `Cache-Control: no-store`.
- The dashboard opens SQLite read-only (`mode=ro`, with a `query_only` fallback for WAL shared memory). It never creates, migrates, or writes the database.
- The dashboard never reads Tor or Telegram credentials and never makes outbound network requests.
- Source URLs are rendered as text, not links.

### Reverse proxy

If you expose the dashboard through nginx, keep it bound to loopback and add TLS and authentication at the proxy:

```nginx
server {
    listen 443 ssl http2;
    server_name intel.example.internal;

    ssl_certificate     /etc/ssl/fullchain.pem;
    ssl_certificate_key /etc/ssl/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Set `DASHBOARD_ALLOWED_HOSTS` to include the proxy hostname and `DASHBOARD_SECURE_COOKIE=true`. Do not rely on `X-Forwarded-For` for authorization.

### Dashboard configuration

```env
DASHBOARD_HOST=127.0.0.1
DASHBOARD_PORT=8787
DASHBOARD_DB_PATH=
DASHBOARD_AUTH_TOKEN=
DASHBOARD_SECURE_COOKIE=false
DASHBOARD_ALLOWED_HOSTS=127.0.0.1,localhost,::1
DASHBOARD_PAGE_SIZE=25
DASHBOARD_POLL_SECONDS=15
DASHBOARD_ACCESS_LOG=false
DASHBOARD_ENABLE_DOCS=false
```

If authentication is enabled, retrieve the token from the root-readable (or service-user-readable) environment file:

```bash
sudo grep DASHBOARD_AUTH_TOKEN /etc/darkweb-dashboard.env
```

For a manual run with the installer-generated environment file:

```bash
DASHBOARD_ENV_FILE=/etc/darkweb-dashboard.env python -m scraper.dashboard
```

---

## Database Architecture

SQLite runs in WAL mode with `secure_delete`, a bounded cache, and `0600` file modes.

- `sites`: URL, name, group, target type (`onion`/`clearnet`), status, last check/up/scrape, failure counters, 30-day uptime window, last error.
- `alerts`: source metadata, content hash, extracted description, stored LLM summary, category, severity, entities, IOCs, timestamp. Unique on `(source_host, content_hash)`.
- `llm_cache`: cache key, model identity, prompt version, relevance, category, severity, summary, IOCs, creation time.

Schema migrations use `PRAGMA user_version` and are additive and idempotent. Legacy rows are backfilled once for `target_type`, `category`, and `severity`. Back up `data/alerts.db` before upgrading a large production database.

Indexes cover timestamp, category/time, source/time, severity/time, host/hash, and site status/type.

---

## Indicators of Compromise

- Bitcoin (legacy, SegWit, Bech32), Ethereum, Monero, Litecoin, Bitcoin Cash
- Telegram channels/usernames, Tox IDs, Keybase handles, email addresses
- Onion v3 addresses
- PGP key blocks, SHA-256-style hashes, and related artifacts

IOC extraction is regex-based and deterministic; results should be validated before operational use.

---

## Dashboard Views

- **Alerts:** live list, severity/category/source/network filters, date range, search, IOC previews.
- **Alert detail:** summary, metadata, indicators with copy buttons, collapsible extracted content, source URL (text only).
- **Sources:** per-target status, uptime, last check, last error.
- **About:** scope, privacy model, operating notes, disclaimer.
- **Statistics:** total, today (UTC), high severity in 7 days, source health, top categories, network split.

The interface is dark-only, monochrome, monospaced, and square-edged. It uses locally served assets and a locally vendored Geist Mono font (SIL OFL); no CDN is required.

---

## Running Tests

```bash
source .venv/bin/activate
pytest -q
```

The suite covers configuration validation, target policy, URL normalisation, parsers, IOC extraction, schema migrations, repositories, dashboard queries, authentication, CSP/escaping, and read-only enforcement.

To run without installing the LLM runtime, tests inject a fake model; `llama-cpp-python` is imported lazily.

---

## Troubleshooting

- **Tor control authentication failed:** ensure `HashedControlPassword` in `/etc/tor/torrc` matches `TOR_CONTROL_PASSWORD` and Tor is restarted.
- **All targets down:** check `systemctl status tor`, then test SOCKS manually with `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`.
- **Clearnet targets skipped:** set `CLEARNET_ALLOWED_DOMAINS` or `CLEARNET_ALLOW_ANY=true`; check logs for the policy warning.
- **Dashboard shows “database not ready”:** run the scraper once, or verify `DB_PATH` points at the same file the scraper writes.
- **Dashboard 503 from `/healthz`:** the database is missing, locked, or lacks the `alerts` table.
- **LLM degraded mode:** confirm `GGUF_MODEL_PATH` exists and `llama-cpp-python` imported successfully.
- **Telegram alerts missing:** check the token/chat ID; the dashboard still records the alert even if delivery fails.

---

## Future Improvements

- STIX 2.1 / TAXII export.
- FTS5 search for very large alert archives.
- Additional notification channels (Discord, Slack, email).
- Per-group rule engine and custom severity policies.
- Read-only share links for selected alert collections.

---

## Disclaimer

> [!CAUTION]
> **For Educational, Defensive Security, and Threat Intelligence Research Only**
>
> This software is intended strictly for authorized threat intelligence collection, defensive cybersecurity monitoring, and educational or academic research.

- **Compliance with Applicable Laws:** Accessing and crawling dark web resources, Tor onion hidden services, clearnet targets, and related networks may be subject to local, state, national, and international laws and regulations. You are solely responsible for ensuring that your usage complies with all legal, regulatory, and institutional guidelines in your jurisdiction.
- **Tor & Dark Web Risks:** The dark web contains unindexed, unmoderated services operated by anonymous or hostile entities. Interacting with these networks carries inherent operational and safety risks, including exposure to malicious content, exploit kits, fraudulent schemes, or illegal material. Do not attempt to access, download, distribute, or store prohibited or illicit materials.
- **Clearnet Targets:** When enabled, clearnet targets are fetched through Tor exit nodes. Target operators may block Tor traffic, and plain HTTP traffic is visible to exit nodes. Respect target terms of service, `robots.txt`, rate limits, and applicable law. Never submit credentials to a target.
- **Operational Security (OpSec):** Ensure appropriate operational security practices, network isolation, host hardening, and firewall configurations before deploying this tool on any infrastructure.
- **Limitation of Liability:** This project is provided "as is" without warranty of any kind, express or implied. The developers and contributors assume no liability and are not responsible for any misuse, damage, legal repercussions, data loss, or operational disruptions resulting from the use of this software.
