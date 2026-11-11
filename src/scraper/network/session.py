"""Tor-backed HTTP transport with redirect and scope enforcement."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Tuple
from urllib.parse import urljoin

import aiohttp
from aiohttp_socks import ProxyConnector

from scraper.config import CONFIG, Config
from scraper.core.exceptions import RetryableFetchError
from scraper.network.policy import is_allowed_target_url, target_kind, TargetKind
from scraper.parsers.url import normalize_page_url, redact_url

logger = logging.getLogger("scraper")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
)

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_TRANSIENT_STATUSES = (429, 500, 502, 503, 504)


def build_tor_connector(limit: int = 100, config: Config | None = None) -> Optional[ProxyConnector]:
    """Create a SOCKS5 connector that resolves DNS remotely through Tor."""
    cfg = config or CONFIG
    try:
        return ProxyConnector.from_url(
            f"socks5://{cfg.tor_host}:{cfg.tor_socks_port}",
            rdns=True,
            limit=limit,
            limit_per_host=cfg.max_fetches_per_domain,
            ttl_dns_cache=300,
        )
    except Exception as exc:
        logger.error("Proxy connector initialization error: %s", type(exc).__name__)
        return None


def _timeout(config: Config, total: int | None = None) -> aiohttp.ClientTimeout:
    overall = total or config.request_timeout
    return aiohttp.ClientTimeout(
        total=overall,
        sock_connect=min(20, overall),
        sock_read=min(30, overall),
    )


def _max_redirects(url: str, config: Config) -> int:
    if target_kind(url) is TargetKind.CLEARNET:
        return config.clearnet_max_redirects
    return 3


def _redirect_target(current: str, location: str, config: Config) -> str | None:
    target = normalize_page_url(urljoin(current, location))
    if not target:
        return None
    if not is_allowed_target_url(target, config):
        logger.info(
            "Redirect blocked by policy: %s -> %s",
            redact_url(current, config),
            redact_url(location, config),
        )
        return None
    return target


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return min(max(seconds, 0.0), 120.0)


async def fetch_full_page(
    url: str,
    session: aiohttp.ClientSession,
    depth: int = 0,
    *,
    config: Config | None = None,
) -> Optional[str]:
    """Fetch an HTML document through the supplied Tor session.

    Redirects are followed manually so every hop can be validated against the
    onion/clearnet policy.  Transient statuses raise
    :class:`RetryableFetchError`; the crawler performs the backoff outside the
    global fetch semaphore.
    """
    cfg = config or CONFIG
    current = url

    for _ in range(_max_redirects(url, cfg) + 1):
        if not is_allowed_target_url(current, cfg):
            logger.warning("Blocked target by policy: %s", redact_url(current, cfg))
            return None

        try:
            async with session.get(
                current,
                headers={"User-Agent": USER_AGENT},
                timeout=_timeout(cfg),
                allow_redirects=False,
            ) as resp:
                if resp.status in _REDIRECT_STATUSES:
                    location = resp.headers.get("Location", "")
                    if not location:
                        return None
                    next_url = _redirect_target(current, location, cfg)
                    if next_url is None:
                        return None
                    current = next_url
                    continue

                if not is_allowed_target_url(str(resp.url), cfg):
                    return None

                if resp.status in _TRANSIENT_STATUSES:
                    raise RetryableFetchError(
                        f"HTTP {resp.status}",
                        retry_after=_retry_after(resp.headers.get("Retry-After")),
                    )

                if resp.status != 200:
                    logger.warning(
                        "Status %s for %s", resp.status, redact_url(current, cfg)
                    )
                    return None

                content = bytearray()
                async for chunk in resp.content.iter_chunked(4096):
                    content.extend(chunk)
                    if len(content) > cfg.max_response_bytes:
                        logger.warning(
                            "Response too large for %s. Aborting.",
                            redact_url(current, cfg),
                        )
                        return None

                charset = resp.charset or "utf-8"
                try:
                    return content.decode(charset, errors="ignore")
                except LookupError:
                    return content.decode("utf-8", errors="ignore")

        except RetryableFetchError:
            raise
        except asyncio.TimeoutError:
            logger.error("Timeout fetching %s", redact_url(current, cfg))
            return None
        except Exception as exc:
            logger.error(
                "Fetch error %s: %s", redact_url(current, cfg), type(exc).__name__
            )
            return None

    logger.warning("Too many redirects for %s", redact_url(url, cfg))
    return None


async def check_site_live(
    url: str,
    session: aiohttp.ClientSession,
    *,
    config: Config | None = None,
) -> Tuple[bool, Optional[int], Optional[str]]:
    """Probe a target with a small read and validate every redirect hop."""
    cfg = config or CONFIG
    current = url

    for _ in range(max(3, _max_redirects(url, cfg)) + 1):
        if not is_allowed_target_url(current, cfg):
            return False, None, "Blocked by policy"

        try:
            async with session.get(
                current,
                headers={"User-Agent": USER_AGENT},
                timeout=_timeout(cfg, cfg.health_timeout),
                allow_redirects=False,
            ) as resp:
                if resp.status in _REDIRECT_STATUSES:
                    location = resp.headers.get("Location", "")
                    if not location:
                        return False, resp.status, "Redirect without Location"
                    next_url = _redirect_target(current, location, cfg)
                    if next_url is None:
                        return False, resp.status, "Clearnet redirect blocked"
                    current = next_url
                    continue

                if not is_allowed_target_url(str(resp.url), cfg):
                    return False, resp.status, "Clearnet redirect blocked"

                total = 0
                async for chunk in resp.content.iter_chunked(4096):
                    total += len(chunk)
                    if total >= 16384:
                        break

                if resp.status >= 400:
                    suffix = ""
                    if resp.status in (403, 429) and target_kind(current) is TargetKind.CLEARNET:
                        suffix = " (possible Tor exit block)"
                    return False, resp.status, f"HTTP {resp.status}{suffix}"
                return True, resp.status, None

        except asyncio.TimeoutError:
            return False, None, "Timeout"
        except Exception as exc:
            return False, None, type(exc).__name__

    return False, None, "Too many redirects"
