import asyncio
import logging
import random
from typing import Optional, Tuple
from urllib.parse import urlparse, urljoin
import aiohttp
from aiohttp_socks import ProxyConnector

from scraper.config import CONFIG
from scraper.parsers.url import is_onion_url, redact_url, normalize_page_url, is_allowed_page_url

logger = logging.getLogger("scraper")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
)


def build_tor_connector(limit: int = 100) -> Optional[ProxyConnector]:
    """Instantiates an aiohttp-socks connector forcing remote DNS lookups through Tor."""
    try:
        return ProxyConnector.from_url(
            f"socks5://{CONFIG.tor_host}:{CONFIG.tor_socks_port}",
            rdns=True,
            limit=limit,
            limit_per_host=CONFIG.max_fetches_per_domain,
            ttl_dns_cache=300
        )
    except Exception as e:
        logger.error(f"Proxy connector initialization error: {type(e).__name__}: {e!r}")
        return None


async def check_site_live(url: str, session: aiohttp.ClientSession) -> Tuple[bool, Optional[int], Optional[str]]:
    """Sends a lightweight health check probe reading at most 16KB of response data."""
    try:
        async with session.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=aiohttp.ClientTimeout(total=CONFIG.health_timeout),
            allow_redirects=True,
            max_redirects=5
        ) as resp:
            if not CONFIG.allow_clearnet_targets and not is_onion_url(str(resp.url)):
                return False, resp.status, "Clearnet redirect blocked"

            total = 0
            async for chunk in resp.content.iter_chunked(4096):
                total += len(chunk)
                if total >= 16384:
                    resp.close()
                    break

            if resp.status >= 400:
                return False, resp.status, f"HTTP {resp.status}"
            return True, resp.status, None
    except asyncio.TimeoutError:
        return False, None, "Timeout"
    except Exception as e:
        return False, None, type(e).__name__


async def fetch_full_page(url: str, session: aiohttp.ClientSession, depth: int = 0) -> Optional[str]:
    """Fetches an HTML document via Tor with strict size safeguards and redirect checks."""
    try:
        hostname = (urlparse(url).hostname or "").lower()
    except Exception:
        hostname = ""

    if not CONFIG.allow_clearnet_targets and not hostname.endswith(".onion"):
        logger.warning(f"Blocked clearnet target by policy: {redact_url(url)}")
        return None

    try:
        async with session.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=aiohttp.ClientTimeout(total=CONFIG.request_timeout),
            allow_redirects=False
        ) as resp:
            if resp.status in (301, 302, 303, 307, 308):
                if depth >= 3:
                    logger.warning(f"Too many redirects for {redact_url(url)}")
                    return None
                loc = resp.headers.get("Location", "")
                if not loc:
                    return None
                nxt = normalize_page_url(urljoin(url, loc))
                if not nxt or not is_allowed_page_url(nxt):
                    logger.info(f"Redirect blocked by policy: {redact_url(url)} -> {redact_url(loc)}")
                    return None
                resp.close()
                return await fetch_full_page(nxt, session, depth + 1)

            if not CONFIG.allow_clearnet_targets and not is_onion_url(str(resp.url)):
                return None

            if resp.status in (429, 500, 502, 503, 504):
                backoff = random.uniform(20, 60)
                logger.warning(f"Status {resp.status} for {redact_url(url)} - backing off {backoff:.0f}s")
                resp.close()
                await asyncio.sleep(backoff)
                return None

            if resp.status != 200:
                logger.warning(f"Status {resp.status} for {redact_url(url)}")
                return None

            content = bytearray()
            async for chunk in resp.content.iter_chunked(4096):
                content.extend(chunk)
                if len(content) > CONFIG.max_response_bytes:
                    logger.warning(f"Response too large for {redact_url(url)}. Aborting.")
                    resp.close()
                    return None
            return content.decode("utf-8", errors="ignore")

    except asyncio.TimeoutError:
        logger.error(f"Timeout fetching {redact_url(url)}")
        return None
    except Exception as e:
        logger.error(f"Fetch error {redact_url(url)}: {type(e).__name__}")
        return None