"""Target classification and scope policy.

All target traffic is sent through the Tor SOCKS proxy by
:mod:`scraper.network.session`.  This module only decides *whether* a URL is in
scope; it never opens a network connection.
"""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import TYPE_CHECKING, Iterable
from urllib.parse import urlparse

if TYPE_CHECKING:
    from scraper.config import Config

_LOCAL_SUFFIXES = (
    ".localhost",
    ".local",
    ".localdomain",
    ".internal",
    ".home.arpa",
    ".lan",
    ".intranet",
    ".corp",
    ".test",
    ".invalid",
)
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


class TargetKind(str, Enum):
    ONION = "onion"
    CLEARNET = "clearnet"


def normalize_host(host: str | None) -> str:
    """Lower-case a hostname and strip the ``www.`` prefix and trailing dot."""
    if not host:
        return ""
    value = host.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if value.startswith("www."):
        value = value[4:]
    return value


def is_onion_host(host: str | None) -> bool:
    value = normalize_host(host)
    return bool(value) and value.endswith(".onion")


def host_from_url(url: str) -> str:
    """Safely extract a normalised hostname from a URL."""
    try:
        return normalize_host(urlparse(url).hostname)
    except ValueError:
        return ""


def target_kind(url: str) -> TargetKind | None:
    """Return the network kind for a URL, or ``None`` for a malformed URL."""
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return None
        hostname = parsed.hostname
    except ValueError:
        return None
    if not hostname:
        return None
    return TargetKind.ONION if is_onion_host(hostname) else TargetKind.CLEARNET


def _is_private_or_local_host(host: str) -> bool:
    value = normalize_host(host)
    if not value:
        return True
    if value in _LOOPBACK_NAMES or any(value.endswith(suffix) for suffix in _LOCAL_SUFFIXES):
        return True
    if "." not in value:
        # Single-label names are usually resolved by local search domains.
        return True
    # Reject decimal/hex IP encodings that the stdlib parser does not normalise.
    if all(part.isdigit() or part.lower().startswith("0x") for part in value.split(".")):
        return True

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    # is_global is false for loopback, private, link-local, multicast,
    # reserved, unspecified and shared (CGNAT) ranges.
    return not address.is_global


def domain_allowed(host: str, allowed_domains: Iterable[str]) -> bool:
    """Match an exact domain or any subdomain of an allowlisted domain."""
    value = normalize_host(host)
    if not value:
        return False
    for entry in allowed_domains:
        domain = normalize_host(entry.lstrip("*."))
        if not domain:
            continue
        if value == domain or value.endswith(f".{domain}"):
            return True
    return False


def is_allowed_target_url(url: str, config: Config | None = None) -> bool:
    """Apply the onion/clearnet scope policy to a target URL.

    Onion hosts are always in scope.  Clearnet hosts require the global opt-in
    plus either an allowlist entry or the explicit ``CLEARNET_ALLOW_ANY`` flag.
    Private, loopback, link-local and single-label hosts are always rejected.
    """
    cfg = config
    if cfg is None:
        from scraper.config import CONFIG

        cfg = CONFIG
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
    except ValueError:
        return False
    if not hostname:
        return False
    if username or password:
        # Embedded credentials must never reach a target or a log line.
        return False
    if any(ch.isspace() for ch in hostname):
        return False

    if is_onion_host(hostname):
        return True

    if not cfg.allow_clearnet_targets or not cfg.clearnet_enabled:
        return False
    if cfg.clearnet_require_https and parsed.scheme.lower() != "https":
        return False
    if cfg.clearnet_allowed_domains and not domain_allowed(
        hostname, cfg.clearnet_allowed_domains
    ):
        return False
    if not cfg.clearnet_allowed_domains and not cfg.clearnet_allow_any:
        return False

    if _is_private_or_local_host(hostname):
        return False

    try:
        port = parsed.port
    except ValueError:
        return False
    effective_port = port if port is not None else (443 if parsed.scheme == "https" else 80)
    if effective_port not in cfg.clearnet_allowed_ports:
        return False

    return True


def network_label(host: str | None) -> str:
    """Return ``onion`` or ``clearnet`` for display purposes."""
    return TargetKind.ONION.value if is_onion_host(host) else TargetKind.CLEARNET.value
