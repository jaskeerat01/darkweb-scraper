"""Cookie signing, login rate limiting, and response headers."""

from __future__ import annotations

import hashlib
import hmac
import time
from collections import defaultdict, deque
from typing import Deque, MutableMapping

COOKIE_NAME = "dwi_session"
SESSION_TTL_SECONDS = 12 * 60 * 60


def _secret(token: str) -> bytes:
    return hashlib.sha256(f"dwi-dashboard:{token}".encode("utf-8")).digest()


def sign_session(token: str, now: int | None = None) -> str:
    expiry = int(now if now is not None else time.time()) + SESSION_TTL_SECONDS
    signature = hmac.new(
        _secret(token), f"v1:{expiry}".encode("ascii"), hashlib.sha256
    ).hexdigest()
    return f"{expiry}.{signature}"


def verify_session(value: str | None, token: str | None) -> bool:
    if not value or not token or "." not in value:
        return False
    expiry_raw, signature = value.split(".", 1)
    try:
        expiry = int(expiry_raw)
    except ValueError:
        return False
    if expiry < int(time.time()):
        return False
    expected = hmac.new(
        _secret(token), f"v1:{expiry}".encode("ascii"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def tokens_match(candidate: str, expected: str) -> bool:
    return hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8"))


class LoginRateLimiter:
    """Small in-memory fixed-window limiter for login attempts."""

    def __init__(self, limit: int = 5, window_seconds: int = 60) -> None:
        self._limit = limit
        self._window = window_seconds
        self._attempts: MutableMapping[str, Deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> Deque[float]:
        bucket = self._attempts[key]
        cutoff = now - self._window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return bucket

    def allowed(self, key: str) -> bool:
        now = time.monotonic()
        return len(self._prune(key, now)) < self._limit

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        self._prune(key, now).append(now)

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Robots-Tag": "noindex, nofollow",
    "Cache-Control": "no-store",
}
