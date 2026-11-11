import pytest

from scraper.config import Config
from scraper.core.exceptions import RetryableFetchError
from scraper.network import session as session_module


class FakeContent:
    def __init__(self, body: bytes):
        self._body = body

    async def iter_chunked(self, size):
        for index in range(0, len(self._body), size):
            yield self._body[index:index + size]


class FakeResponse:
    def __init__(self, url, status=200, headers=None, body=b"<html>ok</html>"):
        self.url = url
        self.status = status
        self.headers = headers or {}
        self.charset = "utf-8"
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def get(self, url, **kwargs):
        self.requests.append(url)
        return self.responses[url]


@pytest.mark.asyncio
async def test_onion_to_clearnet_redirect_is_blocked_before_fetch():
    session = FakeSession(
        {
            "http://abc.onion/start": FakeResponse(
                "http://abc.onion/start",
                status=301,
                headers={"Location": "https://example.com/"},
            )
        }
    )
    result = await session_module.fetch_full_page(
        "http://abc.onion/start", session, config=Config()
    )
    assert result is None
    assert session.requests == ["http://abc.onion/start"]


@pytest.mark.asyncio
async def test_health_check_blocks_cross_policy_redirect():
    session = FakeSession(
        {
            "http://abc.onion/start": FakeResponse(
                "http://abc.onion/start",
                status=302,
                headers={"Location": "https://example.com/"},
            )
        }
    )
    alive, status, error = await session_module.check_site_live(
        "http://abc.onion/start", session, config=Config()
    )
    assert alive is False
    assert status == 302
    assert "blocked" in (error or "").lower()
    assert session.requests == ["http://abc.onion/start"]


@pytest.mark.asyncio
async def test_clearnet_redirect_is_followed_when_policy_allows():
    config = Config(
        allow_clearnet_targets=True,
        clearnet_allowed_domains=("example.com",),
    )
    session = FakeSession(
        {
            "https://example.com/start": FakeResponse(
                "https://example.com/start",
                status=301,
                headers={"Location": "/next"},
            ),
            "https://example.com/next": FakeResponse(
                "https://example.com/next", body=b"<html>hello</html>"
            ),
        }
    )
    result = await session_module.fetch_full_page(
        "https://example.com/start", session, config=config
    )
    assert result == "<html>hello</html>"
    assert session.requests == [
        "https://example.com/start",
        "https://example.com/next",
    ]


@pytest.mark.asyncio
async def test_transient_status_raises_retryable_error():
    session = FakeSession(
        {
            "http://abc.onion/start": FakeResponse(
                "http://abc.onion/start",
                status=503,
                headers={"Retry-After": "7"},
            )
        }
    )
    with pytest.raises(RetryableFetchError) as exc_info:
        await session_module.fetch_full_page(
            "http://abc.onion/start", session, config=Config()
        )
    assert exc_info.value.retry_after == 7
