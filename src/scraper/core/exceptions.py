class ScraperError(Exception):
    """Base exception for all scraper-related errors."""


class ConfigError(ScraperError):
    """Raised when an environment setting is missing, malformed, or out of range."""


class TorCircuitError(ScraperError):
    """Raised when communication with the Tor SOCKS proxy or Control port fails."""


class ContentSizeExceededError(ScraperError):
    """Raised when an HTTP response exceeds the configured maximum byte threshold."""


class LLMInferenceError(ScraperError):
    """Raised when local model inference encounters an unrecoverable fault."""


class RetryableFetchError(ScraperError):
    """Raised when a target returns a transient failure that is safe to retry.

    ``retry_after`` is an optional server-provided hint in seconds.
    """

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class PolicyError(ScraperError):
    """Raised when a URL is rejected by the target/network policy."""
