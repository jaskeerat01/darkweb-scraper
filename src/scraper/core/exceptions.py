class ScraperError(Exception):
    """Base exception for all scraper-related errors."""


class TorCircuitError(ScraperError):
    """Raised when communication with the Tor SOCKS proxy or Control port fails."""


class ContentSizeExceededError(ScraperError):
    """Raised when an HTTP response exceeds the configured maximum byte threshold."""


class LLMInferenceError(ScraperError):
    """Raised when local model inference encounters an unrecoverable fault."""