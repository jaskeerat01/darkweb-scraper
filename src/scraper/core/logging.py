import logging
import os
import sys

logger = logging.getLogger("scraper")


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configures structured stderr logging and silences verbose third-party loggers."""
    try:
        os.umask(0o077)
    except Exception:
        pass

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )
    logging.getLogger("stem").setLevel(logging.WARNING)
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)
    return logger