import asyncio
import logging
import random
import time
from typing import Optional

from stem import Signal
from stem.control import Controller

from scraper.config import CONFIG, Config

logger = logging.getLogger("scraper")


class TorManager:
    """Handle Stem control signals and rate-limited circuit renewals."""

    def __init__(self, config: Config | None = None) -> None:
        self._config = config or CONFIG
        self._last_newnym_time = 0.0
        self._renew_lock: Optional[asyncio.Lock] = None

    def renew_circuit_sync(self, config: Config | None = None) -> bool:
        cfg = config or self._config
        now = time.monotonic()
        elapsed = now - self._last_newnym_time
        if elapsed < cfg.tor_newnym_min_interval:
            time.sleep(cfg.tor_newnym_min_interval - elapsed)

        try:
            with Controller.from_port(
                address=cfg.tor_host,
                port=cfg.tor_control_port,
            ) as controller:
                controller.authenticate(password=cfg.tor_control_password or None)
                controller.signal(Signal.NEWNYM)
                self._last_newnym_time = time.monotonic()
                logger.info("Tor circuit renewed successfully (NEWNYM).")
                return True
        except Exception as exc:
            logger.error("Tor circuit renewal failed: %s", type(exc).__name__)
            return False

    async def renew_circuit(self, config: Config | None = None) -> None:
        if self._renew_lock is None:
            self._renew_lock = asyncio.Lock()
        async with self._renew_lock:
            await asyncio.to_thread(self.renew_circuit_sync, config or self._config)
            await asyncio.sleep(random.uniform(1.0, 2.0))


tor_manager = TorManager()
