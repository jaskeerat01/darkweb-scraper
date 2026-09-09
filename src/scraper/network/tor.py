import asyncio
import logging
import random
import time
from typing import Optional
from stem import Signal
from stem.control import Controller
from scraper.config import CONFIG

logger = logging.getLogger("scraper")


class TorManager:
    """Handles Stem control signals and rate-limited circuit renewals."""

    def __init__(self, config=CONFIG):
        self._config = config
        self._last_newnym_time = 0.0
        self._renew_lock: Optional[asyncio.Lock] = None

    def renew_circuit_sync(self) -> bool:
        now = time.monotonic()
        elapsed = now - self._last_newnym_time
        if elapsed < self._config.tor_newnym_min_interval:
            time.sleep(self._config.tor_newnym_min_interval - elapsed)

        try:
            with Controller.from_port(
                address=self._config.tor_host,
                port=self._config.tor_control_port
            ) as controller:
                controller.authenticate(password=self._config.tor_control_password or None)
                controller.signal(Signal.NEWNYM)
                self._last_newnym_time = time.monotonic()
                logger.info("Tor circuit renewed successfully (NEWNYM).")
                return True
        except Exception as e:
            logger.error(f"Tor circuit renewal failed: {type(e).__name__} - {e}")
            return False

    async def renew_circuit(self):
        if self._renew_lock is None:
            self._renew_lock = asyncio.Lock()
        async with self._renew_lock:
            await asyncio.to_thread(self.renew_circuit_sync)
            await asyncio.sleep(random.uniform(2, 5))


tor_manager = TorManager()