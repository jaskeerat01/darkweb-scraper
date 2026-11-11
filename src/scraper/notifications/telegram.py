import asyncio
import html
import logging
from typing import Any

import aiohttp

from scraper.config import CONFIG, Config

logger = logging.getLogger("scraper")

telegram_queue: asyncio.Queue = asyncio.Queue(
    maxsize=CONFIG.telegram_queue_size
)


def enqueue_alert(payload: dict[str, Any]) -> bool:
    """Queue an alert without blocking the scraping pipeline.

    The database is the source of truth.  If Telegram is down and the bounded
    queue is full, the newest notification is dropped here but remains visible
    in the dashboard.
    """
    try:
        telegram_queue.put_nowait(payload)
        return True
    except asyncio.QueueFull:
        logger.warning(
            "Telegram queue full; notification for %s kept in database only",
            payload.get("source_name", "unknown"),
        )
        return False


def _redact(text: str, token: str | None) -> str:
    if token:
        return text.replace(token, "[redacted]")
    return text


async def send_telegram_immediate(
    payload: dict[str, Any],
    session: aiohttp.ClientSession,
    config: Config | None = None,
) -> bool:
    """Send an HTML-formatted notification to the configured Telegram chat."""
    cfg = config or CONFIG
    if not cfg.telegram_enabled:
        return False

    group = html.escape(str(payload.get("group_name", "Unknown")))
    note = html.escape(str(payload.get("summary", "")))
    severity = html.escape(str(payload.get("severity", "low")).upper())
    category = html.escape(str(payload.get("category", "other")))

    header = (
        f"🚨 <b>Dark Web Alert</b>\n"
        f"Severity: <b>{severity}</b> · Category: {category}\n"
        f"Group: <b>{group}</b>\n"
    )
    footer = ""
    if payload.get("iocs"):
        footer += "\nIOCs: " + html.escape(", ".join(payload["iocs"][:8]))
    if cfg.include_source_url_in_alerts and payload.get("source_url"):
        footer += "\nSource: " + html.escape(str(payload["source_url"]))

    available = max(200, 3950 - len(header) - len(footer) - len("<pre></pre>"))
    if len(note) > available:
        note = note[: available - 3] + "..."

    text = f"{header}<pre>{note}</pre>{footer}"
    url = f"https://api.telegram.org/bot{cfg.telegram_token}/sendMessage"

    try:
        async with session.post(
            url,
            json={
                "chat_id": cfg.telegram_chat_id,
                "text": text,
                "parse_mode": "HTML",
            },
            proxy=cfg.telegram_proxy,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status == 200:
                logger.info("Telegram alert delivered successfully.")
                return True
            if resp.status == 429:
                try:
                    payload_json = await resp.json()
                    retry_sec = float(
                        payload_json.get("parameters", {}).get("retry_after", 5)
                    )
                except Exception:
                    retry_sec = 5.0
                retry_sec = min(max(retry_sec, 1.0), 120.0)
                logger.warning(
                    "Telegram rate-limited; backing off for %.0fs", retry_sec
                )
                await asyncio.sleep(retry_sec)
                return False

            logger.error("Telegram API error: HTTP %s", resp.status)
            return False
    except Exception as exc:
        logger.error(
            "Telegram transport error: %s",
            _redact(type(exc).__name__, cfg.telegram_token),
        )
        return False


async def telegram_worker(
    session: aiohttp.ClientSession,
    stop_event: asyncio.Event,
    config: Config | None = None,
) -> None:
    """Consume the outbound queue until the stop event is set."""
    while not stop_event.is_set():
        try:
            payload = await asyncio.wait_for(telegram_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        except asyncio.CancelledError:
            raise

        try:
            sent = False
            for attempt in range(3):
                if await send_telegram_immediate(payload, session, config):
                    sent = True
                    break
                if stop_event.is_set():
                    break
                await asyncio.sleep(2 * (attempt + 1))
            if not sent:
                logger.error("Failed to deliver Telegram alert after retries.")
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Telegram worker error")
        finally:
            telegram_queue.task_done()
        await asyncio.sleep(1.2)


async def supervise_telegram_worker(
    session: aiohttp.ClientSession,
    stop_event: asyncio.Event,
    config: Config | None = None,
) -> None:
    """Restart the worker if it exits unexpectedly."""
    while not stop_event.is_set():
        try:
            await telegram_worker(session, stop_event, config)
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Telegram worker crashed; restarting in 5s")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=5)
            except asyncio.TimeoutError:
                continue
