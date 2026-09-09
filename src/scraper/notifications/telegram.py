import asyncio
import html
import logging
import aiohttp

from scraper.config import CONFIG

logger = logging.getLogger("scraper")

telegram_queue: asyncio.Queue = asyncio.Queue()


async def send_telegram_immediate(payload: dict, session: aiohttp.ClientSession) -> bool:
    """Sends an HTML-formatted notification to the configured Telegram chat."""
    if not CONFIG.telegram_token or not CONFIG.telegram_chat_id:
        return False

    group = html.escape(str(payload.get("group_name", "Unknown")))
    note = html.escape(str(payload.get("summary", "")))

    header = f"🚨 <b>Dark Web Alert</b>\nGroup: <b>{group}</b>\n"
    footer = ""
    if payload.get("iocs"):
        footer += "\nIOCs: " + html.escape(", ".join(payload["iocs"][:8]))
    if CONFIG.include_source_url_in_alerts and payload.get("source_url"):
        footer += "\nSource: " + html.escape(str(payload["source_url"]))

    avail = max(200, 3950 - len(header) - len(footer) - len("<pre></pre>"))
    if len(note) > avail:
        note = note[:avail - 3] + "..."

    text = f"{header}<pre>{note}</pre>{footer}"
    url = f"https://api.telegram.org/bot{CONFIG.telegram_token}/sendMessage"

    try:
        async with session.post(
            url,
            json={"chat_id": CONFIG.telegram_chat_id, "text": text, "parse_mode": "HTML"},
            proxy=CONFIG.telegram_proxy,
            timeout=aiohttp.ClientTimeout(total=15)
        ) as resp:
            if resp.status == 200:
                logger.info("Telegram alert delivered successfully.")
                return True
            if resp.status == 429:
                try:
                    res_json = await resp.json()
                    retry_sec = res_json.get("parameters", {}).get("retry_after", 5)
                except Exception:
                    retry_sec = 5
                logger.warning(f"Telegram 429 rate-limited. Backing off for {retry_sec}s")
                await asyncio.sleep(retry_sec)
                return False

            err = await resp.text()
            logger.error(f"Telegram API error: Status {resp.status} - {err[:200]}")
            return False
    except Exception as e:
        logger.error(f"Telegram transport error: {type(e).__name__}: {e}")
        return False


async def telegram_worker(session: aiohttp.ClientSession):
    """Worker loop consuming items from the outbound alert queue."""
    while True:
        payload = await telegram_queue.get()
        try:
            sent = False
            for attempt in range(3):
                if await send_telegram_immediate(payload, session):
                    sent = True
                    break
                await asyncio.sleep(2 * (attempt + 1))
            if not sent:
                logger.error("Failed to deliver Telegram alert after maximum retries.")
        except Exception as e:
            logger.error(f"Telegram worker error: {e}")
        finally:
            telegram_queue.task_done()
        await asyncio.sleep(1.2)