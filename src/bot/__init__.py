"""Discord Bot integration package for FAS."""
from __future__ import annotations

import asyncio
import threading
from typing import Any

from ..log import get_logger
from .client import FasDiscordBot

logger = get_logger("bot")

_active_bot: FasDiscordBot | None = None
_bot_thread: threading.Thread | None = None


def get_active_bot() -> FasDiscordBot | None:
    """Return the currently running bot instance, if any."""
    global _active_bot
    return _active_bot


def start_discord_bot(ctx: Any) -> FasDiscordBot | None:
    """Start the Discord bot in a background thread."""
    global _active_bot, _bot_thread

    token = getattr(ctx.cfg.notifications.discord, "bot_token", "")
    if not token:
        logger.debug("Discord bot token not set; skipping bot startup.")
        return None

    if _active_bot is not None and not _active_bot.is_closed():
        logger.info("Discord bot is already running.")
        return _active_bot

    bot = FasDiscordBot(ctx)
    _active_bot = bot

    def _runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            logger.info("Starting Discord bot background thread...")
            loop.run_until_complete(bot.start(token))
        except Exception as exc:
            logger.warning("Discord bot stopped: %s", exc)
        finally:
            loop.close()

    _bot_thread = threading.Thread(target=_runner, daemon=True, name="DiscordBotThread")
    _bot_thread.start()
    return bot


def run_discord_bot_blocking(ctx: Any) -> None:
    """Run the Discord bot in the current thread (blocking CLI command)."""
    global _active_bot
    token = getattr(ctx.cfg.notifications.discord, "bot_token", "")
    if not token:
        logger.error("Cannot run Discord bot: notifications.discord.bot_token is not configured.")
        return

    bot = FasDiscordBot(ctx)
    _active_bot = bot
    logger.info("Starting Discord bot (standalone blocking mode)...")
    bot.run(token)


def dispatch_bot_finding(ctx: Any, finding: dict, triage_status: str, triage_notes: str | None = None) -> bool:
    """Dispatch a finding alert to the active Discord bot if available."""
    bot = get_active_bot()
    if bot is None or not bot.is_ready() or bot.loop is None:
        return False

    try:
        asyncio.run_coroutine_threadsafe(
            bot.post_finding_alert(finding, triage_status, triage_notes),
            bot.loop,
        )
        return True
    except Exception as exc:
        logger.warning("Failed to dispatch finding alert to Discord bot loop: %s", exc)
        return False
