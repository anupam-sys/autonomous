"""Discord Bot client for FAS (Fully Autonomous Scanner)."""
from __future__ import annotations

import asyncio
import re
from typing import Any
import discord
from discord.ext import commands

from ..log import get_logger
from .qa import answer_finding_question

logger = get_logger("bot.client")

FINDING_THREAD_RE = re.compile(r"Finding #(\d+)", re.IGNORECASE)


class FasDiscordBot(commands.Bot):
    """Interactive Discord Bot allowing operators to receive findings,
    ask questions about exposed keys, and launch on-demand scans.
    """

    def __init__(self, ctx: Any, **kwargs):
        intents = discord.Intents.default()
        intents.message_content = True
        intents.guilds = True

        super().__init__(
            command_prefix="!",
            intents=intents,
            help_command=None,
            **kwargs,
        )
        self.ctx = ctx
        self._thread_findings: dict[int, int] = {}
        self._message_findings: dict[int, int] = {}

    async def setup_hook(self) -> None:
        """Register slash commands."""
        from .commands import register_commands
        register_commands(self)

    async def on_ready(self) -> None:
        logger.info("Discord Bot connected as %s (ID: %s)", self.user, self.user.id if self.user else "?")
        try:
            synced = await self.tree.sync()
            logger.info("Synced %d Discord application (slash) commands.", len(synced))
        except Exception as exc:
            logger.warning("Failed to sync slash commands with Discord: %s", exc)

    def is_authorized(self, user_id: int) -> bool:
        """Check if user has permission to execute operator actions."""
        allowed = getattr(self.ctx.cfg.notifications.discord, "authorized_users", [])
        if not allowed:
            return True  # If not explicitly restricted, allow channel operators
        return user_id in allowed

    def get_alert_channel(self) -> discord.abc.Messageable | None:
        """Find configured alert channel or first available text channel."""
        cid = getattr(self.ctx.cfg.notifications.discord, "channel_id", None)
        if cid:
            channel = self.get_channel(int(cid))
            if channel:
                return channel

        for guild in self.guilds:
            for ch in guild.text_channels:
                if ch.permissions_for(guild.me).send_messages:
                    return ch
        return None

    async def post_finding_alert(
        self, finding: dict, triage_status: str, triage_notes: str | None = None
    ) -> discord.Message | None:
        """Post a rich embed for a finding and spawn an interactive thread."""
        channel = self.get_alert_channel()
        if not channel:
            logger.warning("No accessible text channel found to post finding alert.")
            return None

        fid = finding.get("id")
        detector = finding.get("detector", "unknown")
        service = finding.get("service", "unknown")
        severity = str(finding.get("severity", "info")).lower()
        target_name = finding.get("target_name", "unknown")
        target_kind = finding.get("target_kind", "unknown")
        file_path = finding.get("file_path", "unknown")
        line = finding.get("line", "?")

        # Color codes by severity
        colors = {
            "critical": 0xE74C3C,  # Red
            "high": 0xE67E22,      # Orange
            "medium": 0xF1C40F,    # Yellow
            "low": 0x3498DB,       # Blue
            "info": 0x95A5A6,      # Grey
        }
        color = colors.get(severity, 0x3498DB)

        # Retrieve secret value
        secret_val = finding.get("secret_full") or finding.get("secret")
        if not secret_val and fid and hasattr(self.ctx, "db"):
            secret_val = self.ctx.db.get_finding_secret(fid)
        if not secret_val:
            secret_val = finding.get("secret_preview", "unknown")

        secret_str = str(secret_val)
        if len(secret_str) > 1000:
            secret_str = secret_str[:990] + "... [truncated]"

        if "\n" in secret_str:
            secret_formatted = f"```\n{secret_str}\n```"
        else:
            secret_formatted = f"`{secret_str}`"

        title_id = f"Finding #{fid}: " if fid else ""
        embed = discord.Embed(
            title=f"🚨 {title_id}{detector} ({service})",
            color=color,
        )
        embed.add_field(name="Severity", value=f"**{severity.upper()}**", inline=True)
        embed.add_field(name="Target", value=f"{target_name} ({target_kind})", inline=True)
        embed.add_field(name="Location", value=f"`{file_path}:{line}`", inline=True)
        embed.add_field(name="Triage Status", value=triage_status, inline=True)
        if fid:
            embed.add_field(name="Finding ID", value=f"`#{fid}`", inline=True)
        embed.add_field(name="Exposed Secret / Key", value=secret_formatted, inline=False)

        if triage_notes:
            embed.add_field(name="Triage Notes", value=str(triage_notes)[:1000], inline=False)

        embed.set_footer(text="FAS Autonomous Pipeline • Reply or chat in thread to ask questions")

        try:
            msg = await channel.send(embed=embed)
            if fid:
                self._message_findings[msg.id] = fid

            # Create an interactive thread if enabled and supported
            create_threads = getattr(self.ctx.cfg.notifications.discord, "create_threads", True)
            if create_threads and hasattr(msg, "create_thread"):
                try:
                    thread_name = f"Finding #{fid} — {detector} ({service})"[:100]
                    thread = await msg.create_thread(name=thread_name, auto_archive_duration=1440)
                    if fid:
                        self._thread_findings[thread.id] = fid

                    await thread.send(
                        f"💬 **Interactive Analysis Thread for Finding #{fid}**\n"
                        f"You can ask me questions about this credential right here!\n"
                        f"• *Is this key live or dummy?*\n"
                        f"• *What permissions or APIs can it access?*\n"
                        f"• *How do I rotate or revoke this?*"
                    )
                except Exception as t_exc:
                    logger.debug("Could not create thread for finding #%s: %s", fid, t_exc)

            return msg
        except Exception as exc:
            logger.warning("Failed to send finding embed to Discord: %s", exc)
            return None

    async def on_message(self, message: discord.Message) -> None:
        # Ignore our own messages
        if message.author.id == self.user.id:
            return

        # Check if the message is in a discussion thread for a finding
        finding_id: int | None = None
        if message.channel.id in self._thread_findings:
            finding_id = self._thread_findings[message.channel.id]
        elif isinstance(message.channel, discord.Thread):
            match = FINDING_THREAD_RE.search(message.channel.name)
            if match:
                finding_id = int(match.group(1))
                self._thread_findings[message.channel.id] = finding_id

        # Check if replying to a finding message
        if not finding_id and message.reference and message.reference.message_id:
            ref_id = message.reference.message_id
            if ref_id in self._message_findings:
                finding_id = self._message_findings[ref_id]

        # If inside a finding thread and not starting with a command prefix, answer the question!
        if finding_id and not message.content.startswith("!"):
            if not self.is_authorized(message.author.id):
                await message.reply("⛔ You are not authorized to query this pipeline.")
                return

            async with message.channel.typing():
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None, answer_finding_question, self.ctx, finding_id, message.content
                )

            # Send response, splitting if it exceeds Discord's 2000-char limit
            for chunk in _split_message(response):
                await message.reply(chunk)
            return

        # Otherwise handle prefix commands
        await self.process_commands(message)


def _split_message(text: str, limit: int = 1950) -> list[str]:
    """Split long response into Discord-safe chunks."""
    if len(text) <= limit:
        return [text]

    chunks = []
    lines = text.split("\n")
    cur = []
    cur_len = 0
    for line in lines:
        if cur_len + len(line) + 1 > limit:
            chunks.append("\n".join(cur))
            cur = [line]
            cur_len = len(line) + 1
        else:
            cur.append(line)
            cur_len += len(line) + 1

    if cur:
        chunks.append("\n".join(cur))
    return chunks
