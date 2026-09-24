"""Discord Slash and Prefix Commands for FAS."""
from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import discord
from discord import app_commands
from discord.ext import commands

from ..log import get_logger
from .qa import answer_finding_question
from .scanner import scan_target_on_demand

logger = get_logger("bot.commands")


def register_commands(bot: commands.Bot) -> None:
    """Register both Slash commands (bot.tree) and Prefix commands."""
    ctx = bot.ctx

    # ------------------ /status ------------------
    @bot.tree.command(name="status", description="Show current pipeline daemon and queue status")
    async def slash_status(interaction: discord.Interaction):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        counts = ctx.db.counts()
        embed = discord.Embed(title="🛡️ FAS Pipeline Status", color=0x2ECC71)
        embed.add_field(name="Total Findings", value=str(counts["findings_total"]), inline=True)
        embed.add_field(name="Pending Triage", value=str(counts["findings_pending_triage"]), inline=True)
        embed.add_field(name="Pending Targets", value=str(ctx.queue.pending_count()), inline=True)
        embed.add_field(name="Bandwidth Today", value=f"{counts['bandwidth_today_mb']:.1f} MB", inline=True)
        embed.add_field(name="Targets by Status", value=f"```{counts['targets_by_status']}```", inline=False)
        await interaction.response.send_message(embed=embed)

    @bot.command(name="status")
    async def cmd_status(c):
        if not bot.is_authorized(c.author.id):
            return
        counts = ctx.db.counts()
        embed = discord.Embed(title="🛡️ FAS Pipeline Status", color=0x2ECC71)
        embed.add_field(name="Total Findings", value=str(counts["findings_total"]), inline=True)
        embed.add_field(name="Pending Targets", value=str(ctx.queue.pending_count()), inline=True)
        embed.add_field(name="Bandwidth Today", value=f"{counts['bandwidth_today_mb']:.1f} MB", inline=True)
        await c.send(embed=embed)

    # ------------------ /finding ------------------
    @bot.tree.command(name="finding", description="View full details and decrypted secret of a finding")
    @app_commands.describe(finding_id="The numeric ID of the finding")
    async def slash_finding(interaction: discord.Interaction, finding_id: int):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        row = ctx.db.get_finding(finding_id)
        if not row:
            await interaction.response.send_message(f"❌ Finding #{finding_id} not found.", ephemeral=True)
            return

        embed = _build_finding_detail_embed(ctx, row)
        await interaction.response.send_message(embed=embed)

    @bot.command(name="finding")
    async def cmd_finding(c, finding_id: int):
        if not bot.is_authorized(c.author.id):
            return
        row = ctx.db.get_finding(finding_id)
        if not row:
            await c.send(f"❌ Finding #{finding_id} not found.")
            return
        embed = _build_finding_detail_embed(ctx, row)
        await c.send(embed=embed)

    # ------------------ /ask ------------------
    @bot.tree.command(name="ask", description="Ask the LLM a question about a specific finding or security risk")
    @app_commands.describe(
        question="Your question (e.g. 'Can this key be used to access user data?')",
        finding_id="Optional: Finding ID (inferred automatically inside finding threads)",
    )
    async def slash_ask(interaction: discord.Interaction, question: str, finding_id: int | None = None):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        fid = finding_id
        if not fid and interaction.channel_id in bot._thread_findings:
            fid = bot._thread_findings[interaction.channel_id]

        if not fid:
            await interaction.response.send_message(
                "❌ Please specify a `finding_id` or run `/ask` inside a finding thread.", ephemeral=True
            )
            return

        await interaction.response.defer()
        loop = asyncio.get_running_loop()
        ans = await loop.run_in_executor(None, answer_finding_question, ctx, fid, question)

        from .client import _split_message
        chunks = _split_message(ans)
        await interaction.followup.send(chunks[0])
        for chunk in chunks[1:]:
            await interaction.channel.send(chunk)

    # ------------------ /scan_apk ------------------
    @bot.tree.command(name="scan_apk", description="Scan an Android APK for exposed secrets and tokens")
    @app_commands.describe(
        target="Package name (e.g. com.example.app) or direct APK URL",
        file="Directly upload an .apk file attachment to scan",
    )
    async def slash_scan_apk(
        interaction: discord.Interaction,
        target: str | None = None,
        file: discord.Attachment | None = None,
    ):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        if not target and not file:
            await interaction.response.send_message("❌ Provide either a `target` (package/URL) or attach an `.apk` file.", ephemeral=True)
            return

        await interaction.response.defer()
        apk_locator = target
        display_name = target or "uploaded.apk"

        # If a file was attached, save it locally
        if file:
            if not file.filename.lower().endswith((".apk", ".xapk")):
                await interaction.followup.send(f"❌ Uploaded file `{file.filename}` does not appear to be an APK.")
                return
            temp_dir = Path(ctx.cfg.paths.data_dir) / "apk" / "uploads"
            temp_dir.mkdir(parents=True, exist_ok=True)
            save_path = temp_dir / file.filename
            await file.save(save_path)
            apk_locator = str(save_path)
            display_name = file.filename

        status_msg = await interaction.followup.send(f"🔄 **Scanning APK `{display_name}`**... Starting byte-level scan.")

        def progress_cb(msg: str):
            asyncio.run_coroutine_threadsafe(status_msg.edit(content=msg), bot.loop)

        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(
            None, scan_target_on_demand, ctx, "apk", apk_locator, display_name, progress_cb
        )

        embed = discord.Embed(
            title=f"APK Scan Complete: {display_name}",
            color=0x2ECC71 if res["status"] == "completed" else 0xE74C3C,
        )
        embed.add_field(name="Status", value=res["status"].upper(), inline=True)
        embed.add_field(name="New Findings", value=str(res["findings_new"]), inline=True)
        embed.add_field(name="Entries Analysed", value=str(res["files_scanned"]), inline=True)
        if res["error"]:
            embed.add_field(name="Error", value=f"`{res['error']}`", inline=False)

        await status_msg.edit(content=None, embed=embed)

    # ------------------ /scan_repo ------------------
    @bot.tree.command(name="scan_repo", description="Scan a Git repository for exposed credentials")
    @app_commands.describe(git_url="Git clone URL (e.g. https://github.com/org/repo.git)")
    async def slash_scan_repo(interaction: discord.Interaction, git_url: str):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        await interaction.response.defer()
        name = Path(git_url.rstrip("/")).stem.removesuffix(".git")
        status_msg = await interaction.followup.send(f"🔄 **Cloning and scanning repository `{name}`**...")

        def progress_cb(msg: str):
            asyncio.run_coroutine_threadsafe(status_msg.edit(content=msg), bot.loop)

        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(
            None, scan_target_on_demand, ctx, "repo", git_url, name, progress_cb
        )

        embed = discord.Embed(
            title=f"Repo Scan Complete: {name}",
            color=0x2ECC71 if res["status"] == "completed" else 0xE74C3C,
        )
        embed.add_field(name="Status", value=res["status"].upper(), inline=True)
        embed.add_field(name="New Findings", value=str(res["findings_new"]), inline=True)
        embed.add_field(name="Files Analysed", value=str(res["files_scanned"]), inline=True)
        if res["error"]:
            embed.add_field(name="Error", value=f"`{res['error']}`", inline=False)

        await status_msg.edit(content=None, embed=embed)

    # ------------------ /triage ------------------
    @bot.tree.command(name="triage", description="Manually set triage status for a finding")
    @app_commands.describe(
        finding_id="Numeric ID of the finding",
        verdict="Triage verdict",
        notes="Optional notes explaining the verdict",
    )
    @app_commands.choices(
        verdict=[
            app_commands.Choice(name="True Positive (Live Credential)", value="true_positive"),
            app_commands.Choice(name="False Positive (Test/Mock)", value="false_positive"),
            app_commands.Choice(name="Placeholder", value="placeholder"),
            app_commands.Choice(name="Revoked / Rotated", value="revoked"),
        ]
    )
    async def slash_triage(
        interaction: discord.Interaction, finding_id: int, verdict: app_commands.Choice[str], notes: str = ""
    ):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        ctx.db.set_finding_triage(finding_id, verdict.value, notes=notes or None)
        await interaction.response.send_message(
            f"✅ Finding **#{finding_id}** marked as `{verdict.value}`" + (f" with note: *{notes}*" if notes else "")
        )

    # ------------------ /prune ------------------
    @bot.tree.command(name="prune", description="Run intelligence filter to prune spam/bot targets from the queue")
    async def slash_prune(interaction: discord.Interaction):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        await interaction.response.defer()
        from ..discovery.intelligence import evaluate_target
        intel_cfg = getattr(ctx.cfg.discovery, "intelligence", None)
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(
            None, ctx.db.prune_and_rescore_targets, lambda t: evaluate_target(t, cfg=intel_cfg)
        )
        await interaction.followup.send(
            f"🧹 **Queue Pruned**: {res['total']} inspected • **{res['skipped']}** spam/noise removed • **{res['rescored']}** prioritized."
        )

    # ------------------ /report ------------------
    @bot.tree.command(name="report", description="Generate current findings report")
    async def slash_report(interaction: discord.Interaction):
        if not bot.is_authorized(interaction.user.id):
            await interaction.response.send_message("⛔ Unauthorized.", ephemeral=True)
            return

        await interaction.response.defer()
        from ..report.reporter import generate
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, generate, ctx)
        await interaction.followup.send(f"📊 **Report Generated**: `{result}`")

    # ------------------ /help ------------------
    @bot.tree.command(name="help", description="Show available commands and bot capabilities")
    async def slash_help(interaction: discord.Interaction):
        embed = discord.Embed(title="📖 FAS Discord Integration Guide", color=0x3498DB)
        embed.description = (
            "**Autonomous Secret-Exposure Pipeline & Interactive Assistant**\n\n"
            "🚨 **Instant Key Alerts:** The bot immediately posts detected secrets with interactive discussion threads.\n"
            "💬 **Ask Questions:** Chat in any finding's thread or use `/ask` to analyze risk, permissions, and rotation.\n"
            "📱 **Scan APKs:** Use `/scan_apk` or drop an `.apk` file directly in Discord!\n"
            "💻 **Scan Repos:** Use `/scan_repo <git_url>` to scan git repositories."
        )
        embed.add_field(name="/status", value="View daemon health, worker queues, bandwidth", inline=True)
        embed.add_field(name="/finding <id>", value="Retrieve decrypted secret & context for a finding", inline=True)
        embed.add_field(name="/ask <question>", value="Ask LLM questions about a finding", inline=True)
        embed.add_field(name="/scan_apk", value="Scan an APK package, URL, or uploaded file", inline=True)
        embed.add_field(name="/scan_repo", value="Clone and scan a Git repository", inline=True)
        embed.add_field(name="/triage", value="Set finding status (true_positive, etc.)", inline=True)
        embed.add_field(name="/prune", value="Prune spam repositories from queue", inline=True)
        embed.add_field(name="/report", value="Trigger HTML/JSON report generation", inline=True)
        await interaction.response.send_message(embed=embed)


def _build_finding_detail_embed(ctx, row) -> discord.Embed:
    row_dict = dict(row)
    fid = row_dict["id"]
    secret_val = ctx.db.get_finding_secret(fid) or row_dict.get("secret_preview", "unknown")
    secret_display = str(secret_val)
    if len(secret_display) > 1000:
        secret_display = secret_display[:990] + "... [truncated]"

    embed = discord.Embed(
        title=f"Finding #{fid}: {row_dict.get('detector')} ({row_dict.get('service')})",
        color=0xE74C3C if row_dict.get("severity") in ("critical", "high") else 0x3498DB,
    )
    embed.add_field(name="Target", value=f"{row_dict.get('target_name')} ({row_dict.get('target_kind')})", inline=True)
    embed.add_field(name="Location", value=f"`{row_dict.get('file_path')}:{row_dict.get('line')}`", inline=True)
    embed.add_field(name="Severity", value=str(row_dict.get("severity", "info")).upper(), inline=True)
    embed.add_field(name="Triage", value=f"{row_dict.get('triage_status')} {row_dict.get('triage_notes') or ''}", inline=True)
    embed.add_field(name="Decrypted Secret", value=f"```{secret_display}```", inline=False)

    ctx_code = row_dict.get("context", "")
    if ctx_code:
        embed.add_field(name="Code Context", value=f"```\n{ctx_code[:1000]}\n```", inline=False)
    return embed
