"""Online port discovery source for open Ollama and Kobold interfaces."""
from __future__ import annotations

import time
from typing import Iterable

from ..activity import emit
from ..log import get_logger
from ..models import Target, TargetKind
from .port_indexer import scan_and_index_ports

logger = get_logger("discovery.online_ports")


class OnlinePortSource:
    """Discovers and indexes online ports running Ollama or Kobold interfaces.

    Periodically scans configured targets/ports, determines reachability and
    open authentication status, catalogs available models, and indexes
    endpoints in the database.
    """

    name = "online_ports"

    def discover(self, ctx) -> Iterable[Target]:
        cfg_online = getattr(ctx.cfg.discovery, "online_ports", None)
        if not cfg_online or not getattr(cfg_online, "enabled", True):
            return

        last = float(ctx.db.get_kv("online_ports_last") or 0)
        interval_sec = getattr(cfg_online, "interval_minutes", 60) * 60
        if time.time() - last < interval_sec:
            logger.debug("online_ports discovery skipped (interval not elapsed)")
            return
        ctx.db.set_kv("online_ports_last", str(time.time()))

        emit(ctx, "discovery", "Indexing online ports for Ollama and Kobold interfaces...")
        results = scan_and_index_ports(
            ctx,
            hosts=getattr(cfg_online, "hosts", None) if getattr(cfg_online, "mode", "internet") == "custom" else None,
            ports_ollama=getattr(cfg_online, "ports_ollama", None),
            ports_kobold=getattr(cfg_online, "ports_kobold", None),
            concurrency=getattr(cfg_online, "concurrency", 32),
            timeout=getattr(cfg_online, "timeout", 2.0),
            source="discovery",
            mode=getattr(cfg_online, "mode", "internet"),
        )

        open_ollama = sum(1 for r in results if r.is_open and r.service_type == "ollama")
        open_kobold = sum(1 for r in results if r.is_open and r.service_type == "kobold")
        online_count = sum(1 for r in results if r.is_online)

        summary = f"Port indexing complete: {online_count} online ports, {open_ollama} open Ollama, {open_kobold} open Kobold"
        logger.info(summary)
        emit(ctx, "discovery", summary)

        # Yield targets for open interfaces so the pipeline tracks them
        for r in results:
            if r.is_open and r.service_type in ("ollama", "kobold"):
                yield Target(
                    kind=TargetKind.PACKAGE,
                    source="online_ports",
                    locator=r.url,
                    name=f"open-{r.service_type}-{r.host}:{r.port}",
                    version=r.version_info or "live",
                    priority=0.85,
                )
