"""Online port indexer and active network recon for open Ollama and Kobold interfaces.

Inspired by and compatible with IVRE (https://ivre.rocks/):
  - Actively scans network and public Internet ranges (Cloud/VPS GPU subnets).
  - Integrates with local IVRE installations (`ivre.db` Python API / `ivre scancli`).
  - Ingests and exports Nmap/Masscan XML (-oX) and JSON (-oJ) formats.
  - Probes reachable endpoints running:
      * Ollama (default port 11434)
      * KoboldAI / KoboldCpp (default ports 5000, 5001, 5002, 5005)
  - Identifies open, unauthenticated interfaces, parses loaded LLM models,
    measures latency, detects versions, and indexes them in SQLite.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import requests

from ..log import get_logger

logger = get_logger("discovery.port_indexer")

DEFAULT_OLLAMA_PORTS = [11434]
DEFAULT_KOBOLD_PORTS = [5000, 5001, 5002, 5005]

# Public cloud and hosting subnets where self-hosted Ollama & Kobold are widely deployed
CLOUD_AI_SUBNETS = [
    # Hetzner Cloud (Hetzner Online GmbH AS24940)
    "159.69.0.0/16", "168.119.0.0/16", "116.203.0.0/16", "65.108.0.0/16", "49.12.0.0/16",
    # DigitalOcean (AS14061)
    "138.68.0.0/16", "159.203.0.0/16", "167.99.0.0/16", "142.93.0.0/16", "134.209.0.0/16",
    # OVHcloud (AS16276)
    "51.210.0.0/16", "141.94.0.0/16", "147.135.0.0/16", "51.89.0.0/16", "54.39.0.0/16",
    # Linode / Akamai (AS63949)
    "172.104.0.0/16", "139.162.0.0/16", "45.79.0.0/16",
    # Vultr (AS20473)
    "45.76.0.0/16", "149.28.0.0/16", "108.61.0.0/16",
    # Oracle Cloud Infrastructure
    "132.226.0.0/16", "140.238.0.0/16",
    # AWS EC2 public GPU / compute blocks
    "3.80.0.0/13", "54.200.0.0/13", "18.204.0.0/14", "34.192.0.0/12",
]


@dataclass
class PortProbeResult:
    host: str
    port: int
    service_type: str = "unknown"  # "ollama" | "kobold" | "unknown"
    url: str = ""
    api_url: str = ""
    is_online: bool = False
    is_open: bool = False
    models: list[str] = field(default_factory=list)
    latency_ms: float = 0.0
    version_info: str = ""
    source: str = "port_scan"
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "service_type": self.service_type,
            "url": self.url,
            "api_url": self.api_url,
            "is_online": self.is_online,
            "is_open": self.is_open,
            "models": self.models,
            "latency_ms": round(self.latency_ms, 2),
            "version_info": self.version_info,
            "source": self.source,
            "error": self.error,
        }


def expand_targets(hosts: list[str], max_per_subnet: int = 256) -> list[str]:
    """Expand hostnames, single IPs, CIDR blocks, and hyphenated IP ranges into a unique host list."""
    out: list[str] = []
    seen: set[str] = set()

    for item in hosts:
        item = str(item).strip()
        if not item:
            continue

        # Check CIDR notation (e.g. 192.168.1.0/28)
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
                count = 0
                for ip in net.hosts():
                    ip_str = str(ip)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        out.append(ip_str)
                        count += 1
                        if count >= max_per_subnet:
                            logger.warning("Subnet %s capped at %d hosts", item, max_per_subnet)
                            break
                continue
            except ValueError:
                pass

        # Check hyphenated range (e.g. 192.168.1.1-192.168.1.20 or 192.168.1.1-20)
        if "-" in item and not item.startswith("-"):
            parts = item.split("-", 1)
            first_str, second_str = parts[0].strip(), parts[1].strip()
            try:
                start_ip = ipaddress.ip_address(first_str)
                if "." in second_str:
                    end_ip = ipaddress.ip_address(second_str)
                else:
                    prefix = first_str.rsplit(".", 1)[0]
                    end_ip = ipaddress.ip_address(f"{prefix}.{second_str}")

                start_int = int(start_ip)
                end_int = int(end_ip)
                if start_int <= end_int and (end_int - start_int) <= max_per_subnet:
                    for ip_int in range(start_int, end_int + 1):
                        ip_str = str(ipaddress.ip_address(ip_int))
                        if ip_str not in seen:
                            seen.add(ip_str)
                            out.append(ip_str)
                    continue
            except ValueError:
                pass

        # Standard hostname or single IP
        cleaned = item.removeprefix("http://").removeprefix("https://").split("/")[0].split(":")[0]
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)

    return out


def generate_internet_targets(
    sample_size: int = 150,
    custom_subnets: list[str] | None = None,
    use_cloud_subnets: bool = True,
) -> list[str]:
    """Sample public routable IPv4 targets across cloud hosting ranges (like IVRE iprange / masscan)."""
    subnets: list[str] = []
    if custom_subnets:
        subnets.extend(custom_subnets)
    if use_cloud_subnets or not subnets:
        subnets.extend(CLOUD_AI_SUBNETS)

    targets: list[str] = []
    seen: set[str] = set()

    attempts = 0
    max_attempts = sample_size * 10
    while len(targets) < sample_size and attempts < max_attempts:
        attempts += 1
        subnet_str = random.choice(subnets)
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
            start_int = int(net.network_address) + 1
            end_int = int(net.broadcast_address) - 1
            if start_int <= end_int:
                rand_int = random.randint(start_int, end_int)
                ip = ipaddress.IPv4Address(rand_int)
                if ip.is_global and not ip.is_private and not ip.is_reserved and not ip.is_loopback:
                    ip_str = str(ip)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        targets.append(ip_str)
        except Exception:
            pass

    return targets


def query_ivre_db(
    ports: list[int] | None = None,
    ivre_path: str = "ivre",
) -> list[tuple[str, int]]:
    """Query IVRE database or CLI for hosts with open Ollama or Kobold ports.

    Returns:
        List of (host_ip, port) pairs.
    """
    ports = ports or (DEFAULT_OLLAMA_PORTS + DEFAULT_KOBOLD_PORTS)
    results: list[tuple[str, int]] = []

    # 1. Try native IVRE Python API: from ivre.db import db
    try:
        from ivre.db import db as ivre_db
        for p in ports:
            try:
                flt = ivre_db.nmap.flt_port(p)
                cursor = ivre_db.nmap.get(flt)
                for host in cursor:
                    addr = host.get("addr")
                    if addr:
                        results.append((str(addr), int(p)))
            except Exception as e:
                logger.debug("IVRE db query for port %d failed: %s", p, e)
        if results:
            logger.info("Retrieved %d hosts from local IVRE Python DB", len(results))
            return results
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("IVRE Python API import/connect error: %s", exc)

    # 2. Try IVRE CLI `ivre scancli`
    try:
        for p in ports:
            cmd = [ivre_path, "scancli", "--port", str(p), "--json"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        addr = data.get("addr") or data.get("ip")
                        if addr:
                            results.append((str(addr), int(p)))
                    except json.JSONDecodeError:
                        # Fallback simple IP regex in CLI output
                        m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                        if m:
                            results.append((m.group(0), int(p)))
        if results:
            logger.info("Retrieved %d hosts via `ivre scancli`", len(results))
            return results
    except (FileNotFoundError, subprocess.SubprocessError):
        pass

    return results


def parse_scan_output(content_or_path: str | Path) -> list[tuple[str, int]]:
    """Parse Nmap/Masscan XML (-oX) or JSON (-oJ) scan outputs (like IVRE scan2db).

    Returns:
        List of (host_ip, port) pairs found in the scan.
    """
    endpoints: list[tuple[str, int]] = []
    text = ""
    p = Path(content_or_path)
    if p.exists() and p.is_file():
        text = p.read_text(encoding="utf-8", errors="replace")
    else:
        text = str(content_or_path)

    text = text.strip()
    if not text:
        return endpoints

    # 1. Try parsing as Nmap / Masscan XML (-oX)
    if "<nmaprun" in text or "<host" in text:
        try:
            root = ET.fromstring(text)
            for host in root.findall(".//host"):
                addr_el = host.find("./address[@addrtype='ipv4']")
                if addr_el is None:
                    addr_el = host.find("./address")
                if addr_el is not None and "addr" in addr_el.attrib:
                    ip = addr_el.attrib["addr"]
                    for port in host.findall(".//port"):
                        state = port.find("./state")
                        if state is not None and state.attrib.get("state") == "open":
                            try:
                                pid = int(port.attrib.get("portid", 0))
                                if pid:
                                    endpoints.append((ip, pid))
                            except ValueError:
                                pass
            if endpoints:
                return endpoints
        except ET.ParseError:
            pass

    # 2. Try parsing as Masscan JSON output (-oJ)
    if "{" in text:
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line:
                continue
            try:
                data = json.loads(line)
                ip = data.get("ip")
                if ip and "ports" in data:
                    for port_info in data.get("ports", []):
                        if port_info.get("status") == "open":
                            pid = int(port_info.get("port", 0))
                            if pid:
                                endpoints.append((ip, pid))
            except Exception:
                pass

    return endpoints


def export_to_nmap_xml(results: list[PortProbeResult]) -> str:
    """Export indexed online ports to Nmap XML format for direct import into IVRE (`ivre scan2db`)."""
    root = ET.Element("nmaprun", {
        "scanner": "fas-port-indexer",
        "version": "1.0",
        "xmloutputversion": "1.05",
        "start": str(int(time.time())),
    })

    for r in results:
        if not r.is_online:
            continue
        host_el = ET.SubElement(root, "host")
        status_el = ET.SubElement(host_el, "status", {"state": "up", "reason": "syn-ack"})
        ET.SubElement(host_el, "address", {"addr": r.host, "addrtype": "ipv4"})

        ports_el = ET.SubElement(host_el, "ports")
        port_el = ET.SubElement(ports_el, "port", {
            "protocol": "tcp",
            "portid": str(r.port),
        })
        ET.SubElement(port_el, "state", {"state": "open", "reason": "syn-ack"})

        service_name = r.service_type if r.service_type != "unknown" else "http"
        prod = r.version_info or f"{r.service_type} (models: {', '.join(r.models[:2])})"
        svc_el = ET.SubElement(port_el, "service", {
            "name": service_name,
            "product": prod,
            "method": "probed",
        })
        if r.service_type in ("ollama", "kobold"):
            cpe = ET.SubElement(svc_el, "cpe")
            cpe.text = f"cpe:/a:{r.service_type}:{r.service_type}"

    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


def is_port_online(host: str, port: int, timeout: float = 1.5) -> bool:
    """Fast TCP socket connect test to check if port is reachable."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def probe_ollama(host: str, port: int, timeout: float = 2.5) -> tuple[bool, bool, list[str], str, float]:
    """Probe for Ollama interface.

    Returns:
        (is_ollama, is_open, models, version, latency_ms)
    """
    base_url = f"http://{host}:{port}"
    models: list[str] = []
    version = ""
    start_t = time.perf_counter()

    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=timeout, headers={"User-Agent": "IVRE-PortIndexer/1.0"})
        latency = (time.perf_counter() - start_t) * 1000.0

        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict) and "models" in data:
                    for m in data.get("models", []):
                        if isinstance(m, dict) and "name" in m:
                            models.append(str(m["name"]))
                        elif isinstance(m, str):
                            models.append(m)

                    try:
                        v_resp = requests.get(f"{base_url}/api/version", timeout=timeout)
                        if v_resp.status_code == 200:
                            v_data = v_resp.json()
                            if isinstance(v_data, dict) and "version" in v_data:
                                version = f"Ollama {v_data['version']}"
                    except Exception:
                        pass
                    if not version:
                        version = "Ollama"

                    return True, True, models, version, latency
            except json.JSONDecodeError:
                pass

        if resp.status_code in (401, 403):
            return True, False, [], "Ollama (Auth Required)", latency

        try:
            root_resp = requests.get(f"{base_url}/", timeout=timeout)
            if root_resp.status_code == 200 and "Ollama is running" in root_resp.text:
                return True, True, [], "Ollama (Running)", latency
        except Exception:
            pass

    except Exception:
        pass

    return False, False, [], "", 0.0


def probe_kobold(host: str, port: int, timeout: float = 2.5) -> tuple[bool, bool, list[str], str, float]:
    """Probe for KoboldAI / KoboldCpp interface.

    Returns:
        (is_kobold, is_open, models, version, latency_ms)
    """
    base_url = f"http://{host}:{port}"
    models: list[str] = []
    version = ""
    start_t = time.perf_counter()

    try:
        resp = requests.get(f"{base_url}/api/v1/model", timeout=timeout, headers={"User-Agent": "IVRE-PortIndexer/1.0"})
        latency = (time.perf_counter() - start_t) * 1000.0

        if resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, dict) and "result" in data:
                    model_name = str(data.get("result", "")).strip()
                    if model_name:
                        models.append(model_name)

                    try:
                        v_resp = requests.get(f"{base_url}/api/extra/version", timeout=timeout)
                        if v_resp.status_code == 200:
                            v_data = v_resp.json()
                            if isinstance(v_data, dict):
                                prog = v_data.get("result", "KoboldCpp")
                                v_num = v_data.get("version", "")
                                version = f"{prog} {v_num}".strip()
                    except Exception:
                        pass
                    if not version:
                        version = "KoboldAI"

                    return True, True, models, version, latency
            except json.JSONDecodeError:
                pass

        if resp.status_code in (401, 403):
            return True, False, [], "Kobold (Auth Required)", latency

        try:
            v_resp = requests.get(f"{base_url}/api/extra/version", timeout=timeout)
            if v_resp.status_code == 200:
                v_data = v_resp.json()
                if isinstance(v_data, dict) and ("result" in v_data or "version" in v_data):
                    version = f"{v_data.get('result', 'KoboldCpp')} {v_data.get('version', '')}".strip()
                    return True, True, models, version, (time.perf_counter() - start_t) * 1000.0
        except Exception:
            pass

        try:
            o_resp = requests.get(f"{base_url}/v1/models", timeout=timeout)
            if o_resp.status_code == 200:
                o_data = o_resp.json()
                if isinstance(o_data, dict) and "data" in o_data:
                    for item in o_data.get("data", []):
                        if isinstance(item, dict) and "id" in item:
                            mid = str(item["id"])
                            if "kobold" in mid.lower() or "koboldcpp" in mid.lower():
                                models.append(mid)
                                return True, True, models, "KoboldCpp (OpenAI API)", latency
        except Exception:
            pass

    except Exception:
        pass

    return False, False, [], "", 0.0


def probe_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    service_hint: str | None = None,
    source: str = "port_scan",
) -> PortProbeResult:
    """Probe a host:port for open Ollama or Kobold interfaces."""
    res = PortProbeResult(
        host=host,
        port=port,
        url=f"http://{host}:{port}",
        api_url=f"http://{host}:{port}/v1",
        source=source,
    )

    if not is_port_online(host, port, timeout=min(timeout, 1.5)):
        res.is_online = False
        res.error = "port closed or unreachable"
        return res

    res.is_online = True
    port_num = int(port)
    is_ollama_port = (port_num in DEFAULT_OLLAMA_PORTS) or (service_hint == "ollama")
    is_kobold_port = (port_num in DEFAULT_KOBOLD_PORTS) or (service_hint == "kobold")

    if is_ollama_port:
        is_ollama, is_open, models, ver, lat = probe_ollama(host, port_num, timeout=timeout)
        if is_ollama:
            res.service_type = "ollama"
            res.is_open = is_open
            res.models = models
            res.version_info = ver
            res.latency_ms = lat
            return res

    if is_kobold_port:
        is_kobold, is_open, models, ver, lat = probe_kobold(host, port_num, timeout=timeout)
        if is_kobold:
            res.service_type = "kobold"
            res.is_open = is_open
            res.models = models
            res.version_info = ver
            res.latency_ms = lat
            return res

    if not is_ollama_port:
        is_ollama, is_open, models, ver, lat = probe_ollama(host, port_num, timeout=timeout)
        if is_ollama:
            res.service_type = "ollama"
            res.is_open = is_open
            res.models = models
            res.version_info = ver
            res.latency_ms = lat
            return res

    if not is_kobold_port:
        is_kobold, is_open, models, ver, lat = probe_kobold(host, port_num, timeout=timeout)
        if is_kobold:
            res.service_type = "kobold"
            res.is_open = is_open
            res.models = models
            res.version_info = ver
            res.latency_ms = lat
            return res

    res.error = "online port but not identified as Ollama or Kobold"
    return res


def scan_and_index_ports(
    ctx: Any,
    hosts: list[str] | None = None,
    ports_ollama: list[int] | None = None,
    ports_kobold: list[int] | None = None,
    concurrency: int = 16,
    timeout: float = 2.0,
    source: str = "port_scan",
    mode: str = "auto",
) -> list[PortProbeResult]:
    """Scan targets and index open Ollama and Kobold interfaces into SQLite persistence.

    Modes:
      - "internet": samples public routable cloud AI subnets (IVRE-style active internet scan)
      - "ivre": queries local IVRE installation (`ivre.db` or `ivre scancli`)
      - "custom" / "auto": scans specified hosts or config targets
    """
    cfg_online = getattr(ctx.cfg.discovery, "online_ports", None) if hasattr(ctx, "cfg") else None
    effective_mode = mode
    if effective_mode == "auto":
        effective_mode = getattr(cfg_online, "mode", "internet") if cfg_online else "internet"

    ollama_p = ports_ollama or (cfg_online.ports_ollama if cfg_online else DEFAULT_OLLAMA_PORTS)
    kobold_p = ports_kobold or (cfg_online.ports_kobold if cfg_online else DEFAULT_KOBOLD_PORTS)

    tasks: list[tuple[str, int, str]] = []

    # 1. Explicit Hosts Mode
    if hosts:
        expanded = expand_targets(hosts)
        for h in expanded:
            for p in ollama_p:
                tasks.append((h, int(p), "ollama"))
            for p in kobold_p:
                tasks.append((h, int(p), "kobold"))

    # 2. IVRE DB Mode
    elif effective_mode == "ivre":
        ivre_pairs = query_ivre_db(
            ports=ollama_p + kobold_p,
            ivre_path=getattr(cfg_online, "ivre_cli_path", "ivre") if cfg_online else "ivre",
        )
        for h, p in ivre_pairs:
            hint = "ollama" if p in ollama_p else "kobold"
            tasks.append((h, p, hint))
        logger.info("IVRE mode loaded %d target endpoints from IVRE DB", len(tasks))

    # 3. Internet Scanning Mode (Public Cloud & AI Hosting Subnets)
    elif effective_mode == "internet":
        sample_count = getattr(cfg_online, "internet_sample_size", 100) if cfg_online else 100
        custom_subnets = getattr(cfg_online, "subnets", None) if cfg_online else None
        internet_ips = generate_internet_targets(
            sample_size=sample_count,
            custom_subnets=custom_subnets,
            use_cloud_subnets=True,
        )
        for h in internet_ips:
            for p in ollama_p:
                tasks.append((h, int(p), "ollama"))
            for p in kobold_p:
                tasks.append((h, int(p), "kobold"))
        logger.info("Internet recon mode generated %d public target probes across %d hosts",
                    len(tasks), len(internet_ips))

    # Fallback to configured hosts
    if not tasks:
        raw_hosts = getattr(cfg_online, "hosts", None) or ["127.0.0.1", "localhost"]
        expanded = expand_targets(raw_hosts)
        for h in expanded:
            for p in ollama_p:
                tasks.append((h, int(p), "ollama"))
            for p in kobold_p:
                tasks.append((h, int(p), "kobold"))

    logger.info("Starting online port scan (%d endpoints, concurrency=%d, timeout=%.1fs)",
                len(tasks), concurrency, timeout)

    results: list[PortProbeResult] = []
    db = getattr(ctx, "db", None)

    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 64))) as executor:
        future_map = {
            executor.submit(probe_port, host, port, timeout, hint, source): (host, port, hint)
            for host, port, hint in tasks
        }
        for fut in as_completed(future_map):
            try:
                res = fut.result()
                results.append(res)

                if db and (res.is_online or res.service_type != "unknown"):
                    db.upsert_indexed_port(
                        host=res.host,
                        port=res.port,
                        service_type=res.service_type,
                        url=res.url,
                        api_url=res.api_url,
                        is_online=res.is_online,
                        is_open=res.is_open,
                        models=res.models,
                        latency_ms=res.latency_ms,
                        version_info=res.version_info,
                        source=res.source,
                    )
                    if res.is_open and res.service_type in ("ollama", "kobold"):
                        logger.info("Indexed OPEN %s interface on public internet at %s (models: %s, %.1f ms)",
                                    res.service_type.upper(), res.url, res.models, res.latency_ms)
            except Exception as exc:
                h, p, _ = future_map[fut]
                logger.debug("Probe failed for %s:%d: %s", h, p, exc)

    if cfg_online and getattr(cfg_online, "auto_use_for_triage", False) and hasattr(ctx, "cfg"):
        open_candidates = [
            r for r in results
            if r.is_open and r.service_type in ("ollama", "kobold") and r.models
        ]
        if open_candidates:
            fastest = min(open_candidates, key=lambda x: x.latency_ms)
            ctx.cfg.llm.base_url = fastest.api_url
            ctx.cfg.llm.enabled = True
            if fastest.models:
                ctx.cfg.llm.model = fastest.models[0]
            logger.info("Auto-configured LLM triage to indexed %s at %s (model: %s)",
                        fastest.service_type, fastest.api_url, ctx.cfg.llm.model)

    return results
