"""Tests for online port indexing (Ollama & Kobold interfaces)."""
from __future__ import annotations

import http.server
import json
import socket
import threading
import pytest

from src.config import Config
from src.db import Database
from src.discovery.port_indexer import (
    PortProbeResult,
    expand_targets,
    export_to_nmap_xml,
    generate_internet_targets,
    is_port_online,
    parse_scan_output,
    probe_kobold,
    probe_ollama,
    probe_port,
    query_ivre_db,
    scan_and_index_ports,
)
from src.discovery.port_source import OnlinePortSource
from src.detect.rules_loader import load_rules
from src.detect.scanner import Scanner
from src.web.server import create_app


class _MockHandler(http.server.BaseHTTPRequestHandler):
    mode = "ollama"

    def do_GET(self):
        if self.mode == "ollama":
            if self.path == "/api/tags":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "models": [{"name": "llama3:latest"}, {"name": "mistral:7b"}]
                }).encode())
                return
            elif self.path == "/api/version":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"version": "0.3.14"}).encode())
                return
            elif self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Ollama is running")
                return

        elif self.mode == "kobold":
            if self.path == "/api/v1/model":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"result": "Llama-3-8B-Instruct"}).encode())
                return
            elif self.path == "/api/extra/version":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"result": "KoboldCpp", "version": "1.70"}).encode())
                return

        elif self.mode == "ollama_auth":
            if self.path.startswith("/api/"):
                self.send_response(401)
                self.end_headers()
                return

        elif self.mode == "kobold_auth":
            if self.path.startswith("/api/"):
                self.send_response(401)
                self.end_headers()
                return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress logging during tests


@pytest.fixture
def mock_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield server, port
    server.shutdown()
    server.server_close()


def test_expand_targets():
    # Single hosts
    hosts = ["localhost", "127.0.0.1", "http://my-host.local:11434"]
    expanded = expand_targets(hosts)
    assert "localhost" in expanded
    assert "127.0.0.1" in expanded
    assert "my-host.local" in expanded

    # CIDR notation
    cidr = ["192.168.1.0/30"]  # .1 and .2 are valid host addresses
    expanded_cidr = expand_targets(cidr)
    assert len(expanded_cidr) == 2
    assert "192.168.1.1" in expanded_cidr
    assert "192.168.1.2" in expanded_cidr

    # Range notation
    range_hosts = ["10.0.0.1-10.0.0.3"]
    expanded_range = expand_targets(range_hosts)
    assert expanded_range == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_is_port_online(mock_server):
    _, port = mock_server
    assert is_port_online("127.0.0.1", port, timeout=1.0)
    # Closed port
    assert not is_port_online("127.0.0.1", 1, timeout=0.2)


def test_probe_ollama_open(mock_server):
    server, port = mock_server
    _MockHandler.mode = "ollama"
    is_ollama, is_open, models, version, lat = probe_ollama("127.0.0.1", port)
    assert is_ollama is True
    assert is_open is True
    assert "llama3:latest" in models
    assert "mistral:7b" in models
    assert "Ollama 0.3.14" in version
    assert lat >= 0.0


def test_probe_ollama_auth(mock_server):
    server, port = mock_server
    _MockHandler.mode = "ollama_auth"
    is_ollama, is_open, models, version, _ = probe_ollama("127.0.0.1", port)
    assert is_ollama is True
    assert is_open is False
    assert "Auth Required" in version


def test_probe_kobold_open(mock_server):
    server, port = mock_server
    _MockHandler.mode = "kobold"
    is_kobold, is_open, models, version, lat = probe_kobold("127.0.0.1", port)
    assert is_kobold is True
    assert is_open is True
    assert "Llama-3-8B-Instruct" in models
    assert "KoboldCpp 1.70" in version
    assert lat >= 0.0


def test_probe_kobold_auth(mock_server):
    server, port = mock_server
    _MockHandler.mode = "kobold_auth"
    is_kobold, is_open, models, version, _ = probe_kobold("127.0.0.1", port)
    assert is_kobold is True
    assert is_open is False
    assert "Auth Required" in version


def test_probe_port_integration(mock_server):
    server, port = mock_server
    _MockHandler.mode = "ollama"
    res = probe_port("127.0.0.1", port, service_hint="ollama")
    assert res.is_online is True
    assert res.is_open is True
    assert res.service_type == "ollama"
    assert "llama3:latest" in res.models
    assert res.api_url == f"http://127.0.0.1:{port}/v1"


def test_db_indexed_ports(db):
    pid, is_new = db.upsert_indexed_port(
        host="127.0.0.1",
        port=11434,
        service_type="ollama",
        url="http://127.0.0.1:11434",
        api_url="http://127.0.0.1:11434/v1",
        is_online=True,
        is_open=True,
        models=["llama3:latest"],
        latency_ms=12.5,
        version_info="Ollama 0.3.14",
    )
    assert is_new is True
    assert pid > 0

    # Upsert existing (touch / update)
    pid2, is_new2 = db.upsert_indexed_port(
        host="127.0.0.1",
        port=11434,
        service_type="ollama",
        url="http://127.0.0.1:11434",
        api_url="http://127.0.0.1:11434/v1",
        is_online=True,
        is_open=True,
        models=["llama3:latest", "phi3:mini"],
        latency_ms=10.0,
        version_info="Ollama 0.3.14",
    )
    assert is_new2 is False
    assert pid2 == pid

    # Add a Kobold port
    kpid, _ = db.upsert_indexed_port(
        host="127.0.0.1",
        port=5001,
        service_type="kobold",
        url="http://127.0.0.1:5001",
        api_url="http://127.0.0.1:5001/v1",
        is_online=True,
        is_open=True,
        models=["Llama-3-8B-Instruct"],
        latency_ms=8.0,
        version_info="KoboldCpp 1.70",
    )
    assert kpid != pid

    # List
    all_ports = db.list_indexed_ports()
    assert len(all_ports) == 2

    ollama_ports = db.list_indexed_ports(service_type="ollama")
    assert len(ollama_ports) == 1
    assert ollama_ports[0]["port"] == 11434

    kobold_ports = db.list_indexed_ports(service_type="kobold")
    assert len(kobold_ports) == 1
    assert kobold_ports[0]["port"] == 5001

    # Counts
    counts = db.indexed_port_counts()
    assert counts["total"] == 2
    assert counts["online"] == 2
    assert counts["open"] == 2
    assert counts["ollama"] == 1
    assert counts["kobold"] == 1

    # Delete
    assert db.delete_indexed_port(pid) is True
    assert len(db.list_indexed_ports()) == 1


def test_discovery_source(cfg, db, mock_server):
    _, port = mock_server
    _MockHandler.mode = "ollama"

    cfg.discovery.online_ports.enabled = True
    cfg.discovery.online_ports.mode = "custom"
    cfg.discovery.online_ports.hosts = ["127.0.0.1"]
    cfg.discovery.online_ports.ports_ollama = [port]
    cfg.discovery.online_ports.ports_kobold = []
    cfg.discovery.online_ports.interval_minutes = 0

    class _Ctx:
        def __init__(self, c, d):
            self.cfg = c
            self.db = d

    src = OnlinePortSource()
    targets = list(src.discover(_Ctx(cfg, db)))
    assert len(targets) == 1
    assert targets[0].source == "online_ports"
    assert "open-ollama" in targets[0].name

    # Check indexed into db
    indexed = db.list_indexed_ports()
    assert len(indexed) >= 1
    assert indexed[0]["port"] == port


def test_web_api_ports(cfg, db, mock_server, tmp_path):
    _, port = mock_server
    _MockHandler.mode = "ollama"

    # Seed an indexed port
    db.upsert_indexed_port(
        host="127.0.0.1",
        port=port,
        service_type="ollama",
        url=f"http://127.0.0.1:{port}",
        api_url=f"http://127.0.0.1:{port}/v1",
        is_online=True,
        is_open=True,
        models=["llama3:latest"],
        latency_ms=15.0,
        version_info="Ollama 0.3.14",
    )

    overlay = tmp_path / "config.local.yaml"
    cfg._overlay_path = str(overlay)
    app = create_app(cfg, db)
    client = app.test_client()

    # GET /api/ports
    resp = client.get("/api/ports")
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["ports"]) == 1
    assert data["counts"]["ollama"] == 1
    port_id = data["ports"][0]["id"]

    # POST /api/ports/<id>/check
    resp_check = client.post(f"/api/ports/{port_id}/check")
    assert resp_check.status_code == 200
    assert resp_check.get_json()["ok"] is True

    # POST /api/ports/<id>/use
    resp_use = client.post(f"/api/ports/{port_id}/use")
    assert resp_use.status_code == 200
    use_data = resp_use.get_json()
    assert use_data["ok"] is True
    assert use_data["base_url"] == f"http://127.0.0.1:{port}/v1"
    assert use_data["model"] == "llama3:latest"
    assert cfg.llm.enabled is True

    # DELETE /api/ports/<id>
    resp_del = client.delete(f"/api/ports/{port_id}")
    assert resp_del.status_code == 200
    assert resp_del.get_json()["ok"] is True
    assert len(db.list_indexed_ports()) == 0


def test_scanner_detects_ollama_and_kobold_urls(cfg):
    scanner = Scanner(cfg, load_rules("src/detect/rules"))
    content = """
    const OLLAMA_HOST = "http://54.210.10.20:11434/api/generate";
    const KOBOLD_HOST = "http://54.210.10.20:5001/api/v1/model";
    """
    findings = scanner.scan_text(content, "config.ts", 1)
    detectors = {f.detector for f in findings}
    assert "ollama-interface-url" in detectors
    assert "kobold-interface-url" in detectors


def test_generate_internet_targets():
    import ipaddress
    ips = generate_internet_targets(sample_size=15, use_cloud_subnets=True)
    assert len(ips) > 0
    for ip_str in ips:
        ip = ipaddress.ip_address(ip_str)
        assert ip.is_global
        assert not ip.is_private
        assert not ip.is_reserved


def test_parse_scan_output_nmap_xml():
    xml_data = """<?xml version="1.0"?>
    <nmaprun scanner="nmap">
      <host>
        <address addr="141.95.20.10" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="11434"><state state="open"/></port>
          <port protocol="tcp" portid="80"><state state="closed"/></port>
        </ports>
      </host>
      <host>
        <address addr="168.119.50.60" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="5001"><state state="open"/></port>
        </ports>
      </host>
    </nmaprun>
    """
    endpoints = parse_scan_output(xml_data)
    assert len(endpoints) == 2
    assert ("141.95.20.10", 11434) in endpoints
    assert ("168.119.50.60", 5001) in endpoints


def test_parse_scan_output_masscan_json():
    json_data = """
    {"ip": "159.69.10.20", "timestamp": "1610000000", "ports": [{"port": 11434, "proto": "tcp", "status": "open"}]}
    {"ip": "138.68.20.30", "timestamp": "1610000000", "ports": [{"port": 5000, "proto": "tcp", "status": "open"}]}
    """
    endpoints = parse_scan_output(json_data)
    assert len(endpoints) == 2
    assert ("159.69.10.20", 11434) in endpoints
    assert ("138.68.20.30", 5000) in endpoints


def test_export_to_nmap_xml():
    results = [
        PortProbeResult(
            host="159.69.10.20",
            port=11434,
            service_type="ollama",
            is_online=True,
            is_open=True,
            models=["llama3:latest"],
            version_info="Ollama 0.3.14",
        ),
        PortProbeResult(
            host="138.68.20.30",
            port=5001,
            service_type="kobold",
            is_online=True,
            is_open=True,
            models=["Llama-3-8B-Instruct"],
            version_info="KoboldCpp 1.70",
        ),
    ]
    xml_str = export_to_nmap_xml(results)
    assert "<nmaprun" in xml_str
    assert 'addr="159.69.10.20"' in xml_str
    assert 'portid="11434"' in xml_str
    assert 'name="ollama"' in xml_str
    assert 'addr="138.68.20.30"' in xml_str
    assert 'portid="5001"' in xml_str
    assert 'name="kobold"' in xml_str


def test_query_ivre_db_fallback():
    # If IVRE is not installed or returns empty, handles gracefully
    res = query_ivre_db(ports=[11434], ivre_path="nonexistent-ivre-cmd")
    assert isinstance(res, list)


def test_web_api_export_and_import(cfg, db, tmp_path):
    db.upsert_indexed_port(
        host="159.69.1.2",
        port=11434,
        service_type="ollama",
        url="http://159.69.1.2:11434",
        api_url="http://159.69.1.2:11434/v1",
        is_online=True,
        is_open=True,
        models=["llama3:latest"],
    )

    app = create_app(cfg, db)
    client = app.test_client()

    # GET /api/ports/export_nmap
    resp = client.get("/api/ports/export_nmap")
    assert resp.status_code == 200
    assert "xml" in resp.headers.get("Content-Type", "")
    assert b"<nmaprun" in resp.data
    assert b"159.69.1.2" in resp.data

    # POST /api/ports/import_scan
    scan_xml = """<?xml version="1.0"?>
    <nmaprun scanner="nmap">
      <host>
        <address addr="168.119.1.2" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="11434"><state state="open"/></port></ports>
      </host>
    </nmaprun>"""
    resp_imp = client.post("/api/ports/import_scan", json={"content": scan_xml})
    assert resp_imp.status_code == 200
    data = resp_imp.get_json()
    assert data["ok"] is True
    assert data["parsed_endpoints"] == 1
    # Check that 168.119.1.2 was inserted into db
    rows = db.list_indexed_ports()
    hosts = [r["host"] for r in rows]
    assert "168.119.1.2" in hosts

