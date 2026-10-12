"""Integration tests for NIDS FastAPI Control Plane."""

import binascii
import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from nids.api.app import NIDSAppState, app, get_nids_state
from nids.config.settings import Settings
from nids.models.enums import AlertSeverity, PacketProtocol, TCPFlag
from nids.models.schemas import NIDSRule


@pytest.fixture
def client(temp_dir: Path) -> TestClient:
    """Create test client with isolated state and database."""
    settings = Settings(
        environment="testing",
        debug=True,
        base_dir=temp_dir,
        data_dir=temp_dir / "data",
        rules_dir=temp_dir / "rules",
        database_url=f"sqlite:///{temp_dir / 'api_test.db'}",
    )
    settings.ensure_directories()
    test_state = NIDSAppState(settings)
    app.dependency_overrides[get_nids_state] = lambda: test_state
    return TestClient(app)


def test_health_endpoint(client: TestClient) -> None:
    """Verify GET /health returns 200 OK and metrics."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "active_flows" in data


def test_rules_endpoints(client: TestClient) -> None:
    """Verify POST and GET /api/v1/rules."""
    rule = NIDSRule(
        sid=5001,
        name="Suspicious SSH Inbound",
        protocol=PacketProtocol.TCP,
        dst_port="22",
        severity=AlertSeverity.HIGH,
    )
    post_res = client.post("/api/v1/rules", json=rule.model_dump())
    assert post_res.status_code == 201
    assert post_res.json()["sid"] == 5001

    get_res = client.get("/api/v1/rules")
    assert get_res.status_code == 200
    assert any(r["sid"] == 5001 for r in get_res.json())


def test_packet_ingest_and_detection(client: TestClient) -> None:
    """Verify POST /api/v1/packets/ingest with raw frame triggers signature alerts."""
    # Register rule targeting HTTP cmd.php
    rule = NIDSRule(
        sid=9001,
        name="Backdoor Access Attempt",
        protocol=PacketProtocol.TCP,
        dst_port="80",
        content="cmd.php",
        severity=AlertSeverity.CRITICAL,
    )
    client.post("/api/v1/rules", json=rule.model_dump())

    # Build raw synthetic frame
    eth = struct.pack("!6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)
    # IP header (proto 6 = TCP)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        64,
        1,
        0,
        64,
        6,
        0,
        b"\xc0\xa8\x01\x05",  # 192.168.1.5
        b"\x0a\x00\x00\x01",  # 10.0.0.1
    )
    tcp_hdr = struct.pack("!HHIIBBHHH", 45000, 80, 100, 0, (5 << 4), TCPFlag.SYN.value, 8192, 0, 0)
    payload = b"GET /cmd.php HTTP/1.1\r\n\r\n"
    raw_frame = eth + ip + tcp_hdr + payload
    hex_data = binascii.hexlify(raw_frame).decode("ascii")

    res = client.post("/api/v1/packets/ingest", json={"hex_data": hex_data})
    assert res.status_code == 200
    data = res.json()
    assert data["packet"]["src_ip"] == "192.168.1.5"
    assert data["packet"]["dst_port"] == 80
    assert data["flow"]["flow_id"] is not None

    # Alert should have triggered
    assert len(data["alerts"]) >= 1
    assert any(a["sid"] == 9001 for a in data["alerts"])

    # Query alerts endpoint
    alerts_res = client.get("/api/v1/alerts")
    assert alerts_res.status_code == 200
    assert len(alerts_res.json()) >= 1

    # Query flows endpoint
    flows_res = client.get("/api/v1/flows")
    assert flows_res.status_code == 200
    assert len(flows_res.json()) >= 1


def test_packet_ingest_invalid_hex(client: TestClient) -> None:
    """Verify invalid hex returns 400 Bad Request."""
    res = client.post("/api/v1/packets/ingest", json={"hex_data": "NOT_HEX_DATA_ZZZZ"})
    assert res.status_code == 400
