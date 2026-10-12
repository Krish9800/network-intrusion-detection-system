"""Integration tests for NIDS Typer CLI tool."""

import binascii
import struct
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nids.cli.main import app
from nids.db.database import Database
from nids.models.enums import AlertSeverity, AnomalyType, FlowState, PacketProtocol, TCPFlag
from nids.models.schemas import NetworkFlow, NIDSAlert, NIDSRule

runner = CliRunner()


def test_cli_rules_list(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify `nids rules list` displays registered signatures and empty state."""
    db_path = temp_dir / "cli_rules.db"
    monkeypatch.setenv("NIDS_DATA_DIR", str(temp_dir))
    monkeypatch.setenv("NIDS_DATABASE_URL", str(db_path))

    # Empty rules state
    res_empty = runner.invoke(app, ["rules", "list"])
    assert res_empty.exit_code == 0
    assert "No NIDS rules found" in res_empty.stdout

    db = Database(db_path)
    rule = NIDSRule(
        sid=1001,
        name="SSH Inbound Scan",
        protocol=PacketProtocol.TCP,
        dst_port="22",
        severity=AlertSeverity.HIGH,
        mitre_attack_id="T1046",
    )
    db.save_rule(rule)

    res = runner.invoke(app, ["rules", "list"])
    assert res.exit_code == 0
    assert "1001" in res.stdout
    assert "SSH" in res.stdout


def test_cli_alerts_and_flows_list(temp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify `nids alerts list` and `nids flows list` commands and empty states."""
    db_path = temp_dir / "cli_test.db"
    monkeypatch.setenv("NIDS_DATA_DIR", str(temp_dir))
    monkeypatch.setenv("NIDS_DATABASE_URL", str(db_path))

    # Empty alerts and flows state
    res_empty_alerts = runner.invoke(app, ["alerts", "list"])
    assert res_empty_alerts.exit_code == 0
    assert "No alerts found" in res_empty_alerts.stdout

    res_empty_flows = runner.invoke(app, ["flows", "list"])
    assert res_empty_flows.exit_code == 0
    assert "No flows found" in res_empty_flows.stdout

    db = Database(db_path)
    alert = NIDSAlert(
        anomaly_type=AnomalyType.SYN_FLOOD,
        severity=AlertSeverity.CRITICAL,
        title="SYN Flood Detected",
        description="Target overwhelmed",
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
    )
    db.save_alert(alert)

    flow = NetworkFlow(
        flow_id="flow-abc",
        protocol=PacketProtocol.TCP,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=80,
        state=FlowState.ESTABLISHED,
    )
    db.save_flow(flow)

    res_alerts = runner.invoke(app, ["alerts", "list"])
    assert res_alerts.exit_code == 0
    assert "syn_flood" in res_alerts.stdout
    assert alert.alert_id[:8] in res_alerts.stdout

    res_flows = runner.invoke(app, ["flows", "list"])
    assert res_flows.exit_code == 0
    assert "flow-abc" in res_flows.stdout


def test_cli_analyze_packet_hex_and_file(temp_dir: Path) -> None:
    """Verify `nids analyze` command decoding raw hex frame and binary file."""
    # Build synthetic frame
    eth = struct.pack("!6s6sH", b"\x00" * 6, b"\x00" * 6, 0x0800)
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
        b"\xc0\xa8\x01\x0a",  # 192.168.1.10
        b"\x0a\x00\x00\x02",  # 10.0.0.2
    )
    tcp_hdr = struct.pack("!HHIIBBHHH", 4000, 80, 10, 0, (5 << 4), TCPFlag.SYN.value, 1024, 0, 0)
    raw = eth + ip + tcp_hdr
    hex_str = binascii.hexlify(raw).decode("ascii")

    res = runner.invoke(app, ["analyze", hex_str])
    assert res.exit_code == 0
    assert "Decoded Packet: Protocol=TCP" in res.stdout
    assert "192.168.1.10:4000" in res.stdout

    # Test via binary file
    bin_file = temp_dir / "packet.bin"
    bin_file.write_bytes(raw)
    res_file = runner.invoke(app, ["analyze", str(bin_file)])
    assert res_file.exit_code == 0
    assert "Decoded Packet: Protocol=TCP" in res_file.stdout

    # Test invalid hex input
    res_err = runner.invoke(app, ["analyze", "zz-invalid-hex"])
    assert res_err.exit_code == 1
    assert "Failed to parse hex packet" in res_err.stdout

    # Test corrupted packet bytes
    corrupt_file = temp_dir / "corrupt.bin"
    corrupt_file.write_bytes(b"\x00\x01\x02")
    res_corrupt = runner.invoke(app, ["analyze", str(corrupt_file)])
    assert res_corrupt.exit_code == 1
    assert "Decoding error" in res_corrupt.stdout
