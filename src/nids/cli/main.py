"""Typer CLI Tool for Network Intrusion Detection System (NIDS).

Commands:
- analyze: Parse and inspect a raw hex packet or file.
- flows: Query active and recorded network sessions.
- alerts: List intrusion alerts and MITRE ATT&CK mappings.
- rules: List and inspect loaded detection signatures.
- serve: Run the FastAPI control plane daemon.
"""

import binascii
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from nids.config.settings import get_settings
from nids.db.database import Database
from nids.decoders.packet_decoder import PacketDecoder
from nids.detectors.anomaly_detector import AnomalyDetector
from nids.engine.signature_engine import SignatureEngine
from nids.flow.tracker import FlowTracker
from nids.models.enums import AlertSeverity, AnomalyType, FlowState

app = typer.Typer(
    name="nids",
    help="Network Intrusion Detection System (NIDS) CLI.",
    add_completion=False,
)
rules_app = typer.Typer(name="rules", help="Manage and inspect NIDS signatures.")
alerts_app = typer.Typer(name="alerts", help="Query and filter intrusion alerts.")
flows_app = typer.Typer(name="flows", help="Query 5-tuple stateful network flows.")

app.add_typer(rules_app)
app.add_typer(alerts_app)
app.add_typer(flows_app)

console = Console()


# -------------------------------------------------------------
# Analyze Packet Command
# -------------------------------------------------------------
@app.command(name="analyze")
def analyze_packet_cmd(
    target: Annotated[
        str, typer.Argument(help="Hexadecimal packet string or path to raw binary file")
    ],
) -> None:
    """Decode raw packet bytes, track flow state, and evaluate intrusion alerts."""
    target_path = Path(target)
    if target_path.is_file():
        raw_bytes = target_path.read_bytes()
    else:
        try:
            clean = target.replace(" ", "").replace("\n", "").replace(":", "")
            raw_bytes = binascii.unhexlify(clean)
        except Exception as err:
            console.print(f"[red]Failed to parse hex packet:[/] {err}")
            raise typer.Exit(code=1) from err

    decoder = PacketDecoder()
    try:
        pkt = decoder.decode(raw_bytes)
    except Exception as err:
        console.print(f"[red]Decoding error:[/] {err}")
        raise typer.Exit(code=1) from err

    # Print decoded details
    proto_str = pkt.protocol.value.upper()
    console.print(f"[bold green]Decoded Packet:[/] Protocol={proto_str}, Length={pkt.raw_length}B")
    if pkt.src_ip:
        console.print(
            f"Endpoints: [cyan]{pkt.src_ip}:{pkt.src_port}[/] ──> "
            f"[magenta]{pkt.dst_ip}:{pkt.dst_port}[/]"
        )

    # Run inspection
    settings = get_settings()
    db = Database(settings.effective_db_path)
    tracker = FlowTracker()
    flow = tracker.process_packet(pkt)
    if flow:
        console.print(f"Flow State: [yellow]{flow.state.value.upper()}[/] (ID: {flow.flow_id})")

    sig_engine = SignatureEngine(db.list_rules())
    anomaly_detector = AnomalyDetector()

    alerts = sig_engine.match_packet(pkt) + anomaly_detector.inspect_packet(pkt)
    if alerts:
        console.print(f"\n[bold red]Intrusion Alerts Detected ({len(alerts)}):[/]")
        for a in alerts:
            m_id = a.mitre_attack_id or "N/A"
            console.print(f" - [{a.severity.upper()}] [bold]{a.title}[/] (MITRE: {m_id})")
            if a.payload_snippet:
                console.print(f"   Snippet: [dim]{a.payload_snippet}[/]")
    else:
        console.print("[green]No intrusion signatures or anomalies triggered.[/]")


# -------------------------------------------------------------
# Rules Subcommands
# -------------------------------------------------------------
@rules_app.command(name="list")
def list_rules_cmd() -> None:
    """List rules stored in the local SQLite database."""
    settings = get_settings()
    db = Database(settings.effective_db_path)
    rules = db.list_rules()
    if not rules:
        console.print("[yellow]No NIDS rules found in database.[/]")
        return

    table = Table(title="Registered NIDS Signatures")
    table.add_column("SID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Proto", style="blue")
    table.add_column("Dst Port", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("MITRE", style="magenta")
    for r in rules:
        table.add_row(
            str(r.sid),
            r.name,
            r.protocol.value,
            r.dst_port,
            r.severity.value,
            r.mitre_attack_id or "N/A",
        )
    console.print(table)


# -------------------------------------------------------------
# Alerts Subcommands
# -------------------------------------------------------------
@alerts_app.command(name="list")
def list_alerts_cmd(
    anomaly_type: Annotated[AnomalyType | None, typer.Option("--type", "-t")] = None,
    severity: Annotated[AlertSeverity | None, typer.Option("--severity", "-s")] = None,
) -> None:
    """List intrusion alerts from database."""
    settings = get_settings()
    db = Database(settings.effective_db_path)
    alerts = db.list_alerts(anomaly_type=anomaly_type, severity=severity)
    if not alerts:
        console.print("[yellow]No alerts found matching criteria.[/]")
        return

    table = Table(title="Intrusion Alerts")
    table.add_column("Alert ID", style="cyan")
    table.add_column("Timestamp (UTC)", style="white")
    table.add_column("Type", style="magenta")
    table.add_column("Severity", style="yellow")
    table.add_column("Title", style="white")
    table.add_column("Source", style="cyan")
    table.add_column("Target", style="blue")
    for a in alerts:
        table.add_row(
            a.alert_id[:8],
            a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            a.anomaly_type.value,
            a.severity.value,
            a.title,
            f"{a.src_ip or '*'}:{a.src_port or '*'}",
            f"{a.dst_ip or '*'}:{a.dst_port or '*'}",
        )
    console.print(table)


# -------------------------------------------------------------
# Flows Subcommands
# -------------------------------------------------------------
@flows_app.command(name="list")
def list_flows_cmd(
    state_filter: Annotated[FlowState | None, typer.Option("--state")] = None,
) -> None:
    """List network sessions from database."""
    settings = get_settings()
    db = Database(settings.effective_db_path)
    flows = db.list_flows(state=state_filter)
    if not flows:
        console.print("[yellow]No flows found in database.[/]")
        return

    table = Table(title="Network Sessions")
    table.add_column("Flow ID", style="cyan")
    table.add_column("Proto", style="blue")
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="magenta")
    table.add_column("State", style="yellow")
    table.add_column("Packets", style="green")
    table.add_column("Bytes", style="white")
    for f in flows:
        table.add_row(
            f.flow_id,
            f.protocol.value,
            f"{f.src_ip}:{f.src_port}",
            f"{f.dst_ip}:{f.dst_port}",
            f.state.value,
            str(f.total_packets),
            str(f.total_bytes),
        )
    console.print(table)


# -------------------------------------------------------------
# Daemon Server Command
# -------------------------------------------------------------
@app.command(name="serve")
def serve_cmd(
    host: Annotated[str, typer.Option(help="Host to bind")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to bind")] = 8000,
    reload: Annotated[bool, typer.Option(help="Enable auto-reload")] = False,
) -> None:
    """Start the FastAPI control plane daemon."""
    console.print(f"[green]Starting NIDS Control Plane on http://{host}:{port}[/]")
    uvicorn.run("nids.api.app:app", host=host, port=port, reload=reload)
