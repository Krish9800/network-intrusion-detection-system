"""FastAPI Control Plane Application for NIDS.

Endpoints:
- /health: System health and component status
- /api/v1/packets/ingest: Ingest raw hex or decoded packets and execute detection pipeline
- /api/v1/flows: Query active or persisted network flows
- /api/v1/alerts: Query intrusion alerts
- /api/v1/rules: Manage signature rules
"""

import binascii
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from nids.config.settings import Settings, get_settings
from nids.db.database import Database
from nids.decoders.packet_decoder import PacketDecoder
from nids.detectors.anomaly_detector import AnomalyDetector
from nids.engine.signature_engine import SignatureEngine
from nids.flow.tracker import FlowTracker
from nids.models.enums import AlertSeverity, AnomalyType, FlowState
from nids.models.schemas import DecodedPacket, NetworkFlow, NIDSAlert, NIDSRule


class RawPacketIngestRequest(BaseModel):
    """Ingest packet as hex string or base64."""

    hex_data: str = Field(..., description="Raw wire frame encoded as hexadecimal string")


class PacketIngestResponse(BaseModel):
    """Response containing decoded packet details and generated alerts."""

    packet: DecodedPacket
    flow: NetworkFlow | None = None
    alerts: list[NIDSAlert] = Field(default_factory=list)


class NIDSAppState:
    """Encapsulates shared NIDS pipeline components."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.effective_db_path, wal_mode=settings.wal_mode)
        self.decoder = PacketDecoder()
        self.flow_tracker = FlowTracker(
            flow_timeout_seconds=settings.flow_timeout_seconds,
            max_active_flows=settings.max_active_flows,
        )
        self.sig_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector(
            port_scan_threshold=settings.port_scan_threshold,
            port_scan_window_seconds=settings.port_scan_window_seconds,
            syn_flood_threshold=settings.syn_flood_threshold,
            dns_entropy_threshold=settings.dns_entropy_threshold,
            dns_label_length_threshold=settings.dns_label_length_threshold,
        )

        # Preload rules from database into engine
        for r in self.db.list_rules():
            self.sig_engine.add_rule(r)


_nids_state: NIDSAppState | None = None


def get_nids_state() -> NIDSAppState:
    """Dependency provider for NIDS app state."""
    global _nids_state
    if _nids_state is None:
        _nids_state = NIDSAppState(get_settings())
    return _nids_state


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup and shutdown lifecycle handler."""
    get_nids_state()
    yield


app = FastAPI(
    title="Network Intrusion Detection System (NIDS)",
    version="0.1.0",
    description="REST control plane for network traffic inspection and threat detection.",
    lifespan=lifespan,
)


@app.get("/health", tags=["System"])
async def health_check(state: NIDSAppState = Depends(get_nids_state)) -> dict[str, Any]:
    """System health check and live state metrics."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "active_flows": state.flow_tracker.active_flows_count(),
        "rules_loaded": len(state.sig_engine.rules),
        "database": str(state.settings.effective_db_path),
    }


# -------------------------------------------------------------
# Packet Ingestion
# -------------------------------------------------------------
@app.post(
    "/api/v1/packets/ingest",
    response_model=PacketIngestResponse,
    status_code=status.HTTP_200_OK,
    tags=["Packets"],
)
async def ingest_packet(
    req: RawPacketIngestRequest,
    state: NIDSAppState = Depends(get_nids_state),
) -> PacketIngestResponse:
    """Decode raw hex frame, track flow state, and evaluate intrusion alerts."""
    try:
        clean_hex = req.hex_data.replace(" ", "").replace("\n", "").replace(":", "")
        raw_bytes = binascii.unhexlify(clean_hex)
    except (binascii.Error, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid hexadecimal payload: {err}",
        ) from err

    try:
        decoded = state.decoder.decode(raw_bytes)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Packet decoding failure: {err}",
        ) from err

    # Persist packet
    state.db.save_packet(decoded)

    # 1. Update Flow Tracker
    flow = state.flow_tracker.process_packet(decoded)
    if flow:
        state.db.save_flow(flow)

    # 2. Run Signature Matcher
    sig_alerts = state.sig_engine.match_packet(decoded)

    # 3. Run Anomaly Detectors
    anomaly_alerts = state.anomaly_detector.inspect_packet(decoded)

    all_alerts = sig_alerts + anomaly_alerts
    for alert in all_alerts:
        state.db.save_alert(alert)

    return PacketIngestResponse(
        packet=decoded,
        flow=flow,
        alerts=all_alerts,
    )


# -------------------------------------------------------------
# Flows Management
# -------------------------------------------------------------
@app.get(
    "/api/v1/flows",
    response_model=list[NetworkFlow],
    tags=["Flows"],
)
async def list_flows(
    state_filter: FlowState | None = None,
    state: NIDSAppState = Depends(get_nids_state),
) -> list[NetworkFlow]:
    """Query network flows from database."""
    return state.db.list_flows(state=state_filter)


# -------------------------------------------------------------
# Alerts Management
# -------------------------------------------------------------
@app.get(
    "/api/v1/alerts",
    response_model=list[NIDSAlert],
    tags=["Alerts"],
)
async def list_alerts(
    anomaly_type: AnomalyType | None = None,
    severity: AlertSeverity | None = None,
    state: NIDSAppState = Depends(get_nids_state),
) -> list[NIDSAlert]:
    """Query intrusion alerts with optional anomaly type or severity filters."""
    return state.db.list_alerts(anomaly_type=anomaly_type, severity=severity)


# -------------------------------------------------------------
# Rules Management
# -------------------------------------------------------------
@app.get(
    "/api/v1/rules",
    response_model=list[NIDSRule],
    tags=["Rules"],
)
async def list_rules(state: NIDSAppState = Depends(get_nids_state)) -> list[NIDSRule]:
    """List registered detection signatures."""
    return state.db.list_rules()


@app.post(
    "/api/v1/rules",
    response_model=NIDSRule,
    status_code=status.HTTP_201_CREATED,
    tags=["Rules"],
)
async def register_rule(
    rule: NIDSRule,
    state: NIDSAppState = Depends(get_nids_state),
) -> NIDSRule:
    """Register and persist a new detection signature."""
    state.db.save_rule(rule)
    state.sig_engine.add_rule(rule)
    return rule
