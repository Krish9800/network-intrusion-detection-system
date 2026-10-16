# Network Intrusion Detection System (NIDS)

High-performance, pure-Python Network Intrusion Detection System featuring binary multi-layer packet decoding, stateful 5-tuple flow tracking, Snort-compatible signature inspection, heuristic anomaly detectors, SQLite WAL persistence, FastAPI REST control plane, and Typer CLI.

---

## Architecture Overview

```
                                      ┌────────────────────────────────────────────────┐
                                      │              Raw Network Packets               │
                                      │          (Ethernet / IP / TCP / UDP)           │
                                      └───────────────────────┬────────────────────────┘
                                                              │
                                                              ▼
                                      ┌────────────────────────────────────────────────┐
                                      │             PacketDecoder (struct)             │
                                      │   Ethernet II -> IPv4 -> TCP/UDP/ICMP/DNS/HTTP │
                                      └───────────────────────┬────────────────────────┘
                                                              │
                                      ┌───────────────────────┴────────────────────────┐
                                      ▼                                                ▼
         ┌──────────────────────────────────────────────┐    ┌──────────────────────────────────────────────┐
         │          Stateful FlowTracker                │    │           Detection Pipeline                 │
         │  • Canonical 5-Tuple Keying                  │    │  • SignatureEngine (Snort/Suricata rules)    │
         │  • TCP Handshake / Teardown State Machine    │    │  • AnomalyDetector (SYN flood, port scan,    │
         │  • TTL / Inactivity Eviction                 │    │    Shannon entropy DNS tunneling)            │
         └──────────────────────┬───────────────────────┘    └──────────────────────┬───────────────────────┘
                                │                                                   │
                                └───────────────────────┬───────────────────────────┘
                                                        │
                                                        ▼
                                      ┌────────────────────────────────────────────────┐
                                      │            SQLite WAL Database                 │
                                      │      (network_flows, nids_alerts, rules)       │
                                      └───────────────────────┬────────────────────────┘
                                                              │
                                      ┌───────────────────────┴────────────────────────┐
                                      ▼                                                ▼
         ┌──────────────────────────────────────────────┐    ┌──────────────────────────────────────────────┐
         │              FastAPI REST API                │    │                  Typer CLI                   │
         │   • /api/v1/packets/ingest                   │    │   • nids analyze <hex | file>                │
         │   • /api/v1/flows & /api/v1/alerts           │    │   • nids rules list                          │
         │   • /api/v1/rules & /api/v1/health           │    │   • nids alerts list & nids flows list       │
         └──────────────────────────────────────────────┘    └──────────────────────────────────────────────┘
```

---

## Features

- **Binary Multi-Layer Packet Decoder**: Zero external C-dependencies, built purely with Python `struct` and `socket`. Decodes Ethernet II, IPv4, TCP (flags bitfield & options), UDP, ICMP, DNS query domains, and HTTP request headers.
- **Stateful 5-Tuple Flow Tracker**: Bidirectional canonical hashing `(ip_a, port_a, ip_b, port_b, protocol)` maintaining client/server state, TCP connection lifecycle (`NEW` -> `SYN_SENT` -> `SYN_RECV` -> `ESTABLISHED` -> `FIN_WAIT` -> `CLOSED`), and byte/packet counters.
- **Snort-Style Signature Engine**: Rule matching on transport protocol, CIDR/exact IP matching, port ranges/lists, payload content search with `nocase`, `offset`, and `depth`, plus PCRE-style regex evaluation.
- **Statistical & Heuristic Anomaly Detectors**:
  - **SYN Flood**: Tracks half-open SYN sessions without completion over sliding time windows.
  - **Port Scan**: Flags single-source probing of >20 distinct ports within sliding thresholds.
  - **DNS Tunneling**: High Shannon entropy ($H \ge 3.8$) detection on fully qualified domain names and subdomains.
- **Storage Layer**: SQLite WAL engine with parameterized safety, transactional atomicity, and indices.
- **Control Plane**: FastAPI service with OpenAPI docs, and rich Typer CLI with terminal tables.
- **Hardened Deployment**: Multi-stage rootless Dockerfile (`UID 10001:10001`), `cap_drop: ALL`, read-only root filesystems, and health check probes.

---

## Getting Started

### Local Setup

```bash
# Clone and enter directory
git clone https://github.com/Krish9800/network-intrusion-detection-system.git
cd network-intrusion-detection-system

# Create virtual environment and install in editable mode
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running the Test Suite & Quality Gates

```bash
# Code formatting & linting
ruff format .
ruff check . --fix

# Strict static type analysis
mypy --strict src tests

# Security vulnerability scan
bandit -r src/

# Run tests with coverage (>= 90%)
pytest --cov=src/nids --cov-report=term-missing --cov-fail-under=90
```

---

## CLI Usage

The `nids` CLI provides rich terminal-based inspection and daemon controls:

```bash
# Analyze a raw hex-encoded network frame
nids analyze "00000000000000000000000008004500003c00010000400600007f0000017f00000104d2005000000001000000005002040000000000"

# List registered signatures and MITRE ATT&CK mappings
nids rules list

# Inspect recorded alerts
nids alerts list --severity critical

# Inspect active network sessions
nids flows list --state established

# Start the REST control plane daemon
nids serve --host 127.0.0.1 --port 8000
```

---

## Docker Deployment

Run with Rootless Docker Compose:

```bash
docker compose up -d --build
```

Verify service health:
```bash
curl -s http://127.0.0.1:8000/api/v1/health
# {"status":"healthy","version":"0.1.0","active_flows":0}
```

---

## Threat Model & Security

Detailed STRIDE threat analysis, security controls, and adversarial verification tests are documented in [`docs/threat_model.md`](docs/threat_model.md).
