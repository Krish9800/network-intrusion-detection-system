# Changelog

All notable changes to the Network Intrusion Detection System (NIDS) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-12

### Added
- **Phase 1 (Foundation)**: Project scaffold, Pydantic `NIDSSettings` with environment variable loading, Pytest fixtures.
- **Phase 2 (Models & Enums)**: Typed models for `DecodedPacket`, `NetworkFlow`, `NIDSRule`, `NIDSAlert`, and protocol/flag enums.
- **Phase 3 (Binary Packet Decoder)**: Pure Python `struct`-based binary decoder for Ethernet II, IPv4, TCP (flags bitfield & options), UDP, ICMP, DNS query extraction, and HTTP request parsing.
- **Phase 4 (Stateful Flow Tracker)**: Bidirectional canonical 5-tuple hash flow tracking with TCP state machine and inactivity eviction.
- **Phase 5 (Signature Matching Engine)**: Snort/Suricata style signature matching engine supporting CIDR ranges, port lists, content offset/depth/nocase matching, and PCRE regexes.
- **Phase 6 (Anomaly Detectors)**: Statistical and heuristic anomaly engines for SYN floods, horizontal/vertical port scans, and Shannon entropy DNS tunneling ($H \ge 3.8$).
- **Phase 7 (SQLite WAL Persistence)**: SQLite storage repository with WAL journal mode, parameterized SQL, busy timeouts, and flow/alert queries.
- **Phase 8 (FastAPI Control Plane)**: Async REST API endpoints for packet ingestion (`/api/v1/packets/ingest`), flow inspection, alert querying, and rule management.
- **Phase 9 (Typer CLI)**: CLI interface for offline hex/file packet decoding (`nids analyze`), alerts inspection, flows filtering, and daemon management.
- **Phase 10 (Deployment, Security & CI)**: Multi-stage rootless `Dockerfile` (`UID 10001:10001`), `docker-compose.yml`, GitHub Actions CI pipeline, STRIDE threat model documentation, and adversarial security test suite.
