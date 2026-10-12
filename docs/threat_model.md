# STRIDE Threat Model: Network Intrusion Detection System (NIDS)

## 1. System Overview & Boundaries
The NIDS engine decodes raw binary packets, tracks stateful 5-tuple TCP/UDP sessions, matches Snort/Suricata style signatures, flags statistical and heuristic anomalies (SYN floods, port scans, DNS tunneling), and exposes control plane interactions via FastAPI REST and Typer CLI.

### Trust Boundaries
1. **Network Ingestion Boundary**: Raw binary network frames ingested from raw sockets or untrusted client requests.
2. **Control Plane Boundary**: REST API endpoints (`/api/v1/*`) and CLI invocations.
3. **Storage Boundary**: SQLite database stored in WAL mode on local filesystem.

---

## 2. STRIDE Threat Analysis & Mitigations

| Category | Threat Description | Attack Vector | Severity | Implemented Mitigations | Verification Test |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | IP/Port Spoofing to frame benign endpoints or bypass tracking. | Crafted packets with forged source IP addresses in IPv4 header. | High | Bidirectional canonical flow key hashing (`(min_ip, max_ip)`) ensures state tracking remains coherent across client/server flows regardless of spoofing direction. | `tests/unit/test_flow_tracker.py` |
| **Tampering** | Packet Header Truncation & Framing Corruption. | Feeding truncated or zero-length frames to cause index out of bounds or parser crashes. | Critical | Strict length bounds checking in all `struct.unpack` decoders (`PacketDecoder`); raises `PacketDecodeError` and rejects frame cleanly without crash. | `tests/security/test_security_adversarial.py` |
| **Repudiation** | Alert Loss or Session Disavowal. | High-frequency packet bombardment causing alert drops or SQLite locking. | Medium | SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) with synchronous NORMAL and timeout retry parameters guarantees alert auditability. | `tests/unit/test_database.py` |
| **Information Disclosure** | Memory or Payload Leaks across Multi-tenant Flow Sessions. | Buffer over-read or unvalidated payload snippets leaking kernel/process memory. | High | Standard library `struct` slicing with fixed boundaries; payloads sanitized and hex/ascii truncated to configured `max_payload_bytes`. | `tests/security/test_security_adversarial.py` |
| **Denial of Service** | Flow Tracker State Exhaustion / Memory Exhaustion. | High PPS SYN flood attack creating millions of half-open TCP states. | Critical | Sliding window LRU / TTL eviction (`prune_expired()`) based on `flow_idle_timeout` and bounded memory limits. SYN flood detector issues alert upon threshold breach. | `tests/security/test_security_adversarial.py` |
| **Elevation of Privilege** | Container Escape or Root Compromise. | Vulnerabilities exploited to execute code with host root privileges. | Critical | Multi-stage Docker container dropping all capabilities (`cap_drop: ALL`), non-root system user (`UID 10001:10001`), read-only root filesystem. | Dockerfile verification & CI checks |

---

## 3. Defense-in-Depth Implementation Details

### Binary Decoder Resilience
- Zero-length and sub-header payloads safely trigger custom exception hierarchy (`PacketDecodeError`).
- TCP options variable header length (`data_offset * 4`) strictly bounded between 20 and 60 bytes.
- IPv4 IHL strictly checked for minimum 20 bytes (`ihl >= 5`).
- DNS and HTTP decoders fail gracefully to raw application payloads if parsing fails.

### SQLite Parameterization
- All queries strictly utilize SQLite `?` parameterization. No f-string SQL query concatenation exists in `Database`.
- SQLite busy timeouts set to 5000ms with thread-safe connection pooling.

### Unprivileged Execution
- Rootless runtime with unprivileged user `appuser` (UID 10001, GID 10001).
- System files non-writable in container runtime.
