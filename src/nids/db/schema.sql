-- SQLite WAL Schema for Network Intrusion Detection System (NIDS)

CREATE TABLE IF NOT EXISTS decoded_packets (
    packet_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    raw_length INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    src_mac TEXT,
    dst_mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    tcp_flags INTEGER NOT NULL DEFAULT 0,
    tcp_seq INTEGER,
    tcp_ack INTEGER,
    dns_query_name TEXT,
    http_method TEXT,
    http_path TEXT,
    payload_preview TEXT
);

CREATE INDEX IF NOT EXISTS idx_packets_ts ON decoded_packets(timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON decoded_packets(src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON decoded_packets(dst_ip);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON decoded_packets(protocol);

CREATE TABLE IF NOT EXISTS network_flows (
    flow_id TEXT PRIMARY KEY,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    state TEXT NOT NULL,
    packets_forward INTEGER NOT NULL DEFAULT 0,
    packets_reverse INTEGER NOT NULL DEFAULT 0,
    bytes_forward INTEGER NOT NULL DEFAULT 0,
    bytes_reverse INTEGER NOT NULL DEFAULT 0,
    start_time TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flows_state ON network_flows(state);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON network_flows(last_seen);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON network_flows(src_ip);

CREATE TABLE IF NOT EXISTS nids_rules (
    sid INTEGER PRIMARY KEY,
    rev INTEGER NOT NULL DEFAULT 1,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL DEFAULT 'any',
    dst_ip TEXT NOT NULL DEFAULT 'any',
    src_port TEXT NOT NULL DEFAULT 'any',
    dst_port TEXT NOT NULL DEFAULT 'any',
    content TEXT,
    nocase INTEGER NOT NULL DEFAULT 0,
    offset INTEGER NOT NULL DEFAULT 0,
    depth INTEGER,
    regex TEXT,
    severity TEXT NOT NULL,
    mitre_attack_id TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nids_alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    anomaly_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    sid INTEGER,
    mitre_attack_id TEXT,
    payload_snippet TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (sid) REFERENCES nids_rules(sid)
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON nids_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON nids_alerts(anomaly_type);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON nids_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON nids_alerts(src_ip);
