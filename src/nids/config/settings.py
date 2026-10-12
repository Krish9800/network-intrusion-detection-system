"""Configuration management for Network Intrusion Detection System."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """NIDS settings with environment variable override support."""

    model_config = SettingsConfigDict(
        env_prefix="NIDS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # General Configuration
    app_name: str = Field(
        default="Network Intrusion Detection System",
        description="NIDS platform display name",
    )
    environment: Literal["development", "testing", "production"] = Field(
        default="development",
        description="Deployment environment name",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode and detailed packet logging",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )

    # Base Paths
    base_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent,
        description="Project root directory",
    )
    data_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "data",
        description="Directory for PCAP artifacts and persistence",
    )
    rules_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent.parent / "rules",
        description="Directory containing signature and detection rules",
    )

    # Storage & Persistence
    database_url: str = Field(
        default="",
        description="SQLite connection URL or path. Defaults to data/nids.db",
    )
    wal_mode: bool = Field(
        default=True,
        description="Enable SQLite Write-Ahead Logging (WAL) mode",
    )

    # Flow Tracker Parameters
    flow_timeout_seconds: int = Field(
        default=120,
        ge=5,
        description="Inactivity timeout before expiring inactive network flows",
    )
    max_active_flows: int = Field(
        default=50_000,
        ge=100,
        description="Maximum concurrent in-memory flows tracked before LRU eviction",
    )

    # Heuristic & Anomaly Detection Thresholds
    port_scan_threshold: int = Field(
        default=15,
        ge=2,
        description="Number of unique destination ports within window to trigger port scan alert",
    )
    port_scan_window_seconds: int = Field(
        default=10,
        ge=1,
        description="Sliding window in seconds for port scan tracking",
    )
    syn_flood_threshold: int = Field(
        default=50,
        ge=5,
        description="SYN packets per second threshold to trigger SYN flood alert",
    )
    dns_entropy_threshold: float = Field(
        default=3.8,
        ge=1.0,
        le=8.0,
        description="Shannon entropy threshold on DNS query labels for tunneling detection",
    )
    dns_label_length_threshold: int = Field(
        default=30,
        ge=10,
        description="Subdomain query label length threshold for tunneling detection",
    )

    # Control Plane API
    api_host: str = Field(
        default="127.0.0.1",
        description="FastAPI bind host",
    )
    api_port: int = Field(
        default=8000,
        ge=1024,
        le=65535,
        description="FastAPI bind port",
    )

    def ensure_directories(self) -> None:
        """Create necessary runtime directories."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.rules_dir.mkdir(parents=True, exist_ok=True)

    @property
    def effective_db_path(self) -> Path:
        """Resolve the SQLite database path."""
        if self.database_url and not self.database_url.startswith("sqlite:///"):
            return Path(self.database_url)
        if self.database_url.startswith("sqlite:///"):
            return Path(self.database_url.removeprefix("sqlite:///"))
        return self.data_dir / "nids.db"


def get_settings() -> Settings:
    """Return a fresh Settings instance and ensure directories exist."""
    settings = Settings()
    settings.ensure_directories()
    return settings
