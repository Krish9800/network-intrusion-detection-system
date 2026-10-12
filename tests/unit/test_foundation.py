"""Unit tests for foundational NIDS settings and directories."""

from pathlib import Path

import pytest

from nids import __version__
from nids.config.settings import Settings, get_settings


def test_nids_version() -> None:
    """Verify NIDS version string."""
    assert __version__ == "0.1.0"


def test_default_nids_settings() -> None:
    """Verify default NIDS settings and anomaly thresholds."""
    s = Settings()
    assert s.app_name == "Network Intrusion Detection System"
    assert s.environment == "development"
    assert s.debug is False
    assert s.flow_timeout_seconds == 120
    assert s.port_scan_threshold == 15
    assert s.syn_flood_threshold == 50
    assert s.dns_entropy_threshold == 3.8
    assert s.effective_db_path.name == "nids.db"


def test_custom_nids_settings(test_settings: Settings) -> None:
    """Verify custom test settings and path resolutions."""
    assert test_settings.environment == "testing"
    assert test_settings.flow_timeout_seconds == 30
    assert test_settings.data_dir.exists()
    assert test_settings.rules_dir.exists()
    assert test_settings.effective_db_path.name == "nids_test.db"


def test_effective_db_path_raw_string(temp_dir: Path) -> None:
    """Verify raw SQLite path resolution."""
    raw = temp_dir / "custom.sqlite"
    s = Settings(database_url=str(raw))
    assert s.effective_db_path == raw


def test_get_settings_auto_creates_directories(
    monkeypatch: pytest.MonkeyPatch, temp_dir: Path
) -> None:
    """Verify get_settings helper ensures directory creation."""
    c_data = temp_dir / "runtime_data"
    c_rules = temp_dir / "runtime_rules"
    monkeypatch.setenv("NIDS_DATA_DIR", str(c_data))
    monkeypatch.setenv("NIDS_RULES_DIR", str(c_rules))

    s = get_settings()
    assert c_data.exists()
    assert c_rules.exists()
    assert s.data_dir == c_data
