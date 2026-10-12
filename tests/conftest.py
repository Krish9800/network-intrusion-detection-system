"""Shared test fixtures for NIDS test suite."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from nids.config.settings import Settings


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a clean temporary directory."""
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


@pytest.fixture
def test_settings(temp_dir: Path) -> Settings:
    """Provide an isolated Settings instance pointed at a temporary directory."""
    settings = Settings(
        environment="testing",
        debug=True,
        base_dir=temp_dir,
        data_dir=temp_dir / "data",
        rules_dir=temp_dir / "rules",
        database_url=f"sqlite:///{temp_dir / 'nids_test.db'}",
        flow_timeout_seconds=30,
        port_scan_threshold=5,
    )
    settings.ensure_directories()
    return settings
