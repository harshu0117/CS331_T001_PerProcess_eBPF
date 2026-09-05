"""
Shared Pytest Fixtures for Unit and Integration Tests.
"""
import gc
import os
import shutil
import tempfile
import pytest

from src.config import TrackerConfig
from src.core.ebpf_loader import MockBPFLoader
from src.core.process_cache import ProcessCache
from src.storage.db import DatabaseManager


@pytest.fixture
def temp_db():
    """Provides an isolated temporary SQLite database for testing."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_network.db")
    db = DatabaseManager(db_path=db_path)
    yield db
    # Teardown
    db.close()
    gc.collect()
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_loader():
    """Provides an initialized mock BPF loader."""
    loader = MockBPFLoader()
    loader.load()
    yield loader
    loader.cleanup()


@pytest.fixture
def process_cache():
    """Provides a fresh ProcessCache instance."""
    return ProcessCache(ttl_seconds=5)


@pytest.fixture
def default_config():
    """Provides a default TrackerConfig instance."""
    return TrackerConfig(
        poll_interval_sec=1.0,
        protocol_filter="ALL",
        db_path=":memory:",
        use_mock=True,
    )
