"""Tests for sync config/memory loading (production code path)."""

import sqlite3
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_sync.db"


def setup_module():
    if TEST_DB.exists():
        TEST_DB.unlink()
    # Initialize DB and seed via async path, then test sync reads
    import asyncio
    import db.connection as conn
    conn.DB_PATH = TEST_DB
    from db.connection import init_db
    from db.seed_data import seed_data
    asyncio.run(init_db())
    asyncio.run(seed_data())


def teardown_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def test_load_agent_config_sync_returns_config():
    """Sync config loader returns seeded config with correct defaults."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        from agent import _load_agent_config_sync
        config = _load_agent_config_sync()
        assert config["security_level"] == "standard"
        assert config["booking_auto_approve_limit"] == 1000.0
        assert config["fraud_detection_enabled"] == 1
    finally:
        conn.DB_PATH = original


def test_load_instruction_memories_sync_empty_initially():
    """Sync memory loader returns empty list when no instruction memories exist."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        from agent import _load_instruction_memories_sync
        memories = _load_instruction_memories_sync()
        assert isinstance(memories, list)
        assert len(memories) == 0  # seed data doesn't add instruction memories
    finally:
        conn.DB_PATH = original


def test_load_instruction_memories_sync_after_insert():
    """Sync memory loader returns instruction memories after they're inserted."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        import time
        # Insert an instruction memory directly
        direct_conn = sqlite3.connect(str(TEST_DB))
        direct_conn.execute(
            "INSERT INTO agent_memory (id, key, value, category, source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("mem-sync-test", "test_rule", "Always prefer morning flights", "instruction", "test", int(time.time())),
        )
        direct_conn.commit()
        direct_conn.close()

        from agent import _load_instruction_memories_sync
        memories = _load_instruction_memories_sync()
        assert len(memories) >= 1
        values = [m["value"] for m in memories]
        assert "Always prefer morning flights" in values
    finally:
        conn.DB_PATH = original


def test_sync_config_matches_async_config():
    """Sync and async loaders return the same data."""
    import asyncio
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        from agent import _load_agent_config, _load_agent_config_sync
        sync_config = _load_agent_config_sync()
        async_config = asyncio.run(_load_agent_config())
        # Compare key fields
        assert sync_config["security_level"] == async_config["security_level"]
        assert sync_config["booking_auto_approve_limit"] == async_config["booking_auto_approve_limit"]
        assert sync_config["fraud_detection_enabled"] == async_config["fraud_detection_enabled"]
    finally:
        conn.DB_PATH = original
