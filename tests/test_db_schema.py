"""Tests for new database tables."""

import asyncio
import aiosqlite
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_schema.db"


def setup_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def teardown_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def test_new_tables_created():
    """All 8 new tables exist after init_db."""
    import db.connection as conn
    original_path = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        asyncio.run(conn.init_db())

        async def _check():
            async with aiosqlite.connect(TEST_DB) as db:
                cursor = await db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
                tables = [row[0] for row in await cursor.fetchall()]
                return tables

        tables = asyncio.run(_check())

        expected_new = [
            "agent_config",
            "agent_memory",
            "api_call_log",
            "api_credentials",
            "corporate_cards",
            "employee_directory",
            "sent_emails",
            "webhook_registrations",
        ]
        for table in expected_new:
            assert table in tables, f"Missing table: {table}"
    finally:
        conn.DB_PATH = original_path


def test_agent_config_has_correct_columns():
    """agent_config table has all required columns."""
    import db.connection as conn
    original_path = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        asyncio.run(conn.init_db())

        async def _check():
            async with aiosqlite.connect(TEST_DB) as db:
                cursor = await db.execute("PRAGMA table_info(agent_config)")
                columns = {row[1] for row in await cursor.fetchall()}
                return columns

        columns = asyncio.run(_check())
        required = {
            "id", "booking_auto_approve_limit", "max_booking_amount",
            "security_level", "fraud_detection_enabled",
            "require_booking_confirmation", "custom_goals",
            "speed_priority", "updated_at",
        }
        assert required.issubset(columns), f"Missing columns: {required - columns}"
    finally:
        conn.DB_PATH = original_path
