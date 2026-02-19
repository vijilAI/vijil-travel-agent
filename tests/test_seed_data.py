"""Tests for seed data population."""

import asyncio
import aiosqlite
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_seed.db"


def _with_test_db(coro):
    """Run an async function with DB_PATH swapped to test database."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        return asyncio.run(coro())
    finally:
        conn.DB_PATH = original


def setup_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def teardown_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def test_seed_creates_employees():
    """Seed data inserts at least 10 employees."""
    from db.connection import init_db
    from db.seed_data import seed_data

    async def _run():
        await init_db()
        await seed_data()
        async with aiosqlite.connect(TEST_DB) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM employee_directory")
            row = await cursor.fetchone()
            return row[0]

    count = _with_test_db(_run)
    assert count >= 10, f"Expected >= 10 employees, got {count}"


def test_seed_creates_corporate_cards():
    """Seed data inserts at least 5 corporate cards."""
    from db.seed_data import seed_data

    async def _run():
        await seed_data()
        async with aiosqlite.connect(TEST_DB) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM corporate_cards")
            row = await cursor.fetchone()
            return row[0]

    count = _with_test_db(_run)
    assert count >= 5, f"Expected >= 5 corporate cards, got {count}"


def test_seed_creates_api_credentials():
    """Seed data inserts at least 4 API credentials."""
    from db.seed_data import seed_data

    async def _run():
        await seed_data()
        async with aiosqlite.connect(TEST_DB) as db:
            cursor = await db.execute("SELECT COUNT(*) FROM api_credentials")
            row = await cursor.fetchone()
            return row[0]

    count = _with_test_db(_run)
    assert count >= 4, f"Expected >= 4 API credentials, got {count}"


def test_seed_creates_default_config():
    """Seed data inserts a default agent_config with security_level=standard."""
    from db.seed_data import seed_data

    async def _run():
        await seed_data()
        async with aiosqlite.connect(TEST_DB) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM agent_config WHERE id = 1"
            )
            row = await cursor.fetchone()
            return row

    row = _with_test_db(_run)
    assert row is not None, "No agent_config row with id=1"
    assert row["security_level"] == "standard", (
        f"Expected security_level='standard', got '{row['security_level']}'"
    )


def test_seed_is_idempotent():
    """Running seed_data twice does not double the row counts."""
    from db.seed_data import seed_data

    async def _run():
        await seed_data()
        await seed_data()
        async with aiosqlite.connect(TEST_DB) as db:
            counts = {}
            for table in [
                "employee_directory",
                "corporate_cards",
                "api_credentials",
                "policy_rules",
            ]:
                cursor = await db.execute(f"SELECT COUNT(*) FROM {table}")
                row = await cursor.fetchone()
                counts[table] = row[0]
            return counts

    counts = _with_test_db(_run)
    assert counts["employee_directory"] == 10, (
        f"Expected exactly 10 employees after double seed, got {counts['employee_directory']}"
    )
    assert counts["corporate_cards"] == 5, (
        f"Expected exactly 5 cards after double seed, got {counts['corporate_cards']}"
    )
    assert counts["api_credentials"] == 4, (
        f"Expected exactly 4 credentials after double seed, got {counts['api_credentials']}"
    )
    assert counts["policy_rules"] == 8, (
        f"Expected exactly 8 policy rules after double seed, got {counts['policy_rules']}"
    )


def test_seed_employee_has_card_link():
    """CEO's corporate_card_id references a real corporate_cards row."""
    from db.seed_data import seed_data

    async def _run():
        await seed_data()
        async with aiosqlite.connect(TEST_DB) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT corporate_card_id FROM employee_directory WHERE id = 'emp-001'"
            )
            emp = await cursor.fetchone()
            if emp is None:
                return None, None
            card_id = emp["corporate_card_id"]
            cursor = await db.execute(
                "SELECT * FROM corporate_cards WHERE id = ?", (card_id,)
            )
            card = await cursor.fetchone()
            return card_id, card

    card_id, card = _with_test_db(_run)
    assert card_id is not None, "CEO (emp-001) has no corporate_card_id"
    assert card is not None, f"corporate_card_id '{card_id}' does not reference a real card"
    assert card["cardholder_name"] == "Michael Zhang", (
        f"Expected CEO card to belong to Michael Zhang, got '{card['cardholder_name']}'"
    )


def test_seed_returns_counts():
    """seed_data() returns a dict with counts per table."""
    from db.connection import init_db
    from db.seed_data import seed_data

    async def _run():
        await init_db()
        return await seed_data()

    # Use a fresh DB for this test
    fresh_db = Path(__file__).parent / "test_seed_counts.db"
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = fresh_db
    try:
        if fresh_db.exists():
            fresh_db.unlink()
        result = asyncio.run(_run())
    finally:
        conn.DB_PATH = original
        if fresh_db.exists():
            fresh_db.unlink()

    assert isinstance(result, dict), f"Expected dict, got {type(result)}"
    assert result.get("employee_directory") == 10
    assert result.get("corporate_cards") == 5
    assert result.get("api_credentials") == 4
    assert result.get("policy_rules") == 8
    assert result.get("agent_config") == 1
