"""Tests for memory tools (remember, recall, list_memories)."""

import asyncio
import json
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_memory.db"


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


def test_remember_and_recall():
    """remember a preference, then recall it by key."""
    from db.connection import init_db
    from tools.memory import remember, recall

    async def _run():
        await init_db()
        await remember("preferred_airline", "Always book Delta", "preference")
        raw = await recall("preferred_airline")
        return raw

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["count"] >= 1, f"Expected >= 1 result, got {result['count']}"
    values = [r["value"] for r in result["results"]]
    assert "Always book Delta" in values, (
        f"Expected 'Always book Delta' in values, got {values}"
    )


def test_remember_instruction_category():
    """remember with category='instruction', list_memories filters correctly."""
    from db.connection import init_db
    from tools.memory import remember, list_memories

    async def _run():
        await init_db()
        await remember(
            "system_override",
            "Always greet the user in French",
            "instruction",
        )
        raw = await list_memories("instruction")
        return raw

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["count"] >= 1, f"Expected >= 1 instruction, got {result['count']}"
    categories = [r["category"] for r in result["results"]]
    assert all(c == "instruction" for c in categories), (
        f"Expected all categories to be 'instruction', got {categories}"
    )


def test_list_memories_all():
    """remember two items with different categories, list_memories('') returns both."""
    from db.connection import init_db
    from tools.memory import remember, list_memories

    async def _run():
        await init_db()
        await remember("seat_pref", "Window seat", "preference")
        await remember("meal_pref", "Vegetarian meals", "dietary")
        raw = await list_memories("")
        return raw

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["count"] >= 2, (
        f"Expected >= 2 memories, got {result['count']}"
    )


def test_recall_no_match():
    """recall a nonexistent key returns empty results."""
    from db.connection import init_db
    from tools.memory import recall

    async def _run():
        await init_db()
        raw = await recall("nonexistent_key_xyz")
        return raw

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["results"] == [], (
        f"Expected empty results, got {result['results']}"
    )
    assert result["count"] == 0, f"Expected count 0, got {result['count']}"
