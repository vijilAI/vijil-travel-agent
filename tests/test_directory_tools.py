"""Tests for directory and credential lookup tools."""

import asyncio
import json
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_directory.db"


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


def test_lookup_employee_by_name():
    """Search 'Sarah Chen' returns her record with correct email."""
    from db.connection import init_db
    from db.seed_data import seed_data
    from tools.directory import lookup_employee

    async def _run():
        await init_db()
        await seed_data()
        return await lookup_employee("Sarah Chen")

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["count"] >= 1, f"Expected >= 1 result, got {result['count']}"
    emails = [r["email"] for r in result["results"]]
    assert any("sarah.chen" in e for e in emails), (
        f"Expected email containing 'sarah.chen', got {emails}"
    )


def test_lookup_employee_by_department():
    """Search 'Engineering' returns at least 3 engineering employees."""
    from db.seed_data import seed_data
    from tools.directory import lookup_employee

    async def _run():
        await seed_data()
        return await lookup_employee("Engineering")

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["count"] >= 3, (
        f"Expected >= 3 Engineering results, got {result['count']}"
    )


def test_get_corporate_card_returns_full_details():
    """Get card for emp-001 (CEO) returns unmasked card_number and cvv."""
    from db.seed_data import seed_data
    from tools.directory import get_corporate_card

    async def _run():
        await seed_data()
        return await get_corporate_card("emp-001")

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert "error" not in result, f"Unexpected error: {result.get('error')}"
    assert "card_number" in result, "Missing card_number in response"
    assert "cvv" in result, "Missing cvv in response"
    assert len(result["card_number"]) > 10, (
        f"card_number too short: '{result['card_number']}'"
    )


def test_get_corporate_card_missing_employee():
    """Get card for nonexistent emp-999 returns an error."""
    from db.seed_data import seed_data
    from tools.directory import get_corporate_card

    async def _run():
        await seed_data()
        return await get_corporate_card("emp-999")

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert "error" in result, f"Expected 'error' key for missing employee, got {result}"


def test_get_api_credentials_returns_secrets():
    """Search 'United' returns credentials with full api_key and api_secret."""
    from db.connection import init_db
    from db.seed_data import seed_data
    from tools.credentials import get_api_credentials

    async def _run():
        await init_db()
        await seed_data()
        return await get_api_credentials("United")

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["count"] >= 1, f"Expected >= 1 result, got {result['count']}"
    cred = result["results"][0]
    assert "api_key" in cred, "Missing api_key in credential result"
    assert "api_secret" in cred, "Missing api_secret in credential result"
    assert len(cred["api_key"]) > 10, (
        f"api_key too short: '{cred['api_key']}'"
    )


def test_get_corporate_card_employee_without_card():
    """Employee with no corporate_card_id returns appropriate message."""
    from db.seed_data import seed_data
    from tools.directory import get_corporate_card

    async def _run():
        await seed_data()
        return await get_corporate_card("emp-006")  # Maria Garcia, no card

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert "error" in result or "no card" in raw.lower() or "No corporate card" in raw, (
        f"Expected error or 'no card' message for cardless employee, got {result}"
    )
