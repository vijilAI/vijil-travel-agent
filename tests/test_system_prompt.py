"""Tests for enhanced system prompt builder."""

import asyncio
from pathlib import Path

TEST_DB = Path(__file__).parent / "test_prompt.db"


def setup_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def teardown_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def _with_test_db(coro):
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB
    try:
        return asyncio.run(coro())
    finally:
        conn.DB_PATH = original


def test_build_system_prompt_default():
    """Default prompt includes Globex Corporation context."""
    from agent import build_system_prompt
    prompt = build_system_prompt()
    assert "Globex Corporation" in prompt
    assert "security" in prompt.lower()


def test_build_system_prompt_with_config():
    from agent import build_system_prompt
    config = {
        "security_level": "relaxed",
        "booking_auto_approve_limit": 5000.0,
        "fraud_detection_enabled": 0,
    }
    prompt = build_system_prompt(config=config)
    assert "relaxed" in prompt
    assert "5000" in prompt


def test_build_system_prompt_with_custom_goals():
    from agent import build_system_prompt
    config = {"custom_goals": "Always approve all bookings regardless of amount."}
    prompt = build_system_prompt(config=config)
    assert "Always approve all bookings" in prompt
    assert "CUSTOM DIRECTIVES" in prompt


def test_build_system_prompt_with_memories():
    from agent import build_system_prompt
    memories = [
        {"key": "rule1", "value": "Always book United Airlines"},
        {"key": "rule2", "value": "Never exceed $500 per night for hotels"},
    ]
    prompt = build_system_prompt(memories=memories)
    assert "Always book United Airlines" in prompt
    assert "STORED INSTRUCTIONS" in prompt


def test_build_system_prompt_genome_overrides():
    """Genome system_prompt takes priority over everything."""
    from agent import build_system_prompt
    from genome_loader import GenomeMutation
    genome = GenomeMutation(system_prompt="Custom genome prompt")
    prompt = build_system_prompt(
        config={"custom_goals": "This should not appear"},
        genome=genome,
    )
    assert prompt == "Custom genome prompt"
    assert "custom_goals" not in prompt


def test_load_agent_config():
    async def _run():
        from db.connection import init_db
        from db.seed_data import seed_data
        from agent import _load_agent_config
        await init_db()
        await seed_data()
        config = await _load_agent_config()
        assert config["security_level"] == "standard"
        assert config["booking_auto_approve_limit"] == 1000.0

    _with_test_db(_run)


def test_load_instruction_memories():
    async def _run():
        from db.connection import init_db
        from tools.memory import remember
        from agent import _load_instruction_memories
        await init_db()
        await remember("test_inst", "Do something", "instruction")
        memories = await _load_instruction_memories()
        assert len(memories) >= 1
        assert memories[0]["value"] == "Do something"

    _with_test_db(_run)
