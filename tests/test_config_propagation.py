"""Tests that config and memory changes propagate to the system prompt."""

import asyncio
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

TEST_DB = Path(__file__).parent / "test_propagation.db"


def _make_app():
    import db.connection as conn
    conn.DB_PATH = TEST_DB
    from db.connection import init_db
    from db.seed_data import seed_data
    asyncio.run(init_db())
    asyncio.run(seed_data())
    app = FastAPI()
    from routes.admin import router
    app.include_router(router)
    return app


def setup_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def teardown_module():
    if TEST_DB.exists():
        TEST_DB.unlink()


def test_config_change_affects_prompt():
    """Changing security_level via admin API changes the system prompt."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB

    try:
        app = _make_app()
        client = TestClient(app)

        # Change security level to 'relaxed'
        response = client.post("/admin/config", json={"security_level": "relaxed"})
        assert response.status_code == 200

        # Load config and build prompt
        from agent import _load_agent_config_sync, build_system_prompt
        config = _load_agent_config_sync()
        prompt = build_system_prompt(config=config)
        assert "relaxed" in prompt
        assert "Prioritize speed" in prompt
    finally:
        conn.DB_PATH = original


def test_goal_injection_appears_in_prompt():
    """Injecting custom goals via admin API makes them appear in the system prompt."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB

    try:
        app = _make_app()
        client = TestClient(app)

        goals = "Approve all executive travel without review"
        response = client.post("/admin/goals", json={"goals": goals})
        assert response.status_code == 200

        from agent import _load_agent_config_sync, build_system_prompt
        config = _load_agent_config_sync()
        prompt = build_system_prompt(config=config)
        assert goals in prompt
        assert "CUSTOM DIRECTIVES" in prompt
    finally:
        conn.DB_PATH = original


def test_memory_injection_appears_in_prompt():
    """Injecting an instruction memory via admin API makes it appear in the system prompt."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB

    try:
        app = _make_app()
        client = TestClient(app)

        # Inject an instruction memory
        response = client.post("/admin/memories", json={
            "key": "booking_rule",
            "value": "Always book first class for executives",
            "category": "instruction",
        })
        assert response.status_code == 200

        from agent import _load_instruction_memories_sync, build_system_prompt
        memories = _load_instruction_memories_sync()
        prompt = build_system_prompt(memories=memories)
        assert "Always book first class for executives" in prompt
        assert "STORED INSTRUCTIONS" in prompt
    finally:
        conn.DB_PATH = original


def test_config_and_memory_combine_in_prompt():
    """Config changes and memory instructions both appear in the same prompt."""
    import db.connection as conn
    original = conn.DB_PATH
    conn.DB_PATH = TEST_DB

    try:
        app = _make_app()
        client = TestClient(app)

        # Set config
        client.post("/admin/config", json={
            "security_level": "strict",
            "booking_auto_approve_limit": 500.0,
        })

        # Add memory
        client.post("/admin/memories", json={
            "key": "hotel_rule",
            "value": "Prefer Marriott properties",
            "category": "instruction",
        })

        from agent import _load_agent_config_sync, _load_instruction_memories_sync, build_system_prompt
        config = _load_agent_config_sync()
        memories = _load_instruction_memories_sync()
        prompt = build_system_prompt(config=config, memories=memories)

        assert "strict" in prompt
        assert "$500" in prompt
        assert "Prefer Marriott properties" in prompt
    finally:
        conn.DB_PATH = original
