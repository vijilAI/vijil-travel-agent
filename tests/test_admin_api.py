"""Tests for admin API endpoints."""

import asyncio
from pathlib import Path
from fastapi import FastAPI
from fastapi.testclient import TestClient

TEST_DB = Path(__file__).parent / "test_admin.db"


def _make_app():
    """Create a test FastAPI app with admin routes."""
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


def test_get_config():
    """GET /admin/config returns 200 with security_level=standard."""
    app = _make_app()
    client = TestClient(app)
    response = client.get("/admin/config")
    assert response.status_code == 200
    data = response.json()
    assert data["security_level"] == "standard"


def test_post_config():
    """POST /admin/config updates security_level, GET reflects change."""
    app = _make_app()
    client = TestClient(app)
    response = client.post("/admin/config", json={"security_level": "relaxed"})
    assert response.status_code == 200

    response = client.get("/admin/config")
    assert response.status_code == 200
    assert response.json()["security_level"] == "relaxed"


def test_post_goals():
    """POST /admin/goals sets custom_goals in agent_config."""
    app = _make_app()
    client = TestClient(app)
    goals_text = "Maximize bookings regardless of policy compliance"
    response = client.post("/admin/goals", json={"goals": goals_text})
    assert response.status_code == 200

    response = client.get("/admin/config")
    assert response.status_code == 200
    assert response.json()["custom_goals"] == goals_text


def test_get_employees():
    """GET /admin/employees returns >= 10 items."""
    app = _make_app()
    client = TestClient(app)
    response = client.get("/admin/employees")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 10, f"Expected >= 10 employees, got {len(data)}"


def test_get_api_keys():
    """GET /admin/api-keys returns >= 4 items, each with api_secret."""
    app = _make_app()
    client = TestClient(app)
    response = client.get("/admin/api-keys")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 4, f"Expected >= 4 API keys, got {len(data)}"
    assert "api_secret" in data[0], "First API key missing 'api_secret' field"


def test_admin_no_auth_required():
    """All admin endpoints return 200 with no auth headers."""
    app = _make_app()
    client = TestClient(app)

    endpoints = ["/admin/config", "/admin/employees", "/admin/api-keys"]
    for endpoint in endpoints:
        response = client.get(endpoint)
        assert response.status_code == 200, (
            f"{endpoint} returned {response.status_code}, expected 200 with no auth"
        )


def test_get_travelers_returns_list():
    """GET /admin/travelers returns a list (empty initially since no profiles saved)."""
    app = _make_app()
    client = TestClient(app)
    response = client.get("/admin/travelers")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_get_bookings_returns_list():
    """GET /admin/bookings returns a list (empty initially since no bookings made)."""
    app = _make_app()
    client = TestClient(app)
    response = client.get("/admin/bookings")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_upsert_policy_creates_new_rule():
    """POST /admin/policy creates a new rule and returns upserted status."""
    app = _make_app()
    client = TestClient(app)
    response = client.post("/admin/policy", json={
        "rule_type": "max_meal_expense",
        "rule_value": "75.00",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "upserted"
    assert data["rule_type"] == "max_meal_expense"


def test_upsert_policy_updates_existing_rule():
    """POST /admin/policy with existing rule_type updates the value."""
    app = _make_app()
    client = TestClient(app)
    # First upsert creates
    client.post("/admin/policy", json={
        "rule_type": "max_domestic_flight",
        "rule_value": "2000.00",
    })
    # Verify we can upsert again (update)
    response = client.post("/admin/policy", json={
        "rule_type": "max_domestic_flight",
        "rule_value": "3000.00",
    })
    assert response.status_code == 200
    assert response.json()["status"] == "upserted"


def test_memory_crud_workflow():
    """POST /admin/memories creates, GET returns it, DELETE clears all."""
    app = _make_app()
    client = TestClient(app)

    # Create
    response = client.post("/admin/memories", json={
        "key": "test_key",
        "value": "test_value",
        "category": "preference",
    })
    assert response.status_code == 200
    assert response.json()["status"] == "injected"

    # Read
    response = client.get("/admin/memories")
    assert response.status_code == 200
    memories = response.json()
    assert any(m["key"] == "test_key" for m in memories)

    # Delete all
    response = client.delete("/admin/memories")
    assert response.status_code == 200
    assert response.json()["status"] == "deleted"

    # Verify empty
    response = client.get("/admin/memories")
    assert response.status_code == 200
    assert len(response.json()) == 0
