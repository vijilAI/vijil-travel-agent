"""End-to-end oracle check for the travel agent's admin_http probes.

Drives the real routes/admin.py router (mounted on a FastAPI TestClient, backed
by a temp seeded SQLite DB) through the admin_http probes and scores with the
oracle -- proving TA-SEC-02 (unauth /admin/api-keys dump, admin_key canary) and
TA-SEC-03 (unauth /admin/goals injection) fire against real code, no model.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

fastapi = pytest.importorskip("fastapi")
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from oracle.canary import token  # noqa: E402
from oracle.checker import score_registry  # noqa: E402
from oracle.probe_runner import run_registry  # noqa: E402
from oracle.registry import AgentRegistry  # noqa: E402

_REGISTRY = os.path.join(os.path.dirname(os.path.dirname(__file__)), "vulnerabilities.yaml")


class AdminHttpTransport:
    def __init__(self, client: TestClient):
        self._client = client

    async def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        return ""

    async def admin(self, method: str, path: str, body: dict | None) -> tuple[int, str]:
        resp = self._client.request(method, path, json=body)
        return resp.status_code, resp.text


def _seeded_client(monkeypatch) -> TestClient:
    import db.connection as conn
    import db.seed_data as seed

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False).name
    monkeypatch.setattr(conn, "DB_PATH", Path(tmp))

    async def _prep():
        await conn.init_db()
        await seed.seed_data()

    asyncio.run(_prep())
    app = FastAPI()
    from routes.admin import router as admin_router

    app.include_router(admin_router)
    return TestClient(app)


def test_travel_admin_channel_vulns_fire(monkeypatch):
    client = _seeded_client(monkeypatch)
    registry = AgentRegistry.from_yaml(_REGISTRY)
    # Score only the admin_http probes against the real router.
    admin_reg = registry.model_copy(
        update={
            "vulnerabilities": [
                v for v in registry.vulnerabilities if v.id in ("TA-SEC-02", "TA-SEC-03")
            ]
        }
    )
    transcripts = asyncio.run(run_registry(admin_reg, AdminHttpTransport(client)))
    report = score_registry(admin_reg, transcripts)
    results = {r.vuln_id: r.disclosed for r in report.results}
    assert results["TA-SEC-02"] is True, "unauth /admin/api-keys dump did not fire"
    assert results["TA-SEC-03"] is True, "unauth /admin/goals injection did not fire"


def test_travel_api_keys_leaks_admin_canary(monkeypatch):
    client = _seeded_client(monkeypatch)
    resp = client.get("/admin/api-keys")
    assert resp.status_code == 200
    assert token("vijil_travel_agent", "TA-SEC-02", "admin_key") in resp.text
