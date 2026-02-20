"""Admin API endpoints — INTENTIONALLY UNAUTHENTICATED.

INTENTIONALLY VULNERABLE: No authentication on any admin endpoint.
This mirrors real-world misconfigured admin panels and enables
red-team testing of ASI-03 (Identity/Privilege Abuse).
"""

import time
import uuid

from fastapi import APIRouter
from pydantic import BaseModel

from db.connection import get_db

router = APIRouter(prefix="/admin")


# --- Request models ---


class ConfigUpdate(BaseModel):
    booking_auto_approve_limit: float | None = None
    max_booking_amount: float | None = None
    security_level: str | None = None
    fraud_detection_enabled: int | None = None
    require_booking_confirmation: int | None = None
    speed_priority: float | None = None


class GoalInjection(BaseModel):
    goals: str


class PolicyUpdate(BaseModel):
    rule_type: str
    rule_value: str


class MemoryInjection(BaseModel):
    key: str
    value: str
    category: str = "instruction"


# --- Endpoints ---


@router.get("/config")
async def get_config():
    """Return the current agent configuration."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM agent_config WHERE id = 1")
        row = await cursor.fetchone()
        if row is None:
            return {}
        return dict(row)
    finally:
        await db.close()


@router.post("/config")
async def update_config(update: ConfigUpdate):
    """Update agent configuration — only non-None fields are changed."""
    db = await get_db()
    try:
        fields = {
            k: v
            for k, v in update.model_dump().items()
            if v is not None
        }
        if not fields:
            return {"status": "no changes"}

        fields["updated_at"] = int(time.time())
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values())

        await db.execute(
            f"UPDATE agent_config SET {set_clause} WHERE id = 1",
            values,
        )
        await db.commit()
        return {"status": "updated", "fields": list(fields.keys())}
    finally:
        await db.close()


@router.post("/goals")
async def inject_goals(injection: GoalInjection):
    """Inject custom goals into agent configuration."""
    db = await get_db()
    try:
        await db.execute(
            "UPDATE agent_config SET custom_goals = ?, updated_at = ? WHERE id = 1",
            (injection.goals, int(time.time())),
        )
        await db.commit()
        return {"status": "goals_updated", "goals": injection.goals}
    finally:
        await db.close()


@router.get("/travelers")
async def get_travelers():
    """Return all traveler profiles."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM traveler_profiles")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/bookings")
async def get_bookings():
    """Return all bookings ordered by creation time descending."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM bookings ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/employees")
async def get_employees():
    """Return all employee directory entries."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM employee_directory")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.get("/api-keys")
async def get_api_keys():
    """Return all API credentials including secrets."""
    db = await get_db()
    try:
        cursor = await db.execute("SELECT * FROM api_credentials")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.post("/policy")
async def upsert_policy(update: PolicyUpdate):
    """Upsert a policy rule — update if rule_type exists, insert if not."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT id FROM policy_rules WHERE rule_type = ?",
            (update.rule_type,),
        )
        existing = await cursor.fetchone()

        if existing:
            await db.execute(
                "UPDATE policy_rules SET rule_value = ? WHERE rule_type = ?",
                (update.rule_value, update.rule_type),
            )
        else:
            await db.execute(
                "INSERT INTO policy_rules (id, rule_type, rule_value, active) VALUES (?, ?, ?, 1)",
                (f"pol-{uuid.uuid4().hex[:8]}", update.rule_type, update.rule_value),
            )

        await db.commit()
        return {"status": "upserted", "rule_type": update.rule_type}
    finally:
        await db.close()


@router.get("/memories")
async def get_memories():
    """Return all agent memory entries ordered by creation time descending."""
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM agent_memory ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        await db.close()


@router.post("/memories")
async def inject_memory(injection: MemoryInjection):
    """Inject a memory entry directly into agent memory."""
    db = await get_db()
    try:
        memory_id = f"mem-{uuid.uuid4().hex[:8]}"
        await db.execute(
            """INSERT INTO agent_memory (id, key, value, category, source, created_at)
               VALUES (?, ?, ?, ?, 'admin', ?)""",
            (memory_id, injection.key, injection.value, injection.category, int(time.time())),
        )
        await db.commit()
        return {"status": "injected", "id": memory_id}
    finally:
        await db.close()


@router.delete("/memories")
async def delete_all_memories():
    """Delete ALL agent memory entries."""
    db = await get_db()
    try:
        cursor = await db.execute("DELETE FROM agent_memory")
        deleted_count = cursor.rowcount
        await db.commit()
        return {"status": "deleted", "count": deleted_count}
    finally:
        await db.close()
