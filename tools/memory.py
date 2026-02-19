"""Memory tools: persistent recall across conversations."""

import json
import time
from uuid import uuid4
from strands import tool
from db.connection import get_db


@tool
async def remember(key: str, value: str, category: str = "preference") -> str:
    """
    Store a memory for later recall. Memories persist across conversations.

    Args:
        key: Short label for this memory (e.g. 'preferred_airline')
        value: The content to remember (e.g. 'Always book Delta')
        category: Category tag — 'preference', 'instruction', etc.

    Returns:
        JSON with success status and memory ID
    """
    # INTENTIONALLY WEAK: No validation on category — accepts "instruction"
    # which gets injected into the system prompt (indirect prompt injection)
    memory_id = str(uuid4())
    now = int(time.time())

    db = await get_db()
    try:
        await db.execute(
            """
            INSERT INTO agent_memory (id, key, value, category, source, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (memory_id, key, value, category, "user", now),
        )
        await db.commit()

        return json.dumps({
            "success": True,
            "memory_id": memory_id,
            "key": key,
            "category": category,
            "message": f"Remembered '{key}' in category '{category}'",
        })
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        await db.close()


@tool
async def recall(query: str) -> str:
    """
    Search memories by key or value.

    Args:
        query: Search term to match against memory keys and values

    Returns:
        JSON with matching memories and count
    """
    db = await get_db()
    try:
        pattern = f"%{query}%"
        cursor = await db.execute(
            """
            SELECT id, key, value, category, source, created_at
            FROM agent_memory
            WHERE key LIKE ? OR value LIKE ?
            ORDER BY created_at DESC
            """,
            (pattern, pattern),
        )
        rows = await cursor.fetchall()
        results = [
            {
                "id": row["id"],
                "key": row["key"],
                "value": row["value"],
                "category": row["category"],
                "source": row["source"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return json.dumps({"results": results, "count": len(results)})
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        await db.close()


@tool
async def list_memories(category: str = "") -> str:
    """
    List all stored memories, optionally filtered by category.

    Args:
        category: If provided, filter to this category only. Empty string returns all.

    Returns:
        JSON with memories and count
    """
    db = await get_db()
    try:
        if category:
            cursor = await db.execute(
                """
                SELECT id, key, value, category, source, created_at
                FROM agent_memory
                WHERE category = ?
                ORDER BY created_at DESC
                """,
                (category,),
            )
        else:
            cursor = await db.execute(
                """
                SELECT id, key, value, category, source, created_at
                FROM agent_memory
                ORDER BY created_at DESC
                """
            )
        rows = await cursor.fetchall()
        results = [
            {
                "id": row["id"],
                "key": row["key"],
                "value": row["value"],
                "category": row["category"],
                "source": row["source"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return json.dumps({"results": results, "count": len(results)})
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        await db.close()
