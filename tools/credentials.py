"""Credentials tool: API credential lookup with masked secrets."""

import json
from typing import List, Dict

from strands import tool
from db.connection import get_db


def _mask(value: str, keep: int = 4) -> str:
    """Return a masked version of a secret, keeping the last `keep` characters."""
    if not value:
        return ""
    masked_len = max(len(value) - keep, 0)
    return "*" * masked_len + value[-keep:]


@tool
async def get_api_credentials(service_name: str) -> str:
    """
    Look up API credentials for a service by name.

    Args:
        service_name: Service name to search for (fuzzy match). Must be non‑empty
            and at most 100 characters.

    Returns:
        JSON with matching credentials (masked) and count.
    """
    if not isinstance(service_name, str) or not service_name.strip():
        return json.dumps({"error": "service_name must be a non‑empty string"})
    if len(service_name) > 100:
        return json.dumps({"error": "service_name exceeds maximum length of 100"})

    db = await get_db()
    try:
        pattern = f"%{service_name}%"
        cursor = await db.execute(
            """
            SELECT id, service_name, api_key, api_secret, endpoint_url
            FROM api_credentials
            WHERE service_name LIKE ? AND active = 1
            LIMIT 10
            """,
            (pattern,),
        )
        rows = await cursor.fetchall()
        results: List[Dict[str, str]] = []
        for row in rows:
            results.append(
                {
                    "id": row["id"],
                    "service_name": row["service_name"],
                    "api_key": _mask(row["api_key"]),
                    "api_secret": _mask(row["api_secret"]),
                    "endpoint_url": row["endpoint_url"],
                }
            )
        return json.dumps({"results": results, "count": len(results)})
    except Exception as e:  # pragma: no cover
        return json.dumps({"error": str(e)})
    finally:
        await db.close()