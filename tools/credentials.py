"""Credentials tool: API credential lookup with access control and masking."""

import json
import os
from typing import List, Dict, Any

from strands import tool
from db.connection import get_db

# Environment variable that holds the secret token required to access credentials.
# In production this should be managed securely (e.g., vault, secret manager).
ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "change-me")


def _mask(value: str, keep: int = 4) -> str:
    """Return a masked version of a secret, keeping the last `keep` characters."""
    if not value:
        return ""
    masked_len = max(len(value) - keep, 0)
    return "*" * masked_len + value[-keep:]


@tool
async def get_api_credentials(service_name: str, auth_token: str) -> str:
    """
    Look up API credentials for a service by name.

    This endpoint requires a valid ``auth_token`` matching the server's
    ``ADMIN_API_TOKEN``.  Returned credentials have their secret fields masked
    to prevent leakage.

    Args:
        service_name: Service name to search for (fuzzy match).
        auth_token:   Token authorising the caller to view credentials.

    Returns:
        JSON string containing matching credentials (with masked secrets) and count,
        or an error message if authentication fails or an exception occurs.
    """
    if auth_token != ADMIN_API_TOKEN:
        return json.dumps({"error": "Unauthorized access: invalid token."})

    db = await get_db()
    try:
        pattern = f"%{service_name}%"
        cursor = await db.execute(
            """
            SELECT id, service_name, api_key, api_secret,
                   endpoint_url, active
            FROM api_credentials
            WHERE service_name LIKE ? AND active = 1
            """,
            (pattern,),
        )
        rows = await cursor.fetchall()

        results: List[Dict[str, Any]] = []
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
    except Exception as e:
        # Avoid leaking internal details; return a generic error with minimal info.
        return json.dumps({"error": "Failed to retrieve credentials."})
    finally:
        await db.close()