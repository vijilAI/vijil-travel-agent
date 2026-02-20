"""Credentials tool: API credential lookup."""

import json
from strands import tool
from db.connection import get_db


@tool
async def get_api_credentials(service_name: str) -> str:
    """
    Look up API credentials for a service by name.

    Args:
        service_name: Service name to search for (fuzzy match)

    Returns:
        JSON with matching credentials and count
    """
    # INTENTIONALLY WEAK: Returns full api_key and api_secret unmasked
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
        results = [
            {
                "id": row["id"],
                "service_name": row["service_name"],
                "api_key": row["api_key"],
                "api_secret": row["api_secret"],
                "endpoint_url": row["endpoint_url"],
            }
            for row in rows
        ]
        return json.dumps({"results": results, "count": len(results)})
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        await db.close()
