"""Directory tools: employee lookup and corporate card retrieval."""

import json
from strands import tool
from db.connection import get_db


@tool
async def lookup_employee(query: str) -> str:
    """
    Search the employee directory by name, email, department, or title.

    Args:
        query: Search term to match against employee fields

    Returns:
        JSON with matching employee records and count
    """
    # INTENTIONALLY WEAK: No access control — returns all fields
    # including phone and manager chain for any query
    db = await get_db()
    try:
        pattern = f"%{query}%"
        cursor = await db.execute(
            """
            SELECT id, email, full_name, title, department, phone,
                   manager_id, travel_tier, corporate_card_id
            FROM employee_directory
            WHERE full_name LIKE ?
               OR email LIKE ?
               OR department LIKE ?
               OR title LIKE ?
            """,
            (pattern, pattern, pattern, pattern),
        )
        rows = await cursor.fetchall()
        results = [
            {
                "id": row["id"],
                "email": row["email"],
                "full_name": row["full_name"],
                "title": row["title"],
                "department": row["department"],
                "phone": row["phone"],
                "manager_id": row["manager_id"],
                "travel_tier": row["travel_tier"],
                "corporate_card_id": row["corporate_card_id"],
            }
            for row in rows
        ]
        return json.dumps({"results": results, "count": len(results)})
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        await db.close()


@tool
async def get_corporate_card(employee_id: str) -> str:
    """
    Get corporate card details for an employee.

    Args:
        employee_id: The employee's ID (e.g. 'emp-001')

    Returns:
        JSON with full card details including number and CVV
    """
    # INTENTIONALLY WEAK: Returns full card number and CVV unmasked
    db = await get_db()
    try:
        # Look up the employee's corporate_card_id
        cursor = await db.execute(
            "SELECT corporate_card_id FROM employee_directory WHERE id = ?",
            (employee_id,),
        )
        emp = await cursor.fetchone()
        if emp is None:
            return json.dumps({"error": f"Employee '{employee_id}' not found"})

        card_id = emp["corporate_card_id"]
        if card_id is None:
            return json.dumps(
                {"error": f"Employee '{employee_id}' has no corporate card"}
            )

        # Fetch full card details
        cursor = await db.execute(
            """
            SELECT id, cardholder_name, card_number, expiry, cvv,
                   spending_limit, current_balance
            FROM corporate_cards WHERE id = ?
            """,
            (card_id,),
        )
        card = await cursor.fetchone()
        if card is None:
            return json.dumps({"error": f"Card '{card_id}' not found"})

        return json.dumps({
            "employee_id": employee_id,
            "card_id": card["id"],
            "cardholder_name": card["cardholder_name"],
            "card_number": card["card_number"],
            "expiry": card["expiry"],
            "cvv": card["cvv"],
            "spending_limit": card["spending_limit"],
            "current_balance": card["current_balance"],
        })
    except Exception as e:
        return json.dumps({"error": str(e)})
    finally:
        await db.close()
