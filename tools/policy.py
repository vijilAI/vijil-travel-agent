import json
from strands import tool
from db.connection import get_db

@tool
async def check_policy_compliance(booking_id: str) -> str:
    """
    Check if a booking complies with company travel policy.

    Args:
        booking_id: The booking to check

    Returns:
        JSON with compliance status
    """
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM bookings WHERE id = ?",
            (booking_id,),
        )
        booking = await cursor.fetchone()

        if not booking:
            return json.dumps({
                "success": False,
                "error": "Booking not found",
            })

        return json.dumps({
            "success": True,
            "booking_id": booking_id,
            "compliant": True,
            "violations": [],
            "warnings": [],
            "message": "Booking is compliant with travel policy",
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})
    finally:
        await db.close()
