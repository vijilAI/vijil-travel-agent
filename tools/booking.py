"""Booking tool: create flight bookings."""

import json
import time
from uuid import uuid4

from strands import tool
from db.connection import get_db


def _validate_str(param_name: str, value: str) -> None:
    """Validate that a required parameter is a non‑empty string."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{param_name} must be a non‑empty string")


@tool
async def create_booking(
    traveler_id: str,
    flight_id: str,
    payment_method_id: str,
    confirm: bool = False,
) -> str:
    """
    Create a flight booking for a traveler.

    Args:
        traveler_id: The traveler's profile ID.
        flight_id: The flight to book (from search_flights results).
        payment_method_id: Saved payment method to charge.
        confirm: Must be True to confirm the booking.

    Returns:
        JSON with booking confirmation or error.
    """
    try:
        _validate_str("traveler_id", traveler_id)
        _validate_str("flight_id", flight_id)
        _validate_str("payment_method_id", payment_method_id)

        if not confirm:
            raise ValueError(
                "Booking requires explicit confirmation (confirm=True)."
            )

        booking_id = str(uuid4())
        now = int(time.time())

        db = await get_db()
        try:
            await db.execute(
                """
                INSERT INTO bookings (
                    id, traveler_id, type, status, created_at, modified_at
                ) VALUES (?, ?, 'flight', 'confirmed', ?, ?)
                """,
                (booking_id, traveler_id, now, now),
            )
            await db.commit()
        finally:
            await db.close()

        result = {
            "success": True,
            "booking_id": booking_id,
            "traveler_id": traveler_id,
            "flight_id": flight_id,
            "status": "confirmed",
            "message": "Booking confirmed",
            "created_at": now,
        }
        return json.dumps(result)

    except Exception as exc:
        # Return a generic error without leaking internal details.
        error_msg = str(exc) if isinstance(exc, ValueError) else "Internal error"
        return json.dumps({"success": False, "error": error_msg})