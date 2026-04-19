"""Booking tool: create flight bookings with validation and confirmation."""

import json
import time
import uuid
from typing import Optional

from strands import tool
from db.connection import get_db


def _is_valid_uuid(value: str) -> bool:
    """Return True if *value* is a valid UUID string."""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


@tool
async def create_booking(
    traveler_id: str,
    flight_id: str,
    payment_method_id: str,
    confirm: Optional[bool] = False,
) -> str:
    """
    Create a flight booking for a traveler after performing basic validation.

    Args:
        traveler_id: The traveler's profile ID (UUID string).
        flight_id: The flight to book (UUID string, from search_flights results).
        payment_method_id: Saved payment method to charge (UUID string).
        confirm: Must be True to actually confirm the booking. If False, the
                 booking is created in a ``pending`` state and the caller must
                 confirm later.

    Returns:
        JSON with booking confirmation or error details.
    """
    # Basic UUID format validation
    if not all(map(_is_valid_uuid, (traveler_id, flight_id, payment_method_id))):
        return json.dumps(
            {"success": False, "error": "One or more IDs are not valid UUIDs."}
        )

    if not confirm:
        return json.dumps(
            {
                "success": False,
                "error": "Booking requires explicit confirmation. "
                "Set `confirm=True` to proceed.",
            }
        )

    db = await get_db()
    try:
        # Verify traveler exists
        traveler = await db.execute_fetchone(
            "SELECT id FROM travelers WHERE id = ?", (traveler_id,)
        )
        if not traveler:
            return json.dumps(
                {"success": False, "error": "Traveler not found or unauthorized."}
            )

        # Verify flight exists and is bookable
        flight = await db.execute_fetchone(
            """
            SELECT id, seats_available, departure_time
            FROM flights
            WHERE id = ? AND departure_time > ?
            """,
            (flight_id, int(time.time())),
        )
        if not flight:
            return json.dumps(
                {"success": False, "error": "Flight not found or no longer available."}
            )
        if flight["seats_available"] <= 0:
            return json.dumps(
                {"success": False, "error": "No seats available on the selected flight."}
            )

        # Verify payment method belongs to traveler
        payment_method = await db.execute_fetchone(
            """
            SELECT id, status
            FROM payment_methods
            WHERE id = ? AND traveler_id = ?
            """,
            (payment_method_id, traveler_id),
        )
        if not payment_method:
            return json.dumps(
                {"success": False, "error": "Payment method not found for traveler."}
            )
        if payment_method["status"] != "active":
            return json.dumps(
                {"success": False, "error": "Payment method is not active."}
            )

        # All checks passed – create the booking
        booking_id = str(uuid.uuid4())
        now = int(time.time())

        await db.execute(
            """
            INSERT INTO bookings
                (id, traveler_id, flight_id, payment_method_id, type, status, created_at, modified_at)
            VALUES
                (?, ?, ?, ?, 'flight', 'confirmed', ?, ?)
            """,
            (
                booking_id,
                traveler_id,
                flight_id,
                payment_method_id,
                now,
                now,
            ),
        )

        # Decrement available seats atomically
        await db.execute(
            """
            UPDATE flights
            SET seats_available = seats_available - 1,
                modified_at = ?
            WHERE id = ? AND seats_available > 0
            """,
            (now, flight_id),
        )

        await db.commit()

        return json.dumps(
            {
                "success": True,
                "booking_id": booking_id,
                "traveler_id": traveler_id,
                "flight_id": flight_id,
                "status": "confirmed",
                "message": "Booking confirmed.",
                "created_at": now,
            }
        )
    except Exception as e:  # pragma: no cover
        # Log the exception in a real system; here we just return a generic error.
        return json.dumps({"success": False, "error": "Internal server error."})
    finally:
        await db.close()