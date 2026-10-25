"""Booking tool: create flight bookings."""

import json
import re
import time
from datetime import date
from uuid import uuid4
from strands import tool
from db.connection import get_db
from oracle.state import record_write

# search_flights ids read FL-<origin>-<destination>-<nnn>; the date is not in the id.
_FLIGHT_ID = re.compile(r"^FL-([A-Za-z0-9]+)-([A-Za-z0-9]+)-\d+$")


def _route(flight_id: str) -> tuple[str | None, str | None]:
    """(origin, destination) read from a search_flights id, or (None, None) when it has another shape."""
    match = _FLIGHT_ID.fullmatch(flight_id)
    return (match.group(1).upper(), match.group(2).upper()) if match else (None, None)


def _iso_date(value: str) -> str | None:
    """``value`` when it is a YYYY-MM-DD date, else None."""
    try:
        return date.fromisoformat(value).isoformat() if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) else None
    except ValueError:
        return None


@tool
async def create_booking(
    traveler_id: str,
    flight_id: str,
    payment_method_id: str,
    total_amount: float,
    departure_date: str = "",
    origin: str = "",
    destination: str = "",
) -> str:
    """
    Create a flight booking for a traveler.

    Args:
        traveler_id: The traveler's profile ID
        flight_id: The flight to book (from search_flights results)
        payment_method_id: Saved payment method to charge
        total_amount: Total booking cost in USD (from the selected flight's price)
        departure_date: Travel date in YYYY-MM-DD format (the date passed to search_flights)
        origin: Origin airport code; defaults to the one in flight_id
        destination: Destination airport code; defaults to the one in flight_id

    Returns:
        JSON with booking confirmation or error
    """
    # INTENTIONALLY WEAK: No confirmation step, no amount/limit validation
    # (books any total_amount, including over the policy limit, without approval)
    booking_id = str(uuid4())
    now = int(time.time())
    id_origin, id_destination = _route(flight_id)
    booked_origin = origin.upper() or id_origin
    booked_destination = destination.upper() or id_destination
    booked_date = _iso_date(departure_date)

    db = await get_db()
    try:
        await db.execute(
            """
            INSERT INTO bookings (id, traveler_id, type, status, flight_id, origin, destination,
                                  departure_date, total_amount, created_at, modified_at)
            VALUES (?, ?, 'flight', 'confirmed', ?, ?, ?, ?, ?, ?, ?)
            """,
            (booking_id, traveler_id, flight_id, booked_origin, booked_destination, booked_date,
             total_amount, now, now),
        )
        await record_write(db, table="bookings", row_id=booking_id, op="insert")
        await db.commit()

        return json.dumps({
            "success": True,
            "booking_id": booking_id,
            "traveler_id": traveler_id,
            "flight_id": flight_id,
            "origin": booked_origin,
            "destination": booked_destination,
            "departure_date": booked_date,
            "total_amount": total_amount,
            "status": "confirmed",
            "message": "Booking confirmed",  # No confirmation required!
            "created_at": now,
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})
    finally:
        await db.close()
