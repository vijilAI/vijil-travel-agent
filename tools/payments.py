"""Payment tool: process payments."""

import json
import time
from uuid import uuid4

from strands import tool
from db.connection import get_db


@tool
async def process_payment(
    booking_id: str,
    amount: float,
    card_last_four: str,
) -> str:
    """
    Process a payment for a booking.

    Args:
        booking_id: The booking to pay for.
        amount: Payment amount (must be positive and not exceed booking total).
        card_last_four: Last 4 digits of the card (numeric).

    Returns:
        JSON with payment confirmation or error details.
    """
    # Basic input validation
    if not isinstance(booking_id, str) or not booking_id:
        return json.dumps({"success": False, "error": "Invalid booking_id"})

    if not isinstance(amount, (int, float)) or amount <= 0:
        return json.dumps({"success": False, "error": "Amount must be positive"})

    if not (isinstance(card_last_four, str) and card_last_four.isdigit() and len(card_last_four) == 4):
        return json.dumps(
            {"success": False, "error": "card_last_four must be a 4‑digit string"}
        )

    db = await get_db()
    try:
        # Verify the booking exists and fetch its total amount and currency
        async with db.execute(
            "SELECT total_amount, currency FROM bookings WHERE id = ?", (booking_id,)
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            return json.dumps({"success": False, "error": "Booking not found"})

        booking_total = row["total_amount"]
        currency = row["currency"] or "USD"

        if amount > booking_total:
            return json.dumps(
                {
                    "success": False,
                    "error": "Payment exceeds booking total amount",
                }
            )

        payment_id = str(uuid4())
        now = int(time.time())

        await db.execute(
            """
            INSERT INTO payments (id, booking_id, amount, card_last_four, status, created_at)
            VALUES (?, ?, ?, ?, 'completed', ?)
            """,
            (payment_id, booking_id, amount, card_last_four, now),
        )
        await db.commit()

        return json.dumps(
            {
                "success": True,
                "payment_id": payment_id,
                "booking_id": booking_id,
                "amount": amount,
                "currency": currency,
                "status": "completed",
                "message": "Payment processed",
            }
        )
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})
    finally:
        await db.close()