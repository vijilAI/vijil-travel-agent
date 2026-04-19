"""Payment tool: process payments."""

import json
import time
import re
from uuid import uuid4
from strands import tool
from db.connection import get_db

# Configuration constants
MAX_PAYMENT_AMOUNT = 10_000.00  # Upper bound for a single payment
CARD_LAST_FOUR_REGEX = re.compile(r"^\d{4}$")


@tool
async def process_payment(
    booking_id: str,
    amount: float,
    card_last_four: str,
) -> str:
    """
    Process a payment for a booking with basic safety checks.

    Args:
        booking_id: Identifier of the booking to pay for.
        amount: Payment amount in USD. Must be positive and not exceed the
                configured maximum.
        card_last_four: Last four digits of the payment card (numeric).

    Returns:
        JSON string with payment confirmation or an error description.
    """
    # ---- Input validation -------------------------------------------------
    if not isinstance(booking_id, str) or not booking_id.strip():
        return json.dumps({"success": False, "error": "Invalid booking_id."})

    if not isinstance(amount, (int, float)):
        return json.dumps({"success": False, "error": "Amount must be a number."})
    if amount <= 0:
        return json.dumps({"success": False, "error": "Amount must be positive."})
    if amount > MAX_PAYMENT_AMOUNT:
        return json.dumps(
            {
                "success": False,
                "error": f"Amount exceeds the maximum allowed (${MAX_PAYMENT_AMOUNT:.2f}).",
            }
        )

    if not CARD_LAST_FOUR_REGEX.match(card_last_four or ""):
        return json.dumps(
            {"success": False, "error": "card_last_four must be exactly four digits."}
        )

    # ---- Basic business checks --------------------------------------------
    db = await get_db()
    try:
        # Verify the booking exists (placeholder query – adjust table/column names as needed)
        booking = await db.fetchone(
            "SELECT id FROM bookings WHERE id = ?", (booking_id,)
        )
        if not booking:
            return json.dumps({"success": False, "error": "Booking not found."})

        # Prevent duplicate payments for the same booking
        existing = await db.fetchone(
            """
            SELECT id FROM payments
            WHERE booking_id = ? AND status = 'completed'
            """,
            (booking_id,),
        )
        if existing:
            return json.dumps(
                {
                    "success": False,
                    "error": "A completed payment already exists for this booking.",
                }
            )

        # ---- Record the payment --------------------------------------------
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
                "amount": round(amount, 2),
                "currency": "USD",
                "card_last_four": card_last_four,
                "status": "completed",
                "message": "Payment processed successfully.",
            }
        )
    except Exception as e:
        # Log the exception in a real system; here we just return an error.
        return json.dumps({"success": False, "error": str(e)})
    finally:
        await db.close()