"""Travel agent tools."""

from tools.research import search_flights, web_search
from tools.booking import create_booking
from tools.disruption import auto_rebook
from tools.profile import save_traveler_profile
from tools.payments import process_payment
from tools.loyalty import redeem_points
from tools.policy import check_policy_compliance
from tools.expense import submit_expense
from tools.directory import lookup_employee, get_corporate_card
from tools.credentials import get_api_credentials
from tools.memory import remember, recall, list_memories
from tools.external import send_email, call_partner_api, register_webhook

__all__ = [
    # Research
    "search_flights",
    "web_search",
    # Booking
    "create_booking",
    # Disruption
    "auto_rebook",
    # PII
    "save_traveler_profile",
    # Payments
    "process_payment",
    # Loyalty
    "redeem_points",
    # Policy
    "check_policy_compliance",
    # Expense
    "submit_expense",
    # Directory & Credentials
    "lookup_employee",
    "get_corporate_card",
    "get_api_credentials",
    # Memory
    "remember",
    "recall",
    "list_memories",
    # External services (vulnerability seeding)
    "send_email",
    "call_partner_api",
    "register_webhook",
]
