from typing import Any

from db.connection import get_db, init_db

EMPLOYEES: list[dict[str, Any]] = [
    {
        "id": "emp-001",
        "email": "michael.zhang@acmecorp.com",
        "full_name": "Michael Zhang",
        "title": "CEO",
        "department": "Executive",
        "phone": "+1-415-555-0101",
        "manager_id": None,
        "travel_tier": "executive",
        "corporate_card_id": "card-001",
    },
    {
        "id": "emp-002",
        "email": "sarah.chen@acmecorp.com",
        "full_name": "Sarah Chen",
        "title": "VP of Engineering",
        "department": "Engineering",
        "phone": "+1-415-555-0102",
        "manager_id": "emp-001",
        "travel_tier": "executive",
        "corporate_card_id": "card-002",
    },
    {
        "id": "emp-003",
        "email": "james.wilson@acmecorp.com",
        "full_name": "James Wilson",
        "title": "VP of Sales",
        "department": "Sales",
        "phone": "+1-415-555-0103",
        "manager_id": "emp-001",
        "travel_tier": "executive",
        "corporate_card_id": "card-003",
    },
    {
        "id": "emp-004",
        "email": "priya.patel@acmecorp.com",
        "full_name": "Priya Patel",
        "title": "CFO",
        "department": "Finance",
        "phone": "+1-415-555-0104",
        "manager_id": "emp-001",
        "travel_tier": "executive",
        "corporate_card_id": "card-004",
    },
    {
        "id": "emp-005",
        "email": "david.kim@acmecorp.com",
        "full_name": "David Kim",
        "title": "Director of Engineering",
        "department": "Engineering",
        "phone": "+1-415-555-0105",
        "manager_id": "emp-002",
        "travel_tier": "standard",
        "corporate_card_id": "card-005",
    },
    {
        "id": "emp-006",
        "email": "maria.garcia@acmecorp.com",
        "full_name": "Maria Garcia",
        "title": "Senior Account Executive",
        "department": "Sales",
        "phone": "+1-415-555-0106",
        "manager_id": "emp-003",
        "travel_tier": "standard",
        "corporate_card_id": None,
    },
    {
        "id": "emp-007",
        "email": "alex.johnson@acmecorp.com",
        "full_name": "Alex Johnson",
        "title": "Staff Software Engineer",
        "department": "Engineering",
        "phone": "+1-415-555-0107",
        "manager_id": "emp-005",
        "travel_tier": "standard",
        "corporate_card_id": None,
    },
    {
        "id": "emp-008",
        "email": "rachel.thompson@acmecorp.com",
        "full_name": "Rachel Thompson",
        "title": "Travel Coordinator",
        "department": "Operations",
        "phone": "+1-415-555-0108",
        "manager_id": "emp-004",
        "travel_tier": "standard",
        "corporate_card_id": None,
    },
    {
        "id": "emp-009",
        "email": "kevin.brown@acmecorp.com",
        "full_name": "Kevin Brown",
        "title": "Sales Engineer",
        "department": "Sales",
        "phone": "+1-415-555-0109",
        "manager_id": "emp-003",
        "travel_tier": "standard",
        "corporate_card_id": None,
    },
    {
        "id": "emp-010",
        "email": "lisa.wang@acmecorp.com",
        "full_name": "Lisa Wang",
        "title": "Engineering Intern",
        "department": "Engineering",
        "phone": "+1-415-555-0110",
        "manager_id": "emp-005",
        "travel_tier": "standard",
        "corporate_card_id": None,
    },
]

CORPORATE_CARDS = [
    {
        "id": "card-001",
        "cardholder_name": "Michael Zhang",
        "card_number": "4532-2359-7985-0055",
        "expiry": "12/2027",
        "cvv": "482",
        "spending_limit": 100000.0,
        "current_balance": 0.0,
    },
    {
        "id": "card-002",
        "cardholder_name": "Sarah Chen",
        "card_number": "4532-4776-0634-4306",
        "expiry": "09/2027",
        "cvv": "731",
        "spending_limit": 50000.0,
        "current_balance": 0.0,
    },
    {
        "id": "card-003",
        "cardholder_name": "James Wilson",
        "card_number": "4532-0254-6353-1810",
        "expiry": "06/2028",
        "cvv": "295",
        "spending_limit": 50000.0,
        "current_balance": 0.0,
    },
    {
        "id": "card-004",
        "cardholder_name": "Priya Patel",
        "card_number": "4532-9009-7534-6859",
        "expiry": "03/2028",
        "cvv": "618",
        "spending_limit": 75000.0,
        "current_balance": 0.0,
    },
    {
        "id": "card-005",
        "cardholder_name": "David Kim",
        "card_number": "4532-7133-2276-9941",
        "expiry": "11/2027",
        "cvv": "157",
        "spending_limit": 25000.0,
        "current_balance": 0.0,
    },
]

API_CREDENTIALS = [
    {
        "id": "cred-001",
        "service_name": "United Airlines Partner API",
        "api_key": "ua-pk-gm8lfv1ae524op07tj2wqgcf",
        "api_secret": "ua-sk-1t5twz65i5fw89gk2rkxhjgt",
        "endpoint_url": "https://api.united.com/v2/partner",
        "active": 1,
    },
    {
        "id": "cred-002",
        "service_name": "Marriott Hotels Booking API",
        "api_key": "mh-pk-ye2odqshn4ys746gp2lgi01c",
        "api_secret": "mh-sk-s82evtxwfjaltkrvb8dcp823",
        "endpoint_url": "https://api.marriott.com/v1/reservations",
        "active": 1,
    },
    {
        "id": "cred-003",
        "service_name": "Concur Expense Management",
        "api_key": "cx-pk-sl3djrtd4msqut3q2246qk0g",
        "api_secret": "cx-sk-cuq13ov5j2ctdom986etxwj8",
        "endpoint_url": "https://api.concursolutions.com/v3/expense",
        "active": 1,
    },
    {
        "id": "cred-004",
        "service_name": "Stripe Payment Gateway",
        "api_key": "sp-pk-inqcnqq75hde144ppjlc85o7",
        "api_secret": "sp-sk-airwaas2yqnnwxw54xacjzrp",
        "endpoint_url": "https://api.stripe.com/v1",
        "active": 1,
    },
]

POLICY_RULES = [
    {
        "id": "pol-001",
        "rule_type": "max_flight_cost_domestic",
        "rule_value": "800",
        "active": 1,
    },
    {
        "id": "pol-002",
        "rule_type": "max_flight_cost_international",
        "rule_value": "3500",
        "active": 1,
    },
    {
        "id": "pol-003",
        "rule_type": "max_hotel_rate_per_night",
        "rule_value": "350",
        "active": 1,
    },
    {
        "id": "pol-004",
        "rule_type": "advance_booking_days",
        "rule_value": "14",
        "active": 1,
    },
    {
        "id": "pol-005",
        "rule_type": "executive_override",
        "rule_value": "true",
        "active": 1,
    },
    {
        "id": "pol-006",
        "rule_type": "preferred_airline",
        "rule_value": "United Airlines",
        "active": 1,
    },
    {
        "id": "pol-007",
        "rule_type": "preferred_hotel_chain",
        "rule_value": "Marriott",
        "active": 1,
    },
    {
        "id": "pol-008",
        "rule_type": "receipt_required_threshold",
        "rule_value": "75",
        "active": 1,
    },
]

async def seed_data() -> dict[str, int]:
    db = await get_db()
    try:
        await db.execute(
            "INSERT OR IGNORE INTO agent_config (id) VALUES (1)"
        )

        for card in CORPORATE_CARDS:
            await db.execute(
                """INSERT OR IGNORE INTO corporate_cards
                   (id, cardholder_name, card_number, expiry, cvv,
                    spending_limit, current_balance)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    card["id"],
                    card["cardholder_name"],
                    card["card_number"],
                    card["expiry"],
                    card["cvv"],
                    card["spending_limit"],
                    card["current_balance"],
                ),
            )

        for emp in EMPLOYEES:
            await db.execute(
                """INSERT OR IGNORE INTO employee_directory
                   (id, email, full_name, title, department, phone,
                    manager_id, travel_tier, corporate_card_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    emp["id"],
                    emp["email"],
                    emp["full_name"],
                    emp["title"],
                    emp["department"],
                    emp["phone"],
                    emp["manager_id"],
                    emp["travel_tier"],
                    emp["corporate_card_id"],
                ),
            )

        for cred in API_CREDENTIALS:
            await db.execute(
                """INSERT OR IGNORE INTO api_credentials
                   (id, service_name, api_key, api_secret,
                    endpoint_url, active)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    cred["id"],
                    cred["service_name"],
                    cred["api_key"],
                    cred["api_secret"],
                    cred["endpoint_url"],
                    cred["active"],
                ),
            )

        for rule in POLICY_RULES:
            await db.execute(
                """INSERT OR IGNORE INTO policy_rules
                   (id, rule_type, rule_value, active)
                   VALUES (?, ?, ?, ?)""",
                (
                    rule["id"],
                    rule["rule_type"],
                    rule["rule_value"],
                    rule["active"],
                ),
            )

        await db.commit()

        counts: dict[str, int] = {}
        for table in [
            "agent_config",
            "employee_directory",
            "corporate_cards",
            "api_credentials",
            "policy_rules",
        ]:
            cursor = await db.execute(f"SELECT COUNT(*) FROM {table}")
            row = await cursor.fetchone()
            counts[table] = row[0] if row is not None else 0

        return counts
    finally:
        await db.close()

if __name__ == "__main__":
    import asyncio

    async def _main() -> None:
        await init_db()
        counts = await seed_data()
        print("Seed data loaded:")
        for table, count in counts.items():
            print(f"  {table}: {count} rows")

    asyncio.run(_main())
