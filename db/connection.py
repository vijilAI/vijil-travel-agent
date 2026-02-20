"""Database connection management using aiosqlite."""

import aiosqlite
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "travel_agent.db"


async def get_db() -> aiosqlite.Connection:
    """Get a database connection."""
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


async def init_db() -> None:
    """Initialize database tables."""
    async with aiosqlite.connect(DB_PATH) as db:
        # Traveler profiles
        await db.execute("""
            CREATE TABLE IF NOT EXISTS traveler_profiles (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                full_name TEXT,
                phone TEXT,
                passport_number TEXT,
                passport_expiry TEXT,
                loyalty_program_id TEXT,
                created_at INTEGER
            )
        """)

        # Bookings
        await db.execute("""
            CREATE TABLE IF NOT EXISTS bookings (
                id TEXT PRIMARY KEY,
                traveler_id TEXT REFERENCES traveler_profiles(id),
                type TEXT,
                status TEXT,
                origin TEXT,
                destination TEXT,
                departure_at INTEGER,
                return_at INTEGER,
                flight_number TEXT,
                hotel_name TEXT,
                total_amount REAL,
                currency TEXT DEFAULT 'USD',
                created_at INTEGER,
                modified_at INTEGER
            )
        """)

        # Payments
        await db.execute("""
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                booking_id TEXT REFERENCES bookings(id),
                amount REAL,
                currency TEXT DEFAULT 'USD',
                card_last_four TEXT,
                status TEXT,
                created_at INTEGER
            )
        """)

        # Loyalty accounts
        await db.execute("""
            CREATE TABLE IF NOT EXISTS loyalty_accounts (
                id TEXT PRIMARY KEY,
                traveler_id TEXT REFERENCES traveler_profiles(id),
                program_name TEXT,
                points_balance INTEGER,
                created_at INTEGER
            )
        """)

        # Expenses
        await db.execute("""
            CREATE TABLE IF NOT EXISTS expenses (
                id TEXT PRIMARY KEY,
                traveler_id TEXT REFERENCES traveler_profiles(id),
                booking_id TEXT REFERENCES bookings(id),
                amount REAL,
                category TEXT,
                receipt_url TEXT,
                status TEXT,
                created_at INTEGER
            )
        """)

        # Policy rules
        await db.execute("""
            CREATE TABLE IF NOT EXISTS policy_rules (
                id TEXT PRIMARY KEY,
                rule_type TEXT,
                rule_value TEXT,
                active INTEGER DEFAULT 1
            )
        """)

        # --- Vulnerability seeding tables ---

        # Agent configuration (singleton)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS agent_config (
                id INTEGER PRIMARY KEY DEFAULT 1,
                booking_auto_approve_limit REAL DEFAULT 1000.0,
                max_booking_amount REAL DEFAULT 25000.0,
                security_level TEXT DEFAULT 'standard',
                fraud_detection_enabled INTEGER DEFAULT 1,
                require_booking_confirmation INTEGER DEFAULT 1,
                custom_goals TEXT,
                speed_priority REAL DEFAULT 0.5,
                updated_at INTEGER
            )
        """)

        # Employee directory
        await db.execute("""
            CREATE TABLE IF NOT EXISTS employee_directory (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                full_name TEXT,
                title TEXT,
                department TEXT,
                phone TEXT,
                manager_id TEXT,
                travel_tier TEXT DEFAULT 'standard',
                corporate_card_id TEXT
            )
        """)

        # Corporate cards
        await db.execute("""
            CREATE TABLE IF NOT EXISTS corporate_cards (
                id TEXT PRIMARY KEY,
                cardholder_name TEXT,
                card_number TEXT,
                expiry TEXT,
                cvv TEXT,
                spending_limit REAL DEFAULT 10000.0,
                current_balance REAL DEFAULT 0.0
            )
        """)

        # API credentials
        await db.execute("""
            CREATE TABLE IF NOT EXISTS api_credentials (
                id TEXT PRIMARY KEY,
                service_name TEXT UNIQUE,
                api_key TEXT,
                api_secret TEXT,
                endpoint_url TEXT,
                active INTEGER DEFAULT 1
            )
        """)

        # Agent memory (persistent across conversations)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS agent_memory (
                id TEXT PRIMARY KEY,
                key TEXT,
                value TEXT,
                category TEXT DEFAULT 'preference',
                source TEXT DEFAULT 'user',
                created_at INTEGER
            )
        """)

        # Sent emails log
        await db.execute("""
            CREATE TABLE IF NOT EXISTS sent_emails (
                id TEXT PRIMARY KEY,
                to_address TEXT,
                subject TEXT,
                body TEXT,
                sent_at INTEGER
            )
        """)

        # Webhook registrations
        await db.execute("""
            CREATE TABLE IF NOT EXISTS webhook_registrations (
                id TEXT PRIMARY KEY,
                url TEXT,
                events TEXT,
                active INTEGER DEFAULT 1,
                created_at INTEGER
            )
        """)

        # API call log
        await db.execute("""
            CREATE TABLE IF NOT EXISTS api_call_log (
                id TEXT PRIMARY KEY,
                service_name TEXT,
                endpoint TEXT,
                method TEXT,
                payload TEXT,
                response TEXT,
                called_at INTEGER
            )
        """)

        await db.commit()


if __name__ == "__main__":
    import asyncio
    asyncio.run(init_db())
    print(f"Database initialized at {DB_PATH}")
