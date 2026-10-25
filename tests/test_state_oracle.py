"""The read-only state oracle (oracle/state.py): off by default, token-gated, allowlisted, scoped per conversation.

Each test names the guard it defends. The chat path is the production
``/v1/chat/completions`` handler; only the Strands agent is a stand-in, and it
calls the real tools through Strands' own ``run_async`` thread hop, so the
conversation id has to survive the same two thread hops a real run takes.
"""

import asyncio
import sqlite3
import threading
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from strands._async import run_async

import agent
import db.connection as conn
from db.connection import init_db
from db.seed_data import seed_data
from oracle import state as state_oracle
from tools.booking import create_booking
from tools.disruption import auto_rebook
from tools.payments import process_payment
from tools.profile import save_traveler_profile

TOKEN = "t" * 40
CONVERSATION_A = "conv-" + "a" * 32
CONVERSATION_B = "conv-" + "b" * 32
CONVERSATION_C = "conv-" + "c" * 32


@pytest.fixture(autouse=True)
def fresh_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "state_oracle.db"
    monkeypatch.setattr(conn, "DB_PATH", path)
    asyncio.run(init_db())
    asyncio.run(seed_data())
    yield path
    state_oracle._enabled = False  # mount() sets it process-wide; never leak it to another test


class _BookingAgent:
    """Stands in for the Strands agent: books through the real tool, via Strands' own async runner.

    It says nothing about the booking in its reply, so only the database can show it happened.
    """

    def __init__(self, traveler: str, barrier: threading.Barrier | None = None):
        self._traveler = traveler
        self._barrier = barrier

    def __call__(self, user_text: str) -> str:
        if self._barrier is not None:
            self._barrier.wait(timeout=5)  # both conversations are mid-run at once
        run_async(lambda: create_booking(
            traveler_id=self._traveler, flight_id="FL-SFO-BOS-001", payment_method_id="pm-1",
            total_amount=299.0, departure_date="2026-11-12",
        ))
        return "Anything else?"


def _app(environ: dict[str, str]) -> FastAPI:
    app = FastAPI()
    agent.add_chat_completions_endpoint(app)
    state_oracle.mount(app, environ)
    return app


async def _chat(client: httpx.AsyncClient, conversation_id: str | None) -> httpx.Response:
    headers = {state_oracle.CONVERSATION_HEADER: conversation_id} if conversation_id else {}
    body = {"messages": [{"role": "user", "content": "Book me SFO to BOS on 2026-11-12"}]}
    return await client.post("/v1/chat/completions", json=body, headers=headers)


async def _state(client: httpx.AsyncClient, conversation_id: str, token: str | None = TOKEN) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return await client.get("/oracle/state", params={"conversation_id": conversation_id}, headers=headers)


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://agent")


def _oracle_writes(path: Path) -> list[tuple]:
    with sqlite3.connect(path) as db:
        return db.execute("SELECT conversation_id, table_name, op FROM oracle_writes").fetchall()


# ── off by default ──


@pytest.mark.parametrize("environ", [{}, {"STATE_ORACLE_TOKEN": ""}, {"STATE_ORACLE_TOKEN": "x" * 31}],
                         ids=["unset", "empty", "too_short"])
def test_the_route_does_not_exist_unless_a_long_enough_token_is_set(environ: dict[str, str]) -> None:
    app = FastAPI()
    assert state_oracle.mount(app, environ) is False

    async def go() -> httpx.Response:
        async with _client(app) as client:
            return await _state(client, CONVERSATION_A, token="x" * 31)

    assert asyncio.run(go()).status_code == 404
    assert not state_oracle.is_enabled()


def test_with_the_oracle_off_the_header_is_ignored_and_no_write_is_recorded(
    fresh_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent, "create_agent", lambda messages=None: _BookingAgent("emp-010"))

    async def go() -> None:
        async with _client(_app({})) as client:
            assert (await _chat(client, CONVERSATION_A)).status_code == 200

    asyncio.run(go())
    assert _oracle_writes(fresh_db) == []
    with sqlite3.connect(fresh_db) as db:
        assert db.execute("SELECT count(*) FROM bookings").fetchone()[0] == 1  # the booking itself still happened


# ── token ──


@pytest.mark.parametrize(
    "authorization",
    [None, "", f"Bearer {'u' * 40}", TOKEN, f"Basic {TOKEN}", f"Bearer {TOKEN} ", f"bearer {TOKEN}"],
    ids=["missing", "empty", "wrong_same_length", "no_scheme", "wrong_scheme", "trailing_space", "lowercase_scheme"],
)
def test_anything_but_the_exact_bearer_token_is_401(authorization: str | None) -> None:
    async def go() -> httpx.Response:
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            headers = {} if authorization is None else {"Authorization": authorization}
            return await client.get("/oracle/state", params={"conversation_id": CONVERSATION_A}, headers=headers)

    response = asyncio.run(go())
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_the_token_is_compared_in_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    compared: list[tuple[bytes, bytes]] = []
    real = state_oracle.hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        compared.append((a, b))
        return real(a, b)

    monkeypatch.setattr(state_oracle.hmac, "compare_digest", spy)

    async def go() -> httpx.Response:
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            return await _state(client, CONVERSATION_A)

    assert asyncio.run(go()).status_code == 200
    assert compared == [(f"Bearer {TOKEN}".encode(), f"Bearer {TOKEN}".encode())]


@pytest.mark.parametrize("conversation_id", ["x' OR '1'='1", "a" * 31, "a" * 129], ids=["injection", "short", "long"])
def test_a_malformed_conversation_id_is_refused(conversation_id: str) -> None:
    async def go() -> httpx.Response:
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            return await _state(client, conversation_id)

    assert asyncio.run(go()).status_code == 400


def test_a_conversation_id_shorter_than_32_characters_in_the_header_attributes_nothing(
    fresh_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(agent, "create_agent", lambda messages=None: _BookingAgent("emp-010"))

    async def go() -> None:
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            assert (await _chat(client, "a" * 31)).status_code == 200

    asyncio.run(go())
    assert _oracle_writes(fresh_db) == []


# ── allowlist ──


def test_only_allowlisted_tables_and_columns_are_ever_returned(fresh_db: Path) -> None:
    async def write() -> None:
        with state_oracle.conversation(CONVERSATION_A):
            await save_traveler_profile(email="lw@example.com", full_name="Test Person", passport_number="P1234567")
            booked = await create_booking(traveler_id="t-1", flight_id="FL-SFO-BOS-001", payment_method_id="pm",
                                          total_amount=299.0, departure_date="2026-11-12")
            import json
            await process_payment(booking_id=json.loads(booked)["booking_id"], amount=299.0, card_last_four="4242")

    state_oracle._enabled = True
    asyncio.run(write())
    # A write record pointing at a secret table (it cannot be made through record_write) must still never be served.
    with sqlite3.connect(fresh_db) as db:
        for table, row in (("corporate_cards", "card-001"), ("api_credentials", "cred-001"),
                           ("employee_directory", "emp-001")):
            db.execute("INSERT INTO oracle_writes (conversation_id, table_name, row_id, op, at) VALUES (?,?,?,'update',0)",
                       (CONVERSATION_A, table, row))

    async def go() -> dict:
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            response = await _state(client, CONVERSATION_A)
            assert response.status_code == 200
            return response.json()

    body = asyncio.run(go())
    assert set(body["rows"]) == {"traveler_profiles", "bookings", "payments"}
    for table, rows in body["rows"].items():
        assert rows, table
        for row in rows:
            assert set(row) <= set(state_oracle._READABLE[table]), (table, row)
    assert {w["table"] for w in body["writes"]} == {"traveler_profiles", "bookings", "payments"}
    text = str(body)
    assert "P1234567" not in text and "passport" not in text
    with sqlite3.connect(fresh_db) as db:
        for (secret,) in db.execute("SELECT card_number FROM corporate_cards").fetchall():
            assert secret not in text
        for (secret,) in db.execute("SELECT api_key FROM api_credentials").fetchall():
            assert secret not in text


def test_the_write_log_stores_only_allowlisted_columns(fresh_db: Path) -> None:
    async def write() -> None:
        with state_oracle.conversation(CONVERSATION_A):
            await save_traveler_profile(email="lw@example.com", full_name="Test Person", phone="555-0100",
                                        passport_number="P1234567")

    state_oracle._enabled = True
    asyncio.run(write())
    with sqlite3.connect(fresh_db) as db:
        [(stored,)] = db.execute("SELECT row_json FROM oracle_writes").fetchall()
    import json
    assert set(json.loads(stored)) == set(state_oracle._READABLE["traveler_profiles"])
    assert "P1234567" not in stored and "555-0100" not in stored


def test_a_logged_snapshot_with_a_forbidden_column_is_never_served(fresh_db: Path) -> None:
    import json

    with sqlite3.connect(fresh_db) as db:
        db.execute(
            "INSERT INTO oracle_writes (conversation_id, table_name, row_id, op, at, row_json) VALUES (?,?,?,?,0,?)",
            (CONVERSATION_A, "bookings", "bk-1", "insert",
             json.dumps({"id": "bk-1", "status": "confirmed", "card_number": "4111111111111111"})),
        )

    async def go() -> dict:
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            return (await _state(client, CONVERSATION_A)).json()

    body = asyncio.run(go())
    assert body["rows"] == {"bookings": [{"id": "bk-1", "status": "confirmed"}]}


def test_a_write_with_an_op_outside_insert_or_update_cannot_be_recorded() -> None:
    async def go() -> None:
        db = await conn.get_db()
        try:
            with state_oracle.conversation(CONVERSATION_A):
                await state_oracle.record_write(db, table="bookings", row_id="bk-1", op="update: free text")
        finally:
            await db.close()

    state_oracle._enabled = True
    with pytest.raises(ValueError, match="not a state-oracle op"):
        asyncio.run(go())


def test_a_write_to_a_table_outside_the_allowlist_cannot_be_recorded() -> None:
    async def go() -> None:
        db = await conn.get_db()
        try:
            with state_oracle.conversation(CONVERSATION_A):
                await state_oracle.record_write(db, table="corporate_cards", row_id="card-001", op="update")
        finally:
            await db.close()

    state_oracle._enabled = True
    with pytest.raises(ValueError, match="not a state-oracle table"):
        asyncio.run(go())


# ── scoping ──


def test_two_concurrent_conversations_each_see_only_their_own_writes(
    fresh_db: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    barrier = threading.Barrier(2)
    travelers = iter(["emp-010", "emp-009"])
    lock = threading.Lock()

    def make(messages=None) -> _BookingAgent:
        with lock:
            return _BookingAgent(next(travelers), barrier)

    monkeypatch.setattr(agent, "create_agent", make)

    async def go() -> tuple[dict, dict, dict]:
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            replies = await asyncio.gather(_chat(client, CONVERSATION_A), _chat(client, CONVERSATION_B))
            assert [r.status_code for r in replies] == [200, 200]
            a, b, none = [(await _state(client, c)).json()
                          for c in (CONVERSATION_A, CONVERSATION_B, CONVERSATION_C)]
            return a, b, none

    a, b, none = asyncio.run(go())
    assert len(a["rows"]["bookings"]) == 1 and len(b["rows"]["bookings"]) == 1
    assert {a["rows"]["bookings"][0]["traveler_id"], b["rows"]["bookings"][0]["traveler_id"]} == {"emp-010", "emp-009"}
    assert a["rows"]["bookings"][0]["id"] != b["rows"]["bookings"][0]["id"]
    assert none == {"schema_version": 1, "conversation_id": CONVERSATION_C, "truncated": False,
                    "writes": [], "rows": {}}


def test_a_later_write_by_another_conversation_or_by_none_never_changes_what_this_one_did(fresh_db: Path) -> None:
    import json

    async def go() -> tuple[dict, dict]:
        with state_oracle.conversation(CONVERSATION_A):
            booked = json.loads(await create_booking(
                traveler_id="emp-010", flight_id="FL-SFO-BOS-001", payment_method_id="pm", total_amount=299.0,
                departure_date="2026-11-12",
            ))
        with state_oracle.conversation(CONVERSATION_B):
            await auto_rebook(booking_id=booked["booking_id"], reason="delay")  # B cancels A's booking
        db = await conn.get_db()
        try:
            await db.execute("UPDATE bookings SET total_amount = 1 WHERE id = ?", (booked["booking_id"],))
            await db.commit()
        finally:
            await db.close()
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            return (await _state(client, CONVERSATION_A)).json(), (await _state(client, CONVERSATION_B)).json()

    state_oracle._enabled = True
    a, b = asyncio.run(go())
    [row] = a["rows"]["bookings"]
    assert (row["status"], row["total_amount"]) == ("confirmed", 299.0), "another writer changed A's reported state"
    assert [w["op"] for w in a["writes"]] == ["insert"] and a["writes"][0]["row"] == row
    seqs = [w["seq"] for w in b["writes"]]
    assert seqs == sorted(set(seqs)) and len(seqs) == 2, "writes are not reported in strictly increasing write order"
    # B's update of A's booking carries the row as B left it, attributed to B only.
    assert [(w["op"], w["row"]["status"]) for w in b["writes"]] == [
        ("update", "cancelled"), ("insert", "confirmed"),
    ]
    assert sorted(r["status"] for r in b["rows"]["bookings"]) == ["cancelled", "confirmed"]


def test_a_write_outside_any_conversation_belongs_to_none(fresh_db: Path) -> None:
    state_oracle._enabled = True
    asyncio.run(create_booking(traveler_id="emp-010", flight_id="FL-SFO-BOS-001", payment_method_id="pm",
                               total_amount=1.0))
    assert _oracle_writes(fresh_db) == []


def test_more_writes_than_the_cap_are_reported_as_truncated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state_oracle, "MAX_WRITES", 2)

    async def go() -> dict:
        with state_oracle.conversation(CONVERSATION_A):
            for _ in range(3):
                await create_booking(traveler_id="t", flight_id="FL-A-B-001", payment_method_id="pm", total_amount=1.0)
        async with _client(_app({"STATE_ORACLE_TOKEN": TOKEN})) as client:
            return (await _state(client, CONVERSATION_A)).json()

    state_oracle._enabled = True
    body = asyncio.run(go())
    assert body["truncated"] is True and len(body["writes"]) == 2


# ── route and date on a booking (owner decision 2) ──


def test_a_booking_persists_its_flight_route_and_date(fresh_db: Path) -> None:
    import json

    reply = json.loads(asyncio.run(create_booking(
        traveler_id="emp-010", flight_id="FL-sfo-BOS-002", payment_method_id="pm", total_amount=349.0,
        departure_date="2026-11-12",
    )))
    with sqlite3.connect(fresh_db) as db:
        row = db.execute("SELECT flight_id, origin, destination, departure_date FROM bookings WHERE id = ?",
                         (reply["booking_id"],)).fetchone()
    assert row == ("FL-sfo-BOS-002", "SFO", "BOS", "2026-11-12")
    assert (reply["origin"], reply["destination"], reply["departure_date"]) == ("SFO", "BOS", "2026-11-12")


@pytest.mark.parametrize("departure_date", ["", "11/12/2026", "2026-13-40"], ids=["omitted", "other_format", "invalid"])
def test_a_booking_without_a_valid_date_still_books_with_no_date(fresh_db: Path, departure_date: str) -> None:
    import json

    reply = json.loads(asyncio.run(create_booking(
        traveler_id="emp-010", flight_id="FL-SFO-BOS-001", payment_method_id="pm", total_amount=299.0,
        departure_date=departure_date,
    )))
    assert reply["success"] is True and reply["departure_date"] is None


def test_the_old_four_argument_call_still_books(fresh_db: Path) -> None:
    import json

    reply = json.loads(asyncio.run(create_booking("emp-010", "custom-flight", "pm", 10.0)))
    assert reply["success"] is True and (reply["origin"], reply["destination"]) == (None, None)


def test_a_rebook_keeps_the_route_and_records_both_writes(fresh_db: Path) -> None:
    import json

    async def go() -> tuple[dict, dict]:
        with state_oracle.conversation(CONVERSATION_A):
            booked = json.loads(await create_booking(
                traveler_id="emp-010", flight_id="FL-SFO-BOS-001", payment_method_id="pm", total_amount=299.0,
                departure_date="2026-11-12",
            ))
            rebooked = json.loads(await auto_rebook(booking_id=booked["booking_id"], reason="delay"))
        return booked, rebooked

    state_oracle._enabled = True
    booked, rebooked = asyncio.run(go())
    with sqlite3.connect(fresh_db) as db:
        new = db.execute("SELECT origin, destination, departure_date, status FROM bookings WHERE id = ?",
                         (rebooked["new_booking_id"],)).fetchone()
        old = db.execute("SELECT status FROM bookings WHERE id = ?", (booked["booking_id"],)).fetchone()
    assert new == ("SFO", "BOS", "2026-11-12", "confirmed") and old == ("cancelled",)
    assert [(t, op) for _, t, op in _oracle_writes(fresh_db)] == [
        ("bookings", "insert"), ("bookings", "update"), ("bookings", "insert"),
    ]


def test_a_database_from_before_the_route_columns_gains_them(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE bookings (id TEXT PRIMARY KEY, traveler_id TEXT, total_amount REAL)")
    monkeypatch.setattr(conn, "DB_PATH", path)
    asyncio.run(init_db())
    with sqlite3.connect(path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(bookings)")}
    assert {"flight_id", "departure_date"} <= columns
