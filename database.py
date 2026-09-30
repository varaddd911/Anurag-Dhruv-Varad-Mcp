"""SQLite schema, deterministic seed data and *enforced* per-server data-source scoping.

Isolation model (spec section 3 NOTE)
-------------------------------------
All three servers share one ``neobank.db`` (WAL mode) but **no server ever gets a raw
connection**. ``connect_scoped(server_name)`` returns a connection with a SQLite
*authorizer callback* installed. SQLite consults that callback while compiling every
statement, so a ``SELECT`` against a table outside the server's whitelist is refused
by the database engine itself (``DataAccessViolationError``) - it is not a convention
the tool code happens to follow. ``products_server`` is therefore structurally unable
to read ``customers`` even if someone edits a query. DDL, ``PRAGMA`` and ``ATTACH`` are
denied on every scoped connection; only ``connect_admin()`` (used by this module's CLI
and the tests) can create or seed tables.

Usage: ``python database.py --seed [--reset] [--path neobank.db]``
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from contextlib import contextmanager
from typing import Any, Callable, Iterator

from errors import BankForgeError, DataAccessViolationError
from guardrails import redact_for_logging
from logging_config import get_logger, trace

logger = get_logger("bankforge.database")

DEFAULT_DB_PATH = "neobank.db"


class DatabaseNotInitialisedError(BankForgeError):
    code = "DATABASE_NOT_INITIALISED"


def get_db_path(path: str | None = None) -> str:
    """Resolve the database file: explicit arg > ``BANKFORGE_DB_PATH`` env > ``./neobank.db``."""
    return os.path.abspath(path or os.getenv("BANKFORGE_DB_PATH") or DEFAULT_DB_PATH)


# ------------------------------------------------------------------ permissions
READ, INSERT, UPDATE, DELETE = "read", "insert", "update", "delete"

SERVER_TABLE_PERMISSIONS: dict[str, dict[str, frozenset[str]]] = {
    # transactions is required by get_transaction_history; customers only for existence checks
    "accounts_server": {
        "customers": frozenset({READ}),
        "accounts": frozenset({READ}),
        "transactions": frozenset({READ}),
    },
    # NO customer tables at all - KYC is obtained from compliance_comms_server over MCP
    "products_server": {
        "loan_products": frozenset({READ}),
        "loan_applications": frozenset({READ, INSERT, UPDATE}),
    },
    "compliance_comms_server": {
        "customers": frozenset({READ}),
        "communications_log": frozenset({READ, INSERT, UPDATE}),
        "fraud_flags": frozenset({READ}),
        "audit_log": frozenset({READ, INSERT}),   # append-only: no update/delete of audit rows
    },
}

_ACTION_TO_PERMISSION = {
    sqlite3.SQLITE_READ: READ,
    sqlite3.SQLITE_INSERT: INSERT,
    sqlite3.SQLITE_UPDATE: UPDATE,
    sqlite3.SQLITE_DELETE: DELETE,
}
_DENIED_ACTION_NAMES = {  # for readable DataAccessViolationError messages
    1: "CREATE_INDEX", 2: "CREATE_TABLE", 3: "CREATE_TEMP_INDEX", 4: "CREATE_TEMP_TABLE", 5: "CREATE_TEMP_TRIGGER",
    6: "CREATE_TEMP_VIEW", 7: "CREATE_TRIGGER", 8: "CREATE_VIEW", 10: "DROP_INDEX", 11: "DROP_TABLE",
    12: "DROP_TEMP_INDEX", 13: "DROP_TEMP_TABLE", 14: "DROP_TEMP_TRIGGER", 15: "DROP_TEMP_VIEW", 16: "DROP_TRIGGER",
    17: "DROP_VIEW", 19: "PRAGMA", 24: "ATTACH", 25: "DETACH", 26: "ALTER_TABLE", 27: "REINDEX", 28: "ANALYZE",
    29: "CREATE_VTABLE", 30: "DROP_VTABLE",
}
_ALWAYS_ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT,
    getattr(sqlite3, "SQLITE_RECURSIVE", 33),
}


def make_authorizer(server_name: str, permissions: dict[str, frozenset[str]],
                    denied_sink: list[tuple[str, str]]) -> Callable[..., int]:
    """Build the SQLite authorizer callback for one server. Records denials into ``denied_sink``."""

    def authorizer(action: int, arg1: str | None, arg2: str | None, db_name: str | None, trigger: str | None) -> int:
        if action in _ALWAYS_ALLOWED_ACTIONS:
            return sqlite3.SQLITE_OK
        needed = _ACTION_TO_PERMISSION.get(action)
        if needed is None:  # DDL, PRAGMA, ATTACH, DETACH, REINDEX, ... never allowed for a server
            denied_sink.append((_DENIED_ACTION_NAMES.get(action, f"action:{action}"), arg1 or ""))
            return sqlite3.SQLITE_DENY
        table = arg1 or ""
        if table.startswith("sqlite_"):  # engine-internal bookkeeping tables
            return sqlite3.SQLITE_OK
        if needed in permissions.get(table, frozenset()):
            return sqlite3.SQLITE_OK
        denied_sink.append((needed, table))
        return sqlite3.SQLITE_DENY

    return authorizer


# ----------------------------------------------------------------- connections
class ScopedDB:
    """Thin wrapper around a scoped ``sqlite3.Connection`` with dict rows and explicit transactions."""

    def __init__(self, server_name: str, path: str | None = None) -> None:
        if server_name not in SERVER_TABLE_PERMISSIONS:
            raise BankForgeError(f"unknown server '{server_name}'", server=server_name)
        self.server_name = server_name
        self.path = get_db_path(path)
        if not os.path.exists(self.path):
            raise DatabaseNotInitialisedError(
                f"database file {self.path} does not exist - run `python database.py --seed`", path=self.path)
        self._denied: list[tuple[str, str]] = []
        self.conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)  # autocommit; we BEGIN explicitly
        self.conn.row_factory = sqlite3.Row
        # pragmas must be issued *before* the authorizer is installed (it denies PRAGMA afterwards)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.set_authorizer(make_authorizer(server_name, SERVER_TABLE_PERMISSIONS[server_name], self._denied))

    # -- error translation -------------------------------------------------
    def _translate(self, exc: sqlite3.Error, sql: str) -> BaseException:
        text = str(exc).lower()
        # SQLite words authorizer denials differently per action ("not authorized" for
        # INSERT/UPDATE/DDL, "access to <table>.<col> is prohibited" for READ)
        if isinstance(exc, sqlite3.DatabaseError) and ("not authorized" in text or "prohibited" in text):
            op, table = self._denied[-1] if self._denied else ("?", "?")
            what = f"{op} table '{table}'" if op in (READ, INSERT, UPDATE, DELETE) else f"run {op} ('{table}')"
            return DataAccessViolationError(
                f"{self.server_name} is not permitted to {what}",
                server=self.server_name, operation=op, table=table, sql=sql.strip()[:120],
            )
        return exc

    def query(self, sql: str, params: tuple | dict = ()) -> list[dict[str, Any]]:
        try:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]
        except sqlite3.Error as exc:
            raise self._translate(exc, sql) from exc

    def query_one(self, sql: str, params: tuple | dict = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple | dict = ()) -> sqlite3.Cursor:
        try:
            return self.conn.execute(sql, params)
        except sqlite3.Error as exc:
            raise self._translate(exc, sql) from exc

    @contextmanager
    def transaction(self) -> Iterator["ScopedDB"]:
        """``BEGIN IMMEDIATE`` ... ``COMMIT``, rolling back on any exception (including non-DB ones)."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        else:
            self.conn.execute("COMMIT")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "ScopedDB":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


@trace(logger, redact=redact_for_logging)
def connect_scoped(server_name: str, path: str | None = None) -> ScopedDB:
    """The only sanctioned way for a server to obtain database access."""
    return ScopedDB(server_name, path)


def connect_admin(path: str | None = None) -> sqlite3.Connection:
    """Unrestricted connection for schema management, seeding and test assertions. Not for servers."""
    conn = sqlite3.connect(get_db_path(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# ---------------------------------------------------------------------- schema
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id        TEXT PRIMARY KEY,
    full_name          TEXT NOT NULL,
    email              TEXT,
    phone              TEXT,
    date_of_birth      TEXT,
    city               TEXT,
    tier               TEXT NOT NULL CHECK (tier IN ('basic','silver','gold','platinum')),
    kyc_status         TEXT NOT NULL CHECK (kyc_status IN ('verified','pending','rejected','expired')),
    kyc_verified_at    TEXT,
    kyc_expires_at     TEXT,
    kyc_document_type  TEXT,
    risk_rating        TEXT NOT NULL CHECK (risk_rating IN ('low','medium','high')),
    customer_since     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    account_id          TEXT PRIMARY KEY,
    customer_id         TEXT NOT NULL REFERENCES customers(customer_id),
    account_number      TEXT NOT NULL UNIQUE,
    account_type        TEXT NOT NULL CHECK (account_type IN ('savings','current','salary','fixed_deposit')),
    balance             REAL NOT NULL DEFAULT 0,
    currency            TEXT NOT NULL DEFAULT 'INR',
    status              TEXT NOT NULL CHECK (status IN ('active','frozen','closed')),
    branch_code         TEXT,
    opened_at           TEXT NOT NULL,
    last_txn_at         TEXT,
    is_dormant          INTEGER NOT NULL DEFAULT 0,
    overdraft_limit     REAL NOT NULL DEFAULT 0,
    interest_rate       REAL NOT NULL DEFAULT 0,
    avg_monthly_balance REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS transactions (
    txn_id               TEXT PRIMARY KEY,
    account_id           TEXT NOT NULL REFERENCES accounts(account_id),
    txn_ts               TEXT NOT NULL,
    amount               REAL NOT NULL,
    direction            TEXT NOT NULL CHECK (direction IN ('credit','debit')),
    channel              TEXT NOT NULL,
    category             TEXT NOT NULL,
    counterparty         TEXT,
    counterparty_account TEXT,
    balance_after        REAL NOT NULL,
    description          TEXT
);
CREATE INDEX IF NOT EXISTS idx_transactions_account_ts ON transactions(account_id, txn_ts DESC);

CREATE TABLE IF NOT EXISTS loan_products (
    product_id           TEXT PRIMARY KEY,
    name                 TEXT NOT NULL,
    category             TEXT NOT NULL,
    description          TEXT,
    min_amount           REAL NOT NULL,
    max_amount           REAL NOT NULL,
    min_tenure_months    INTEGER NOT NULL,
    max_tenure_months    INTEGER NOT NULL,
    interest_rate_apr    REAL NOT NULL,
    processing_fee_pct   REAL NOT NULL DEFAULT 0,
    allowed_risk_ratings TEXT NOT NULL,
    status               TEXT NOT NULL CHECK (status IN ('active','discontinued'))
);

CREATE TABLE IF NOT EXISTS loan_applications (
    application_id           TEXT PRIMARY KEY,
    customer_id              TEXT NOT NULL,      -- opaque reference; products_server cannot dereference it
    product_id               TEXT NOT NULL REFERENCES loan_products(product_id),
    requested_amount         REAL NOT NULL,
    tenure_months            INTEGER NOT NULL,
    applicant_risk_rating    TEXT NOT NULL,
    purpose                  TEXT,
    status                   TEXT NOT NULL CHECK (status IN ('submitted','under_review','approved','rejected','withdrawn')),
    submitted_at             TEXT NOT NULL,
    submitted_by             TEXT NOT NULL,
    kyc_status_at_submission TEXT NOT NULL,
    decision_notes           TEXT
);

CREATE TABLE IF NOT EXISTS communications_log (
    communication_id INTEGER PRIMARY KEY,
    customer_id      TEXT NOT NULL REFERENCES customers(customer_id),
    channel          TEXT NOT NULL,
    message_type     TEXT NOT NULL,
    template_name    TEXT,
    message          TEXT NOT NULL,
    status           TEXT NOT NULL,
    sent_at          TEXT NOT NULL,
    performed_by     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fraud_flags (
    flag_id     TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(customer_id),
    account_id  TEXT,
    severity    TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    flag_type   TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL CHECK (status IN ('open','resolved')),
    raised_at   TEXT NOT NULL,
    resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id      INTEGER PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    action_type   TEXT NOT NULL,
    performed_by  TEXT NOT NULL,
    customer_id   TEXT,
    outcome       TEXT NOT NULL CHECK (outcome IN ('SUCCESS','BLOCKED','FAILED','DENIED')),
    details       TEXT,               -- JSON, already PII-redacted
    source_server TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_customer_ts ON audit_log(customer_id, timestamp DESC);
"""

ALL_TABLES = ("customers", "accounts", "transactions", "loan_products", "loan_applications",
              "communications_log", "fraud_flags", "audit_log")


# ------------------------------------------------------------------- seed data
# Deterministic fixtures: the Showcase Scenario (Priya Sharma / CUS-10042 / PROD-PL-01) and one
# customer per KYC state so every guardrail branch is reachable from the demo and the tests.
CUSTOMERS = [
    # id, name, email, phone, dob, city, tier, kyc_status, verified_at, expires_at, doc, risk, since
    ("CUS-10042", "Priya Sharma", "priya.sharma@example.in", "+919812345678", "1990-04-12", "Pune",
     "gold", "verified", "2024-01-15T10:30:00+05:30", "2029-01-15T00:00:00+05:30", "aadhaar", "low", "2019-06-01"),
    ("CUS-10043", "Rahul Verma", "rahul.verma@example.in", "+919823456789", "1995-11-02", "Delhi",
     "silver", "pending", None, None, None, "medium", "2026-08-20"),
    ("CUS-10044", "Anita Desai", "anita.desai@example.in", "+919834567890", "1982-07-19", "Mumbai",
     "platinum", "verified", "2023-05-10T09:00:00+05:30", "2028-05-10T00:00:00+05:30", "passport", "low", "2015-03-11"),
    ("CUS-10045", "Vikram Iyer", "vikram.iyer@example.in", "+919845678901", "1978-01-30", "Chennai",
     "basic", "rejected", None, None, "pan", "high", "2026-07-02"),
    ("CUS-10046", "Meera Nair", "meera.nair@example.in", "+919856789012", "1998-09-08", "Kochi",
     "silver", "verified", "2025-02-01T14:15:00+05:30", "2030-02-01T00:00:00+05:30", "aadhaar", "medium", "2022-11-25"),
    ("CUS-10047", "Arjun Mehta", None, "+919867890123", "1969-12-24", "Ahmedabad",
     "gold", "expired", "2019-03-03T11:00:00+05:30", "2024-03-03T00:00:00+05:30", "voter_id", "low", "2012-01-17"),
]

ACCOUNTS = [
    # id, customer, number, type, balance, currency, status, branch, opened, last_txn, dormant, od_limit, rate, amb
    ("ACC-20001", "CUS-10042", "50100234567891", "savings", 482350.75, "INR", "active", "PUN001",
     "2019-06-01", "2026-09-28T18:42:00+05:30", 0, 0.0, 3.5, 410200.00),
    ("ACC-20002", "CUS-10042", "50100234567892", "salary", 96500.00, "INR", "active", "PUN001",
     "2021-04-15", "2026-09-30T09:05:00+05:30", 0, 50000.0, 3.0, 88000.00),
    ("ACC-20003", "CUS-10043", "50100345678901", "savings", 15200.40, "INR", "active", "DEL014",
     "2026-08-20", "2026-09-25T12:10:00+05:30", 0, 0.0, 3.5, 14000.00),
    ("ACC-20004", "CUS-10044", "50100456789012", "current", 2350000.00, "INR", "frozen", "MUM003",
     "2015-03-11", "2026-09-29T16:20:00+05:30", 0, 500000.0, 0.0, 1900000.00),
    ("ACC-20005", "CUS-10045", "50100567890123", "savings", 820.00, "INR", "active", "CHE007",
     "2026-07-02", "2026-07-02T10:00:00+05:30", 1, 0.0, 3.5, 820.00),
    ("ACC-20006", "CUS-10046", "50100678901234", "savings", 145670.10, "INR", "active", "KOC002",
     "2022-11-25", "2026-09-27T20:30:00+05:30", 0, 0.0, 3.5, 132000.00),
    ("ACC-20007", "CUS-10046", "50100678901235", "fixed_deposit", 500000.00, "INR", "active", "KOC002",
     "2025-01-10", "2025-01-10T11:00:00+05:30", 0, 0.0, 7.1, 500000.00),
    ("ACC-20008", "CUS-10047", "50100789012345", "savings", 67890.00, "INR", "active", "AHM005",
     "2012-01-17", "2026-09-15T13:45:00+05:30", 0, 0.0, 3.5, 70000.00),
    ("ACC-20009", "CUS-10044", "50100456789013", "savings", 0.00, "INR", "closed", "MUM003",
     "2016-08-01", "2024-02-29T10:00:00+05:30", 1, 0.0, 3.5, 0.00),
]

TRANSACTIONS = [
    # txn_id, account, ts, amount, direction, channel, category, counterparty, cp_account, balance_after, description
    ("TXN-300001", "ACC-20001", "2026-09-01T09:00:00+05:30", 125000.00, "credit", "neft", "salary", "Infotech Solutions Pvt Ltd", "12345678901234", 402850.75, "Salary Sep 2026"),
    ("TXN-300002", "ACC-20001", "2026-09-03T19:22:00+05:30", 2499.00, "debit", "upi", "shopping", "Flipkart", None, 400351.75, "UPI/Flipkart/ORD8891"),
    ("TXN-300003", "ACC-20001", "2026-09-05T08:15:00+05:30", 18000.00, "debit", "neft", "rent", "Mrs Kulkarni", "98765432109876", 382351.75, "Rent September"),
    ("TXN-300004", "ACC-20001", "2026-09-07T13:40:00+05:30", 1200.00, "debit", "card", "dining", "Cafe Goodluck", None, 381151.75, "POS 4412 Cafe Goodluck"),
    ("TXN-300005", "ACC-20001", "2026-09-10T10:05:00+05:30", 4500.00, "debit", "upi", "utilities", "MSEDCL", None, 376651.75, "Electricity bill"),
    ("TXN-300006", "ACC-20001", "2026-09-12T16:30:00+05:30", 15000.00, "debit", "auto_debit", "investment", "NeoBank Mutual Fund SIP", None, 361651.75, "SIP Sep 2026"),
    ("TXN-300007", "ACC-20001", "2026-09-15T11:11:00+05:30", 3000.00, "credit", "upi", "transfer_in", "Meera Nair", "50100678901234", 364651.75, "UPI from Meera"),
    ("TXN-300008", "ACC-20001", "2026-09-18T20:45:00+05:30", 899.00, "debit", "card", "subscription", "Netflix", None, 363752.75, "Netflix monthly"),
    ("TXN-300009", "ACC-20001", "2026-09-20T09:30:00+05:30", 120000.00, "credit", "imps", "transfer_in", "Priya Sharma (salary a/c)", "50100234567892", 483752.75, "Self transfer"),
    ("TXN-300010", "ACC-20001", "2026-09-22T14:00:00+05:30", 650.00, "debit", "upi", "groceries", "BigBasket", None, 483102.75, "UPI/BigBasket"),
    ("TXN-300011", "ACC-20001", "2026-09-26T18:10:00+05:30", 252.00, "debit", "upi", "transport", "Uber", None, 482850.75, "UPI/Uber"),
    ("TXN-300012", "ACC-20001", "2026-09-28T18:42:00+05:30", 500.00, "debit", "upi", "dining", "Swiggy", None, 482350.75, "UPI/Swiggy"),
    ("TXN-300013", "ACC-20002", "2026-09-01T08:55:00+05:30", 125000.00, "credit", "neft", "salary", "Infotech Solutions Pvt Ltd", "12345678901234", 216500.00, "Salary Sep 2026"),
    ("TXN-300014", "ACC-20002", "2026-09-20T09:29:00+05:30", 120000.00, "debit", "imps", "transfer_out", "Priya Sharma (savings)", "50100234567891", 96500.00, "Self transfer"),
    ("TXN-300015", "ACC-20002", "2026-09-30T09:05:00+05:30", 0.00, "credit", "system", "interest", "NeoBank", None, 96500.00, "Quarterly interest (rounded)"),
    ("TXN-300016", "ACC-20003", "2026-08-21T10:00:00+05:30", 15000.00, "credit", "cash", "deposit", "Branch DEL014", None, 15000.00, "Initial deposit"),
    ("TXN-300017", "ACC-20003", "2026-09-10T12:00:00+05:30", 1200.00, "debit", "upi", "shopping", "Amazon", None, 13800.00, "UPI/Amazon"),
    ("TXN-300018", "ACC-20003", "2026-09-25T12:10:00+05:30", 1400.40, "credit", "upi", "transfer_in", "Friend", "11112222333344", 15200.40, "UPI from friend"),
    ("TXN-300019", "ACC-20004", "2026-09-27T09:00:00+05:30", 1500000.00, "credit", "rtgs", "business_receipt", "Desai Exports LLP", "44445555666677", 3850000.00, "Invoice 2211"),
    ("TXN-300020", "ACC-20004", "2026-09-28T09:05:00+05:30", 750000.00, "debit", "rtgs", "transfer_out", "Overseas Ltd", "88889999000011", 3100000.00, "Wire transfer"),
    ("TXN-300021", "ACC-20004", "2026-09-29T16:20:00+05:30", 750000.00, "debit", "rtgs", "transfer_out", "Overseas Ltd", "88889999000011", 2350000.00, "Wire transfer (velocity alert)"),
    ("TXN-300022", "ACC-20006", "2026-09-01T09:10:00+05:30", 62000.00, "credit", "neft", "salary", "Kerala Health Services", "55556666777788", 140670.10, "Salary Sep 2026"),
    ("TXN-300023", "ACC-20006", "2026-09-15T11:10:00+05:30", 3000.00, "debit", "upi", "transfer_out", "Priya Sharma", "50100234567891", 137670.10, "UPI to Priya"),
    ("TXN-300024", "ACC-20006", "2026-09-27T20:30:00+05:30", 8000.00, "credit", "upi", "transfer_in", "Cousin", "22223333444455", 145670.10, "Gift"),
    ("TXN-300025", "ACC-20008", "2026-09-15T13:45:00+05:30", 12000.00, "credit", "neft", "pension", "EPFO", None, 67890.00, "Pension Sep 2026"),
]

LOAN_PRODUCTS = [
    # id, name, category, description, min_amt, max_amt, min_ten, max_ten, apr, fee_pct, risk csv, status
    ("PROD-PL-01", "Personal Loan - Standard", "personal", "Unsecured personal loan for salaried customers.",
     50000, 1500000, 12, 60, 11.5, 1.0, "low,medium", "active"),
    ("PROD-PL-02", "Personal Loan - Premium", "personal", "Lower-rate personal loan for gold/platinum tier, low-risk applicants.",
     100000, 2500000, 12, 72, 10.25, 0.5, "low", "active"),
    ("PROD-HL-01", "Home Loan - Standard", "home", "Secured home loan against residential property.",
     500000, 50000000, 60, 360, 8.4, 0.25, "low,medium", "active"),
    ("PROD-CL-01", "Car Loan", "vehicle", "New and used car financing.",
     100000, 5000000, 12, 84, 9.2, 0.5, "low,medium,high", "active"),
    ("PROD-EL-01", "Education Loan", "education", "Domestic and overseas education financing with moratorium.",
     50000, 4000000, 12, 180, 9.0, 0.0, "low,medium", "active"),
    ("PROD-GL-01", "Gold Loan", "secured", "Short-tenure loan against pledged gold.",
     10000, 2000000, 3, 36, 12.0, 0.0, "low,medium,high", "active"),
    ("PROD-BL-01", "Business Loan (legacy)", "business", "Discontinued unsecured MSME product.",
     200000, 10000000, 12, 60, 14.0, 2.0, "low", "discontinued"),
]

FRAUD_FLAGS = [
    # id, customer, account, severity, type, description, status, raised, resolved
    ("FRD-40001", "CUS-10044", "ACC-20004", "high", "velocity_anomaly",
     "Two RTGS transfers of Rs 7.5 lakh to the same overseas beneficiary within 31 hours.",
     "open", "2026-09-29T16:25:00+05:30", None),
    ("FRD-40002", "CUS-10042", "ACC-20001", "low", "card_retry",
     "Three declined card attempts at a single merchant; customer confirmed genuine.",
     "resolved", "2026-06-11T21:00:00+05:30", "2026-06-12T10:15:00+05:30"),
    ("FRD-40003", "CUS-10046", "ACC-20006", "medium", "new_device_login",
     "Login from a previously unseen device followed by a beneficiary addition.",
     "open", "2026-09-26T22:05:00+05:30", None),
]


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    conn.commit()


@trace(logger)
def seed_database(conn: sqlite3.Connection) -> dict[str, int]:
    """Insert the deterministic fixtures. Idempotent: existing rows are replaced, never duplicated."""
    with conn:
        conn.executemany("INSERT OR REPLACE INTO customers VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", CUSTOMERS)
        conn.executemany("INSERT OR REPLACE INTO accounts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ACCOUNTS)
        conn.executemany("INSERT OR REPLACE INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?)", TRANSACTIONS)
        conn.executemany("INSERT OR REPLACE INTO loan_products VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", LOAN_PRODUCTS)
        conn.executemany("INSERT OR REPLACE INTO fraud_flags VALUES (?,?,?,?,?,?,?,?,?)", FRAUD_FLAGS)
    return table_counts(conn)


def table_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ALL_TABLES}


@trace(logger)
def init_database(path: str | None = None, *, seed: bool = True, reset: bool = False) -> dict[str, Any]:
    """Create (optionally wipe) the database file, build the schema and seed it."""
    db_path = get_db_path(path)
    if reset:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_path + suffix)
            except FileNotFoundError:
                pass
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = connect_admin(db_path)
    try:
        init_schema(conn)
        counts = seed_database(conn) if seed else table_counts(conn)
    finally:
        conn.close()
    return {"path": db_path, "seeded": seed, "reset": reset, "row_counts": counts}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build and seed the BankForge SQLite database.")
    parser.add_argument("--seed", action="store_true", help="insert the deterministic fixture data")
    parser.add_argument("--reset", action="store_true", help="delete the existing database file first")
    parser.add_argument("--path", default=None, help="database file (default: $BANKFORGE_DB_PATH or ./neobank.db)")
    args = parser.parse_args(argv)
    from logging_config import configure_logging
    configure_logging(os.getenv("LOG_LEVEL", "INFO"))
    result = init_database(args.path, seed=args.seed, reset=args.reset)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
