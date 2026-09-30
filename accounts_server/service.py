"""Business logic for accounts_server. Pure Python, no MCP dependency: the demo and the
tests call these functions directly; ``server.py`` registers the very same objects as tools.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from database import ScopedDB, connect_scoped
from errors import AccountNotFoundError, CustomerNotFoundError, InvalidArgumentError
from guardrails import (
    mask_account_number,
    mask_email,
    mask_phone,
    minimize_account_fields,
    redact_for_logging,
    sanitize_free_text,
    validate_account_id,
    validate_customer_id,
    validate_scope,
)
from logging_config import get_logger, trace

from . import SERVER_NAME

logger = get_logger(f"bankforge.{SERVER_NAME}")
MAX_TRANSACTION_LIMIT = 100
DEFAULT_TRANSACTION_LIMIT = 20
RESOURCE_SCOPE = "teller"  # resources have no caller identity -> most restrictive scope


def _db() -> ScopedDB:
    return connect_scoped(SERVER_NAME)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fetch_account(db: ScopedDB, account_id: str) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
    if row is None:
        raise AccountNotFoundError(f"account {account_id} does not exist", account_id=account_id)
    return row


def _assert_customer_exists(db: ScopedDB, customer_id: str) -> dict[str, Any]:
    row = db.query_one(
        "SELECT customer_id, full_name, email, phone, tier, city, customer_since FROM customers WHERE customer_id = ?",
        (customer_id,),
    )
    if row is None:
        raise CustomerNotFoundError(f"customer {customer_id} does not exist", customer_id=customer_id)
    return row


# ------------------------------------------------------------------------ tools
@trace(logger, redact=redact_for_logging)
def get_account_summary(account_id: str, caller_scope: str) -> dict[str, Any]:
    """Look up one account. Returned fields are minimised for ``caller_scope``
    (teller | loan_officer | compliance_officer | admin); the account number is always masked."""
    account_id = validate_account_id(account_id)
    scope = validate_scope(caller_scope)
    with _db() as db:
        row = _fetch_account(db, account_id)
    return minimize_account_fields(row, scope)


@trace(logger, redact=redact_for_logging)
def get_accounts_for_customer(customer_id: str, caller_scope: str) -> dict[str, Any]:
    """All accounts belonging to a customer, each minimised for ``caller_scope``."""
    customer_id = validate_customer_id(customer_id)
    scope = validate_scope(caller_scope)
    with _db() as db:
        _assert_customer_exists(db, customer_id)
        rows = db.query("SELECT * FROM accounts WHERE customer_id = ? ORDER BY opened_at, account_id", (customer_id,))
    return {
        "customer_id": customer_id,
        "caller_scope": scope,
        "count": len(rows),
        "accounts": [minimize_account_fields(r, scope) for r in rows],
    }


@trace(logger, redact=redact_for_logging)
def get_transaction_history(account_id: str, limit: int = DEFAULT_TRANSACTION_LIMIT) -> dict[str, Any]:
    """Most-recent-first transactions for an account. ``limit`` must be 1..100.
    Counterparty account numbers are masked."""
    account_id = validate_account_id(account_id)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise InvalidArgumentError("limit must be an integer", field="limit", received=limit)
    if not 1 <= limit <= MAX_TRANSACTION_LIMIT:
        raise InvalidArgumentError(f"limit must be between 1 and {MAX_TRANSACTION_LIMIT}", field="limit", received=limit)
    with _db() as db:
        account = _fetch_account(db, account_id)
        rows = db.query(
            "SELECT txn_id, txn_ts, amount, direction, channel, category, counterparty, counterparty_account, "
            "balance_after, description FROM transactions WHERE account_id = ? "
            "ORDER BY txn_ts DESC, txn_id DESC LIMIT ?",
            (account_id, limit),
        )
    for r in rows:
        r["counterparty_account"] = mask_account_number(r["counterparty_account"]) if r["counterparty_account"] else None
        r["amount"] = round(float(r["amount"]), 2)
        r["balance_after"] = round(float(r["balance_after"]), 2)
    return {
        "account_id": account_id,
        "account_number": mask_account_number(account["account_number"]),
        "currency": account["currency"],
        "limit": limit,
        "count": len(rows),
        "transactions": rows,
    }


# -------------------------------------------------------------------- resources
@trace(logger, redact=redact_for_logging)
def get_customer_profile(customer_id: str) -> dict[str, Any]:
    """Backing data for ``customer://{customer_id}/profile``: contact details masked, accounts at
    teller scope, and *no* KYC detail (only compliance_comms_server.get_kyc_status returns that)."""
    customer_id = validate_customer_id(customer_id)
    with _db() as db:
        customer = _assert_customer_exists(db, customer_id)
        rows = db.query("SELECT * FROM accounts WHERE customer_id = ? ORDER BY opened_at, account_id", (customer_id,))
    return {
        "customer_id": customer_id,
        "full_name": customer["full_name"],
        "tier": customer["tier"],
        "city": customer["city"],
        "customer_since": customer["customer_since"],
        "email": mask_email(customer["email"]),
        "phone": mask_phone(customer["phone"]),
        "accounts": [minimize_account_fields(r, RESOURCE_SCOPE) for r in rows],
        "generated_at": _now(),
    }


@trace(logger, redact=redact_for_logging)
def get_account_summary_resource(account_id: str) -> dict[str, Any]:
    """Backing data for ``account://{account_id}/summary`` - reuses the teller-scope minimiser."""
    return get_account_summary(account_id, RESOURCE_SCOPE)


# ---------------------------------------------------------------------- prompts
@trace(logger, redact=redact_for_logging)
def transaction_analysis_prompt(customer_name: str, account_type: str, analysis_period: str) -> str:
    """Reusable analyst instructions. Deliberately contains no account data: it tells the client
    which Tools/Resources to call so the data path stays governed by the guardrails."""
    customer_name = sanitize_free_text(customer_name, field="customer_name", max_length=100)
    account_type = sanitize_free_text(account_type, field="account_type", max_length=40)
    analysis_period = sanitize_free_text(analysis_period, field="analysis_period", max_length=60)
    return (
        f"You are a NeoBank India transaction analyst preparing a spending review for {customer_name}'s "
        f"{account_type} account covering {analysis_period}.\n\n"
        "Follow these steps, using only the tools and resources listed - never ask the user for raw account numbers:\n"
        "1. Call `get_accounts_for_customer(customer_id, caller_scope=\"teller\")` to find the customer's "
        f"{account_type} account ID (the customer ID is a CUS-XXXXX identifier the operator will supply).\n"
        "2. Call `get_transaction_history(account_id, limit=50)` for that account. Transactions arrive most-recent-first; "
        f"keep only those inside {analysis_period}.\n"
        "3. Optionally read `account://{account_id}/summary` for the current balance and status.\n"
        "4. Produce: (a) total credits vs debits, (b) top 3 spending categories with amounts, (c) any single debit "
        "above 10% of the period's total credits, (d) recurring payments (same counterparty in consecutive months), "
        "(e) one concise, neutral observation about cash-flow health.\n\n"
        "Rules: quote account numbers only in the masked form the tools return (last four digits). Do not infer or "
        "state KYC status, fraud status or creditworthiness - those belong to compliance_comms_server. If a tool "
        "returns an error such as CUSTOMER_NOT_FOUND or ACCOUNT_NOT_FOUND, report it plainly and stop."
    )
