"""Security guardrails shared by every BankForge server (spec section 4).

Contents
--------
* ID format validation (``CUS-XXXXX`` / ``ACC-XXXXX`` / ``PROD-XX-XX`` / ``APP-XXXXXX``)
  with typed ``InvalidIdFormatError``;
* scoped field visibility - ``minimize_account_fields(record, caller_scope)``;
* account-number / phone / e-mail masking;
* ``sanitize_free_text`` - length limit, HTML stripping, prompt-injection signatures;
* ``redact_for_logging`` - PII-shaped argument names are masked before logging;
* KYC gates - ``can_send_communication`` / ``can_submit_loan_application``;
* deterministic compliance rules - ``evaluate_compliance``.

Nothing here touches a database: these are pure functions so every server, every
Resource and the test-suite reuse *exactly* the same logic instead of duplicating it.
"""
from __future__ import annotations

import html
import re
import unicodedata
from typing import Any, Iterable, Mapping

from errors import (
    FreeTextRejectedError,
    InjectionDetectedError,
    InvalidArgumentError,
    InvalidIdFormatError,
    InvalidScopeError,
)

# --------------------------------------------------------------------------- IDs
ID_PATTERNS: dict[str, re.Pattern[str]] = {
    "customer_id": re.compile(r"^CUS-\d{5}$"),
    "account_id": re.compile(r"^ACC-\d{5}$"),
    "product_id": re.compile(r"^PROD-[A-Z]{2}-\d{2}$"),
    "application_id": re.compile(r"^APP-\d{6}$"),
    "template_name": re.compile(r"^[a-z0-9_]{1,64}$"),
}
ID_EXAMPLES = {
    "customer_id": "CUS-10042",
    "account_id": "ACC-20001",
    "product_id": "PROD-PL-01",
    "application_id": "APP-000001",
    "template_name": "loan_application_received",
}


def validate_id(kind: str, value: Any) -> str:
    """Return the normalised ID or raise ``InvalidIdFormatError`` (typed, never a bare ValueError)."""
    pattern = ID_PATTERNS[kind]
    if not isinstance(value, str):
        raise InvalidIdFormatError(
            f"{kind} must be a string like {ID_EXAMPLES[kind]}", field=kind, received_type=type(value).__name__
        )
    candidate = value.strip()
    if not pattern.fullmatch(candidate):
        raise InvalidIdFormatError(
            f"{kind} '{candidate}' does not match the required format (expected like {ID_EXAMPLES[kind]})",
            field=kind, value=candidate, expected=pattern.pattern,
        )
    return candidate


def validate_customer_id(value: Any) -> str:
    return validate_id("customer_id", value)


def validate_account_id(value: Any) -> str:
    return validate_id("account_id", value)


def validate_product_id(value: Any) -> str:
    return validate_id("product_id", value)


def validate_application_id(value: Any) -> str:
    return validate_id("application_id", value)


def validate_template_name(value: Any) -> str:
    """Template names double as file names, so the whitelist regex also blocks path traversal."""
    return validate_id("template_name", value)


# ------------------------------------------------------------------ masking helpers
def mask_account_number(number: Any) -> str:
    """Show only the last four digits. Hard requirement everywhere account data leaves a server."""
    if number is None:
        return ""
    digits = str(number)
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_phone(phone: Any) -> str:
    if not phone:
        return ""
    text = str(phone)
    return "*" * max(len(text) - 2, 3) + text[-2:]


def mask_email(email: Any) -> str:
    if not email or "@" not in str(email):
        return "***" if email else ""
    local, _, domain = str(email).partition("@")
    return f"{local[:1]}***@{domain}"


def mask_id(value: str) -> str:
    """``CUS-10042`` -> ``CUS-***42`` : enough to correlate a log line, not enough to identify."""
    prefix, _, rest = value.partition("-")
    if not rest:
        return value[:1] + "***"
    return f"{prefix}-***{rest[-2:]}"


# ------------------------------------------------------------ scoped field visibility
CALLER_SCOPES: tuple[str, ...] = ("teller", "loan_officer", "compliance_officer", "admin")

_ACCOUNT_BASE_FIELDS = ("account_id", "account_number", "account_type", "status", "currency")
SCOPE_ACCOUNT_FIELDS: dict[str, tuple[str, ...]] = {
    # front-desk: what is needed to service a walk-in - no ownership / risk data
    "teller": _ACCOUNT_BASE_FIELDS + ("balance",),
    # underwriting: needs ownership, tenure and credit-related limits
    "loan_officer": _ACCOUNT_BASE_FIELDS + (
        "balance", "customer_id", "opened_at", "overdraft_limit", "interest_rate", "avg_monthly_balance",
    ),
    # compliance: ownership, branch, activity - but no credit-pricing details
    "compliance_officer": _ACCOUNT_BASE_FIELDS + (
        "balance", "customer_id", "opened_at", "branch_code", "last_txn_at", "is_dormant",
    ),
    # admin: everything (account number is *still* masked - masking is non-negotiable)
    "admin": _ACCOUNT_BASE_FIELDS + (
        "balance", "customer_id", "opened_at", "branch_code", "last_txn_at", "is_dormant",
        "overdraft_limit", "interest_rate", "avg_monthly_balance",
    ),
}


def validate_scope(caller_scope: Any) -> str:
    if not isinstance(caller_scope, str) or caller_scope.strip().lower() not in CALLER_SCOPES:
        raise InvalidScopeError(
            f"caller_scope must be one of {list(CALLER_SCOPES)}", received=caller_scope,
        )
    return caller_scope.strip().lower()


def minimize_account_fields(record: Mapping[str, Any], caller_scope: str) -> dict[str, Any]:
    """Return only the fields the caller's scope may see. Account numbers are always masked."""
    scope = validate_scope(caller_scope)
    allowed = SCOPE_ACCOUNT_FIELDS[scope]
    out: dict[str, Any] = {}
    for field in allowed:
        if field not in record.keys():
            continue
        value = record[field]
        if field == "account_number":
            value = mask_account_number(value)
        elif field in ("balance", "overdraft_limit", "avg_monthly_balance") and value is not None:
            value = round(float(value), 2)
        elif field == "is_dormant" and value is not None:
            value = bool(value)
        out[field] = value
    out["caller_scope"] = scope
    return out


# ------------------------------------------------------- free-text sanitisation
MAX_FREE_TEXT_LENGTH = 1000
_HTML_TAG_RE = re.compile(r"<[^>]{0,500}>")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏  ‪-‮⁠-⁤﻿]")
_WS_RE = re.compile(r"[ \t]{2,}")

INJECTION_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pat, re.IGNORECASE | re.DOTALL))
    for name, pat in [
        ("ignore_instructions", r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|all|earlier|your|the)\b.{0,40}\b(instructions?|prompts?|rules?|guidelines?|policy|policies|guardrails?)\b"),
        ("role_override", r"\byou are now\b|\bact as (?:an? |the )?(?:admin|administrator|system|developer|root|unrestricted)|\bpretend (?:to be|you are)\b"),
        ("system_prompt_probe", r"\b(reveal|show|print|repeat|leak|dump)\b.{0,40}\b(system prompt|hidden prompt|instructions|configuration|secrets?)\b"),
        ("system_prompt_literal", r"\bsystem prompt\b|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\]|<<SYS>>"),
        ("jailbreak_keywords", r"\bjailbreak\b|\bdeveloper mode\b|\bDAN mode\b|\bdo anything now\b"),
        ("guardrail_bypass", r"\b(bypass|skip|disable|turn off|circumvent)\b.{0,40}\b(kyc|compliance|audit|guardrails?|checks?|verification|validation|filters?)\b"),
        ("tool_hijack", r"\b(call|invoke|run|execute)\b.{0,30}\b(tool|function)\b.{0,60}\b(transfer|send|submit|write_audit_log|delete|drop)\b"),
        ("data_exfil", r"\b(send|email|forward|post)\b.{0,40}\b(all|every|entire)\b.{0,40}\b(customer|account|card|kyc|pan|aadhaar)\b.{0,40}\b(data|details|records|numbers?)\b"),
        ("markdown_role_block", r"(^|\n)\s*(system|assistant|user)\s*:\s"),
        ("sql_injection", r"(;|\b)(drop|delete|truncate|alter)\s+(table|from|database)\b|\bunion\s+select\b|--\s*$|'\s*or\s+'?1'?\s*=\s*'?1"),
    ]
)


def detect_injection(text: str) -> list[str]:
    """Return the names of every injection signature the text matches (empty list = clean)."""
    return [name for name, pattern in INJECTION_SIGNATURES if pattern.search(text)]


def sanitize_free_text(text: Any, *, field: str = "message", max_length: int = MAX_FREE_TEXT_LENGTH,
                       allow_empty: bool = False) -> str:
    """Normalise free text and refuse anything dangerous.

    Order matters: unescape HTML entities -> strip tags -> strip control / zero-width
    characters -> NFKC-normalise (defeats look-alike unicode obfuscation) -> length
    check -> injection-signature scan. Raises ``FreeTextRejectedError`` for benign
    problems and ``InjectionDetectedError`` for anything matching a signature.
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise FreeTextRejectedError(f"{field} must be a string", field=field, received_type=type(text).__name__)
    if len(text) > max_length * 4:  # refuse absurd payloads before doing regex work on them
        raise FreeTextRejectedError(f"{field} exceeds the maximum length of {max_length} characters",
                                    field=field, length=len(text), max_length=max_length)
    unescaped = unicodedata.normalize("NFKC", _CONTROL_RE.sub("", html.unescape(text)))
    cleaned = _HTML_TAG_RE.sub("", unescaped)
    cleaned = html.unescape(cleaned)  # entities that were hidden inside tags
    cleaned = _CONTROL_RE.sub("", cleaned)
    cleaned = unicodedata.normalize("NFKC", cleaned)
    cleaned = _WS_RE.sub(" ", cleaned).strip()
    if not cleaned and not allow_empty:
        raise FreeTextRejectedError(f"{field} must not be empty", field=field)
    if len(cleaned) > max_length:
        raise FreeTextRejectedError(f"{field} exceeds the maximum length of {max_length} characters",
                                    field=field, length=len(cleaned), max_length=max_length)
    # Scan the text both before and after tag stripping: a payload such as <|im_start|> would
    # otherwise be "cleaned away" instead of being reported and audited as an attack.
    hits = sorted(set(detect_injection(unescaped)) | set(detect_injection(cleaned)))
    if hits:
        raise InjectionDetectedError(
            f"{field} rejected: matched prompt-injection signature(s) {hits}", field=field, signatures=hits,
        )
    return cleaned


# ------------------------------------------------------------- PII-safe logging
PII_ID_KEYS = {"account_id", "customer_id", "id"}  # application_id is an opaque ticket number, not PII
PII_CONTACT_KEYS = {"phone", "phone_number", "mobile", "email", "email_address", "recipient", "to"}
PII_NAME_KEYS = {"name", "customer_name", "full_name", "first_name", "last_name", "performed_by_name"}
PII_SECRET_KEYS = {"account_number", "pan", "aadhaar", "aadhaar_number", "pan_number", "card_number", "ifsc", "password", "token", "otp"}
FREE_TEXT_KEYS = {"message", "body", "text", "specific_detail", "purpose", "details", "rendered", "content",
                  "context", "description", "notes", "subject", "message_preview"}


_SCRUB_ID_RE = re.compile(r"\b(CUS|ACC)-(\d{3})(\d{2})\b")
_SCRUB_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_SCRUB_LONG_DIGITS_RE = re.compile(r"\+?\d{10,}")


def scrub_text(text: str) -> str:
    """Pattern-based scrub for free text that may *contain* PII (exception messages, tracebacks,
    previews): customer/account IDs keep their last two digits, e-mails keep first letter + domain,
    any run of 10+ digits (phone numbers, account numbers, Aadhaar) keeps its last four."""
    text = _SCRUB_ID_RE.sub(lambda m: f"{m.group(1)}-***{m.group(3)}", text)
    text = _SCRUB_EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    text = _SCRUB_LONG_DIGITS_RE.sub(lambda m: "*" * (len(m.group(0)) - 4) + m.group(0)[-4:], text)
    return text


def _mask_value(key: str, value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [_mask_value(key, v) for v in value]
    if isinstance(value, dict):
        return redact_for_logging(value)
    text = str(value)
    if key in PII_ID_KEYS:
        return mask_id(text) if "-" in text else "***"
    if key in PII_CONTACT_KEYS:
        return mask_email(text) if "@" in text else mask_phone(text)
    if key in PII_SECRET_KEYS:
        return mask_account_number(text) if key == "account_number" else "***"
    if key in PII_NAME_KEYS:
        return text[:1] + "***" if text else ""
    return "***"


def redact_for_logging(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Mask PII-shaped keys before a structured log line is written.

    Data-minimisation rationale: logs are the widest-read artefact in the system
    (developers, SREs, log aggregators). Tracing every tool call at DEBUG would
    otherwise copy every customer/account identifier, phone, e-mail and message
    body into that channel. Redacting *by argument name* keeps the trace useful
    (you can still correlate ``CUS-***42`` across ENTER/EXIT lines and see that a
    message of length N was sent) while guaranteeing raw identifiers and message
    bodies never leave the service boundary. Unknown keys are recursed into so
    nested payloads (audit ``details``, resource JSON) are redacted too.
    """
    out: dict[str, Any] = {}
    for raw_key, value in arguments.items():
        key = str(raw_key).lower()
        if key in FREE_TEXT_KEYS:
            if isinstance(value, dict):
                out[raw_key] = redact_for_logging(value)
            elif value is None:
                out[raw_key] = None
            else:
                out[raw_key] = f"<redacted len={len(str(value))}>"
        elif key in PII_ID_KEYS or key in PII_CONTACT_KEYS or key in PII_SECRET_KEYS or key in PII_NAME_KEYS \
                or key.endswith(("_email", "_phone", "_mobile", "_account_number")):
            out[raw_key] = _mask_value(key, value)
        else:
            out[raw_key] = _scrub_any(value)
    return out


def _scrub_any(value: Any) -> Any:
    """Non-PII keys still get pattern-scrubbed: an error message or preview may embed an identifier."""
    if isinstance(value, dict):
        return redact_for_logging(value)
    if isinstance(value, (list, tuple)):
        return [_scrub_any(v) for v in value]
    if isinstance(value, str):
        return scrub_text(value)
    return value


# ------------------------------------------------------------------- KYC gates
KYC_VERIFIED = "verified"
KYC_STATUSES: tuple[str, ...] = ("verified", "pending", "rejected", "expired")
MESSAGE_TYPES: tuple[str, ...] = ("transactional", "marketing", "regulatory")
CHANNELS: tuple[str, ...] = ("sms", "email", "push")


def can_send_communication(kyc_status: str | None, message_type: str) -> tuple[bool, str]:
    """KYC-based comms rule: marketing requires verified KYC; transactional/regulatory always allowed.

    Transactional and regulatory messages (OTPs, KYC reminders, statutory notices) must
    reach unverified customers - that is how they *become* verified - so only the
    marketing category is gated.
    """
    if message_type not in MESSAGE_TYPES:
        raise InvalidArgumentError(f"message_type must be one of {list(MESSAGE_TYPES)}", received=message_type)
    if message_type == "marketing" and kyc_status != KYC_VERIFIED:
        return False, f"marketing communication blocked: customer KYC status is '{kyc_status}', not '{KYC_VERIFIED}'"
    return True, "allowed"


def can_submit_loan_application(kyc_status: str | None) -> tuple[bool, str]:
    """Loan applications are credit exposure: verified KYC is mandatory, no exceptions."""
    if kyc_status == KYC_VERIFIED:
        return True, "allowed"
    return False, f"loan application blocked: customer KYC status is '{kyc_status}', not '{KYC_VERIFIED}'"


# ------------------------------------------------- deterministic compliance rules
LARGE_TRANSACTION_THRESHOLD_INR = 1_000_000.0   # Rs 10 lakh: PMLA cash-transaction reporting threshold
ENHANCED_DUE_DILIGENCE_THRESHOLD_INR = 5_000_000.0  # Rs 50 lakh: flagged for EDD, still allowed
MAX_SINGLE_TRANSACTION_INR = 1_000_000_000.0  # Rs 100 crore: hard sanity ceiling
BLOCKING_FRAUD_SEVERITIES = ("high", "critical")


def validate_amount(amount: Any, *, field: str = "transaction_amount",
                    maximum: float = MAX_SINGLE_TRANSACTION_INR) -> float:
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise InvalidArgumentError(f"{field} must be a number", field=field, received_type=type(amount).__name__)
    value = float(amount)
    if value != value or value in (float("inf"), float("-inf")):
        raise InvalidArgumentError(f"{field} must be finite", field=field)
    if value <= 0:
        raise InvalidArgumentError(f"{field} must be greater than zero", field=field, received=value)
    if value > maximum:
        raise InvalidArgumentError(f"{field} exceeds the maximum permitted value of {maximum:,.0f}",
                                   field=field, received=value, maximum=maximum)
    return round(value, 2)


def evaluate_compliance(*, kyc_status: str | None, open_fraud_flags: Iterable[Mapping[str, Any]],
                        transaction_amount: float) -> dict[str, Any]:
    """Pure, deterministic rule engine. Same inputs always give the same decision.

    Rules (evaluated in order, all of them always run so the caller gets every reason):
    1. KYC must be ``verified``                -> otherwise BLOCK (KYC_NOT_VERIFIED)
    2. No open high/critical fraud flag        -> otherwise BLOCK (ACTIVE_FRAUD_FLAG)
    3. Amount >= Rs 10 lakh                    -> large_transaction_report = True (does *not* block)
    4. Amount >= Rs 50 lakh                    -> note ENHANCED_DUE_DILIGENCE (does not block)
    5. Open low/medium fraud flag              -> note MANUAL_REVIEW_RECOMMENDED (does not block)
    """
    flags = list(open_fraud_flags)
    block_reasons: list[str] = []
    notes: list[str] = []
    if kyc_status != KYC_VERIFIED:
        block_reasons.append(f"KYC_NOT_VERIFIED:{kyc_status}")
    blocking = [f for f in flags if str(f.get("severity", "")).lower() in BLOCKING_FRAUD_SEVERITIES]
    if blocking:
        block_reasons.append("ACTIVE_FRAUD_FLAG:" + ",".join(str(f.get("flag_id", "?")) for f in blocking))
    elif flags:
        notes.append("MANUAL_REVIEW_RECOMMENDED:open_low_or_medium_fraud_flag")
    large = transaction_amount >= LARGE_TRANSACTION_THRESHOLD_INR
    if large:
        notes.append("LARGE_TRANSACTION_REPORTED")
    if transaction_amount >= ENHANCED_DUE_DILIGENCE_THRESHOLD_INR:
        notes.append("ENHANCED_DUE_DILIGENCE")
    return {
        "decision": "BLOCK" if block_reasons else "PASS",
        "block_reasons": block_reasons,
        "notes": notes,
        "large_transaction_report": large,
        "large_transaction_threshold_inr": LARGE_TRANSACTION_THRESHOLD_INR,
        "transaction_amount": round(float(transaction_amount), 2),
        "kyc_status": kyc_status,
        "open_fraud_flag_count": len(flags),
    }
