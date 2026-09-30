"""Business logic for products_server (5 tools + product resource)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from database import ScopedDB, connect_scoped
from errors import (
    ApplicationNotFoundError,
    BankForgeError,
    ComplianceUnavailableError,
    InvalidArgumentError,
    KycGateError,
    LoanEligibilityError,
    ProductNotFoundError,
)
from guardrails import (
    can_submit_loan_application,
    redact_for_logging,
    sanitize_free_text,
    validate_amount,
    validate_application_id,
    validate_customer_id,
    validate_product_id,
)
from logging_config import get_logger, trace

from . import SERVER_NAME
from .compliance_gateway import ComplianceGateway, gateway_from_env

logger = get_logger(f"bankforge.{SERVER_NAME}")

LOAN_CATEGORIES: tuple[str, ...] = ("personal", "home", "vehicle", "education", "secured", "business")
RISK_RATINGS: tuple[str, ...] = ("low", "medium", "high")
MAX_TENURE_MONTHS = 480
ACTION_SUBMIT_LOAN = "SUBMIT_LOAN_APPLICATION"

_gateway: ComplianceGateway | None = None


def get_compliance_gateway() -> ComplianceGateway:
    global _gateway
    if _gateway is None:
        _gateway = gateway_from_env()
    return _gateway


def set_compliance_gateway(gateway: ComplianceGateway | None) -> None:
    """Dependency injection for the demo/tests (``None`` resets to the env-configured gateway)."""
    global _gateway
    _gateway = gateway


def _db() -> ScopedDB:
    return connect_scoped(SERVER_NAME)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _product_dict(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    out["allowed_risk_ratings"] = [r for r in str(row["allowed_risk_ratings"]).split(",") if r]
    for key in ("min_amount", "max_amount", "interest_rate_apr", "processing_fee_pct"):
        out[key] = round(float(out[key]), 2)
    return out


def _fetch_product(db: ScopedDB, product_id: str) -> dict[str, Any]:
    row = db.query_one("SELECT * FROM loan_products WHERE product_id = ?", (product_id,))
    if row is None:
        raise ProductNotFoundError(f"loan product {product_id} does not exist", product_id=product_id)
    return _product_dict(row)


def _risk(value: Any) -> str:
    if not isinstance(value, str) or value.strip().lower() not in RISK_RATINGS:
        raise InvalidArgumentError(f"applicant_risk_rating must be one of {list(RISK_RATINGS)}",
                                   field="applicant_risk_rating", received=value)
    return value.strip().lower()


def _tenure(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TENURE_MONTHS:
        raise InvalidArgumentError(f"tenure_months must be an integer between 1 and {MAX_TENURE_MONTHS}",
                                   field="tenure_months", received=value)
    return value


def _evaluate(product: dict[str, Any], risk: str, amount: float | None, tenure: int | None) -> dict[str, Any]:
    checks = [
        {"check": "product_active", "passed": product["status"] == "active",
         "detail": f"status is '{product['status']}'"},
        {"check": "risk_rating_allowed", "passed": risk in product["allowed_risk_ratings"],
         "detail": f"'{risk}' vs allowed {product['allowed_risk_ratings']}"},
    ]
    if amount is not None:
        checks.append({"check": "amount_within_range",
                       "passed": product["min_amount"] <= amount <= product["max_amount"],
                       "detail": f"{amount:,.2f} vs [{product['min_amount']:,.0f}, {product['max_amount']:,.0f}]"})
    if tenure is not None:
        checks.append({"check": "tenure_within_range",
                       "passed": product["min_tenure_months"] <= tenure <= product["max_tenure_months"],
                       "detail": f"{tenure} months vs [{product['min_tenure_months']}, {product['max_tenure_months']}]"})
    failed = [c["check"] for c in checks if not c["passed"]]
    return {"eligible": not failed, "checks": checks, "failed_checks": failed}


# ------------------------------------------------------------------------ tools
@trace(logger, redact=redact_for_logging)
def list_loan_products(category: str | None = None, include_discontinued: bool = False) -> dict[str, Any]:
    """Browse the loan catalogue, optionally filtered by category
    (personal | home | vehicle | education | secured | business)."""
    if category is not None:
        if not isinstance(category, str) or category.strip().lower() not in LOAN_CATEGORIES:
            raise InvalidArgumentError(f"category must be one of {list(LOAN_CATEGORIES)}", field="category",
                                       received=category)
        category = category.strip().lower()
    with _db() as db:
        sql, params = "SELECT * FROM loan_products", []
        clauses = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if not include_discontinued:
            clauses.append("status = 'active'")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        rows = db.query(sql + " ORDER BY category, product_id", tuple(params))
    return {"category": category, "count": len(rows), "products": [_product_dict(r) for r in rows]}


@trace(logger, redact=redact_for_logging)
def get_loan_product_details(product_id: str) -> dict[str, Any]:
    """Full detail for one loan product (PROD-XX-XX)."""
    product_id = validate_product_id(product_id)
    with _db() as db:
        return _fetch_product(db, product_id)


@trace(logger, redact=redact_for_logging)
def check_eligibility_criteria(product_id: str, applicant_risk_rating: str, requested_amount: float | None = None,
                               tenure_months: int | None = None) -> dict[str, Any]:
    """Criteria-only check (no write, no customer data): product status, allowed risk ratings and,
    when supplied, amount and tenure ranges."""
    product_id = validate_product_id(product_id)
    risk = _risk(applicant_risk_rating)
    amount = validate_amount(requested_amount, field="requested_amount") if requested_amount is not None else None
    tenure = _tenure(tenure_months) if tenure_months is not None else None
    with _db() as db:
        product = _fetch_product(db, product_id)
    return {"product_id": product_id, "product_name": product["name"], "applicant_risk_rating": risk,
            **_evaluate(product, risk, amount, tenure)}


def _next_application_id(db: ScopedDB) -> str:
    row = db.query_one("SELECT MAX(CAST(SUBSTR(application_id, 5) AS INTEGER)) AS n FROM loan_applications")
    return f"APP-{(row['n'] or 0) + 1:06d}"


@trace(logger, redact=redact_for_logging)
def submit_loan_application(customer_id: str, product_id: str, requested_amount: float, tenure_months: int,
                            applicant_risk_rating: str, purpose: str | None = None,
                            submitted_by: str = "loan_officer") -> dict[str, Any]:
    """Create a loan application. Order of enforcement, all server-side:
    1. argument validation (IDs, amount, tenure, risk rating, free text);
    2. product eligibility;
    3. KYC gate via compliance_comms_server - unverified KYC is refused, and if the compliance
       server cannot be reached the request fails closed (nothing is written);
    4. audit entry first, then the application row: no row can exist without its audit entry."""
    customer_id = validate_customer_id(customer_id)
    product_id = validate_product_id(product_id)
    amount = validate_amount(requested_amount, field="requested_amount")
    tenure = _tenure(tenure_months)
    risk = _risk(applicant_risk_rating)
    purpose_clean = sanitize_free_text(purpose, field="purpose", max_length=300) if purpose else None
    submitted_by = sanitize_free_text(submitted_by, field="submitted_by", max_length=64)
    gateway = get_compliance_gateway()
    base_detail = {"product_id": product_id, "requested_amount": amount, "tenure_months": tenure,
                   "applicant_risk_rating": risk, "gateway": gateway.name}

    def _audit_best_effort(outcome: str, extra: dict[str, Any]) -> int | None:
        try:
            return gateway.write_audit_log(ACTION_SUBMIT_LOAN, submitted_by, outcome, customer_id,
                                           {**base_detail, **extra})["audit_id"]
        except ComplianceUnavailableError:
            logger.warning("audit entry could not be written - compliance server unavailable",
                           extra={"action": ACTION_SUBMIT_LOAN, "outcome": outcome})
            return None

    with _db() as db:
        product = _fetch_product(db, product_id)
        evaluation = _evaluate(product, risk, amount, tenure)
        if not evaluation["eligible"]:
            audit_id = _audit_best_effort("BLOCKED", {"reason": "LOAN_NOT_ELIGIBLE", "failed_checks": evaluation["failed_checks"]})
            raise LoanEligibilityError(
                f"application does not meet criteria for {product_id}: failed {evaluation['failed_checks']}",
                product_id=product_id, failed_checks=evaluation["failed_checks"], checks=evaluation["checks"],
                audit_id=audit_id,
            )

        # KYC gate. ComplianceUnavailableError propagates untouched: fail closed, nothing written.
        try:
            kyc = gateway.get_kyc_status(customer_id)
        except ComplianceUnavailableError:
            raise
        except BankForgeError as exc:  # e.g. CUSTOMER_NOT_FOUND from the compliance server
            exc.details["audit_id"] = _audit_best_effort("FAILED", {"reason": exc.code})
            raise
        allowed, reason = can_submit_loan_application(kyc.get("kyc_status"))
        if not allowed:
            audit_id = _audit_best_effort("BLOCKED", {"reason": "KYC_GATE_BLOCKED", "kyc_status": kyc.get("kyc_status")})
            raise KycGateError(reason, customer_id=customer_id, kyc_status=kyc.get("kyc_status"), audit_id=audit_id)

        submitted_at = _now()
        application_id = _next_application_id(db)
        # Audit FIRST, then insert. Both servers share one SQLite file, and SQLite allows a single
        # writer: holding a products_server write transaction open while compliance_comms_server
        # writes the audit row would deadlock ("database is locked"). Writing the audit entry first
        # keeps the fail-closed guarantee (compliance down -> ComplianceUnavailableError -> nothing
        # inserted); a failed insert afterwards is followed by a compensating FAILED entry.
        audit = gateway.write_audit_log(ACTION_SUBMIT_LOAN, submitted_by, "SUCCESS", customer_id,
                                        {**base_detail, "application_id": application_id})
        try:
            db.execute(
                "INSERT INTO loan_applications (application_id, customer_id, product_id, requested_amount, tenure_months, "
                "applicant_risk_rating, purpose, status, submitted_at, submitted_by, kyc_status_at_submission) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (application_id, customer_id, product_id, amount, tenure, risk, purpose_clean, "submitted",
                 submitted_at, submitted_by, kyc["kyc_status"]),
            )
        except BaseException as exc:
            _audit_best_effort("FAILED", {"reason": "INSERT_FAILED", "application_id": application_id,
                                          "error": type(exc).__name__, "supersedes_audit_id": audit["audit_id"]})
            raise
    return {
        "application_id": application_id,
        "status": "submitted",
        "customer_id": customer_id,
        "product_id": product_id,
        "product_name": product["name"],
        "requested_amount": amount,
        "tenure_months": tenure,
        "applicant_risk_rating": risk,
        "interest_rate_apr": product["interest_rate_apr"],
        "kyc_status_at_submission": kyc["kyc_status"],
        "submitted_at": submitted_at,
        "submitted_by": submitted_by,
        "audit_id": audit["audit_id"],
    }


@trace(logger, redact=redact_for_logging)
def get_loan_application_status(application_id: str) -> dict[str, Any]:
    """Status of a stored loan application (APP-XXXXXX)."""
    application_id = validate_application_id(application_id)
    with _db() as db:
        row = db.query_one(
            "SELECT a.*, p.name AS product_name FROM loan_applications a JOIN loan_products p "
            "ON p.product_id = a.product_id WHERE a.application_id = ?", (application_id,))
    if row is None:
        raise ApplicationNotFoundError(f"loan application {application_id} does not exist", application_id=application_id)
    row["requested_amount"] = round(float(row["requested_amount"]), 2)
    return row


# -------------------------------------------------------------------- resources
@trace(logger, redact=redact_for_logging)
def get_product_details_resource(product_id: str) -> dict[str, Any]:
    """Backing data for ``product://{product_id}/details`` (same lookup as the tool)."""
    return get_loan_product_details(product_id)
