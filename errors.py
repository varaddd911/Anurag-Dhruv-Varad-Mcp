"""Typed error hierarchy shared by all BankForge servers.

Every error carries a stable machine-readable ``code`` so MCP clients (and the
demo/test suites) can branch on the *type* of failure rather than parsing text.
FastMCP surfaces raised exceptions as tool errors, so raising these from the
service layer is the MCP-idiomatic way to return "typed errors".
"""
from __future__ import annotations

from typing import Any


class BankForgeError(Exception):
    """Base class for all domain errors. ``code`` is stable and machine-readable."""

    code = "BANKFORGE_ERROR"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "message": self.message, "details": self.details}

    def __str__(self) -> str:  # what MCP clients will see
        return f"[{self.code}] {self.message}"


# --- input / validation -----------------------------------------------------
class InvalidIdFormatError(BankForgeError):
    code = "INVALID_ID_FORMAT"


class InvalidScopeError(BankForgeError):
    code = "INVALID_CALLER_SCOPE"


class InvalidArgumentError(BankForgeError):
    code = "INVALID_ARGUMENT"


class FreeTextRejectedError(InvalidArgumentError):
    """Free text failed sanitisation for a non-malicious reason (e.g. too long)."""

    code = "FREE_TEXT_REJECTED"


class InjectionDetectedError(InvalidArgumentError):
    """Free text matched a prompt-injection signature. Always blocked and audited."""

    code = "PROMPT_INJECTION_DETECTED"


# --- not found --------------------------------------------------------------
class NotFoundError(BankForgeError):
    code = "NOT_FOUND"


class CustomerNotFoundError(NotFoundError):
    code = "CUSTOMER_NOT_FOUND"


class AccountNotFoundError(NotFoundError):
    code = "ACCOUNT_NOT_FOUND"


class ProductNotFoundError(NotFoundError):
    code = "PRODUCT_NOT_FOUND"


class ApplicationNotFoundError(NotFoundError):
    code = "APPLICATION_NOT_FOUND"


class TemplateNotFoundError(NotFoundError):
    code = "TEMPLATE_NOT_FOUND"


# --- policy / guardrail outcomes ---------------------------------------------
class KycGateError(BankForgeError):
    """A write operation was blocked because the customer's KYC is not verified."""

    code = "KYC_GATE_BLOCKED"


class LoanEligibilityError(BankForgeError):
    code = "LOAN_NOT_ELIGIBLE"


class TemplateRenderError(BankForgeError):
    code = "TEMPLATE_RENDER_ERROR"


# --- infrastructure ---------------------------------------------------------
class ComplianceUnavailableError(BankForgeError):
    """compliance_comms_server could not be reached. Callers must fail closed."""

    code = "COMPLIANCE_SERVER_UNAVAILABLE"


class DataAccessViolationError(BankForgeError):
    """A server tried to touch a table outside its whitelist (SQLite authorizer denied it)."""

    code = "DATA_ACCESS_VIOLATION"


ERROR_TYPES_BY_CODE: dict[str, type[BankForgeError]] = {
    cls.code: cls
    for cls in [
        BankForgeError, InvalidIdFormatError, InvalidScopeError, InvalidArgumentError,
        FreeTextRejectedError, InjectionDetectedError, NotFoundError, CustomerNotFoundError,
        AccountNotFoundError, ProductNotFoundError, ApplicationNotFoundError,
        TemplateNotFoundError, KycGateError, LoanEligibilityError, TemplateRenderError,
        ComplianceUnavailableError, DataAccessViolationError,
    ]
}


def error_from_remote_message(text: str) -> BankForgeError:
    """Rebuild a typed error from the ``[CODE] message`` string a remote MCP tool returned."""
    text = text or ""
    for code, cls in ERROR_TYPES_BY_CODE.items():
        if f"[{code}]" in text:
            return cls(text.split(f"[{code}]", 1)[1].strip() or text)
    return BankForgeError(text or "remote tool failed")
