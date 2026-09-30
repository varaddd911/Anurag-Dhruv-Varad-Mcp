"""How products_server reaches compliance_comms_server without touching customer tables.

Three interchangeable gateways implement the same two calls (``get_kyc_status`` and
``write_audit_log``):

* ``HttpComplianceGateway``      - real MCP client over streamable-http (production path,
                                   default; ``COMPLIANCE_SERVER_URL``, default http://127.0.0.1:8003/mcp)
* ``InProcessComplianceGateway`` - calls the compliance *service functions* directly. Used by the
                                   demo and tests so they run without live servers. The compliance
                                   code still runs on its own scoped connection, so table isolation
                                   is unchanged.
* ``OfflineComplianceGateway``   - always raises ``ComplianceUnavailableError`` (stress test 3).

Every transport failure is normalised to ``ComplianceUnavailableError`` so the caller can fail
closed with one ``except`` clause. Remote typed errors (``[CUSTOMER_NOT_FOUND] ...``) are rebuilt
into the matching local exception class.
"""
from __future__ import annotations

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Protocol

from errors import BankForgeError, ComplianceUnavailableError, error_from_remote_message
from guardrails import redact_for_logging
from logging_config import get_logger, trace

from . import SERVER_NAME

logger = get_logger(f"bankforge.{SERVER_NAME}.gateway")
DEFAULT_COMPLIANCE_URL = "http://127.0.0.1:8003/mcp"


class ComplianceGateway(Protocol):
    name: str

    def get_kyc_status(self, customer_id: str) -> dict[str, Any]: ...

    def write_audit_log(self, action_type: str, performed_by: str, outcome: str,
                        customer_id: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]: ...


class InProcessComplianceGateway:
    name = "inprocess"

    @trace(logger, redact=redact_for_logging)
    def get_kyc_status(self, customer_id: str) -> dict[str, Any]:
        from compliance_comms_server import service as compliance
        return compliance.get_kyc_status(customer_id)

    @trace(logger, redact=redact_for_logging)
    def write_audit_log(self, action_type: str, performed_by: str, outcome: str,
                        customer_id: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
        from compliance_comms_server import service as compliance
        return compliance.write_audit_log(action_type, performed_by, outcome, customer_id, details)


class OfflineComplianceGateway:
    name = "offline"

    def __init__(self, reason: str = "compliance_comms_server is offline (simulated)") -> None:
        self.reason = reason

    @trace(logger, redact=redact_for_logging)
    def get_kyc_status(self, customer_id: str) -> dict[str, Any]:
        raise ComplianceUnavailableError(self.reason, gateway=self.name)

    @trace(logger, redact=redact_for_logging)
    def write_audit_log(self, action_type: str, performed_by: str, outcome: str,
                        customer_id: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
        raise ComplianceUnavailableError(self.reason, gateway=self.name)


class HttpComplianceGateway:
    name = "http"

    def __init__(self, url: str | None = None, timeout_seconds: float = 5.0) -> None:
        self.url = url or os.getenv("COMPLIANCE_SERVER_URL") or DEFAULT_COMPLIANCE_URL
        self.timeout = timeout_seconds

    async def _call_async(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        from datetime import timedelta

        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        async with streamablehttp_client(self.url, timeout=self.timeout, sse_read_timeout=self.timeout) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool, arguments, read_timeout_seconds=timedelta(seconds=self.timeout))
        text = "".join(getattr(c, "text", "") for c in result.content)
        if result.isError:
            raise error_from_remote_message(text)
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict):
            return structured["result"] if set(structured) == {"result"} else structured
        return json.loads(text) if text else {}

    def _call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        # Tool functions are synchronous and may be invoked from inside FastMCP's running event
        # loop, so the client round-trip runs on a private loop in a helper thread.
        def runner() -> dict[str, Any]:
            return asyncio.run(self._call_async(tool, arguments))

        try:
            with ThreadPoolExecutor(max_workers=1, thread_name_prefix="compliance-gw") as pool:
                return pool.submit(runner).result(timeout=self.timeout * 3)
        except BankForgeError:
            raise
        except BaseException as exc:  # ExceptionGroup, httpx errors, timeouts, OSError...
            leaf = exc
            while isinstance(leaf, BaseExceptionGroup) and leaf.exceptions:  # noqa: F821 (py3.11+)
                leaf = leaf.exceptions[0]
            if isinstance(leaf, BankForgeError):
                raise leaf from exc
            raise ComplianceUnavailableError(
                f"could not reach compliance_comms_server at {self.url}: {type(leaf).__name__}: {leaf}",
                gateway=self.name, url=self.url,
            ) from exc

    @trace(logger, redact=redact_for_logging)
    def get_kyc_status(self, customer_id: str) -> dict[str, Any]:
        return self._call("get_kyc_status", {"customer_id": customer_id})

    @trace(logger, redact=redact_for_logging)
    def write_audit_log(self, action_type: str, performed_by: str, outcome: str,
                        customer_id: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
        return self._call("write_audit_log", {"action_type": action_type, "performed_by": performed_by,
                                              "outcome": outcome, "customer_id": customer_id, "details": details})


def gateway_from_env() -> ComplianceGateway:
    """``COMPLIANCE_GATEWAY`` = http (default) | inprocess | offline."""
    kind = (os.getenv("COMPLIANCE_GATEWAY") or "http").strip().lower()
    if kind == "inprocess":
        return InProcessComplianceGateway()
    if kind == "offline":
        return OfflineComplianceGateway()
    if kind == "http":
        return HttpComplianceGateway()
    raise BankForgeError(f"unknown COMPLIANCE_GATEWAY '{kind}'", allowed=["http", "inprocess", "offline"])
