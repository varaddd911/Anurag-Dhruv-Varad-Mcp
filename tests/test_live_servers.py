"""Each server started as a real local process and driven by a real MCP client.

* stdio: ``python -m <server>`` for all three servers -> initialize, list_tools, call a tool, read a resource.
* streamable-http: compliance_comms_server on a free port; products_server reaches it through
  ``HttpComplianceGateway`` for a real cross-process KYC gate, and a closed port proves fail-closed.
"""
from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
from datetime import timedelta

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tests.conftest import PERSONAL_LOAN, PRIYA, PRIYA_SAVINGS, ROOT


def _env(db_path: str) -> dict[str, str]:
    return {**os.environ, "PYTHONPATH": str(ROOT), "BANKFORGE_DB_PATH": db_path, "LOG_LEVEL": "WARNING",
            "COMPLIANCE_GATEWAY": "inprocess", "PYTHONUNBUFFERED": "1"}


async def _drive_stdio(server: str, db_path: str, tool: str, args: dict, resource: str | None):
    params = StdioServerParameters(command=sys.executable, args=["-m", server], env=_env(db_path), cwd=str(ROOT))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            tools = await session.list_tools()
            result = await session.call_tool(tool, args, read_timeout_seconds=timedelta(seconds=30))
            resource_payload = None
            if resource:
                res = await session.read_resource(resource)
                resource_payload = json.loads(res.contents[0].text)
            return init.serverInfo.name, {t.name for t in tools.tools}, result, resource_payload


@pytest.mark.parametrize("server,tool,args,resource,expect_key", [
    ("accounts_server", "get_account_summary", {"account_id": PRIYA_SAVINGS, "caller_scope": "teller"},
     f"account://{PRIYA_SAVINGS}/summary", "account_number"),
    ("products_server", "get_loan_product_details", {"product_id": PERSONAL_LOAN},
     f"product://{PERSONAL_LOAN}/details", "product_id"),
    ("compliance_comms_server", "get_kyc_status", {"customer_id": PRIYA},
     "template://welcome", "template_name"),
])
def test_server_starts_over_stdio_and_answers_a_live_client(fresh_db, server, tool, args, resource, expect_key):
    name, tools, result, resource_payload = asyncio.run(_drive_stdio(server, fresh_db, tool, args, resource))
    assert name == server
    assert len(tools) == {"accounts_server": 3, "products_server": 5, "compliance_comms_server": 6}[server]
    assert not result.isError
    payload = json.loads(result.content[0].text)
    assert expect_key in payload or expect_key in (resource_payload or {})
    if server == "accounts_server":
        assert payload["account_number"] == "**********7891"
    assert resource_payload and expect_key in resource_payload


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, proc: subprocess.Popen, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"server exited early with code {proc.returncode}: {proc.stderr.read().decode(errors='replace')[-2000:]}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"port {port} never opened")


@pytest.fixture
def compliance_http_server(fresh_db):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "compliance_comms_server", "--transport", "streamable-http", "--port", str(port)],
        cwd=str(ROOT), env=_env(fresh_db), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        _wait_for_port(port, proc)
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_products_server_gates_kyc_through_a_live_compliance_server(compliance_http_server):
    from errors import ComplianceUnavailableError, CustomerNotFoundError, KycGateError
    from products_server import service as products
    from products_server.compliance_gateway import HttpComplianceGateway

    gateway = HttpComplianceGateway(compliance_http_server, timeout_seconds=15)
    assert gateway.get_kyc_status(PRIYA)["kyc_status"] == "verified"
    with pytest.raises(CustomerNotFoundError):          # remote typed error rebuilt locally
        gateway.get_kyc_status("CUS-99999")

    products.set_compliance_gateway(gateway)
    ok = products.submit_loan_application(PRIYA, PERSONAL_LOAN, 500000, 36, "low")
    assert ok["application_id"] == "APP-000001" and ok["audit_id"] >= 1
    with pytest.raises(KycGateError):
        products.submit_loan_application("CUS-10043", PERSONAL_LOAN, 500000, 36, "low")

    # audit rows really landed in the compliance server's table
    from compliance_comms_server import service as compliance
    outcomes = [e["outcome"] for e in compliance.get_audit_entries(action_type="SUBMIT_LOAN_APPLICATION")]
    assert outcomes == ["BLOCKED", "SUCCESS"]

    # offline: point at a port nobody listens on -> fail closed, nothing written
    products.set_compliance_gateway(HttpComplianceGateway(f"http://127.0.0.1:{_free_port()}/mcp", timeout_seconds=3))
    with pytest.raises(ComplianceUnavailableError):
        products.submit_loan_application(PRIYA, PERSONAL_LOAN, 500000, 36, "low")
    assert products.get_loan_application_status("APP-000001")["status"] == "submitted"
    from errors import ApplicationNotFoundError
    with pytest.raises(ApplicationNotFoundError):
        products.get_loan_application_status("APP-000002")
