"""Registration against the *real* mcp package (FastMCP), not a stub."""
import asyncio
import json

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from accounts_server.server import mcp as accounts_mcp
from compliance_comms_server.server import mcp as compliance_mcp
from products_server.server import mcp as products_mcp
from tests.conftest import PERSONAL_LOAN, PRIYA, PRIYA_SAVINGS

EXPECTED_TOOLS = {
    accounts_mcp: {"get_account_summary", "get_accounts_for_customer", "get_transaction_history"},
    products_mcp: {"list_loan_products", "get_loan_product_details", "check_eligibility_criteria",
                   "submit_loan_application", "get_loan_application_status"},
    compliance_mcp: {"get_kyc_status", "run_compliance_check", "send_customer_communication", "get_fraud_flags",
                     "write_audit_log", "generate_customer_communication"},
}
EXPECTED_RESOURCES = {
    accounts_mcp: {"customer://{customer_id}/profile", "account://{account_id}/summary"},
    products_mcp: {"product://{product_id}/details"},
    compliance_mcp: {"template://{template_name}"},
}
EXPECTED_PROMPTS = {
    accounts_mcp: {"transaction_analysis_prompt"},
    products_mcp: set(),
    compliance_mcp: {"customer_communication_prompt"},
}


def run(coro):
    return asyncio.run(coro)


def test_fourteen_tools_four_resources_two_prompts():
    total_tools = total_resources = total_prompts = 0
    for server, names in EXPECTED_TOOLS.items():
        tools = run(server.list_tools())
        assert {t.name for t in tools} == names
        assert all(t.description for t in tools), "every tool needs a docstring-derived description"
        total_tools += len(tools)
        templates = run(server.list_resource_templates())
        assert {t.uriTemplate for t in templates} == EXPECTED_RESOURCES[server]
        total_resources += len(templates)
        prompts = run(server.list_prompts())
        assert {p.name for p in prompts} == EXPECTED_PROMPTS[server]
        total_prompts += len(prompts)
    assert (total_tools, total_resources, total_prompts) == (14, 4, 2)


def test_tool_schemas_expose_typed_parameters():
    tools = {t.name: t for t in run(accounts_mcp.list_tools())}
    props = tools["get_account_summary"].inputSchema["properties"]
    assert set(props) == {"account_id", "caller_scope"}
    assert set(tools["get_account_summary"].inputSchema["required"]) == {"account_id", "caller_scope"}
    submit = {t.name: t for t in run(products_mcp.list_tools())}["submit_loan_application"]
    assert {"customer_id", "product_id", "requested_amount", "tenure_months", "applicant_risk_rating"} <= set(submit.inputSchema["required"])


def test_call_tool_through_fastmcp():
    result = run(accounts_mcp.call_tool("get_account_summary", {"account_id": PRIYA_SAVINGS, "caller_scope": "teller"}))
    payload = result[1] if isinstance(result, tuple) else json.loads(result[0].text)
    assert payload["account_number"] == "**********7891" and "customer_id" not in payload


def test_typed_errors_surface_as_tool_errors_with_code():
    with pytest.raises(ToolError) as exc:
        run(accounts_mcp.call_tool("get_account_summary", {"account_id": "bad", "caller_scope": "teller"}))
    assert "INVALID_ID_FORMAT" in str(exc.value)
    with pytest.raises(ToolError) as exc:
        run(products_mcp.call_tool("submit_loan_application", {
            "customer_id": "CUS-10043", "product_id": PERSONAL_LOAN, "requested_amount": 100000,
            "tenure_months": 24, "applicant_risk_rating": "medium"}))
    assert "KYC_GATE_BLOCKED" in str(exc.value)


def test_read_resources_through_fastmcp():
    contents = run(accounts_mcp.read_resource(f"account://{PRIYA_SAVINGS}/summary"))
    data = json.loads(list(contents)[0].content)
    assert data["account_number"] == "**********7891" and data["caller_scope"] == "teller"
    profile = json.loads(list(run(accounts_mcp.read_resource(f"customer://{PRIYA}/profile")))[0].content)
    assert profile["full_name"] == "Priya Sharma" and "kyc_status" not in profile
    product = json.loads(list(run(products_mcp.read_resource(f"product://{PERSONAL_LOAN}/details")))[0].content)
    assert product["product_id"] == PERSONAL_LOAN
    template = json.loads(list(run(compliance_mcp.read_resource("template://loan_approval")))[0].content)
    assert "approved_amount" in template["placeholders"]


def test_get_prompts_through_fastmcp():
    result = run(accounts_mcp.get_prompt("transaction_analysis_prompt", {
        "customer_name": "Priya Sharma", "account_type": "savings", "analysis_period": "Sep 2026"}))
    assert "get_transaction_history" in result.messages[0].content.text
    result = run(compliance_mcp.get_prompt("customer_communication_prompt", {
        "template_name": "welcome", "customer_name": "Priya Sharma", "account_tier": "gold",
        "specific_detail": "opened a savings account"}))
    assert "template://welcome" in result.messages[0].content.text
