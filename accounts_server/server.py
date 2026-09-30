"""FastMCP registration for accounts_server: 3 Tools, 2 Resources, 1 Prompt."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from logging_config import jsonable

from . import SERVER_NAME, service

mcp = FastMCP(
    SERVER_NAME,
    instructions=(
        "NeoBank India account data. Every tool needs an explicit caller_scope "
        "(teller | loan_officer | compliance_officer | admin). Account numbers are always masked. "
        "IDs look like CUS-10042 / ACC-20001."
    ),
)

# Tools - the traced service functions are registered directly so there is exactly one implementation.
mcp.tool()(service.get_account_summary)
mcp.tool()(service.get_accounts_for_customer)
mcp.tool()(service.get_transaction_history)


@mcp.resource("customer://{customer_id}/profile", mime_type="application/json",
              description="Masked customer profile with teller-scope account list. No KYC detail.")
def customer_profile(customer_id: str) -> str:
    return json.dumps(jsonable(service.get_customer_profile(customer_id)), indent=2)


@mcp.resource("account://{account_id}/summary", mime_type="application/json",
              description="Teller-scope account summary. Account number masked to last four digits.")
def account_summary(account_id: str) -> str:
    return json.dumps(jsonable(service.get_account_summary_resource(account_id)), indent=2)


@mcp.prompt(name="transaction_analysis_prompt",
            description="Analyst instructions for reviewing a customer's transactions over a period.")
def transaction_analysis_prompt(customer_name: str, account_type: str, analysis_period: str) -> str:
    return service.transaction_analysis_prompt(customer_name, account_type, analysis_period)
