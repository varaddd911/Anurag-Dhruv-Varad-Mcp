"""FastMCP registration for compliance_comms_server: 6 Tools, 1 Resource, 1 Prompt."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from logging_config import jsonable

from . import SERVER_NAME, service

mcp = FastMCP(
    SERVER_NAME,
    instructions=(
        "NeoBank India compliance and communications. get_kyc_status is the only source of raw KYC data. "
        "run_compliance_check is deterministic. send_customer_communication sanitises input, enforces the "
        "KYC marketing rule and audits every attempt. Templates live under template://{template_name}."
    ),
)

mcp.tool()(service.get_kyc_status)
mcp.tool()(service.run_compliance_check)
mcp.tool()(service.send_customer_communication)
mcp.tool()(service.get_fraud_flags)
mcp.tool()(service.write_audit_log)
mcp.tool()(service.generate_customer_communication)


@mcp.resource("template://{template_name}", mime_type="application/json",
              description="A communication template from communication_templates/ with its placeholder list.")
def template_resource(template_name: str) -> str:
    return json.dumps(jsonable(service.get_template_resource(template_name)), indent=2)


@mcp.prompt(name="customer_communication_prompt",
            description="Drafting instructions that route the client through generate -> KYC gate -> send.")
def customer_communication_prompt(template_name: str, customer_name: str, account_tier: str,
                                  specific_detail: str) -> str:
    return service.customer_communication_prompt(template_name, customer_name, account_tier, specific_detail)
