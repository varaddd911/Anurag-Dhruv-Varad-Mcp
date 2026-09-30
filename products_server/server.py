"""FastMCP registration for products_server: 5 Tools, 1 Resource."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from logging_config import jsonable

from . import SERVER_NAME, service

mcp = FastMCP(
    SERVER_NAME,
    instructions=(
        "NeoBank India loan catalogue and applications. Product IDs look like PROD-PL-01. "
        "submit_loan_application enforces the KYC gate itself by consulting compliance_comms_server; "
        "if that server is unreachable the submission is refused."
    ),
)

mcp.tool()(service.list_loan_products)
mcp.tool()(service.get_loan_product_details)
mcp.tool()(service.check_eligibility_criteria)
mcp.tool()(service.submit_loan_application)
mcp.tool()(service.get_loan_application_status)


@mcp.resource("product://{product_id}/details", mime_type="application/json",
              description="Loan product detail (rates, limits, tenure, allowed risk ratings).")
def product_details(product_id: str) -> str:
    return json.dumps(jsonable(service.get_product_details_resource(product_id)), indent=2)
