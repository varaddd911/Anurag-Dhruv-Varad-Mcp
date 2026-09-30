"""products_server - loan catalogue, eligibility and loan applications.

Data access: ``loan_products`` (read), ``loan_applications`` (read/write). No customer tables at
all: the KYC gate and audit trail for submit_loan_application are obtained from
compliance_comms_server through ``compliance_gateway`` (MCP streamable-http by default).
Run with ``python -m products_server [--transport ...]``.
"""
SERVER_NAME = "products_server"
