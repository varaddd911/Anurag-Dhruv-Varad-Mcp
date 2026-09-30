"""compliance_comms_server - KYC, deterministic compliance checks, customer communications, fraud
flags and the audit log.

Data access: ``customers`` (read), ``communications_log`` (read/write), ``fraud_flags`` (read),
``audit_log`` (read/append). Run with ``python -m compliance_comms_server [--transport ...]``.
"""
SERVER_NAME = "compliance_comms_server"
BANK_NAME = "NeoBank India"
