"""Shared fixtures: every test gets a freshly seeded SQLite file and an in-process compliance gateway."""
from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from database import init_database  # noqa: E402
from logging_config import configure_logging  # noqa: E402
from products_server import service as products_service  # noqa: E402
from products_server.compliance_gateway import InProcessComplianceGateway  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _json_logging():
    # JSON trace lines for the whole run land in logs/pytest_trace.jsonl for line-by-line inspection.
    configure_logging("DEBUG", log_file=str(ROOT / "logs" / "pytest_trace.jsonl"))


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    db_path = tmp_path / "neobank_test.db"
    monkeypatch.setenv("BANKFORGE_DB_PATH", str(db_path))
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("COMPLIANCE_GATEWAY", "inprocess")
    init_database(str(db_path), seed=True, reset=True)
    products_service.set_compliance_gateway(InProcessComplianceGateway())
    yield str(db_path)
    products_service.set_compliance_gateway(None)


# Well-known fixture identities (see database.py)
PRIYA = "CUS-10042"          # verified KYC, gold, low risk  - Showcase Scenario
RAHUL = "CUS-10043"          # pending KYC
ANITA = "CUS-10044"          # verified but open HIGH fraud flag
VIKRAM = "CUS-10045"         # rejected KYC
MEERA = "CUS-10046"          # verified, open MEDIUM fraud flag
ARJUN = "CUS-10047"          # expired KYC, no e-mail on file
MISSING_CUSTOMER = "CUS-99999"
PRIYA_SAVINGS = "ACC-20001"
PERSONAL_LOAN = "PROD-PL-01"
