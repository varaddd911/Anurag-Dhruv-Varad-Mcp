# BankForge - MCP Server Ecosystem for Digital Banking

Three independently deployable MCP servers for the fictional **NeoBank India**, built from
scratch on the official `mcp` Python SDK (FastMCP), backed by one SQLite database with
engine-enforced per-server table isolation, structured JSON tracing on every primitive, and a
dedicated guardrails module.

| Server | Port (streamable-http / sse) | Tools | Resources | Prompts |
|---|---|---|---|---|
| `accounts_server` | 8001 / 8011 | 3 | `customer://{id}/profile`, `account://{id}/summary` | `transaction_analysis_prompt` |
| `products_server` | 8002 / 8012 | 5 | `product://{id}/details` | - |
| `compliance_comms_server` | 8003 / 8013 | 6 | `template://{name}` | `customer_communication_prompt` |

14 Tools, 4 Resources, 2 Prompts. Design rationale, data model and the honest
"what did not work" log live in [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows      |  source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt   # mcp<2 (FastMCP API) + pytest

python database.py --seed --reset # build + seed ./neobank.db (deterministic fixtures)
python run_local_demo.py          # every scenario from the brief, no MCP client needed
pytest                            # 140 tests incl. live stdio + streamable-http server tests
```

`run_local_demo.py` uses its own `neobank_demo.db`, exits non-zero if any expectation fails, and
writes the full DEBUG trace to `logs/demo_trace.jsonl` (add `--verbose` to stream it to stderr).

## Running the servers

Each server is a plain local Python process. Default transport is `stdio` (what Claude Desktop
speaks); the HTTP transports use the ports in the table above.

```bash
python -m accounts_server                                   # stdio
python -m products_server --transport streamable-http       # http://127.0.0.1:8002/mcp
python -m compliance_comms_server --transport sse           # http://127.0.0.1:8013/sse
python -m compliance_comms_server --audit-tail 20           # print newest audit rows and exit
```

Flags: `--transport stdio|streamable-http|sse`, `--host`, `--port`, `--db PATH`, `--no-bootstrap`
(fail instead of auto-creating a missing database).

### products_server needs a KYC source

`products_server` has **no access to customer tables**, so `submit_loan_application` asks
`compliance_comms_server` for the KYC status and writes its audit entry there. Pick the gateway
with `COMPLIANCE_GATEWAY`:

| value | behaviour |
|---|---|
| `http` (default) | real MCP client to `COMPLIANCE_SERVER_URL` (default `http://127.0.0.1:8003/mcp`). Start compliance with `--transport streamable-http` first. If it is down, submissions fail closed with `COMPLIANCE_SERVER_UNAVAILABLE`. |
| `inprocess` | calls the compliance service functions in-process (still on their own scoped DB connection). Handy for Claude Desktop stdio setups and the demo. |
| `offline` | always unavailable - used to demonstrate stress test 3. |

### Claude Desktop

Copy the entries from [claude_desktop_config.example.json](claude_desktop_config.example.json)
into your `claude_desktop_config.json`, replacing `<REPO>` and `<PYTHON>`.

### Environment variables

| variable | default | purpose |
|---|---|---|
| `LOG_LEVEL` | `DEBUG` | JSON log verbosity (stderr) |
| `LOG_FILE` | unset | also append JSON lines to this file |
| `BANKFORGE_DB_PATH` | `./neobank.db` | SQLite file shared by the servers |
| `COMPLIANCE_GATEWAY` | `http` | see above |
| `COMPLIANCE_SERVER_URL` | `http://127.0.0.1:8003/mcp` | target for the http gateway |
| `COMMUNICATION_TEMPLATES_DIR` | `./communication_templates` | Markdown template folder |
| `MCP_TRANSPORT` / `MCP_HOST` | `stdio` / `127.0.0.1` | defaults for the CLI flags |

## Repository layout

```
errors.py                    typed error hierarchy (stable codes, e.g. KYC_GATE_BLOCKED)
logging_config.py            JSON formatter + @trace(logger) decorator (ENTER/EXIT/FAILED)
guardrails.py                ID validation, scope minimisation, masking, sanitisation, redaction,
                             KYC gates, deterministic compliance rules
database.py                  schema, seed data, SQLite-authorizer-scoped connections, CLI
server_runtime.py            shared argparse / port plan / bootstrap for `python -m <server>`
accounts_server/             service.py (logic)  server.py (FastMCP registration)  __main__.py
products_server/             + compliance_gateway.py (http | inprocess | offline)
compliance_comms_server/     + templates.py (Markdown renderer)
communication_templates/     7 Markdown templates with {{placeholders}} and front-matter
tests/                       140 pytest tests (unit, FastMCP registration, live servers)
run_local_demo.py            graded demo script (spec section 8)
```

## Tool inventory

| Server | Tool | Notes |
|---|---|---|
| accounts | `get_account_summary(account_id, caller_scope)` | fields minimised per scope, number masked |
| accounts | `get_accounts_for_customer(customer_id, caller_scope)` | same minimisation per account |
| accounts | `get_transaction_history(account_id, limit=20)` | newest first, limit 1..100, counterparties masked |
| products | `list_loan_products(category=None, include_discontinued=False)` | |
| products | `get_loan_product_details(product_id)` | |
| products | `check_eligibility_criteria(product_id, applicant_risk_rating, requested_amount=None, tenure_months=None)` | read-only |
| products | `submit_loan_application(customer_id, product_id, requested_amount, tenure_months, applicant_risk_rating, purpose=None, submitted_by=...)` | **write**; eligibility -> KYC gate via compliance -> audit -> insert |
| products | `get_loan_application_status(application_id)` | `APP-XXXXXX` |
| compliance | `get_kyc_status(customer_id)` | only source of raw KYC data |
| compliance | `run_compliance_check(customer_id, transaction_amount)` | deterministic PASS/BLOCK + large-transaction flag (>= Rs 10 lakh) |
| compliance | `send_customer_communication(customer_id, channel, message, message_type="transactional", performed_by=...)` | **write**; sanitised, KYC marketing gate, audited |
| compliance | `get_fraud_flags(customer_id, include_resolved=False)` | |
| compliance | `write_audit_log(action_type, performed_by, outcome, customer_id=None, details=None)` | **write**; append-only, details PII-redacted |
| compliance | `generate_customer_communication(customer_id, template_name, context=None)` | renders `communication_templates/*.md` |

Errors are raised as typed exceptions and reach MCP clients as tool errors of the form
`[CODE] message`, e.g. `[INVALID_ID_FORMAT] customer_id 'CUS-1' does not match ...`.

## Seed data worth knowing

| Customer | ID | KYC | Why it exists |
|---|---|---|---|
| Priya Sharma | `CUS-10042` | verified | Showcase Scenario (accounts `ACC-20001`, `ACC-20002`) |
| Rahul Verma | `CUS-10043` | pending | KYC-blocked transaction / marketing / loan |
| Anita Desai | `CUS-10044` | verified | open HIGH fraud flag -> compliance BLOCK |
| Vikram Iyer | `CUS-10045` | rejected | second KYC-gate case |
| Meera Nair | `CUS-10046` | verified | open MEDIUM fraud flag -> PASS with review note |
| Arjun Mehta | `CUS-10047` | expired | no e-mail on file -> channel validation |

Loan products: `PROD-PL-01/02` personal, `PROD-HL-01` home, `PROD-CL-01` car, `PROD-EL-01`
education, `PROD-GL-01` gold, `PROD-BL-01` discontinued (invalid-submission fixture).
