"""Shared process entry-point logic for the three servers (argparse, ports, DB bootstrap).

Each ``python -m <server>`` module builds its FastMCP instance and hands it to
``run_server``. Transport defaults to ``stdio`` (what Claude Desktop speaks); the
HTTP transports use the port plan from the architecture diagram:

    server                    streamable-http   sse
    accounts_server           8001              8011
    products_server           8002              8012
    compliance_comms_server   8003              8013
"""
from __future__ import annotations

import argparse
import os
from typing import Any

from database import get_db_path, init_database
from logging_config import configure_logging, get_logger

SERVER_PORTS: dict[str, dict[str, int]] = {
    "accounts_server": {"streamable-http": 8001, "sse": 8011},
    "products_server": {"streamable-http": 8002, "sse": 8012},
    "compliance_comms_server": {"streamable-http": 8003, "sse": 8013},
}
TRANSPORTS = ("stdio", "streamable-http", "sse")


def build_arg_parser(server_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"python -m {server_name}", description=f"BankForge {server_name}")
    parser.add_argument("--transport", choices=TRANSPORTS, default=os.getenv("MCP_TRANSPORT", "stdio"))
    parser.add_argument("--host", default=os.getenv("MCP_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=None,
                        help="port for HTTP transports (defaults: %s)" % SERVER_PORTS[server_name])
    parser.add_argument("--db", default=None, help="SQLite file (default: $BANKFORGE_DB_PATH or ./neobank.db)")
    parser.add_argument("--no-bootstrap", action="store_true",
                        help="fail instead of creating+seeding the database when it is missing")
    return parser


def ensure_database(path: str | None, *, bootstrap: bool, logger) -> str:
    db_path = get_db_path(path)
    os.environ["BANKFORGE_DB_PATH"] = db_path  # every scoped connection in this process resolves the same file
    if not os.path.exists(db_path):
        if not bootstrap:
            raise SystemExit(f"database {db_path} not found - run `python database.py --seed` first")
        logger.warning("database missing - bootstrapping with seed data", extra={"db_path": db_path})
        init_database(db_path, seed=True)
    return db_path


def run_server(mcp: Any, server_name: str, argv: list[str] | None = None) -> None:
    args = build_arg_parser(server_name).parse_args(argv)
    configure_logging()  # LOG_LEVEL env, default DEBUG, JSON to stderr (+ LOG_FILE)
    logger = get_logger(f"bankforge.{server_name}")
    db_path = ensure_database(args.db, bootstrap=not args.no_bootstrap, logger=logger)
    port = args.port or SERVER_PORTS[server_name].get(args.transport, 8000)
    mcp.settings.host = args.host
    mcp.settings.port = port
    logger.info("server starting", extra={"server": server_name, "transport": args.transport,
                                          "host": args.host if args.transport != "stdio" else None,
                                          "port": port if args.transport != "stdio" else None,
                                          "db_path": db_path, "log_level": os.getenv("LOG_LEVEL", "DEBUG")})
    mcp.run(transport=args.transport)
