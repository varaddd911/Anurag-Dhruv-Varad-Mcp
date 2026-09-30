import json
import sys

from server_runtime import run_server

from . import SERVER_NAME


def _audit_tail(argv: list[str]) -> int:
    """``python -m compliance_comms_server --audit-tail [N]`` prints the newest audit rows and exits."""
    from logging_config import configure_logging
    from . import service

    configure_logging("WARNING")
    limit = int(argv[0]) if argv else 20
    print(json.dumps(service.get_audit_entries(limit=limit), indent=2, default=str))
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--audit-tail":
        sys.exit(_audit_tail(sys.argv[2:]))
    from .server import mcp

    run_server(mcp, SERVER_NAME)
