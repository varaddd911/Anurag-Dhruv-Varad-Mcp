from server_runtime import run_server

from . import SERVER_NAME
from .server import mcp

if __name__ == "__main__":
    run_server(mcp, SERVER_NAME)
