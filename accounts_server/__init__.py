"""accounts_server - account and transaction reads with scope-based field minimisation.

Data access: ``customers`` (read, existence checks only), ``accounts`` (read), ``transactions`` (read).
Run with ``python -m accounts_server [--transport stdio|streamable-http|sse]``.
"""
SERVER_NAME = "accounts_server"
