"""Structured JSON logging and the ``@trace(logger)`` decorator.

Guarantees (see spec section 5):
* every log line is exactly one JSON object;
* ``LOG_LEVEL`` env var controls verbosity and defaults to ``DEBUG``;
* ``@trace`` emits ENTER (DEBUG) / EXIT (DEBUG) / FAILED (ERROR) lines that share a
  ``call_id``, carry ``duration_ms`` and a truncated result preview, and re-raise
  exceptions unchanged;
* log output goes to **stderr** (and optionally ``LOG_FILE``) - never stdout, because
  the MCP stdio transport owns stdout.
"""
from __future__ import annotations

import functools
import inspect
import json
import logging
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

DEFAULT_LOG_LEVEL = "DEBUG"
_RESERVED = set(logging.LogRecord("x", 0, "x", 0, "", (), None).__dict__) | {"message", "asctime"}


def jsonable(value: Any, _depth: int = 0) -> Any:
    """Convert arbitrary Python values into something ``json.dumps`` accepts."""
    if _depth > 6:
        return repr(value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        return {str(k): jsonable(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [jsonable(v, _depth + 1) for v in value]
    if isinstance(value, bytes):
        return f"<bytes len={len(value)}>"
    if hasattr(value, "keys") and hasattr(value, "__getitem__"):  # sqlite3.Row etc.
        try:
            return {str(k): jsonable(value[k], _depth + 1) for k in value.keys()}
        except Exception:  # pragma: no cover - defensive
            return repr(value)
    return repr(value)


class JsonFormatter(logging.Formatter):
    """One JSON object per line. Extra attributes passed via ``extra=`` are merged in."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, val in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = jsonable(val)
        if record.exc_info and "traceback" not in payload:
            payload["traceback"] = "".join(traceback.format_exception(*record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str | None = None, *, stream=None, log_file: str | None = None,
                      file_mode: str = "a") -> logging.Logger:
    """Install the JSON formatter on the root logger. Idempotent (re-installs our handlers).

    ``file_mode`` is the open mode for ``log_file``: ``"a"`` (default) appends, which is what a
    long-running server wants; the demo passes ``"w"`` so each run's trace file holds exactly
    that run and the line count it reports is the number of lines it actually produced.
    """
    level_name = (level or os.getenv("LOG_LEVEL") or DEFAULT_LOG_LEVEL).upper()
    root = logging.getLogger()
    root.setLevel(getattr(logging, level_name, logging.DEBUG))
    for h in list(root.handlers):
        if getattr(h, "_bankforge", False):
            root.removeHandler(h)
            h.close()
    handlers: list[logging.Handler] = [logging.StreamHandler(stream or sys.stderr)]
    log_file = log_file or os.getenv("LOG_FILE")
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, mode=file_mode, encoding="utf-8"))
    for h in handlers:
        h.setFormatter(JsonFormatter())
        h._bankforge = True  # type: ignore[attr-defined]
        root.addHandler(h)
    # third-party chatter stays out of DEBUG traces
    for noisy in ("httpx", "httpcore", "anyio", "asyncio", "uvicorn", "mcp", "sse_starlette"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return root


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def _preview(value: Any, limit: int) -> str:
    try:
        text = json.dumps(jsonable(value), ensure_ascii=False, default=str)
    except Exception:
        text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def trace(logger: logging.Logger, *, redact: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
          preview_len: int = 200) -> Callable:
    """Decorator producing ENTER / EXIT / FAILED structured lines around a call.

    ``redact`` (e.g. ``guardrails.redact_for_logging``) is applied to the bound
    arguments *and* to dict-shaped return values before they hit the log, so
    PII never reaches a log line even at DEBUG. Works for sync and async callables
    and preserves the wrapped signature (FastMCP introspects it for schemas).
    """

    def decorator(fn: Callable) -> Callable:
        qualname = f"{fn.__module__}.{fn.__qualname__}"
        sig = inspect.signature(fn)

        def _bind(args: tuple, kwargs: dict) -> dict[str, Any]:
            try:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                arguments: dict[str, Any] = dict(bound.arguments)
            except TypeError:
                arguments = {"args": list(args), "kwargs": dict(kwargs)}
            return redact(arguments) if redact else arguments

        def _enter(args: tuple, kwargs: dict) -> tuple[str, float]:
            call_id = uuid.uuid4().hex[:12]
            logger.debug("ENTER", extra={"event_type": "ENTER", "function": qualname, "call_id": call_id,
                                         "arguments": jsonable(_bind(args, kwargs))})
            return call_id, time.perf_counter()

        def _exit(call_id: str, start: float, result: Any) -> None:
            # wrap so dict / list / scalar results all pass through the same redaction rules
            shown = redact({"result": jsonable(result)})["result"] if redact else result
            logger.debug("EXIT", extra={"event_type": "EXIT", "function": qualname, "call_id": call_id,
                                        "duration_ms": round((time.perf_counter() - start) * 1000, 3),
                                        "result_preview": _preview(shown, preview_len)})

        def _failed(call_id: str, start: float, exc: BaseException) -> None:
            texts = {"exception_message": str(exc), "traceback": traceback.format_exc()}
            if redact:  # exception text and traceback frames can embed identifiers -> scrub them too
                texts = redact(texts)
            logger.error("FAILED", extra={"event_type": "FAILED", "function": qualname, "call_id": call_id,
                                          "duration_ms": round((time.perf_counter() - start) * 1000, 3),
                                          "exception_type": type(exc).__name__,
                                          "error_code": getattr(exc, "code", None), **texts})

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                call_id, start = _enter(args, kwargs)
                try:
                    result = await fn(*args, **kwargs)
                except BaseException as exc:
                    _failed(call_id, start, exc)
                    raise
                _exit(call_id, start, result)
                return result
            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_id, start = _enter(args, kwargs)
            try:
                result = fn(*args, **kwargs)
            except BaseException as exc:
                _failed(call_id, start, exc)
                raise
            _exit(call_id, start, result)
            return result
        return wrapper

    return decorator
