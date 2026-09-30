import asyncio
import inspect
import io
import json
import logging

import pytest

from guardrails import redact_for_logging
from logging_config import JsonFormatter, configure_logging, trace


@pytest.fixture
def captured():
    stream = io.StringIO()
    logger = logging.getLogger("test.trace")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    yield logger, stream
    logger.removeHandler(handler)


def _lines(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


def test_enter_and_exit_lines_share_call_id_and_are_valid_json(captured):
    logger, stream = captured

    @trace(logger)
    def add(a, b=2):
        return a + b

    assert add(1) == 3
    lines = _lines(stream)
    assert [l["event"] for l in lines] == ["ENTER", "EXIT"]
    assert lines[0]["call_id"] == lines[1]["call_id"]
    assert lines[0]["level"] == "DEBUG" and lines[1]["level"] == "DEBUG"
    assert lines[0]["function"].endswith("add")
    assert lines[0]["arguments"] == {"a": 1, "b": 2}
    assert isinstance(lines[1]["duration_ms"], float)
    assert lines[1]["result_preview"] == "3"


def test_failed_line_has_traceback_and_exception_is_reraised(captured):
    logger, stream = captured

    @trace(logger)
    def boom():
        raise ValueError("nope")

    with pytest.raises(ValueError):
        boom()
    lines = _lines(stream)
    assert [l["event"] for l in lines] == ["ENTER", "FAILED"]
    failed = lines[1]
    assert failed["level"] == "ERROR"
    assert failed["exception_type"] == "ValueError"
    assert "Traceback" in failed["traceback"]
    assert failed["call_id"] == lines[0]["call_id"]
    assert "duration_ms" in failed


def test_redact_hook_masks_pii_in_arguments_and_results(captured):
    logger, stream = captured

    @trace(logger, redact=redact_for_logging)
    def lookup(customer_id, email, message):
        return {"customer_id": customer_id, "phone": "+919812345678"}

    lookup("CUS-10042", "priya@example.in", "hello there")
    enter, exit_ = _lines(stream)
    assert enter["arguments"]["customer_id"] == "CUS-***42"
    assert enter["arguments"]["email"] == "p***@example.in"
    assert enter["arguments"]["message"].startswith("<redacted")
    assert "CUS-10042" not in stream.getvalue()
    assert "+919812345678" not in stream.getvalue()
    assert "CUS-***42" in exit_["result_preview"]


def test_failed_lines_and_list_results_are_scrubbed(captured):
    logger, stream = captured

    @trace(logger, redact=redact_for_logging)
    def fails(customer_id):
        raise LookupError(f"customer {customer_id} (priya.sharma@example.in, +919812345678) does not exist")

    @trace(logger, redact=redact_for_logging)
    def listing():
        return [{"customer_id": "CUS-10043", "note": "account 50100234567891"}]

    with pytest.raises(LookupError):
        fails("CUS-10042")
    listing()
    raw = stream.getvalue()
    for leaked in ("CUS-10042", "CUS-10043", "priya.sharma@example.in", "+919812345678", "50100234567891"):
        assert leaked not in raw
    failed = _lines(stream)[1]
    assert "CUS-***42" in failed["exception_message"] and "CUS-***42" in failed["traceback"]
    assert "Traceback" in failed["traceback"]


def test_result_preview_is_truncated(captured):
    logger, stream = captured

    @trace(logger, preview_len=50)
    def big():
        return "x" * 500

    big()
    assert len(_lines(stream)[1]["result_preview"]) == 50


def test_async_functions_are_traced(captured):
    logger, stream = captured

    @trace(logger)
    async def later(x):
        await asyncio.sleep(0)
        return x * 2

    assert asyncio.run(later(4)) == 8
    assert [l["event"] for l in _lines(stream)] == ["ENTER", "EXIT"]


def test_signature_and_metadata_preserved_for_fastmcp_introspection(captured):
    logger, _ = captured

    @trace(logger)
    def documented(account_id: str, limit: int = 20) -> dict:
        """Docstring survives."""
        return {}

    assert documented.__name__ == "documented"
    assert documented.__doc__ == "Docstring survives."
    assert list(inspect.signature(documented).parameters) == ["account_id", "limit"]


def test_configure_logging_defaults_to_debug_and_emits_json(monkeypatch):
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    stream = io.StringIO()
    root = configure_logging(stream=stream)
    assert root.level == logging.DEBUG
    logging.getLogger("bankforge.test").debug("hello", extra={"k": 1})
    line = json.loads(stream.getvalue().strip().splitlines()[-1])
    assert line["event"] == "hello" and line["k"] == 1 and line["level"] == "DEBUG"


def test_configure_logging_honours_env_level(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    stream = io.StringIO()
    root = configure_logging(stream=stream)
    assert root.level == logging.WARNING


def test_log_file_appends_by_default_and_truncates_with_file_mode_w(tmp_path):
    """The demo reports how many trace lines *it* wrote, which only holds if it truncates."""
    path = tmp_path / "trace.jsonl"

    def emit(mode: str) -> int:
        configure_logging("DEBUG", stream=io.StringIO(), log_file=str(path), file_mode=mode)
        logging.getLogger("bankforge.test").debug("line")
        for handler in list(logging.getLogger().handlers):
            handler.flush()
        return len(path.read_text(encoding="utf-8").strip().splitlines())

    assert emit("a") == 1
    assert emit("a") == 2      # a server appends across restarts
    assert emit("w") == 1      # the demo starts each run from an empty file
