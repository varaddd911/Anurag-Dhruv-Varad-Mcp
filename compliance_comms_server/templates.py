"""Filesystem Markdown templates for customer communications.

Template files live in ``communication_templates/<name>.md`` (override the directory with
``COMMUNICATION_TEMPLATES_DIR``). Each file has a small ``---`` front-matter block
(``subject``, ``message_type``, ``channel_hint``) followed by a Markdown body with
``{{placeholder}}`` slots. Template names are validated against ``^[a-z0-9_]{1,64}$`` and
the resolved path is checked to stay inside the templates directory, so a name can never
escape into the filesystem.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Mapping

from errors import TemplateNotFoundError, TemplateRenderError
from guardrails import redact_for_logging, validate_template_name
from logging_config import get_logger, trace

from . import SERVER_NAME

logger = get_logger(f"bankforge.{SERVER_NAME}.templates")

PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")
FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)
_DEFAULT_DIR = Path(__file__).resolve().parent.parent / "communication_templates"


def templates_dir() -> Path:
    return Path(os.getenv("COMMUNICATION_TEMPLATES_DIR") or _DEFAULT_DIR).resolve()


@trace(logger)
def list_templates() -> list[str]:
    directory = templates_dir()
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.md"))


def _parse(raw: str) -> tuple[dict[str, str], str]:
    meta: dict[str, str] = {}
    body = raw
    match = FRONT_MATTER_RE.match(raw)
    if match:
        for line in match.group(1).splitlines():
            if ":" in line:
                key, _, value = line.partition(":")
                meta[key.strip().lower()] = value.strip()
        body = raw[match.end():]
    return meta, body.strip("\n")


@trace(logger)
def load_template(template_name: str) -> dict[str, Any]:
    """Read and parse one template. Raises ``TemplateNotFoundError`` for unknown/invalid names."""
    name = validate_template_name(template_name)
    directory = templates_dir()
    path = (directory / f"{name}.md").resolve()
    if directory not in path.parents or not path.is_file():
        raise TemplateNotFoundError(f"template '{name}' not found", template_name=name,
                                    available=sorted(p.stem for p in directory.glob("*.md")) if directory.is_dir() else [])
    meta, body = _parse(path.read_text(encoding="utf-8"))
    placeholders = sorted(set(PLACEHOLDER_RE.findall(body)) | set(PLACEHOLDER_RE.findall(meta.get("subject", ""))))
    return {
        "template_name": name,
        "path": str(path),
        "subject_template": meta.get("subject", name.replace("_", " ").title()),
        "message_type": meta.get("message_type", "transactional"),
        "channel_hint": meta.get("channel_hint", "email"),
        "placeholders": placeholders,
        "body_template": body,
    }


@trace(logger, redact=redact_for_logging)
def render_template(template_name: str, context: Mapping[str, Any]) -> dict[str, Any]:
    """Fill every ``{{placeholder}}``. Missing keys are an error - we never send half-rendered text."""
    template = load_template(template_name)
    missing = [p for p in template["placeholders"] if p not in context or context[p] is None]
    if missing:
        raise TemplateRenderError(f"template '{template['template_name']}' is missing values for {missing}",
                                  template_name=template["template_name"], missing=missing)

    def _sub(match: re.Match[str]) -> str:
        return str(context[match.group(1)])

    return {
        "template_name": template["template_name"],
        "message_type": template["message_type"],
        "channel_hint": template["channel_hint"],
        "subject": PLACEHOLDER_RE.sub(_sub, template["subject_template"]),
        "body": PLACEHOLDER_RE.sub(_sub, template["body_template"]),
        "placeholders_filled": template["placeholders"],
    }
