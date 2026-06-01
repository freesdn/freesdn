# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Structured Logging Module
=======================================

JSON-formatted logging with correlation IDs and context injection.
Supports both development (colored) and production (JSON) formats.
"""

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings

# Context variables for request correlation
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
user_id_var: ContextVar[str | None] = ContextVar("user_id", default=None)
organization_id_var: ContextVar[str | None] = ContextVar("organization_id", default=None)


# a denylist of key-name patterns we always redact when serializing
# LogRecord extras. This is a defence-in-depth guard: today no call site logs
# a raw password, but without this filter any future contributor who writes
# ``logger.info("foo", extra={"token": "abc"})`` would land the token in the
# JSON log stream. Pattern is intentionally broad (matches anywhere in the
# key) and case-insensitive.
_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|bearer|"
    r"cookie|credential|private[_-]?key|session[_-]?id|csrf|"
    r"client[_-]?secret|access[_-]?key|\brefresh[_-]?token\b)"
)

_REDACTED = "[REDACTED]"


def _redact_sensitive(obj: Any) -> Any:
    """Recursively redact sensitive keys in a structured log payload.

    Applied to every dict/list extras value before serialization so that a
    nested secret (``extra={"device": {"password": "..."}}``) is redacted
    even though the top-level key is innocuous.
    """
    if isinstance(obj, dict):
        return {
            k: (_REDACTED if _SENSITIVE_KEY_PATTERN.search(str(k)) else _redact_sensitive(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_redact_sensitive(item) for item in obj]
    return obj


# Distinctive secret FORMATS that may appear in a rendered log MESSAGE body
# (the structured-extras redaction above only covers ``extra`` keys, not the
# message string). High-precision prefixes/shapes only — near-zero false
# positives — so a future call site that interpolates a token/JWT/key into a
# message string is scrubbed, while ordinary log text is left untouched.
_BEARER_RE = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]{12,}")
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b"),  # GitHub OAuth/PAT (classic)
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),  # GitHub fine-grained PAT
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),  # Google API key
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack token
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),  # OpenAI-style secret key
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
)


def _redact_message(msg: str) -> str:
    """Redact distinctive secret formats from a rendered log message body."""
    if not msg:
        return msg
    redacted = _BEARER_RE.sub(rf"\1 {_REDACTED}", msg)
    for pat in _SECRET_VALUE_PATTERNS:
        redacted = pat.sub(_REDACTED, redacted)
    return redacted


class JSONLogFormatter(logging.Formatter):
    """
    JSON log formatter for structured logging in production.

    Produces machine-readable JSON logs with standardized fields.

    applies :data:`_SENSITIVE_KEY_PATTERN` to every extras key
    (top-level and nested) before serialization. Keys whose name matches
    are replaced with ``[REDACTED]``; keys whose *value* is a dict are
    recursively filtered so nested secrets don't leak either.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": _redact_message(record.getMessage()),
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        }

        # Add location info
        if record.pathname:
            log_entry["location"] = {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add context variables
        if request_id := request_id_var.get():
            log_entry["request_id"] = request_id
        if user_id := user_id_var.get():
            log_entry["user_id"] = user_id
        if org_id := organization_id_var.get():
            log_entry["organization_id"] = org_id

        # Add extra fields from record (with redaction)
        if hasattr(record, "extra_fields"):
            extra_fields = record.extra_fields
            if isinstance(extra_fields, dict):
                log_entry.update(_redact_sensitive(extra_fields))

        # Include standard extra attributes (with redaction)
        excluded = {
            "name",
            "msg",
            "args",
            "created",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "module",
            "msecs",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "exc_info",
            "exc_text",
            "thread",
            "threadName",
            "taskName",
            "message",
            "extra_fields",
        }
        for key, value in record.__dict__.items():
            if key in excluded or key.startswith("_"):
                continue
            if _SENSITIVE_KEY_PATTERN.search(key):
                log_entry[key] = _REDACTED
            else:
                log_entry[key] = _redact_sensitive(value)

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class ColoredFormatter(logging.Formatter):
    """
    Colored console formatter for development.

    Uses ANSI colors for better readability during development.
    """

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)

        # Get context
        request_id = request_id_var.get()

        # Build prefix
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        level = f"{color}{record.levelname:8}{self.RESET}"
        logger_name = f"\033[34m{record.name:30}\033[0m"

        # Build message
        message = _redact_message(record.getMessage())

        # Add request ID if available
        prefix = f"[{request_id[:8]}] " if request_id else ""

        formatted = f"{timestamp} | {level} | {logger_name} | {prefix}{message}"

        # Add exception if present
        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"

        return formatted


class ContextFilter(logging.Filter):
    """
    Filter that adds context variables to log records.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        record.user_id = user_id_var.get()
        record.organization_id = organization_id_var.get()
        return True


def setup_logging(
    level: str = "INFO",
    json_format: bool | None = None,
) -> None:
    """
    Configure application logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: Force JSON format (default: auto-detect from environment)
    """
    # Determine format
    if json_format is None:
        json_format = settings.ENVIRONMENT == "production"

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, level.upper()))

    # Add filter for context
    console_handler.addFilter(ContextFilter())

    # Set formatter based on environment
    if json_format:
        console_handler.setFormatter(JSONLogFormatter())
    else:
        console_handler.setFormatter(ColoredFormatter())

    root_logger.addHandler(console_handler)

    # Reroute uvicorn's own loggers through our handler so their access/error
    # lines respect the configured format (JSON in prod, colored in dev).
    # Without this, uvicorn installs its own StreamHandler with a plain format.
    for uv_name in ("uvicorn", "uvicorn.access", "uvicorn.error"):
        uv_logger = logging.getLogger(uv_name)
        uv_logger.handlers = [console_handler]
        uv_logger.propagate = False

    # Configure library loggers to reduce noise
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Log startup message
    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured: level={level}, format={'JSON' if json_format else 'colored'}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured logger instance
    """
    return logging.getLogger(name)


class LogContext:
    """
    Context manager for adding temporary context to logs.

    Usage:
        with LogContext(request_id="abc123", user_id="user1"):
            logger.info("This will include context")
    """

    def __init__(
        self,
        request_id: str | None = None,
        user_id: str | None = None,
        organization_id: str | None = None,
    ):
        self.request_id = request_id
        self.user_id = user_id
        self.organization_id = organization_id
        self.tokens: list[Any] = []

    def __enter__(self) -> "LogContext":
        if self.request_id:
            self.tokens.append(request_id_var.set(self.request_id))
        if self.user_id:
            self.tokens.append(user_id_var.set(self.user_id))
        if self.organization_id:
            self.tokens.append(organization_id_var.set(self.organization_id))
        return self

    def __exit__(self, *args: Any) -> None:
        for token in self.tokens:
            try:
                # Reset to previous value
                token.var.reset(token)
            except Exception:
                pass
