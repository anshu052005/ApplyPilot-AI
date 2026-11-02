"""Structured JSON logging with redaction of credential-like values."""

import json
import logging
import re
import sys
from datetime import datetime, timezone

_SECRET_PATTERNS = [
    re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),  # JWT
    re.compile(r"(postgres(?:ql)?(?:\+\w+)?://[^:\s]+:)[^@\s]+(@)"),  # DB password in URL
    # Value must not start with "[" so that an already-redacted marker is left intact.
    re.compile(r"((?:password|secret|token|cookie)[\"'=:\s]+)(?!\[REDACTED)[^\s,\"'\[][^\s,\"']*", re.IGNORECASE),
]


def redact(text: str) -> str:
    text = _SECRET_PATTERNS[0].sub("[REDACTED_JWT]", text)
    text = _SECRET_PATTERNS[1].sub(r"\1[REDACTED]\2", text)
    text = _SECRET_PATTERNS[2].sub(r"\1[REDACTED]", text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
        }
        if record.exc_info:
            payload["exception"] = redact(self.formatException(record.exc_info))
        for key in ("request_id", "user_id", "event"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
