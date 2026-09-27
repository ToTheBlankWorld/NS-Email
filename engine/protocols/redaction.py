"""Credential redaction for session events.

Captures may contain usernames, passwords, tokens, and message content.
This module is the single gate between parsed protocol lines and stored
event detail: authentication material is replaced with the literal
``redacted`` before it can reach evidence models, API responses, or logs.
"""

import re
from typing import Final

from engine.core.events import REDACTED, safe_value

# Commands whose arguments are always credentials.
SENSITIVE_COMMANDS: Final[frozenset[str]] = frozenset(
    {"AUTH", "AUTHENTICATE", "LOGIN", "PASS", "USER"}
)

_SPLIT: Final[re.Pattern[str]] = re.compile(r"\s+")


def command_and_args(line: str) -> tuple[str, str]:
    """Split a protocol line into (first word, remainder)."""
    parts = _SPLIT.split(line.strip(), maxsplit=1)
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0].upper(), ""
    return parts[0].upper(), parts[1].strip()


def redact_arguments(command: str, arguments: str) -> str:
    """Redact the arguments of sensitive commands; pass others through.

    SMTP envelope addresses (MAIL FROM / RCPT TO) are forensic metadata,
    not credentials, and are preserved (sanitized, length-bounded).
    Authentication material (AUTH, USER, PASS, LOGIN, AUTHENTICATE) is
    never preserved.
    """
    if command in SENSITIVE_COMMANDS:
        return REDACTED
    return safe_value(arguments)


def redact_line(line: str) -> str:
    """Return a safe version of a protocol line for diagnostics.

    Credential arguments are removed before the line can reach any log or
    exception message.
    """
    command, arguments = command_and_args(line)
    if command in SENSITIVE_COMMANDS and arguments:
        return f"{command} {REDACTED}"
    return safe_value(line)
