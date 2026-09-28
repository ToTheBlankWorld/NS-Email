"""Deterministic normalization for multi-capture correlation (Stage 12).

Normalization is conservative and fully offline: lowercase hostnames
with only a semantically safe trailing-dot trim, canonical IP
representation via the standard library, canonical enum values for
protocols/TLS fields, and SHA-256 fingerprints as authoritative
certificate identity. No DNS, WHOIS, geolocation, reverse DNS, or any
external enrichment — ever.

Every helper returns ``None`` for values it cannot normalize safely;
the engine skips un-normalizable values instead of guessing.
"""

import ipaddress
import re
from typing import Final

MAX_HOSTNAME_LENGTH: Final[int] = 253
MAX_EVIDENCE_KEY_LENGTH: Final[int] = 512
MAX_SUBJECT_LENGTH: Final[int] = 512

_HEX_RUN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]+$")
_WHITESPACE_RUN: Final[re.Pattern[str]] = re.compile(r"\s+")


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def normalize_ip(raw: str | None) -> str | None:
    """Canonical IP representation, or ``None`` when not parseable."""
    if raw is None:
        return None
    text = raw.strip()
    if not text or len(text) > 64 or _has_control_chars(text):
        return None
    try:
        return ipaddress.ip_address(text).compressed.lower()
    except ValueError:
        return None


def normalize_hostname(raw: str | None) -> str | None:
    """Conservative hostname normalization, or ``None`` when unsafe.

    Lowercase plus a single trailing-dot trim only. Internationalized
    names are kept as-is (no IDNA conversion: decoding choices would be
    an interpretation, not an observation). Values that are empty,
    overlong, or carry control characters/whitespace are rejected.
    """
    if raw is None:
        return None
    text = raw.strip().lower()
    if not text or len(text) > MAX_HOSTNAME_LENGTH or _has_control_chars(text):
        return None
    if any(ch.isspace() for ch in text):
        return None
    if text.endswith("."):
        text = text[:-1]
    if not text or len(text) > MAX_HOSTNAME_LENGTH:
        return None
    return text


def normalize_port(port: int | None) -> int | None:
    """Validate a TCP/UDP port number, or ``None`` when out of range."""
    if isinstance(port, bool):
        return None
    if isinstance(port, int) and 0 <= port <= 65535:
        return port
    return None


def normalize_protocol(raw: str | None) -> str | None:
    """Canonical email protocol name (smtp/imap/pop3), or ``None``."""
    if raw is None:
        return None
    text = raw.strip().lower()
    return text if text in ("smtp", "imap", "pop3") else None


def normalize_token(raw: str | None) -> str | None:
    """Conservative token normalization for TLS versions, ciphers, key exchange.

    Collapses internal whitespace and lowercases descriptors that are
    case-insensitive by specification ("TLS 1.2", cipher suite names,
    key exchange families). Cipher suite *identifiers* keep their exact
    registry spelling via lowercasing, which is stable for IANA names.
    """
    if raw is None:
        return None
    text = _WHITESPACE_RUN.sub(" ", raw.strip()).lower()
    if not text or len(text) > 128 or _has_control_chars(text):
        return None
    return text


def normalize_fingerprint(raw: str | None) -> str | None:
    """Canonical hex fingerprint (colons/whitespace stripped, lowercase)."""
    if raw is None:
        return None
    text = raw.strip().lower().replace(":", "").replace(" ", "")
    if not text or len(text) > 128 or not _HEX_RUN.fullmatch(text):
        return None
    return text


def normalize_subject(raw: str | None) -> str | None:
    """Conservative certificate subject/issuer normalization."""
    if raw is None:
        return None
    text = _WHITESPACE_RUN.sub(" ", raw.strip()).lower()
    if not text or len(text) > MAX_SUBJECT_LENGTH or _has_control_chars(text):
        return None
    return text


def normalize_evidence_key(raw: str) -> str | None:
    """Bound a composite evidence key; reject oversized or hostile keys."""
    if not raw or len(raw) > MAX_EVIDENCE_KEY_LENGTH or _has_control_chars(raw):
        return None
    return raw


__all__ = [
    "MAX_EVIDENCE_KEY_LENGTH",
    "MAX_HOSTNAME_LENGTH",
    "MAX_SUBJECT_LENGTH",
    "normalize_evidence_key",
    "normalize_fingerprint",
    "normalize_hostname",
    "normalize_ip",
    "normalize_port",
    "normalize_protocol",
    "normalize_subject",
    "normalize_token",
]
