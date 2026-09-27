"""X.509 certificate evidence extracted from TLS handshakes."""

import re
from typing import Final

from pydantic import AwareDatetime, Field, field_validator

from engine.core.base import ForensicBase

_HEX_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]+$")


class CertificateEvidence(ForensicBase):
    """Facts extracted from an X.509 certificate observed on the wire.

    This model records observations only. Verdicts (trust, hostname
    match, revocation, expiry findings) are produced by later analysis
    stages and recorded as ``SecurityFinding`` objects — never stored on
    the evidence itself.
    """

    session_id: str
    subject: str
    issuer: str
    serial_number: str
    not_before: AwareDatetime
    not_after: AwareDatetime
    signature_algorithm: str
    public_key_algorithm: str | None = None
    public_key_size_bits: int | None = Field(default=None, ge=0)
    subject_alternative_names: list[str] = Field(default_factory=list)
    fingerprint_sha256: str | None = None

    @field_validator("serial_number", "fingerprint_sha256")
    @classmethod
    def _normalize_hex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower().replace(":", "")
        if not _HEX_PATTERN.fullmatch(normalized):
            raise ValueError("value must be a hexadecimal string")
        return normalized

    def is_expired(self, as_of: AwareDatetime) -> bool:
        """Return True when ``as_of`` is strictly past the notAfter instant."""
        return as_of > self.not_after
