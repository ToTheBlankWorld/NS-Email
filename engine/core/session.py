"""Session evidence: a reconstructed TCP connection carrying email traffic."""

import re
from enum import StrEnum
from typing import Final

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress

from engine.core.base import ForensicBase
from engine.core.certificate import CertificateEvidence
from engine.core.events import SessionEvent
from engine.core.tls import TLSHandshake

# Session identifiers are derived deterministically from the capture id and
# the canonical bidirectional flow 5-tuple (see engine.transport.flows).
SESSION_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^session_[0-9a-f]{16}$")


class EmailProtocol(StrEnum):
    """Email application-layer protocols reconstructed by the engine."""

    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"

    @classmethod
    def from_port(cls, port: int) -> "EmailProtocol | None":
        """Map a well-known email server port to its protocol.

        Returns ``None`` for ports outside the standard email service set;
        non-standard ports require identification from protocol banners.
        """
        if port in (25, 587, 465):
            return cls.SMTP
        if port in (143, 993):
            return cls.IMAP
        if port in (110, 995):
            return cls.POP3
        return None

    @classmethod
    def is_implicit_tls_port(cls, port: int) -> bool:
        """Return True when the port is served over TLS from the first byte."""
        return port in (465, 993, 995)


class Confidence(StrEnum):
    """Explicit, explainable protocol-detection confidence.

    The engine never emits numeric confidence percentages — detection
    reports the matched evidence so analysts can judge for themselves.
    """

    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Orientation(StrEnum):
    """Client/server orientation of a session.

    ``unknown`` is recorded when neither SYN evidence, service ports, nor
    protocol greeting evidence establish which endpoint is the server.
    """

    CLIENT_SERVER = "client_server"
    UNKNOWN = "unknown"


class StarttlsObservation(BaseModel):
    """Plaintext STARTTLS/STLS observation for one session.

    Stage 2 records only the existence of the negotiation on the wire;
    TLS handshake analysis (version, cipher, certificate) is Stage 3.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    advertised: bool = False
    requested: bool = False
    response_seen: bool = False
    packet_number: int | None = None
    timestamp: AwareDatetime | None = None


class Session(ForensicBase):
    """A reconstructed TCP session associated with an email protocol exchange.

    The identifier is deterministic — derived from the capture id and the
    canonical bidirectional 5-tuple — so re-analysis of the same evidence
    produces the same session identity. Events reference the packets they
    were observed in; raw payloads are never part of the session model.

    Tri-state fields use ``None`` to mean "not yet determined during
    reconstruction", distinct from a definite ``False``.
    """

    id: str = Field(pattern=SESSION_ID_PATTERN.pattern)
    capture_id: str
    client_ip: IPvAnyAddress
    server_ip: IPvAnyAddress
    client_port: int = Field(ge=0, le=65535)
    server_port: int = Field(ge=0, le=65535)
    protocol: EmailProtocol | None = None
    confidence: Confidence = Confidence.UNKNOWN
    orientation: Orientation = Orientation.UNKNOWN
    implicit_tls: bool | None = None
    started_at: AwareDatetime | None = None
    ended_at: AwareDatetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    packet_count: int = Field(default=0, ge=0)
    bytes_client_to_server: int = Field(default=0, ge=0)
    bytes_server_to_client: int = Field(default=0, ge=0)
    complete: bool = False
    completeness_reason: str | None = None
    retransmissions: int = Field(default=0, ge=0)
    gap_count: int = Field(default=0, ge=0)
    gap_bytes: int = Field(default=0, ge=0)
    starttls: StarttlsObservation | None = None
    handshake: TLSHandshake | None = None
    certificates: list[CertificateEvidence] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    events: list[SessionEvent] = Field(default_factory=list)
