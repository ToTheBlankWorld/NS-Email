"""Session evidence: a reconstructed TCP connection carrying email traffic."""

from enum import StrEnum

from pydantic import AwareDatetime, Field, IPvAnyAddress

from engine.core.base import ForensicBase


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


class Session(ForensicBase):
    """A TCP session associated with an email protocol exchange.

    Tri-state fields use ``None`` to mean "not yet determined during
    reconstruction", distinct from a definite ``False``.
    """

    capture_id: str
    client_ip: IPvAnyAddress
    server_ip: IPvAnyAddress
    client_port: int = Field(ge=0, le=65535)
    server_port: int = Field(ge=0, le=65535)
    protocol: EmailProtocol | None = None
    starttls_observed: bool | None = None
    implicit_tls: bool | None = None
    started_at: AwareDatetime | None = None
    ended_at: AwareDatetime | None = None
