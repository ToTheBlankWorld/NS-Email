"""Application protocol detection for SMTP, IMAP, and POP3.

Detection combines multiple evidence classes — server greetings, client
commands, and service ports — and reports every matched signal. Port
numbers alone never identify a protocol. Confidence is a small explainable
scale (unknown/low/medium/high), never a fabricated percentage.
"""

import re
from dataclasses import dataclass, field
from typing import Final

from engine.core.session import Confidence, EmailProtocol
from engine.transport.reassembly import StreamAssembly

_INSPECTION_WINDOW: Final[int] = 8192

# Server greeting patterns (anchored at the stream start).
_SMTP_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^220[ -]\S")
_IMAP_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^\* (OK|PREAUTH|BYE)")
_POP3_GREETING: Final[re.Pattern[bytes]] = re.compile(rb"^\+OK|-ERR")

# Client command patterns (searched over the first inspection window).
_SMTP_COMMANDS: Final[re.Pattern[bytes]] = re.compile(
    rb"^(EHLO|HELO|MAIL FROM|RCPT TO|DATA|RSET|NOOP|QUIT|STARTTLS|AUTH|VRFY|EXPN|HELP)[ \r\n]",
    re.IGNORECASE | re.MULTILINE,
)
_IMAP_COMMANDS: Final[re.Pattern[bytes]] = re.compile(
    rb"^\S{1,32} (CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|SELECT|EXAMINE"
    rb"|FETCH|STORE|LIST|LSUB|STATUS|APPEND|CREATE|DELETE|RENAME|CLOSE"
    rb"|UNSELECT|EXPUNGE|SEARCH|CHECK|NOOP|SUBSCRIBE|UNSUBSCRIBE|LOGOUT)\b",
    re.IGNORECASE | re.MULTILINE,
)
_POP3_COMMANDS: Final[re.Pattern[bytes]] = re.compile(
    rb"^(USER|PASS|STAT|LIST|RETR|DELE|TOP|UIDL|APOP|CAPA|STLS|NOOP|RSET|QUIT)\b",
    re.IGNORECASE | re.MULTILINE,
)

_SMTP_BANNER_HINT: Final[re.Pattern[bytes]] = re.compile(rb"SMTP|ESMTP", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Outcome of application protocol detection."""

    protocol: EmailProtocol | None
    confidence: Confidence
    evidence: list[str] = field(default_factory=list)
    greeting_direction: str | None = None  # "a" or "b": direction the server greeted from


def _has_greeting(protocol: EmailProtocol, stream: StreamAssembly) -> bool:
    head = stream.stream()[:64]
    if protocol is EmailProtocol.SMTP:
        return _SMTP_GREETING.match(head) is not None
    if protocol is EmailProtocol.IMAP:
        return _IMAP_GREETING.match(head) is not None
    return _POP3_GREETING.match(head) is not None


def _count_commands(protocol: EmailProtocol, stream: StreamAssembly) -> int:
    window = stream.stream()[:_INSPECTION_WINDOW]
    if protocol is EmailProtocol.SMTP:
        return len(set(_SMTP_COMMANDS.findall(window)))
    if protocol is EmailProtocol.IMAP:
        return len(set(_IMAP_COMMANDS.findall(window)))
    return len(set(_POP3_COMMANDS.findall(window)))


def _banner_hint(protocol: EmailProtocol, stream: StreamAssembly) -> bool:
    return (
        protocol is EmailProtocol.SMTP
        and _SMTP_BANNER_HINT.search(stream.stream()[:256]) is not None
    )


def _matching_port(protocol: EmailProtocol, port_a: int, port_b: int) -> int | None:
    for port in (port_a, port_b):
        if EmailProtocol.from_port(port) is protocol:
            return port
    return None


def _score_candidate(
    protocol: EmailProtocol,
    server_stream: StreamAssembly,
    client_stream: StreamAssembly,
    port_a: int,
    port_b: int,
    server_label: str,
) -> tuple[int, DetectionResult]:
    """Score one protocol assuming ``server_stream`` is the server side."""
    evidence: list[str] = []
    score = 0
    greeting = _has_greeting(protocol, server_stream)
    if greeting:
        score += 2
        evidence.append(f"server greeting matched {protocol.value} ({server_label} direction)")
    commands = _count_commands(protocol, client_stream)
    if commands >= 2:
        score += 2
        evidence.append(f"{commands} distinct {protocol.value} client commands observed")
    elif commands == 1:
        score += 1
        evidence.append(f"one {protocol.value} client command observed")
    if _banner_hint(protocol, server_stream):
        score += 1
        evidence.append("server banner identifies itself as SMTP/ESMTP")
    matched_port = _matching_port(protocol, port_a, port_b)
    if matched_port is not None:
        score += 1
        evidence.append(f"service port {matched_port} matches {protocol.value}")
    return score, DetectionResult(
        protocol=protocol,
        confidence=Confidence.UNKNOWN,
        evidence=evidence,
        greeting_direction=server_label if greeting else None,
    )


def _confidence_for(score: int) -> Confidence:
    if score >= 4:
        return Confidence.HIGH
    if score >= 2:
        return Confidence.MEDIUM
    if score >= 1:
        return Confidence.LOW
    return Confidence.UNKNOWN


def detect_protocol(
    stream_a: StreamAssembly,
    stream_b: StreamAssembly,
    port_a: int,
    port_b: int,
) -> DetectionResult:
    """Detect the application protocol of a flow from both directions.

    Both orientation hypotheses are evaluated; the strongest evidence wins
    and ties are reported as unknown rather than guessed.
    """
    candidates: list[tuple[int, DetectionResult]] = []
    for protocol in EmailProtocol:
        for server_stream, client_stream, server_label in (
            (stream_a, stream_b, "a"),
            (stream_b, stream_a, "b"),
        ):
            score, result = _score_candidate(
                protocol, server_stream, client_stream, port_a, port_b, server_label
            )
            if result.evidence:
                candidates.append((score, result))

    if not candidates:
        return DetectionResult(
            protocol=None,
            confidence=Confidence.UNKNOWN,
            evidence=["no email protocol signatures matched"],
        )

    candidates.sort(key=lambda item: item[0], reverse=True)
    best_score, best = candidates[0]
    if (
        len(candidates) > 1
        and candidates[1][0] == best_score
        and best.protocol != candidates[1][1].protocol
    ):
        return DetectionResult(
            protocol=None,
            confidence=Confidence.UNKNOWN,
            evidence=[
                "ambiguous protocol evidence: "
                + "; ".join(
                    sorted(
                        str(candidate.protocol.value)
                        for candidate in (best, candidates[1][1])
                        if candidate.protocol is not None
                    )
                )
            ],
        )
    confidence = _confidence_for(best_score)
    identified = best.protocol if confidence in (Confidence.MEDIUM, Confidence.HIGH) else None
    return DetectionResult(
        protocol=identified,
        confidence=confidence,
        evidence=best.evidence,
        greeting_direction=best.greeting_direction,
    )
