"""Email application-layer protocol detection and session reconstruction."""

from engine.protocols.base import ConversationLine, RawEvent, ReconstructedConversation
from engine.protocols.detection import DetectionResult, detect_protocol
from engine.protocols.imap import build_imap_conversation
from engine.protocols.pop3 import build_pop3_conversation
from engine.protocols.reconstruct import reconstruct_session
from engine.protocols.redaction import redact_arguments, redact_line
from engine.protocols.smtp import build_smtp_conversation

__all__ = [
    "ConversationLine",
    "DetectionResult",
    "RawEvent",
    "ReconstructedConversation",
    "build_imap_conversation",
    "build_pop3_conversation",
    "build_smtp_conversation",
    "detect_protocol",
    "reconstruct_session",
    "redact_arguments",
    "redact_line",
]
