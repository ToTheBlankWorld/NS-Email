"""Shared base configuration and helpers for forensic evidence models."""

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def new_evidence_id() -> str:
    """Return a random, opaque identifier for an evidence object."""
    return uuid4().hex


def utc_now() -> datetime:
    """Return the current timezone-aware UTC instant."""
    return datetime.now(UTC)


class ForensicBase(BaseModel):
    """Base model for all forensic evidence.

    Evidence is immutable once recorded (``frozen``) and rejects unknown
    fields (``extra='forbid'``) so malformed input cannot silently inject
    attributes into forensic records. Every concrete evidence model is
    JSON-serializable so it can be persisted and exchanged canonically.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=new_evidence_id)
