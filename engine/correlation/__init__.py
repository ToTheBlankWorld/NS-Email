"""Multi-capture correlation for forensic investigation (Stage 12)."""

from engine.correlation.engine import (
    FLAGGED_ANOMALY_BANDS,
    AnomalyView,
    CaptureCorrelationInput,
    correlate_case,
)
from engine.correlation.model import (
    CORRELATION_ID_PREFIX,
    MAX_CORRELATIONS_PER_CASE,
    MAX_OCCURRENCES_PER_CORRELATION,
    Correlation,
    CorrelationReport,
    CorrelationStrength,
    CorrelationType,
    Occurrence,
    correlation_id,
)
from engine.correlation.normalize import (
    MAX_EVIDENCE_KEY_LENGTH,
    MAX_HOSTNAME_LENGTH,
    MAX_SUBJECT_LENGTH,
    normalize_evidence_key,
    normalize_fingerprint,
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_protocol,
    normalize_subject,
    normalize_token,
)

__all__ = [
    "CORRELATION_ID_PREFIX",
    "FLAGGED_ANOMALY_BANDS",
    "MAX_CORRELATIONS_PER_CASE",
    "MAX_EVIDENCE_KEY_LENGTH",
    "MAX_HOSTNAME_LENGTH",
    "MAX_OCCURRENCES_PER_CORRELATION",
    "MAX_SUBJECT_LENGTH",
    "AnomalyView",
    "CaptureCorrelationInput",
    "Correlation",
    "CorrelationReport",
    "CorrelationStrength",
    "CorrelationType",
    "Occurrence",
    "correlate_case",
    "correlation_id",
    "normalize_evidence_key",
    "normalize_fingerprint",
    "normalize_hostname",
    "normalize_ip",
    "normalize_port",
    "normalize_protocol",
    "normalize_subject",
    "normalize_token",
]
