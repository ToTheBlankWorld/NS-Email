"""Local behavioral anomaly detection over TLS session features (Stage 6).

Unsupervised IsolationForest over typed, versioned feature vectors.
Local-only processing: no packet data, certificates, hostnames, or
credentials ever leave the process.
"""

from engine.ml.anomaly import (
    AnomalyEngine,
    AnomalyReport,
    BaselineStatistics,
    SessionAnomaly,
    anomaly_band,
)
from engine.ml.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    SessionFeatures,
    extract_features,
)

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SCHEMA_VERSION",
    "AnomalyEngine",
    "AnomalyReport",
    "BaselineStatistics",
    "SessionAnomaly",
    "SessionFeatures",
    "anomaly_band",
    "extract_features",
]
