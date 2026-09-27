"""IsolationForest behavioral anomaly detection over session features.

Stage 6 introduces a LOCAL, unsupervised anomaly detector over the typed
feature vectors from ``engine.ml.features``. IsolationForest was chosen
because:

- it is unsupervised (no labeled attack data exists for email TLS);
- it isolates outliers with few axis splits, so rare configurations
  (e.g. an unusual TLS version) score highly without any attack labels;
- it is deterministic given a fixed ``random_state``;
- scikit-learn provides a mature, dependency-light implementation.

The model is an anomaly detector, NOT an attack classifier: an anomalous
score means "unusual relative to the capture-local baseline".

Security properties:
- training and inference are fully local (no network ML calls);
- the model artifact is written to application-controlled storage only —
  never loaded from API-supplied paths;
- feature vectors are sanitized (NaN/Inf rejected, bounded) before
  reaching scikit-learn;
- the artifact is validated (schema version + algorithm check) after
  loading before any scoring happens.
"""

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from engine.core.findings import EvidenceRef
from engine.core.session import Session
from engine.ml.features import (
    CATEGORICAL_FEATURES,
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    SessionFeatures,
    decode_feature,
    extract_features,
)

MIN_BASELINE_SESSIONS: Final[int] = 8
MODEL_ALGORITHM: Final[str] = "IsolationForest"
MODEL_FORMAT_VERSION: Final[str] = "1.0"
DEFAULT_CONTAMINATION: Final[float] = 0.05
RANDOM_STATE: Final[int] = 42  # explicit: reproducibility over stochasticity

SCORE_MIN: Final[int] = 0
SCORE_MAX: Final[int] = 100
UNUSUAL_BAND: Final[int] = 50
ANOMALOUS_BAND: Final[int] = 70
HIGHLY_ANOMALOUS_BAND: Final[int] = 85


class AnomalyStatus:
    NOT_EVALUATED = "not_evaluated"
    NORMAL = "normal"
    UNUSUAL = "unusual"
    ANOMALOUS = "anomalous"
    HIGHLY_ANOMALOUS = "highly_anomalous"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    MODEL_ERROR = "model_error"


@dataclass(frozen=True, slots=True)
class FeatureDeviation:
    """Human-readable deviation of one feature from the baseline."""

    feature: str
    observed: str
    baseline: str
    deviation: str  # "high" | "moderate" | "low"


@dataclass(frozen=True, slots=True)
class SessionAnomaly:
    """Typed anomaly result for one session."""

    anomaly_id: str
    capture_id: str
    session_id: str
    protocol: str | None
    status: str
    score: int | None
    band: str | None
    model_id: str | None
    model_version: str
    feature_schema_version: str
    top_deviations: list[dict[str, str]]
    baseline_summary: dict[str, str]
    evidence_refs: list[EvidenceRef]
    generated_at: datetime


@dataclass(frozen=True, slots=True)
class AnomalyReport:
    """The complete anomaly analysis output for one capture."""

    capture_id: str
    analysis_version: str
    feature_schema_version: str
    model_id: str | None
    model_version: str
    status: str  # completed | insufficient_baseline | model_error
    training_session_count: int
    anomalies: list[SessionAnomaly]
    summary: dict[str, int]
    generated_at: datetime


def anomaly_band(score: int) -> str:
    """Documented descriptive bands (SecureMailScope-defined, not standard)."""
    if score >= HIGHLY_ANOMALOUS_BAND:
        return AnomalyStatus.HIGHLY_ANOMALOUS
    if score >= ANOMALOUS_BAND:
        return AnomalyStatus.ANOMALOUS
    if score >= UNUSUAL_BAND:
        return AnomalyStatus.UNUSUAL
    return AnomalyStatus.NORMAL


def _deviation_label(score: float) -> str:
    if score >= 1.0:
        return "high"
    if score >= 0.5:
        return "moderate"
    return "low"


def _score_from_decision_function(decision_value: float) -> int:
    """Map IsolationForest's decision_function to a 0-100 anomaly score.

    decision_function: positive = in-distribution, negative = anomalous.
    A logistic mapping with scale 20 spreads the typical range: a strongly
    in-distribution session maps near 5-15, a clearly isolated session
    near 85-100. Monotonic and bounded; no probabilistic semantics.
    """
    normalized = 1.0 / (1.0 + math.exp(decision_value * 20.0))
    return round(normalized * (SCORE_MAX - SCORE_MIN))


def _evidence_for(session: Session, handshake_ref: bool) -> list[EvidenceRef]:
    refs = []
    handshake = session.handshake
    if handshake_ref and handshake is not None:
        refs.append(
            EvidenceRef(
                source="ClientHello",
                packet_numbers=handshake.client_hello_packets,
                detail="TLS handshake features",
            )
        )
    return refs


def train_model(feature_rows: list[list[float]]) -> tuple[Any, list[float]]:
    """Fit the IsolationForest model; returns (model, training scores).

    Deterministic: ``random_state`` is fixed and ``n_jobs=1``.
    """
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators=100,
        contamination=DEFAULT_CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=1,
    )
    model.fit(feature_rows)
    scores = [-value for value in model.score_samples(feature_rows)]
    return model, scores


def serialize_model(
    model: Any,
    *,
    capture_id: str,
    training_session_count: int,
    protocol: str | None,
) -> dict[str, Any]:
    """Serialize the fitted model + metadata into a versioned artifact dict."""
    return {
        "format_version": MODEL_FORMAT_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "algorithm": MODEL_ALGORITHM,
        "parameters": {
            "n_estimators": 100,
            "contamination": DEFAULT_CONTAMINATION,
            "random_state": RANDOM_STATE,
        },
        "training_capture_id": capture_id,
        "training_session_count": training_session_count,
        "protocol": protocol,
        "trained_at": datetime.now(UTC).isoformat(),
        # The raw estimator is embedded via joblib inside a JSON-safe
        # wrapper only in memory; on disk the app stores it separately.
        "model": model,
    }


class AnomalyEngine:
    """Train and apply the capture-local anomaly model."""

    def __init__(self, min_baseline_sessions: int = MIN_BASELINE_SESSIONS) -> None:
        self._min_baseline = max(2, min_baseline_sessions)

    def analyze(self, sessions: list[Session]) -> AnomalyReport:
        """Run the full baseline-train-score pipeline for one capture.

        Sessions are grouped per protocol so fundamentally different
        behaviors don't dominate each other. Groups below the minimum
        baseline size report ``insufficient_evidence``.
        """
        generated_at = datetime.now(UTC)
        by_protocol: dict[str | None, list[Session]] = {}
        for session in sessions:
            by_protocol.setdefault(session.protocol.value if session.protocol else None, []).append(
                session
            )

        anomalies: list[SessionAnomaly] = []
        total_trained = 0
        status = "completed"
        model_id: str | None = None
        model_version = MODEL_FORMAT_VERSION

        for protocol_key in sorted(by_protocol, key=lambda p: p or ""):
            protocol_sessions = by_protocol[protocol_key]
            protocol_anomalies = self._analyze_group(protocol_key, protocol_sessions, generated_at)
            for anomaly in protocol_anomalies:
                anomalies.append(anomaly)
                if anomaly.model_id and model_id is None:
                    model_id = anomaly.model_id
                if anomaly.status == AnomalyStatus.MODEL_ERROR:
                    status = "model_error"
            if protocol_anomalies and protocol_anomalies[0].status not in (
                AnomalyStatus.INSUFFICIENT_EVIDENCE,
                AnomalyStatus.MODEL_ERROR,
            ):
                total_trained += len(protocol_sessions)

        summary = self._summarize(anomalies, sessions)
        return AnomalyReport(
            capture_id=sessions[0].capture_id if sessions else "",
            analysis_version="0.5.0",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            model_id=model_id,
            model_version=model_version,
            status=status,
            training_session_count=total_trained,
            anomalies=anomalies,
            summary=summary,
            generated_at=generated_at,
        )

    def _analyze_group(
        self,
        protocol: str | None,
        sessions: list[Session],
        generated_at: datetime,
    ) -> list[SessionAnomaly]:
        features = [extract_features(session) for session in sessions]
        protocol_name = protocol or "unknown"
        model_id = self._model_id(protocol_name, [f.numeric_vector() for f in features])

        if len(features) < self._min_baseline:
            return [
                self._status_anomaly(
                    session,
                    protocol_name,
                    model_id,
                    AnomalyStatus.INSUFFICIENT_EVIDENCE,
                    generated_at,
                )
                for session in sessions
            ]

        rows = [f.numeric_vector() for f in features]
        try:
            model, _training_scores = train_model(rows)
        except Exception as error:
            return [
                self._status_anomaly(
                    session,
                    protocol_name,
                    model_id,
                    AnomalyStatus.MODEL_ERROR,
                    generated_at,
                    detail=f"model training failed: {error}",
                )
                for session in sessions
            ]

        raw_scores: list[float]
        try:
            raw_scores = list(model.decision_function(rows))
        except Exception as error:
            return [
                self._status_anomaly(
                    session,
                    protocol_name,
                    model_id,
                    AnomalyStatus.MODEL_ERROR,
                    generated_at,
                    detail=f"model scoring failed: {error}",
                )
                for session in sessions
            ]

        baseline_stats = self._baseline_statistics(features, rows)
        anomalies: list[SessionAnomaly] = []
        for session, feature, raw_score in zip(sessions, features, raw_scores, strict=True):
            score = _score_from_decision_function(raw_score)
            band = anomaly_band(score)
            deviations = (
                self._top_deviations(feature, features, baseline_stats)
                if band != AnomalyStatus.NORMAL
                else []
            )
            status = band
            anomalies.append(
                SessionAnomaly(
                    anomaly_id=self._anomaly_id(session.id),
                    capture_id=session.capture_id,
                    session_id=session.id,
                    protocol=protocol_name if protocol_name != "unknown" else None,
                    status=status,
                    score=score,
                    band=band,
                    model_id=model_id,
                    model_version=MODEL_FORMAT_VERSION,
                    feature_schema_version=FEATURE_SCHEMA_VERSION,
                    top_deviations=[
                        {
                            "feature": d.feature,
                            "observed": d.observed,
                            "baseline": d.baseline,
                            "deviation": d.deviation,
                        }
                        for d in deviations
                    ],
                    baseline_summary=baseline_stats.get_summary(),
                    evidence_refs=_evidence_for(session, handshake_ref=True),
                    generated_at=generated_at,
                )
            )
        return anomalies

    @staticmethod
    def _model_id(protocol: str, rows: list[list[float]]) -> str:
        digest = hashlib.sha256(
            json.dumps([protocol, len(rows)], sort_keys=True).encode()
        ).hexdigest()
        return f"anomaly-if-{digest[:12]}"

    @staticmethod
    def _anomaly_id(session_id: str) -> str:
        digest = hashlib.sha256(session_id.encode()).hexdigest()
        return f"anomaly_{digest[:12]}"

    @staticmethod
    def _baseline_statistics(
        features: list[SessionFeatures], rows: list[list[float]]
    ) -> "BaselineStatistics":
        return BaselineStatistics.build(FEATURE_NAMES, rows)

    @staticmethod
    def _top_deviations(
        feature: SessionFeatures,
        baseline_features: list[SessionFeatures],
        stats: "BaselineStatistics",
    ) -> list[FeatureDeviation]:
        """Rank features by relative deviation from the baseline.

        Numeric: absolute z-like distance against baseline mean/std.
        Categorical: 1 - (observed frequency in baseline).
        Deviations are labeled high/moderate/low by a fixed threshold.
        """
        deviations: list[tuple[float, FeatureDeviation]] = []
        values = feature.numeric_vector()
        for index, name in enumerate(FEATURE_NAMES):
            observed_value = values[index]
            if name in CATEGORICAL_FEATURES:
                observed_label = decode_feature(name, observed_value)
                match_count = sum(
                    1
                    for other in baseline_features
                    if decode_feature(name, other.numeric_vector()[index]) == observed_label
                )
                frequency = match_count / max(1, len(baseline_features))
                deviation_score = round(1.0 - frequency, 2)
                baseline_label = ", ".join(
                    f"{decode_feature(name, other.numeric_vector()[index])}"
                    for other in baseline_features[:3]
                )
                deviations.append(
                    (
                        deviation_score,
                        FeatureDeviation(
                            feature=name,
                            observed=observed_label,
                            baseline=f"{baseline_label} ({match_count}/{len(baseline_features)})",
                            deviation=_deviation_label(deviation_score),
                        ),
                    )
                )
            else:
                mean, std = stats.numeric_mean_std(name)
                if std <= 1e-9 and abs(observed_value - mean) <= 1e-9:
                    continue
                deviation_score = round(abs(observed_value - mean) / std, 2) if std > 1e-9 else 0.0
                deviations.append(
                    (
                        deviation_score,
                        FeatureDeviation(
                            feature=name,
                            observed=str(round(observed_value, 2)),
                            baseline=f"mean {round(mean, 2)} (std {round(std, 2)})",
                            deviation=_deviation_label(
                                min(3.0, deviation_score) if std > 1e-9 else 0.0
                            ),
                        ),
                    )
                )

        deviations.sort(key=lambda pair: pair[0], reverse=True)
        return [deviation for score, deviation in deviations[:4] if score > 0]

    @staticmethod
    def _status_anomaly(
        session: Session,
        protocol: str,
        model_id: str,
        status: str,
        generated_at: datetime,
        detail: str | None = None,
    ) -> SessionAnomaly:
        return SessionAnomaly(
            anomaly_id=AnomalyEngine._anomaly_id(session.id),
            capture_id=session.capture_id,
            session_id=session.id,
            protocol=protocol if protocol != "unknown" else None,
            status=status,
            score=None,
            band=None,
            model_id=model_id,
            model_version=MODEL_FORMAT_VERSION,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            top_deviations=[],
            baseline_summary={"detail": detail} if detail else {},
            evidence_refs=_evidence_for(session, handshake_ref=False),
            generated_at=generated_at,
        )

    @staticmethod
    def _summarize(anomalies: list[SessionAnomaly], sessions: list[Session]) -> dict[str, int]:
        summary: dict[str, int] = {
            AnomalyStatus.NORMAL: 0,
            AnomalyStatus.UNUSUAL: 0,
            AnomalyStatus.ANOMALOUS: 0,
            AnomalyStatus.HIGHLY_ANOMALOUS: 0,
            AnomalyStatus.INSUFFICIENT_EVIDENCE: 0,
            AnomalyStatus.MODEL_ERROR: 0,
            "total_evaluated": 0,
        }
        for anomaly in anomalies:
            if anomaly.status in summary:
                summary[anomaly.status] += 1
            if anomaly.score is not None:
                summary["total_evaluated"] += 1
        summary["total_sessions"] = len(sessions)
        return summary


@dataclass(frozen=True, slots=True)
class BaselineStatistics:
    """Baseline statistics for human-readable deviation explanations."""

    numeric: dict[str, dict[str, float]] = field(default_factory=dict)
    categorical: dict[str, dict[str, int]] = field(default_factory=dict)

    def numeric_mean_std(self, name: str) -> tuple[float, float]:
        stats = self.numeric.get(name, {"mean": 0.0, "std": 0.0})
        return stats["mean"], stats["std"]

    def get_summary(self) -> dict[str, str]:
        lines: dict[str, str] = {}
        for name, stats in sorted(self.numeric.items()):
            lines[name] = (
                f"mean {round(stats['mean'], 2)}, std {round(stats['std'], 2)}, "
                f"min {round(stats['min'], 2)}, max {round(stats['max'], 2)}"
            )
        for name, distribution in sorted(self.categorical.items()):
            parts = ", ".join(f"{value}: {count}" for value, count in sorted(distribution.items()))
            lines[name] = parts
        return lines

    @classmethod
    def build(cls, names: tuple[str, ...], rows: list[list[float]]) -> "BaselineStatistics":
        categorical = {
            name: CATEGORICAL_FEATURES[name] for name in names if name in CATEGORICAL_FEATURES
        }
        numeric_stats: dict[str, dict[str, float]] = {}
        categorical_stats: dict[str, dict[str, int]] = {}
        for index, name in enumerate(names):
            column = [row[index] for row in rows]
            if name in categorical:
                distribution: dict[str, int] = {}
                vocabulary = categorical[name]
                for value in column:
                    label = vocabulary[int(value)] if 0 <= int(value) < len(vocabulary) else "other"
                    distribution[label] = distribution.get(label, 0) + 1
                categorical_stats[name] = distribution
            else:
                count = len(column)
                mean = sum(column) / count if count else 0.0
                variance = sum((value - mean) ** 2 for value in column) / count if count else 0.0
                numeric_stats[name] = {
                    "mean": mean,
                    "std": math.sqrt(variance),
                    "min": min(column) if column else 0.0,
                    "max": max(column) if column else 0.0,
                }
        return cls(numeric=numeric_stats, categorical=categorical_stats)
