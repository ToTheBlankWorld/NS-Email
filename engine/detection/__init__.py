"""Deterministic security rules: policy evaluation over Stage 2/3 evidence.

Every rule is a pure function of the structured evidence and the loaded
policy. Findings cite the packets they were observed in; unknown evidence
stays unknown.
"""

from engine.detection.evaluator import evaluate_session, evaluate_sessions
from engine.detection.policy import (
    Policy,
    load_builtin_policy,
    load_policy_from_file,
)
from engine.detection.registry import RuleRegistry, default_registry

__all__ = [
    "Policy",
    "RuleRegistry",
    "default_registry",
    "evaluate_session",
    "evaluate_sessions",
    "load_builtin_policy",
    "load_policy_from_file",
]
