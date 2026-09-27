"""Capture analysis: packets → flows → sessions.

The pipeline is deliberately modular — each stage is a pure function over
the previous stage's output, so stages are independently testable and a
future batch/asynchronous runner can reuse them unchanged.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field

from engine.core.session import Session
from engine.protocols.reconstruct import reconstruct_session
from engine.transport.flows import build_flows
from engine.transport.packets import PacketRecord


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Outcome of analyzing one registered capture."""

    sessions: list[Session]
    coverage_warnings: list[str] = field(default_factory=list)


def analyze_capture_packets(
    capture_id: str,
    packets: Iterable[PacketRecord],
    coverage_warnings: list[str] | None = None,
) -> AnalysisResult:
    """Reconstruct email sessions from the packet stream of one capture.

    Stages: flow grouping → per-direction reassembly → protocol detection →
    orientation → session reconstruction. Flows whose streams contain no
    data still produce transport-level sessions so coverage is explicit.
    """
    flows = build_flows(capture_id, packets)
    sessions = [reconstruct_session(flow) for flow in flows]
    return AnalysisResult(
        sessions=sessions,
        coverage_warnings=list(coverage_warnings or []),
    )
