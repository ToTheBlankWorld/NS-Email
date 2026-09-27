"""Client/server orientation for TCP flows.

Orientation is established from evidence, in order of strength:

1. **SYN evidence** — the endpoint that sent a bare SYN is the client and
   the SYN+ACK responder is the server (strongest).
2. **Well-known email service ports** — the endpoint whose port is a
   standard email service port (25/587/465/143/993/110/995) is the
   server. The lower port is *never* used as a heuristic on its own.
3. **Protocol greeting** — SMTP/IMAP/POP3 servers speak first; the
   direction that produced the greeting identifies the server. Applied by
   the reconstruction layer after protocol detection.

When no evidence applies, orientation stays ``unknown`` rather than
guessing.
"""

from dataclasses import dataclass

from engine.core.session import EmailProtocol, Orientation
from engine.transport.flows import Flow
from engine.transport.packets import TCP_ACK


@dataclass(frozen=True, slots=True)
class OrientationResult:
    """Outcome of orientation analysis for one flow."""

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    orientation: Orientation
    basis: str


def determine_orientation(flow: Flow) -> OrientationResult | None:
    """Establish client/server orientation from SYN and service-port evidence.

    Returns ``None`` when orientation cannot be established here; the
    reconstruction layer may still resolve it from the protocol greeting.
    """
    endpoint_a = (flow.direction_a.ip, flow.direction_a.port)
    endpoint_b = (flow.direction_b.ip, flow.direction_b.port)

    syn_from_a = any(p.has_syn and not p.tcp_flags & TCP_ACK for p in flow.direction_a.packets)
    syn_from_b = any(p.has_syn and not p.tcp_flags & TCP_ACK for p in flow.direction_b.packets)
    synack_from_a = any(p.has_syn and p.tcp_flags & TCP_ACK for p in flow.direction_a.packets)
    synack_from_b = any(p.has_syn and p.tcp_flags & TCP_ACK for p in flow.direction_b.packets)

    if syn_from_a and synack_from_b:
        return _result(endpoint_a, endpoint_b, "syn")
    if syn_from_b and synack_from_a:
        return _result(endpoint_b, endpoint_a, "syn")

    protocol_b = EmailProtocol.from_port(endpoint_b[1])
    protocol_a = EmailProtocol.from_port(endpoint_a[1])
    if protocol_b is not None and protocol_a is None:
        return _result(endpoint_a, endpoint_b, "well_known_service_port")
    if protocol_a is not None and protocol_b is None:
        return _result(endpoint_b, endpoint_a, "well_known_service_port")

    return None


def _result(client: tuple[str, int], server: tuple[str, int], basis: str) -> OrientationResult:
    return OrientationResult(
        client_ip=client[0],
        client_port=client[1],
        server_ip=server[0],
        server_port=server[1],
        orientation=Orientation.CLIENT_SERVER,
        basis=basis,
    )
