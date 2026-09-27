"""Packet-tool capture inspection behind a replaceable interface.

The inspector extracts ONLY generic capture metadata (packet count, time
range, link type) — protocol and cryptographic analysis belong to later
stages. ``CaptureInspector`` is the extension point; ``TsharkCaptureInspector``
is the tool-backed implementation.
"""

import re
import subprocess
import threading
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from engine.ingestion.errors import InspectorError, InvalidCaptureError

# Link-layer types from the tcpdump.org LINKTYPE registry that tshark reports.
_LINK_TYPES: Final[dict[str, str]] = {
    "0": "Null/Loopback",
    "1": "Ethernet",
    "101": "Raw IP",
    "105": "802.11",
    "113": "Linux SLL",
    "127": "Radiotap",
}

_TSHARK_VERSION_PATTERN: Final[re.Pattern[str]] = re.compile(r"TShark \(Wireshark\) (\S+)")

# Output of `tshark -T fields -e frame.time_epoch -e frame.encap_type`.
_FIELDS_LINE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(\d+(?:\.\d+)?)\t(\d*)$")

_STDERR_TAIL_CHARS: Final[int] = 2000


class InspectionStatus(StrEnum):
    """Outcome of the inspection step for a capture."""

    INSPECTED = "inspected"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class CaptureInspection(BaseModel):
    """Generic metadata extracted from one capture.

    Every field except ``status`` may be ``None``: inspection results are
    reported honestly, never filled with placeholders.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: InspectionStatus
    tool: str | None = None
    tool_version: str | None = None
    packet_count: int | None = Field(default=None, ge=0)
    first_packet_at: AwareDatetime | None = None
    last_packet_at: AwareDatetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    link_type: str | None = None
    message: str | None = None
    warnings: list[str] = Field(default_factory=list)


class CaptureInspector(Protocol):
    """Anything that can inspect capture evidence and report metadata."""

    tool_name: str

    def inspect(self, evidence_path: Path) -> CaptureInspection:
        """Inspect the evidence file; raise InvalidCaptureError when the
        bytes are not a valid capture, InspectorError on tool failure."""
        ...


def parse_tshark_version(first_output_line: str) -> str | None:
    """Extract the version from a `tshark --version` first output line."""
    match = _TSHARK_VERSION_PATTERN.match(first_output_line)
    return match.group(1) if match else None


def parse_fields_line(line: str) -> tuple[float, str] | None:
    """Parse one `-T fields` output line into (epoch seconds, encap value).

    Returns ``None`` for lines that do not carry the expected fields.
    """
    match = _FIELDS_LINE_PATTERN.match(line.strip())
    if match is None:
        return None
    return float(match.group(1)), match.group(2)


def describe_link_type(encap_value: str) -> str:
    """Map a numeric LINKTYPE value to its common name."""
    return _LINK_TYPES.get(encap_value, f"linktype {encap_value}")


def _epoch_to_datetime(epoch_seconds: float) -> datetime:
    return datetime.fromtimestamp(epoch_seconds, tz=UTC)


class TsharkCaptureInspector:
    """Inspect captures with the tshark binary (Wireshark CLI).

    Subprocesses are always launched with argument arrays containing only
    controlled constants plus the internally derived evidence path — never
    the original upload filename and never a shell string. ``-n`` disables
    name resolution so inspection performs no network calls.
    """

    tool_name: str = "tshark"

    def __init__(self, tshark_path: str, timeout_seconds: float = 120.0) -> None:
        self._tshark_path = tshark_path
        self._timeout_seconds = timeout_seconds
        self._version: str | None = None

    def version(self) -> str | None:
        """Return the cached tshark version string, if it can be determined."""
        if self._version is None:
            result = self._run_to_completion(["--version"])
            if result is not None and result.returncode == 0:
                first_line = result.stdout.decode(errors="replace").splitlines()[:1]
                if first_line:
                    self._version = parse_tshark_version(first_line[0])
        return self._version

    def inspect(self, evidence_path: Path) -> CaptureInspection:
        """Validate the capture and extract generic metadata in one pass.

        The `-T fields` pass streams packet records through stdout line by
        line, so memory use stays constant regardless of capture size.
        """
        try:
            process = subprocess.Popen(
                [
                    self._tshark_path,
                    "-n",
                    "-r",
                    str(evidence_path),
                    "-T",
                    "fields",
                    "-e",
                    "frame.time_epoch",
                    "-e",
                    "frame.encap_type",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise InspectorError(f"failed to launch {self.tool_name}: {error}") from error

        if process.stdout is None:  # stdout=PIPE always yields a stream; defensive
            raise InspectorError(f"{self.tool_name} produced no output stream")
        packet_count = 0
        first: tuple[float, str] | None = None
        last: tuple[float, str] | None = None
        timed_out = threading.Event()

        def _kill_on_timeout() -> None:
            timed_out.set()
            process.kill()

        # Watchdog: bound the whole streaming pass; kill the process when the
        # timeout fires so a hung tool cannot block ingestion indefinitely.
        watchdog = threading.Timer(self._timeout_seconds, _kill_on_timeout)
        try:
            watchdog.start()
            with process.stdout:
                for raw_line in process.stdout:
                    line = raw_line.decode(errors="replace").strip()
                    if not line:
                        continue
                    packet_count += 1
                    parsed = parse_fields_line(line)
                    if parsed is not None:
                        if first is None:
                            first = parsed
                        last = parsed
            returncode = process.wait()
        finally:
            watchdog.cancel()

        if timed_out.is_set():
            raise InspectorError(
                f"{self.tool_name} exceeded the inspection timeout of {self._timeout_seconds:g}s"
            )

        stderr_tail = self._drain_stderr(process)
        if returncode != 0:
            detail = (
                stderr_tail.splitlines()[-1].strip() if stderr_tail else f"exit code {returncode}"
            )
            raise InvalidCaptureError(f"{self.tool_name} rejected the capture: {detail}")
        if packet_count == 0:
            raise InvalidCaptureError(f"{self.tool_name} reported zero packets")

        warnings: list[str] = []
        first_packet_at = None
        last_packet_at = None
        duration_seconds = None
        link_type = None
        if first is None or last is None:
            warnings.append("packet timestamps could not be parsed from tool output")
        else:
            first_packet_at = _epoch_to_datetime(first[0])
            last_packet_at = _epoch_to_datetime(last[0])
            duration_seconds = max(0.0, last[0] - first[0])
            if first[1]:
                link_type = describe_link_type(first[1])
            else:
                warnings.append("link-layer type was not present in tool output")

        return CaptureInspection(
            status=InspectionStatus.INSPECTED,
            tool=self.tool_name,
            tool_version=self.version(),
            packet_count=packet_count,
            first_packet_at=first_packet_at,
            last_packet_at=last_packet_at,
            duration_seconds=duration_seconds,
            link_type=link_type,
            warnings=warnings,
        )

    def _run_to_completion(self, args: list[str]) -> subprocess.CompletedProcess[bytes] | None:
        try:
            return subprocess.run(
                [self._tshark_path, *args],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=self._timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

    @staticmethod
    def _drain_stderr(process: subprocess.Popen[bytes]) -> str:
        if process.stderr is None:
            return ""
        try:
            data: bytes = process.stderr.read(_STDERR_TAIL_CHARS)
        finally:
            process.stderr.close()
        return data.decode(errors="replace")
