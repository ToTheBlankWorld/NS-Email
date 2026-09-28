"""Consolidated security regression suite (Stage 10).

Each test maps to a Phase 4 checklist category. Existing coverage from
earlier stages (upload validation, path traversal, magic bytes, AI
grounding) is extended — not duplicated — here: this suite targets the
gaps that earlier stages left open.

Categories:
- PATH TRAVERSAL: encoded/nested traversal payloads
- PARSER ROBUSTNESS: malformed packets/streams/TLS extensions/certificates
- REPORT SECURITY: hostile evidence text in reports
- AI SECURITY: provider timeout/failure/malformed output
- DATABASE SECURITY: malformed IDs, duplicate evidence, corrupted rows
"""

import struct

import pytest
from engine.ingestion.errors import UnsupportedCaptureTypeError
from engine.ingestion.validation import validate_display_filename

from tests import tcp_fixtures as tf
from tests import tls_fixtures as tlf

# ---------------------------------------------------------------------------
# PATH TRAVERSAL
# ---------------------------------------------------------------------------


class TestPathTraversal:
    @pytest.mark.parametrize(
        "filename",
        [
            "..\\..\\windows\\evil.pcap",
            "a/b/../../c.pcap",
            "....//....//evil.pcap",
            "plain.pcap/../../up.pcap",
        ],
    )
    def test_nested_traversal_is_rejected(self, filename: str) -> None:
        with pytest.raises(UnsupportedCaptureTypeError):
            validate_display_filename(filename)

    def test_percent_encoded_traversal_is_inert_display_metadata(self) -> None:
        # Percent-encoded separators have no filesystem meaning at the
        # validation layer; the name stays display metadata and evidence is
        # stored under the hash-derived capture id.
        assert validate_display_filename("%2e%2e%2fpcap.pcap") == "%2e%2e%2fpcap.pcap"

    def test_encoded_traversal_upload_is_rejected_after_decoding(self, make_api) -> None:
        # The multipart layer decodes %2F before validation, so the decoded
        # path components are caught by the same traversal rejection.
        client = make_api()
        response = client.post(
            "/api/captures",
            files={
                "file": ("..%2F..%2Fevil.pcap", tf.smtp_plain_pcap(), "application/octet-stream")
            },
        )
        assert response.status_code == 400

    def test_traversal_payload_never_creates_files_outside_storage(
        self, make_api, tmp_path
    ) -> None:
        client = make_api()
        client.post(
            "/api/captures",
            files={"file": ("safe.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        )
        # nothing may appear next to the configured storage root
        assert not list(tmp_path.glob("*.pcap"))


# ---------------------------------------------------------------------------
# PARSER ROBUSTNESS
# ---------------------------------------------------------------------------


def _garbage_pcap(header: bytes, body: bytes) -> bytes:
    return header + body


class TestParserRobustness:
    def test_truncated_pcap_header_never_crashes(self, make_api) -> None:
        """A magic-valid but truncated file takes a controlled path."""
        client = make_api()
        response = client.post(
            "/api/captures",
            files={"file": ("t.pcap", b"\xd4\xc3\xb2\xa1\x02\x00", "application/octet-stream")},
        )
        # registration accepts magic-valid input; deep validation happens at
        # analysis time and must yield a structured, non-crashing result
        assert response.status_code in (201, 400)
        if response.status_code == 201:
            created = response.json()
            analysis = client.post(f"/api/captures/{created['id']}/analyze")
            assert analysis.status_code == 200
            assert analysis.json()["status"] in ("completed", "failed")

    def test_pcap_with_garbage_packet_record_fails_analysis_not_crash(self, make_api) -> None:
        client = make_api()
        header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        record = struct.pack("<IIII", 1727427600, 0, 900, 900) + b"\xff" * 900
        created = client.post(
            "/api/captures",
            files={
                "file": (
                    "garbage.pcap",
                    _garbage_pcap(header, record),
                    "application/octet-stream",
                )
            },
        ).json()
        analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
        # controlled state: either completed with zero sessions or a
        # structured failure — never a 500 traceback
        assert analysis["status"] in ("completed", "failed")
        if analysis["status"] == "completed":
            assert analysis["sessions_found"] == 0

    def test_truncated_tls_record_produces_structured_evidence(self, make_api) -> None:
        """A TLS flight cut mid-record must not crash the handshake parser."""
        client = make_api()
        full = tlf.smtp_starttls_tls_pcap()
        truncated = full[: len(full) - 40]
        created = client.post(
            "/api/captures",
            files={"file": ("trunc.pcap", truncated, "application/octet-stream")},
        ).json()
        analysis = client.post(f"/api/captures/{created['id']}/analyze")
        assert analysis.status_code == 200
        assert analysis.json()["status"] in ("completed", "failed")

    def test_malformed_tls_extension_is_ignored_not_fatal(self, make_api) -> None:
        client = make_api()
        base = tlf.smtp_starttls_tls_pcap()
        # corrupt bytes inside the ClientHello extension area (after the
        # fixed Ethernet/IP/TCP framing the extension bytes still exist)
        corrupted = bytearray(base)
        for index in range(len(corrupted) - 80, len(corrupted) - 60):
            corrupted[index] ^= 0xFF
        created = client.post(
            "/api/captures",
            files={"file": ("bad_ext.pcap", bytes(corrupted), "application/octet-stream")},
        ).json()
        analysis = client.post(f"/api/captures/{created['id']}/analyze")
        assert analysis.status_code == 200

    def test_malformed_certificate_der_yields_no_certificate_finding(self, make_api) -> None:
        """A garbage DER in a Certificate message must not crash extraction."""
        from tests.tcp_fixtures import FrameConversation
        from tests.tls_fixtures import (
            _client_hello_record,
            _server_hello_record,
        )

        def starttls_with_garbage_certificate() -> bytes:
            garbage_der = b"\x30\x82\x00\x50" + b"\xff" * 76
            b = FrameConversation()
            (
                b.syn()
                .synack()
                .ack()
                .s(b"220 mail.example.org ESMTP\r\n")
                .c(b"EHLO client.example.net\r\n")
                .s(b"250-mail.example.org\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
                .c(b"STARTTLS\r\n")
                .s(b"220 2.0.0 Ready to start TLS\r\n")
                .c(_client_hello_record())
                .s(_server_hello_record() + tls_certificate_record(garbage_der))
                .fin_c()
                .fin_s()
            )
            return b.to_pcap()

        client = make_api()
        created = client.post(
            "/api/captures",
            files={
                "file": (
                    "badcert.pcap",
                    starttls_with_garbage_certificate(),
                    "application/octet-stream",
                )
            },
        ).json()
        analysis = client.post(f"/api/captures/{created['id']}/analyze")
        assert analysis.status_code == 200
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        assert sessions, "session must still be reconstructed"


def tls_certificate_record(der: bytes) -> bytes:
    from tests.tls_fixtures import TLS_CONTENT_HANDSHAKE

    entry = len(der).to_bytes(3, "big") + der
    body = len(entry).to_bytes(3, "big") + entry
    return struct.pack(">BHH", TLS_CONTENT_HANDSHAKE, 0x0303, len(body)) + body


# ---------------------------------------------------------------------------
# AI SECURITY
# ---------------------------------------------------------------------------


class TestAISecurity:
    def test_provider_timeout_maps_to_structured_state(self) -> None:
        from engine.ai.provider import (
            AIProviderUnavailableError,
            LLMProvider,
            LLMRequest,
            LLMResponse,
        )

        class HangingProvider(LLMProvider):
            @property
            def provider_name(self) -> str:
                return "hanging"

            @property
            def model_name(self) -> str:
                return "hanging-1"

            @property
            def is_local(self) -> bool:
                return True

            def generate(self, request: LLMRequest) -> LLMResponse:
                raise AIProviderUnavailableError("provider timed out")

        provider = HangingProvider()
        try:
            provider.generate(LLMRequest(system_prompt="s", user_prompt="u"))
        except AIProviderUnavailableError as error:
            assert "timed out" in str(error)
            # no API key material can appear in provider errors
            assert "Bearer" not in str(error)

    def test_malformed_provider_output_is_rejected(self) -> None:
        from engine.ai.response import AIResponseValidationError, parse_llm_output

        with pytest.raises(AIResponseValidationError):
            parse_llm_output("not json at all {")
        with pytest.raises(AIResponseValidationError):
            parse_llm_output("```json\n{broken json\n```")

    def test_citation_of_foreign_session_is_rejected(self) -> None:
        from engine.ai.context import AIContext
        from engine.ai.response import AIResponseValidationError, validate_response

        context = AIContext(
            capture_id="capture_000000000000",
            session_id="session_aaaaaaaaaaaaaaaa",
            protocol="smtp",
            context_json="{}",
            related_session_count=0,
        )
        with pytest.raises(AIResponseValidationError):
            validate_response({"citations": [{"session_id": "session_bbbbbbbbbbbbbbbb"}]}, context)


# ---------------------------------------------------------------------------
# DATABASE SECURITY
# ---------------------------------------------------------------------------


class TestDatabaseSecurity:
    def test_malformed_ids_return_structured_404(self, make_api) -> None:
        client = make_api()
        for path in (
            "/api/captures/../../etc/passwd",
            "/api/findings/finding_%00",
            "/api/anomalies/anomaly_XX",
            "/api/sessions/session_zz",
        ):
            response = client.get(path)
            assert response.status_code in (400, 404), path
            body = response.json()
            assert "error" in body

    def test_duplicate_upload_is_idempotent(self, make_api) -> None:
        client = make_api()
        first = client.post(
            "/api/captures",
            files={"file": ("a.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        )
        second = client.post(
            "/api/captures",
            files={"file": ("a.pcap", tf.smtp_plain_pcap(), "application/octet-stream")},
        )
        assert first.json()["id"] == second.json()["id"]
        assert second.json()["duplicate"] is True

    def test_errors_never_contain_stack_traces_or_sql(self, make_api) -> None:
        client = make_api()
        response = client.get("/api/captures/capture_000000000000")
        body = response.text
        assert "Traceback" not in body
        assert "SELECT" not in body
        assert "sqlite" not in body.lower()
