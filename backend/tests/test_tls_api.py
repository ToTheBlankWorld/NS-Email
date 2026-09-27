"""Stage 3 API tests: TLS handshake and certificate evidence."""

from tests import tcp_fixtures as tf
from tests import tls_fixtures as tlf


def upload(client, name: str, content: bytes):
    return client.post(
        "/api/captures",
        files={"file": (name, content, "application/octet-stream")},
    )


def ingest_analyze_and_get_session(client, name: str, content: bytes):
    created = upload(client, name, content).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
    return created, analysis, sessions


class TestTlsEvidenceApi:
    def test_starttls_session_exposes_tls_evidence(self, make_api) -> None:
        client = make_api()
        _created, analysis, sessions = ingest_analyze_and_get_session(
            client, "tls.pcap", tlf.smtp_starttls_tls_pcap()
        )

        assert analysis["status"] == "completed"
        assert analysis["sessions_found"] == 1
        summary = sessions[0]
        handshake = summary["handshake"]
        assert handshake is not None
        assert handshake["tls_version"] == "TLS 1.2"
        assert handshake["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        assert handshake["cipher_suite_code"] == 0xC02F
        assert handshake["key_exchange"] == "ecdhe"
        assert handshake["sni_server_name"] == "mail.example.org"
        assert handshake["handshake_complete"] is True
        assert handshake["cipher_suites_offered"] == [
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
        ]
        extension_names = {e["name"] for e in handshake["extensions"]}
        assert "server_name" in extension_names
        assert "supported_versions" in extension_names

    def test_certificate_chain_via_session_detail(self, make_api) -> None:
        client = make_api()
        _created, _, sessions = ingest_analyze_and_get_session(
            client, "tls.pcap", tlf.smtp_starttls_tls_pcap()
        )

        # summaries carry no certificates; the detail view does
        assert sessions[0]["certificates"] == []
        session_id = sessions[0]["id"]
        detail = client.get(f"/api/sessions/{session_id}").json()

        certificates = detail["certificates"]
        assert len(certificates) == 1
        leaf = certificates[0]
        assert leaf["position_in_chain"] == 0
        assert leaf["subject"] == "CN=mail.example.org"
        assert leaf["public_key_algorithm"] == "RSA"
        assert leaf["public_key_size_bits"] == 2048
        assert len(leaf["fingerprint_sha256"]) == 64
        assert "mail.example.org" in leaf["subject_alternative_names"]
        assert detail["handshake"]["certificate_ids"] == [leaf["id"]]

    def test_implicit_tls_session_analysis(self, make_api) -> None:
        client = make_api()
        created = upload(client, "imaps.pcap", tlf.imaps_tls_pcap()).json()
        analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()

        assert analysis["sessions_found"] == 1
        session = sessions[0]
        assert session["implicit_tls"] is True
        assert session["protocol"] == "imap"  # implicit-TLS port + valid handshake
        assert session["confidence"] == "medium"
        handshake = session["handshake"]
        assert handshake["tls_version"] == "TLS 1.2"
        assert handshake["sni_server_name"] == "mail.example.org"

    def test_plain_session_has_no_tls_evidence(self, make_api) -> None:
        client = make_api()
        _created, _, sessions = ingest_analyze_and_get_session(
            client, "smtp.pcap", tf.smtp_plain_pcap()
        )

        assert sessions[0]["handshake"] is None
        detail = client.get(f"/api/sessions/{sessions[0]['id']}").json()
        assert detail["handshake"] is None
        assert detail["certificates"] == []
