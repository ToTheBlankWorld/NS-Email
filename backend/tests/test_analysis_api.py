"""Stage 2 API tests: capture analysis, session retrieval, credential safety.

Runs the real analysis pipeline (pure-Python packet source) over synthetic
TCP conversation captures — no tshark, no fakes, no fabricated results.
"""

import sqlite3

from tests import tcp_fixtures as tf
from tests.conftest import build_pcap, build_pcapng


def upload(client, name: str, content: bytes):
    return client.post(
        "/api/captures",
        files={"file": (name, content, "application/octet-stream")},
    )


def ingest_and_analyze(client, name: str, content: bytes):
    created = upload(client, name, content).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze")
    return created, analysis


class TestAnalysisApi:
    def test_smtp_analysis_completes_with_one_session(self, make_api) -> None:
        client = make_api()
        created, analysis = ingest_and_analyze(client, "smtp.pcap", tf.smtp_plain_pcap())

        assert analysis.status_code == 200
        body = analysis.json()
        assert body == {
            "capture_id": created["id"],
            "status": "completed",
            "sessions_found": 1,
            "error_code": None,
            "error_message": None,
        }

        detail = client.get(f"/api/captures/{created['id']}").json()
        assert detail["analysis"]["status"] == "completed"
        assert detail["analysis"]["session_count"] == 1

    def test_smtp_session_summary_and_detail(self, make_api) -> None:
        client = make_api()
        created, _ = ingest_and_analyze(client, "smtp.pcap", tf.smtp_plain_pcap())

        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        assert len(sessions) == 1
        summary = sessions[0]
        assert summary["protocol"] == "smtp"
        assert summary["confidence"] == "high"
        assert summary["orientation"] == "client_server"
        assert summary["complete"] is True
        assert summary["client_ip"] == "10.10.0.23"
        assert summary["server_port"] == 587
        assert summary["events"] == []  # summaries exclude the timeline

        detail = client.get(f"/api/sessions/{summary['id']}").json()
        event_types = [event["type"] for event in detail["events"]]
        assert event_types[0] == "connection_established"
        assert "server_greeting" in event_types
        assert "mail_transaction_start" in event_types
        assert "mail_transaction_complete" in event_types
        assert event_types[-1] == "connection_closed"
        # evidence references: events cite packet numbers
        greeting = next(e for e in detail["events"] if e["type"] == "server_greeting")
        assert greeting["packet_numbers"]
        assert greeting["timestamp"] is not None

    def test_smtp_starttls_negotiation_recorded(self, make_api) -> None:
        client = make_api()
        created, _ = ingest_and_analyze(client, "starttls.pcap", tf.smtp_starttls_pcap())

        session = client.get(f"/api/captures/{created['id']}/sessions").json()[0]
        detail = client.get(f"/api/sessions/{session['id']}").json()

        assert detail["starttls"]["advertised"] is True
        assert detail["starttls"]["requested"] is True
        assert detail["starttls"]["response_seen"] is True
        assert detail["starttls"]["packet_number"] is not None
        event_types = [event["type"] for event in detail["events"]]
        assert "tls_transition" in event_types
        # plaintext parsing stopped after the transition
        assert event_types[-2] == "tls_transition"
        assert event_types[-1] == "connection_closed"

    def test_imap_session_preserves_tags_and_redacts_login(self, make_api) -> None:
        client = make_api()
        created, _ = ingest_and_analyze(client, "imap.pcap", tf.imap_pcap())

        session = client.get(f"/api/captures/{created['id']}/sessions").json()[0]
        assert session["protocol"] == "imap"

        detail = client.get(f"/api/sessions/{session['id']}").json()
        auth = next(e for e in detail["events"] if e["type"] == "authentication")
        assert auth["detail"]["tag"] == "a002"
        assert auth["detail"]["credential_data"] == "redacted"

    def test_pop3_session_records_auth_shape_only(self, make_api) -> None:
        client = make_api()
        created, _ = ingest_and_analyze(client, "pop3.pcap", tf.pop3_pcap())

        session = client.get(f"/api/captures/{created['id']}/sessions").json()[0]
        assert session["protocol"] == "pop3"

        detail = client.get(f"/api/sessions/{session['id']}").json()
        auth = [e for e in detail["events"] if e["type"] == "authentication"]
        assert {e["detail"].get("command") for e in auth} == {"USER", "PASS"}
        assert all(e["detail"].get("argument") == "redacted" for e in auth)

    def test_reassembly_edge_cases_produce_honest_sessions(self, make_api) -> None:
        client = make_api()
        cases = [
            ("frag.pcap", tf.smtp_fragmented_pcap(), {"complete": True, "gap_count": 0}),
            ("ooo.pcap", tf.smtp_out_of_order_pcap(), {"complete": True, "gap_count": 0}),
            ("retrans.pcap", tf.smtp_retransmission_pcap(), {"complete": True, "gap_count": 0}),
            ("incomplete.pcap", tf.incomplete_pcap(), {"complete": False}),
            ("unknown.pcap", tf.unknown_protocol_pcap(), {"protocol": None}),
            ("malformed.pcap", tf.malformed_pcap(), {"protocol": None}),
        ]
        for name, content, expectations in cases:
            created, analysis = ingest_and_analyze(client, name, content)
            assert analysis.json()["status"] == "completed", name
            assert analysis.json()["sessions_found"] == 1, name
            session = client.get(f"/api/captures/{created['id']}/sessions").json()[0]
            for key, value in expectations.items():
                assert session[key] == value, f"{name}: {key}"

        # retransmission evidence is explicit
        retrans = client.get(
            "/api/captures/"
            + upload(client, "again.pcap", tf.smtp_retransmission_pcap()).json()["id"]
            + "/sessions"
        ).json()[0]
        assert retrans["retransmissions"] >= 1
        # incomplete stream explains why
        incomplete = client.get(
            "/api/captures/"
            + upload(client, "inc2.pcap", tf.incomplete_pcap()).json()["id"]
            + "/sessions"
        ).json()[0]
        assert "gap" in (incomplete["completeness_reason"] or "")

    def test_reanalysis_replaces_results_deterministically(self, make_api) -> None:
        client = make_api()
        created, _ = ingest_and_analyze(client, "smtp.pcap", tf.smtp_plain_pcap())
        first = client.get(f"/api/captures/{created['id']}/sessions").json()

        second_run = client.post(f"/api/captures/{created['id']}/analyze").json()
        second = client.get(f"/api/captures/{created['id']}/sessions").json()

        assert second_run["sessions_found"] == 1
        assert len(second) == 1
        assert second[0]["id"] == first[0]["id"]  # deterministic identity

    def test_analyze_unknown_capture_is_not_found(self, make_api) -> None:
        client = make_api()

        response = client.post("/api/captures/capture_000000000000/analyze")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "capture_not_found"

    def test_sessions_of_unanalyzed_capture_are_empty(self, make_api) -> None:
        client = make_api()
        created = upload(client, "smtp.pcap", tf.smtp_plain_pcap()).json()

        response = client.get(f"/api/captures/{created['id']}/sessions")

        assert response.status_code == 200
        assert response.json() == []
        detail = client.get(f"/api/captures/{created['id']}").json()
        assert detail["analysis"]["status"] == "not_analyzed"

    def test_sessions_of_unknown_capture_are_not_found(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/captures/capture_000000000000/sessions")

        assert response.status_code == 404

    def test_non_tcp_capture_analyzes_to_zero_sessions(self, make_api) -> None:
        client = make_api()
        created = upload(client, "empty-ish.pcap", build_pcap([(1727430000, b"")])).json()

        analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()

        assert analysis["status"] == "completed"
        assert analysis["sessions_found"] == 0
        assert sessions == []

    def test_pcapng_container_analyzes(self, make_api) -> None:
        client = make_api()
        created = upload(client, "office.pcapng", build_pcapng([(1727430000, b"")])).json()

        analysis = client.post(f"/api/captures/{created['id']}/analyze").json()

        assert analysis["status"] == "completed"


class TestCredentialSafety:
    def test_secrets_never_reach_api_responses(self, make_api) -> None:
        client = make_api()
        imap = upload(client, "imap.pcap", tf.imap_pcap()).json()
        pop3 = upload(client, "pop3.pcap", tf.pop3_pcap()).json()
        client.post(f"/api/captures/{imap['id']}/analyze")
        client.post(f"/api/captures/{pop3['id']}/analyze")

        imap_session = client.get(f"/api/captures/{imap['id']}/sessions").json()[0]
        bodies = [
            client.get("/api/captures").text,
            client.get(f"/api/captures/{imap['id']}").text,
            client.get(f"/api/captures/{imap['id']}/sessions").text,
            client.get(f"/api/sessions/{imap_session['id']}").text,
            client.get(f"/api/captures/{pop3['id']}").text,
            client.get(f"/api/captures/{pop3['id']}/sessions").text,
        ]

        for body in bodies:
            assert "s3cret-password" not in body
            assert "hunter2-secret" not in body
            assert "carol" not in body
            assert "dave" not in body

    def test_secrets_never_reach_persisted_rows(self, make_api, tmp_path) -> None:
        client = make_api()
        pop3 = upload(client, "pop3.pcap", tf.pop3_pcap()).json()
        client.post(f"/api/captures/{pop3['id']}/analyze")

        db_path = client.app.state.session_store._db_path
        connection = sqlite3.connect(db_path)
        rows = connection.execute("SELECT detail FROM session_events").fetchall()
        connection.close()

        for (detail,) in rows:
            assert "hunter2-secret" not in detail
            assert "dave" not in detail

    def test_redaction_survives_in_event_details(self, make_api) -> None:
        client = make_api()
        pop3 = upload(client, "pop3.pcap", tf.pop3_pcap()).json()
        client.post(f"/api/captures/{pop3['id']}/analyze")

        session = client.get(f"/api/captures/{pop3['id']}/sessions").json()[0]
        detail = client.get(f"/api/sessions/{session['id']}").json()

        auth = [e for e in detail["events"] if e["type"] == "authentication"]
        assert len(auth) == 2  # USER and PASS observed
        assert all(e["detail"]["argument"] == "redacted" for e in auth)
