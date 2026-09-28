"""Stage 11 API tests: forensic case management and evidence preservation.

Covers case CRUD, capture association, notes, tags, bookmarks, the
investigation timeline, summaries, reports, JSON export, reproducible
bundles, import, security validation, and the critical data-integrity
guarantee: case metadata never mutates forensic truth.
"""

import io
import json
import zipfile

from tests import tcp_fixtures as tf
from tests import tls_fixtures as tlf

_MALICIOUS = "<img src=x onerror=alert(1)>"
_TRAVERSAL_IDS = [
    "../registry.sqlite3",
    "..\\registry.sqlite3",
    "case_' OR '1'='1",
    "case_<script>",
    "capture_abc",
    "CASE_DEADBEEFDEADBEEF",
]


def upload_and_analyze(client, name: str = "smtp.pcap", content: bytes | None = None):
    created = client.post(
        "/api/captures",
        files={"file": (name, content or tf.smtp_plain_pcap(), "application/octet-stream")},
    ).json()
    analysis = client.post(f"/api/captures/{created['id']}/analyze").json()
    return created, analysis


def make_case(client, title: str = "TLS investigation", priority: str = "HIGH"):
    response = client.post(
        "/api/cases",
        json={"title": title, "description": "Stage 11 test case", "priority": priority},
    )
    assert response.status_code == 200, response.text
    return response.json()


def attach_analyzed(client, case_id: str, content: bytes | None = None):
    created, analysis = upload_and_analyze(client, content=content)
    assert analysis["status"] == "completed"
    response = client.post(f"/api/cases/{case_id}/captures", json={"capture_id": created["id"]})
    assert response.status_code == 200, response.text
    return created


def strip_dynamic(value):
    """Remove explicitly dynamic metadata (wall-clock timestamps)."""
    if isinstance(value, dict):
        return {
            key: strip_dynamic(item)
            for key, item in value.items()
            if key
            not in {
                "created_at",
                "updated_at",
                "closed_at",
                "attached_at",
                "exported_at",
                "generated_at",
            }
        }
    if isinstance(value, list):
        return [strip_dynamic(item) for item in value]
    return value


class TestCaseCRUD:
    def test_create_case_returns_secure_id_and_number(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        assert case["case_id"].startswith("case_")
        assert len(case["case_id"]) == len("case_") + 16
        assert case["case_number"].startswith("CASE-")
        assert case["title"] == "TLS investigation"
        assert case["status"] == "OPEN"
        assert case["priority"] == "HIGH"
        assert case["schema_version"] == "1.0"
        assert case["closed_at"] is None

    def test_case_ids_are_unique(self, make_api) -> None:
        client = make_api()
        first = make_case(client, "First")
        second = make_case(client, "Second")
        assert first["case_id"] != second["case_id"]
        assert first["case_number"] != second["case_number"]

    def test_list_get_update_delete(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        listed = client.get("/api/cases").json()
        assert [c["case_id"] for c in listed] == [case["case_id"]]

        fetched = client.get(f"/api/cases/{case['case_id']}").json()
        assert fetched["title"] == "TLS investigation"

        updated = client.patch(
            f"/api/cases/{case['case_id']}",
            json={"priority": "CRITICAL", "status": "IN_REVIEW", "title": "Renamed"},
        ).json()
        assert updated["priority"] == "CRITICAL"
        assert updated["status"] == "IN_REVIEW"
        assert updated["title"] == "Renamed"

        closed = client.patch(f"/api/cases/{case['case_id']}", json={"status": "CLOSED"}).json()
        assert closed["status"] == "CLOSED"
        assert closed["closed_at"] is not None

        reopened = client.patch(f"/api/cases/{case['case_id']}", json={"status": "OPEN"}).json()
        assert reopened["closed_at"] is None

        assert client.delete(f"/api/cases/{case['case_id']}").status_code == 204
        assert client.get(f"/api/cases/{case['case_id']}").status_code == 404

    def test_status_filter(self, make_api) -> None:
        client = make_api()
        first = make_case(client, "Open case")
        second = make_case(client, "Closed case")
        client.patch(f"/api/cases/{second['case_id']}", json={"status": "CLOSED"})
        open_cases = client.get("/api/cases?status=OPEN").json()
        assert {c["case_id"] for c in open_cases} == {first["case_id"]}

    def test_create_rejects_bad_input(self, make_api) -> None:
        client = make_api()
        assert client.post("/api/cases", json={"title": "", "priority": "HIGH"}).status_code == 422
        assert (
            client.post("/api/cases", json={"title": "x", "priority": "URGENT"}).status_code == 422
        )
        case = make_case(client)
        assert (
            client.patch(f"/api/cases/{case['case_id']}", json={"status": "DONE"}).status_code
            == 422
        )

    def test_malformed_ids_are_not_found(self, make_api) -> None:
        client = make_api()
        for bad in _TRAVERSAL_IDS:
            response = client.get(f"/api/cases/{bad}")
            # Path-normalized traversals miss routing entirely ("not_found");
            # matched-but-invalid ids hit the case guard ("case_not_found").
            # Both must be structured 404s with no internals.
            assert response.status_code == 404, bad
            body = response.json()
            assert body["error"]["code"] in ("case_not_found", "not_found"), bad
            assert "traceback" not in response.text.lower()
            assert ".py" not in response.text


class TestCaptureAssociation:
    def test_attach_and_detach(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"])
        summary = client.get(f"/api/cases/{case['case_id']}/summary").json()
        assert summary["counts"]["captures"] == 1
        assert summary["captures"][0]["capture_id"] == created["id"]
        assert summary["captures"][0]["sha256"] == created["sha256"]

        # Re-attach is idempotent: one timeline event, one reference.
        before = client.get(f"/api/cases/{case['case_id']}/timeline").json()
        client.post(f"/api/cases/{case['case_id']}/captures", json={"capture_id": created["id"]})
        after = client.get(f"/api/cases/{case['case_id']}/timeline").json()
        assert len(before) == len(after)

        assert (
            client.delete(f"/api/cases/{case['case_id']}/captures/{created['id']}").status_code
            == 204
        )
        assert client.get(f"/api/cases/{case['case_id']}/summary").json()["counts"]["captures"] == 0
        assert (
            client.delete(f"/api/cases/{case['case_id']}/captures/{created['id']}").status_code
            == 422
        )

    def test_attach_unknown_capture_is_not_found(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        response = client.post(
            f"/api/cases/{case['case_id']}/captures", json={"capture_id": "capture_0123456789ab"}
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "capture_not_found"

    def test_capture_may_belong_to_multiple_cases(self, make_api) -> None:
        client = make_api()
        first = make_case(client, "First")
        second = make_case(client, "Second")
        created = attach_analyzed(client, first["case_id"])
        response = client.post(
            f"/api/cases/{second['case_id']}/captures", json={"capture_id": created["id"]}
        )
        assert response.status_code == 200


class TestNotes:
    def test_note_lifecycle(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        assert findings, "fixture must yield at least one finding"

        note = client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={
                "target_type": "finding",
                "target_id": findings[0]["id"],
                "content": "Follow up with the mail team.",
            },
        ).json()
        assert note["target_type"] == "finding"

        case_note = client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "case", "target_id": case["case_id"], "content": "Scope note."},
        ).json()
        assert case_note["target_id"] == case["case_id"]

        assert len(client.get(f"/api/cases/{case['case_id']}/notes").json()) == 2

        updated = client.patch(
            f"/api/cases/{case['case_id']}/notes/{note['note_id']}",
            json={"content": "Updated hypothesis."},
        ).json()
        assert updated["content"] == "Updated hypothesis."

        assert (
            client.delete(f"/api/cases/{case['case_id']}/notes/{note['note_id']}").status_code
            == 204
        )
        assert len(client.get(f"/api/cases/{case['case_id']}/notes").json()) == 1

    def test_notes_reject_nonexistent_evidence(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        for target_type, target_id in (
            ("finding", "finding_missing"),
            ("session", "session_missing"),
            ("anomaly", "anomaly_missing"),
            ("capture", "capture_0123456789ab"),
            ("case", "case_0123456789abcdef"),
        ):
            response = client.post(
                f"/api/cases/{case['case_id']}/notes",
                json={"target_type": target_type, "target_id": target_id, "content": "x"},
            )
            assert response.status_code == 422, (target_type, target_id)

    def test_notes_reject_bad_targets_and_sizes(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/notes",
                json={"target_type": "packet", "target_id": "1", "content": "x"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/notes",
                json={"target_type": "case", "target_id": case["case_id"], "content": "x" * 10001},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/notes",
                json={"target_type": "case", "target_id": "../../etc", "content": "x"},
            ).status_code
            == 422
        )

    def test_notes_are_case_scoped(self, make_api) -> None:
        client = make_api()
        first = make_case(client, "First")
        second = make_case(client, "Second")
        note = client.post(
            f"/api/cases/{first['case_id']}/notes",
            json={"target_type": "case", "target_id": first["case_id"], "content": "private"},
        ).json()
        assert (
            client.patch(
                f"/api/cases/{second['case_id']}/notes/{note['note_id']}",
                json={"content": "hijack"},
            ).status_code
            == 422
        )
        assert (
            client.delete(f"/api/cases/{second['case_id']}/notes/{note['note_id']}").status_code
            == 422
        )


class TestTags:
    def test_tag_lifecycle_and_normalization(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        assert (
            client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": " TLS "}).json()["tag"]
            == "tls"
        )
        assert (
            client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": "tls"}).json()["tag"]
            == "tls"
        )
        assert client.get(f"/api/cases/{case['case_id']}/tags").json()["tags"] == ["tls"]
        assert client.delete(f"/api/cases/{case['case_id']}/tags/tls").status_code == 204
        assert client.get(f"/api/cases/{case['case_id']}/tags").json()["tags"] == []
        assert client.delete(f"/api/cases/{case['case_id']}/tags/tls").status_code == 422

    def test_tags_reject_unsafe_values(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        for bad in ["has space", "UPPER!", "a/b", "..", "x" * 65, "<script>", "semi;colon"]:
            assert (
                client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": bad}).status_code
                == 422
            ), bad


class TestBookmarks:
    def test_bookmark_lifecycle(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()

        first = client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={
                "target_type": "finding",
                "target_id": findings[0]["id"],
                "label": "root cause candidate",
            },
        ).json()
        duplicate = client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={"target_type": "finding", "target_id": findings[0]["id"], "label": "other"},
        ).json()
        assert duplicate["bookmark_id"] == first["bookmark_id"]

        session_mark = client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={"target_type": "session", "target_id": sessions[0]["id"]},
        ).json()
        assert session_mark["target_type"] == "session"

        assert len(client.get(f"/api/cases/{case['case_id']}/bookmarks").json()) == 2
        assert (
            client.delete(
                f"/api/cases/{case['case_id']}/bookmarks/{first['bookmark_id']}"
            ).status_code
            == 204
        )
        assert (
            client.delete(
                f"/api/cases/{case['case_id']}/bookmarks/{first['bookmark_id']}"
            ).status_code
            == 422
        )

    def test_bookmarks_reject_nonexistent_evidence(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/bookmarks",
                json={"target_type": "finding", "target_id": "finding_missing"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/bookmarks",
                json={"target_type": "email", "target_id": "1"},
            ).status_code
            == 422
        )


class TestTimeline:
    def test_timeline_records_investigation_not_packets(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={"target_type": "finding", "target_id": findings[0]["id"]},
        )
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "case", "target_id": case["case_id"], "content": "note"},
        )
        client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": "reviewed"})
        client.get(f"/api/cases/{case['case_id']}/report.json")

        entries = client.get(f"/api/cases/{case['case_id']}/timeline").json()
        event_types = [entry["event_type"] for entry in entries]
        assert event_types[:6] == [
            "case_created",
            "capture_attached",
            "finding_bookmarked",
            "note_created",
            "tag_added",
            "report_generated",
        ]
        created_times = [entry["created_at"] for entry in entries]
        assert created_times == sorted(created_times)


class TestSummary:
    def test_summary_quotes_posture_without_case_score(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        first = attach_analyzed(client, case["case_id"])
        second = attach_analyzed(client, case["case_id"], tlf.smtp_starttls_tls_pcap())
        findings = client.get(f"/api/captures/{first['id']}/findings").json()
        client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={"target_type": "finding", "target_id": findings[0]["id"]},
        )
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "case", "target_id": case["case_id"], "content": "note"},
        )
        client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": "tls"})

        summary = client.get(f"/api/cases/{case['case_id']}/summary").json()
        assert summary["counts"]["captures"] == 2
        assert summary["counts"]["sessions"] >= 2
        assert summary["counts"]["bookmarks"] == 1
        assert summary["counts"]["notes"] == 1
        assert summary["counts"]["tags"] == 1
        # No invented case-level score anywhere in the summary.
        assert "case_score" not in summary
        assert "overall_score" not in summary["counts"]
        for card in summary["captures"]:
            posture = client.get(f"/api/captures/{card['capture_id']}/posture").json()
            assert card["posture_state"] == posture["posture_state"]
            assert card["posture_score"] == posture["overall_score"]
        assert {c["capture_id"] for c in summary["captures"]} == {first["id"], second["id"]}


class TestCaseReports:
    def test_json_html_pdf_reports(self, make_api) -> None:
        client = make_api(ai_provider="mock")
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={"target_type": "finding", "target_id": findings[0]["id"], "label": "key"},
        )
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "case", "target_id": case["case_id"], "content": _MALICIOUS},
        )
        client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": "tls"})

        report = client.get(f"/api/cases/{case['case_id']}/report.json").json()
        assert report["report"]["schema_version"] == "1.0"
        assert report["report"]["report_id"].startswith("case_report_")
        assert report["case"]["case_id"] == case["case_id"]
        assert report["evidence"]["captures"][0]["sha256"] == created["sha256"]
        assert report["analyst_work"]["notes"][0]["content"] == _MALICIOUS
        # Analyst content is labeled as such, never as evidence.
        assert "not forensic evidence" in report["analyst_work"]["notice"]
        # No validated AI history exists, so no observations leak in.
        assert report["ai_interpretation"]["observations"] == []
        assert report["provenance"]["captures"][0]["sha256"] == created["sha256"]

        html_body = client.get(f"/api/cases/{case['case_id']}/report.html").text
        assert "&lt;img" in html_body
        assert _MALICIOUS not in html_body

        pdf = client.get(f"/api/cases/{case['case_id']}/report.pdf").content
        assert pdf.startswith(b"%PDF-")

        history = client.get(f"/api/cases/{case['case_id']}/summary").json()
        assert history["counts"]["reports"] == 3

    def test_report_is_deterministic_for_stable_state(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        attach_analyzed(client, case["case_id"])
        first = json.loads(client.get(f"/api/cases/{case['case_id']}/report.json").content)
        second = json.loads(client.get(f"/api/cases/{case['case_id']}/report.json").content)
        first_norm = strip_dynamic(first)
        second_norm = strip_dynamic(second)
        # Each generation appends one report_generated timeline event after
        # serializing, so compare everything except the trailing entries.
        first_timeline = first_norm["analyst_work"].pop("timeline")
        second_timeline = second_norm["analyst_work"].pop("timeline")
        assert first_norm == second_norm
        assert [e["event_type"] for e in second_timeline] == [
            e["event_type"] for e in first_timeline
        ] + ["report_generated"]
        # Reports history itself is stable between the two builds.
        assert first["analyst_work"]["timeline"] != []


class TestExportBundleImport:
    def test_export_structure_and_determinism(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"])
        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={"target_type": "finding", "target_id": findings[0]["id"]},
        )
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "case", "target_id": case["case_id"], "content": "export me"},
        )
        client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": "tls"})

        first = client.get(f"/api/cases/{case['case_id']}/export").json()
        assert first["schema_version"] == "1.1"
        for key in (
            "case",
            "captures",
            "findings",
            "anomalies",
            "bookmarks",
            "notes",
            "tags",
            "timeline",
            "reports",
            "correlations",
            "correlation_summary",
            "provenance",
        ):
            assert key in first, key
        assert first["captures"][0]["sha256"] == created["sha256"]
        raw = json.dumps(first).lower()
        assert "api_key" not in raw
        assert "password" not in raw
        assert "begin private key" not in raw

        second = client.get(f"/api/cases/{case['case_id']}/export").json()
        first_norm = strip_dynamic(first)
        second_norm = strip_dynamic(second)
        first_timeline = first_norm.pop("timeline")
        second_timeline = second_norm.pop("timeline")
        assert first_norm == second_norm
        assert len(second_timeline) == len(first_timeline) + 1

    def test_bundle_contents(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"])

        bundle = client.get(f"/api/cases/{case['case_id']}/bundle").content
        archive = zipfile.ZipFile(io.BytesIO(bundle))
        names = set(archive.namelist())
        assert names == {
            "case.json",
            "README.txt",
            "evidence-manifest.json",
            "reports/case-report.json",
        }
        manifest = json.loads(archive.read("evidence-manifest.json"))
        assert manifest["captures"][0]["sha256"] == created["sha256"]
        assert manifest["captures"][0]["evidence_included"] is False
        readme = archive.read("README.txt").decode()
        assert "not a legal" in readme
        assert "case.json" in readme

        full = client.get(f"/api/cases/{case['case_id']}/bundle?include_evidence=true").content
        full_archive = zipfile.ZipFile(io.BytesIO(full))
        evidence_names = [n for n in full_archive.namelist() if n.startswith("evidence/")]
        assert len(evidence_names) == 1
        assert (
            json.loads(full_archive.read("evidence-manifest.json"))["captures"][0][
                "evidence_included"
            ]
            is True
        )

    def test_import_round_trip_creates_new_case(self, make_api) -> None:
        client = make_api()
        case = make_case(client, "Original")
        attach_analyzed(client, case["case_id"])
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "case", "target_id": case["case_id"], "content": "keep me"},
        )
        client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": "tls"})
        export = client.get(f"/api/cases/{case['case_id']}/export").json()

        imported = client.post("/api/cases/import", json=export)
        assert imported.status_code == 200, imported.text
        new_case = imported.json()
        assert new_case["case_id"] != case["case_id"]
        assert new_case["title"] == "Original"
        summary = client.get(f"/api/cases/{new_case['case_id']}/summary").json()
        assert summary["counts"]["captures"] == 1
        assert summary["counts"]["notes"] == 1
        assert summary["counts"]["tags"] == 1
        events = client.get(f"/api/cases/{new_case['case_id']}/timeline").json()
        assert events[-1]["event_type"] == "case_imported"

    def test_import_rejects_malformed_bundles(self, make_api) -> None:
        client = make_api()
        for bad in (
            {},
            {"schema_version": "9.9"},
            {"schema_version": "1.0"},
            {"schema_version": "1.0", "case": {"title": "", "priority": "HIGH"}},
            {"schema_version": "1.0", "case": {"title": "x", "priority": "NOPE"}},
            {
                "schema_version": "1.0",
                "case": {"title": "x", "priority": "LOW"},
                "captures": "nope",
            },
        ):
            assert client.post("/api/cases/import", json=bad).status_code == 422, bad

    def test_import_skips_unknown_captures_and_malicious_notes(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        attach_analyzed(client, case["case_id"])
        export = client.get(f"/api/cases/{case['case_id']}/export").json()
        export["captures"].append({"capture_id": "capture_0123456789ab", "sha256": "0" * 64})
        export["notes"].append(
            {"target_type": "case", "target_id": case["case_id"], "content": "x" * 20000}
        )
        export["notes"].append(
            {"target_type": "finding", "target_id": "../../etc/passwd", "content": "evil"}
        )
        export["tags"].append("bad tag!")
        imported = client.post("/api/cases/import", json=export).json()
        summary = client.get(f"/api/cases/{imported['case_id']}/summary").json()
        assert summary["counts"]["captures"] == 1
        assert summary["counts"]["notes"] == 0
        assert summary["counts"]["tags"] == 0


class TestCaseSecurity:
    def test_error_shape_never_leaks_internals(self, make_api) -> None:
        client = make_api()
        response = client.get("/api/cases/case_doesnotexist00")
        assert response.status_code == 404
        assert set(response.json()) == {"error"}
        assert "traceback" not in response.text
        assert ".py" not in response.text

    def test_oversized_and_control_inputs_rejected(self, make_api) -> None:
        client = make_api()
        assert (
            client.post("/api/cases", json={"title": "x" * 201, "priority": "LOW"}).status_code
            == 422
        )
        response = client.post("/api/cases", json={"title": "bad\x00title", "priority": "LOW"})
        assert response.status_code == 422
        case = make_case(client)
        assert (
            client.post(
                f"/api/cases/{case['case_id']}/tags", json={"tag": "bad\x01tag"}
            ).status_code
            == 422
        )


class TestCaseDataIntegrity:
    """Case metadata must never mutate underlying forensic truth."""

    def _snapshot(self, client, capture_id):
        posture = client.get(f"/api/captures/{capture_id}/posture").json()
        findings = client.get(f"/api/captures/{capture_id}/findings").json()
        anomalies = client.get(f"/api/captures/{capture_id}/anomalies").json()
        graph = client.get(f"/api/captures/{capture_id}/graph").json()
        return {
            "posture": posture,
            "findings": findings,
            "anomalies": anomalies,
            "graph": graph,
        }

    def test_workflow_leaves_evidence_identical(self, make_api) -> None:
        client = make_api()
        case = make_case(client)
        created = attach_analyzed(client, case["case_id"], tlf.smtp_starttls_tls_pcap())
        before = self._snapshot(client, created["id"])

        findings = client.get(f"/api/captures/{created['id']}/findings").json()
        sessions = client.get(f"/api/captures/{created['id']}/sessions").json()
        client.post(
            f"/api/cases/{case['case_id']}/notes",
            json={"target_type": "finding", "target_id": findings[0]["id"], "content": "note"},
        )
        client.post(f"/api/cases/{case['case_id']}/tags", json={"tag": "suspicious"})
        client.post(
            f"/api/cases/{case['case_id']}/bookmarks",
            json={"target_type": "session", "target_id": sessions[0]["id"]},
        )
        client.patch(f"/api/cases/{case['case_id']}", json={"priority": "CRITICAL"})
        client.patch(f"/api/cases/{case['case_id']}", json={"status": "CLOSED"})
        client.get(f"/api/cases/{case['case_id']}/report.json")
        client.get(f"/api/cases/{case['case_id']}/export")

        after = self._snapshot(client, created["id"])
        assert before == after
