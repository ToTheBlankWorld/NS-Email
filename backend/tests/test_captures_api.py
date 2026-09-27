"""End-to-end capture ingestion API tests, including security cases.

tshark is unavailable in this environment, so the "inspected" path is
exercised with a scriptable fake inspector; the unavailable path is
exercised against the real default wiring (no tshark).
"""

from app.config import MAX_CAPTURE_SIZE_BYTES
from tests.conftest import FakeInspector, build_pcap, build_pcapng

PCAP = build_pcap([(1727430000, b"\x00" * 60), (1727430050, b"\x00" * 60)])
PCAPNG = build_pcapng([(1727430000, b"\x00" * 60)])


def upload(client, name: str, content: bytes):
    return client.post(
        "/api/captures",
        files={"file": (name, content, "application/octet-stream")},
    )


class TestUploadSuccess:
    def test_valid_pcap_is_registered_and_inspected(self, make_api) -> None:
        client = make_api(inspector=FakeInspector(packet_count=2))

        response = upload(client, "mail-traffic.pcap", PCAP)

        assert response.status_code == 201
        body = response.json()
        assert body["filename"] == "mail-traffic.pcap"
        assert body["format"] == "pcap"
        assert body["size_bytes"] == len(PCAP)
        assert body["status"] == "ready"
        assert body["duplicate"] is False
        assert body["packet_count"] == 2
        assert body["duration_seconds"] == 90.0
        assert body["link_type"] == "Ethernet"
        assert body["started_at"].startswith("2026-09-27T12:00:00")
        assert body["inspection"]["status"] == "inspected"
        assert body["inspection"]["tool"] == "fake-tshark"

    def test_valid_pcapng_is_registered(self, make_api) -> None:
        client = make_api(inspector=FakeInspector(packet_count=1))

        response = upload(client, "office.pcapng", PCAPNG)

        assert response.status_code == 201
        body = response.json()
        assert body["format"] == "pcapng"
        assert body["status"] == "ready"

    def test_sha256_is_computed_from_actual_bytes(self, make_api) -> None:
        import hashlib

        client = make_api(inspector=FakeInspector())

        body = upload(client, "sha-check.pcap", PCAP).json()

        assert body["sha256"] == hashlib.sha256(PCAP).hexdigest()

    def test_capture_id_is_derived_from_the_hash(self, make_api) -> None:
        import hashlib

        client = make_api(inspector=FakeInspector())

        body = upload(client, "id-check.pcap", PCAP).json()

        expected = f"capture_{hashlib.sha256(PCAP).hexdigest()[:12]}"
        assert body["id"] == expected

    def test_evidence_and_metadata_are_stored_by_capture_id(self, make_api) -> None:
        import json

        client = make_api(inspector=FakeInspector())
        body = upload(client, "layout.pcap", PCAP).json()

        capture_dir = (
            client.app.state.capture_storage.root / body["id"]  # type: ignore[attr-defined]
        )
        assert (capture_dir / "evidence.pcap").read_bytes() == PCAP
        metadata = json.loads((capture_dir / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["capture"]["sha256"] == body["sha256"]
        assert metadata["inspection"]["status"] == "inspected"

    def test_inspector_never_receives_the_upload_filename(self, make_api) -> None:
        import hashlib

        inspector = FakeInspector()
        client = make_api(inspector=inspector)
        upload(client, "sneaky-name.pcap", PCAP).json()

        seen = inspector.seen_paths[0]
        assert seen.name == "evidence.pcap"
        assert "sneaky" not in str(seen)
        assert seen.parent.name == f"capture_{hashlib.sha256(PCAP).hexdigest()[:12]}"


class TestUploadRejection:
    def test_unsupported_extension_is_rejected(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())

        response = upload(client, "notes.txt", b"hello world")

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "invalid_capture_type"

    def test_oversized_upload_is_rejected(self, make_api) -> None:
        client = make_api(inspector=FakeInspector(), max_capture_bytes=64)
        big = build_pcap([(1, b"\x00" * 500)])

        response = upload(client, "big.pcap", big)

        assert response.status_code == 413
        assert response.json()["error"]["code"] == "capture_too_large"

    def test_empty_file_is_rejected(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())

        response = upload(client, "empty.pcap", b"")

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_capture"

    def test_malformed_capture_with_valid_magic_is_rejected(self, make_api) -> None:
        truncated = PCAP[:20]  # header only, packet record cut off
        client = make_api(inspector=FakeInspector(invalid=True))

        response = upload(client, "damaged.pcap", truncated)

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_capture"
        # nothing left behind
        storage_root = client.app.state.capture_storage.root  # type: ignore[attr-defined]
        assert [p.name for p in storage_root.iterdir()] == [".staging", "registry.sqlite3"]

    def test_bytes_that_are_not_a_capture_are_rejected(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())

        response = upload(client, "junk.pcap", b"definitely not a capture header at all")

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "invalid_capture"

    def test_unsupported_extension_beats_content(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())

        response = upload(client, "shell.pcap.txt", PCAP)

        assert response.status_code == 400


class TestSecurity:
    def test_path_traversal_filenames_are_rejected(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())
        for name in ["../../evil.pcap", "..\\..\\evil.pcap", "/etc/passwd"]:
            response = upload(client, name, PCAP)
            assert response.status_code == 400, name

    def test_windows_path_components_never_reach_storage(self, make_api) -> None:
        import hashlib

        # The multipart layer strips path components (defense layer 1) and the
        # filename validator would reject them if they arrived (layer 2); the
        # evidence path itself is always hash-derived (layer 3).
        client = make_api(inspector=FakeInspector())

        body = upload(client, "C:\\Windows\\System32\\evil.pcap", PCAP).json()

        assert body["filename"] == "evil.pcap"
        evidence = client.app.state.capture_storage.root / body["id"] / "evidence.pcap"  # type: ignore[attr-defined]
        assert evidence.is_file()
        assert evidence.parent.name == f"capture_{hashlib.sha256(PCAP).hexdigest()[:12]}"

    def test_nothing_is_written_outside_the_storage_root(self, make_api, tmp_path) -> None:
        client = make_api(inspector=FakeInspector())
        for name in ["../../evil.pcap", "..\\evil.pcap", "\x01ctrl.pcap", "данные📊.pcap"]:
            upload(client, name, PCAP)

        storage_root = client.app.state.capture_storage.root  # type: ignore[attr-defined]
        entries = sorted(p.name for p in storage_root.iterdir())
        # Only the staging dir, the registry, and hash-named capture dirs exist.
        assert all(
            e in {".staging", "registry.sqlite3"} or e.startswith("capture_") for e in entries
        )
        # nothing escaped into the parent directory either
        assert [p.name for p in tmp_path.iterdir()] == ["captures"]

    def test_capture_id_cannot_escape_the_storage_root(self, make_api) -> None:
        from engine.ingestion.errors import CaptureStorageError

        client = make_api()
        storage = client.app.state.capture_storage  # type: ignore[attr-defined]
        for bad in ["../evil", "capture_../../../../etc", "", "capture_", "normal"]:
            try:
                storage.capture_dir(bad)
            except CaptureStorageError:
                continue
            raise AssertionError(f"storage accepted unsafe id: {bad!r}")

    def test_api_rejects_non_id_capture_paths(self, make_api) -> None:
        client = make_api()

        # ids that are not hash-derived are unknown by definition and can
        # never address the filesystem
        for bad in ["capture_%2E%2E", "capture_zzzz", "anything"]:
            response = client.get(f"/api/captures/{bad}")
            assert response.status_code == 404, bad
            assert response.json()["error"]["code"] == "capture_not_found"

    def test_size_limit_matches_configured_maximum(self, make_api) -> None:
        client = make_api(inspector=FakeInspector(), max_capture_bytes=len(PCAP))

        ok = upload(client, "exact.pcap", PCAP)
        too_big = upload(client, "over.pcap", PCAP + b"\x00")

        assert ok.status_code == 201
        assert too_big.status_code == 413


class TestDuplicates:
    def test_identical_evidence_returns_existing_capture(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())

        first = upload(client, "one.pcap", PCAP)
        second = upload(client, "two-different-name.pcap", PCAP)

        assert first.status_code == 201
        assert second.status_code == 200
        assert second.json()["duplicate"] is True
        assert second.json()["id"] == first.json()["id"]
        # the original registration is authoritative for identical evidence
        assert second.json()["filename"] == "one.pcap"

    def test_duplicate_stores_only_one_evidence_copy(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())
        upload(client, "one.pcap", PCAP)
        upload(client, "two.pcapng", PCAPNG)
        upload(client, "one-again.pcap", PCAP)

        storage_root = client.app.state.capture_storage.root  # type: ignore[attr-defined]
        capture_dirs = [
            p for p in storage_root.iterdir() if p.is_dir() and not p.name.startswith(".")
        ]
        assert len(capture_dirs) == 2


class TestRetrieval:
    def test_list_returns_registered_captures(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())
        upload(client, "one.pcap", PCAP)
        upload(client, "two.pcapng", PCAPNG)

        response = client.get("/api/captures")

        assert response.status_code == 200
        listing = response.json()
        assert len(listing) == 2
        assert {c["format"] for c in listing} == {"pcap", "pcapng"}

    def test_get_single_capture(self, make_api) -> None:
        client = make_api(inspector=FakeInspector())
        created = upload(client, "one.pcap", PCAP).json()

        response = client.get(f"/api/captures/{created['id']}")

        assert response.status_code == 200
        assert response.json()["id"] == created["id"]

    def test_unknown_capture_id_is_not_found(self, make_api) -> None:
        client = make_api()

        response = client.get("/api/captures/capture_000000000000")

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "capture_not_found"


class TestInspectionCapability:
    def test_missing_tshark_registers_without_metadata(self, make_api) -> None:
        client = make_api(inspector=None)

        response = upload(client, "no-tshark.pcap", PCAP)

        assert response.status_code == 201
        body = response.json()
        assert body["status"] == "registered"
        assert body["packet_count"] is None
        assert body["started_at"] is None
        assert body["inspection"]["status"] == "unavailable"
        assert body["inspection"]["tool"] is None
        assert "tshark" in body["inspection"]["message"]

    def test_inspector_crash_keeps_evidence_registered(self, make_api) -> None:
        client = make_api(inspector=FakeInspector(crash=True))

        response = upload(client, "crashy.pcap", PCAP)

        assert response.status_code == 201
        body = response.json()
        assert body["status"] == "registered"
        assert body["inspection"]["status"] == "error"
        created_id = body["id"]
        assert client.get(f"/api/captures/{created_id}").status_code == 200

    def test_error_responses_have_structured_shape(self, make_api) -> None:
        client = make_api()

        response = upload(client, "notes.txt", b"data")

        error = response.json()["error"]
        assert set(error.keys()) == {"code", "message"}
        assert isinstance(error["code"], str)
        assert isinstance(error["message"], str)

    def test_default_max_limit_is_the_engine_ceiling(self) -> None:
        from app.config import load_settings

        assert load_settings().max_capture_bytes == MAX_CAPTURE_SIZE_BYTES
