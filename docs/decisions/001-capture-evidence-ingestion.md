# ADR 001 — Capture Evidence Ingestion

- **Status:** Accepted (Stage 1)
- **Date:** 2026-09-27
- **Scope:** `engine/ingestion`, `backend/app` (storage, registry, service, API)

## Context

Stage 1 introduces the first real forensic capability: turning an uploaded PCAP/PCAPNG into
registered, hash-verified evidence that every later analysis stage can trust. Uploads are
untrusted input from potentially hostile sources, and the platform must remain easy to run
locally (no external services) while being honest about what was and was not analyzed.

## Decisions

1. **Evidence identity is the content hash, not the filename.**
   The SHA-256 of the uploaded bytes is computed streaming (constant memory, single pass
   shared with the staging write). The capture id is deterministic: `capture_<first 12 hex
   chars of the sha256>`. Identical evidence always maps to the same id and directory;
   original filenames are display metadata only and never touch the filesystem.

2. **Duplicates are rejections of new evidence, not new records.**
   Re-uploading identical bytes returns the existing registration (HTTP 200, `duplicate:
   true`). The first registration is authoritative, including its display filename. A
   `UNIQUE` constraint on `sha256` backs this up against concurrent ingestion races.

3. **Storage is a controlled, layout-stable directory root.**
   `<NS_EMAIL_CAPTURE_STORAGE>/<capture-id>/evidence.<format>` plus `metadata.json`, with
   a `.staging/` directory inside the root for in-progress uploads and
   `registry.sqlite3` for the registry. Uploads land in staging first and move into place
   with `os.replace` (atomic within the root), so a crash cannot leave partial evidence
   under a valid capture id. The capture id is regex-validated before any path is derived,
   and the resolved path is asserted to remain under the root (defense in depth).

4. **Registry is SQLite, in the storage root.**
   Single-process, file-based persistence is sufficient for the local forensic workstation
   and keeps the demo simple. A small `CaptureRegistry` protocol isolates the API/service
   layer from SQL; PostgreSQL is deliberately deferred.

5. **Packet inspection is behind a `CaptureInspector` interface, backed by tshark.**
   `TsharkCaptureInspector` launches tshark with fixed argument arrays (no shell, no
   user-controlled strings — the evidence path is derived internally). One streaming
   `tshark -T fields` pass yields packet count, first/last packet timestamps, duration,
   and link-layer type. `-n` disables name resolution so inspection performs no network
   calls. A watchdog kills hung tool runs. Alternative/future inspectors plug into the
   same protocol.

6. **Degradation is explicit, never faked.**
   The API distinguishes: (a) invalid capture → rejected with a structured error;
   (b) valid capture, inspector unavailable (tshark not installed) → registered with
   `status: "registered"` and `inspection.status: "unavailable"`; (c) valid capture,
   inspected → `status: "ready"`. Packet metadata fields are `null` — never placeholders.

7. **Validation is layered.**
   Extension allow-list → container magic-byte sniffing (extension is never trusted
   alone) → tool-level structural validation when tshark is available. Size limits are
   enforced during the streaming copy (aborting oversized uploads early) and mirrored by
   an absolute ceiling in the `Capture` model.

## Consequences

- The system runs with zero external dependencies; installing tshark upgrades capture
  registrations from "registered" to "ready" without any code change.
- Large captures cost one full streaming pass for hashing and (with tshark) one
  dissection pass for metadata; both are bounded by the configured size limit and the
  inspection watchdog timeout.
- Deleting/archiving evidence later must remove both the capture directory and the
  registry row (deferred to a later stage; nothing currently deletes evidence).
