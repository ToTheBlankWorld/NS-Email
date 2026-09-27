# ADR 002 — TCP Stream & Email Protocol Reconstruction

- **Status:** Accepted (Stage 2)
- **Date:** 2026-09-27
- **Scope:** `engine/transport`, `engine/protocols`, `engine/analysis`, backend analysis APIs

## Context

Stage 2 turns a registered capture into structured email sessions. The overriding principle:
**never make security conclusions from incomplete or fabricated evidence.** Every session and
event must be traceable to specific packets, and uncertainty (orientation unknown, gaps,
unparseable data) must be recorded as uncertainty.

## Decisions

1. **`PacketSource` decouples analysis from packet tooling.**
   The pipeline consumes normalized `PacketRecord`s from a `PacketSource`. Stage 2 ships a
   pure-Python `PcapPacketSource` (pcap + pcapng, Ethernet/raw-IP link layers, IPv4/TCP) so
   analysis runs on real evidence without tshark. Unparseable traffic is counted and reported
   (per-reason skip stats), never guessed; a container with an uninterpretable link layer
   fails analysis honestly. Tool-backed sources (tshark, Scapy) plug into the same protocol.

2. **Bidirectional flows, deterministic identity.**
   Packets are grouped by the canonical 5-tuple with sorted endpoints — both directions form
   one logical flow. Session ids are `session_<16 hex>` derived from SHA-256 of the capture id
   plus the canonical flow tuple: stable across re-analysis, filesystem-safe, free of user
   input. Known limitation: two separate connections reusing the exact same 5-tuple within one
   capture merge into one session (documented; connection splitting is future work).

3. **Two-phase reassembly with explicit gap accounting.**
   Segments are placed relative to ISN+1 when the SYN is observed, otherwise relative to the
   smallest observed sequence (deterministic; no data loss). Overlaps are classified as
   duplicates (identical re-send over one range) or retransmissions (partial/multi-range
   overlap) and are counted, not double-inserted. Missing ranges become explicit gaps with
   byte counts. `complete = no gaps AND (FIN or RST observed)`; otherwise a
   `completeness_reason` explains exactly what is missing. Stale segments below an
   ISN-anchored base are reported as ignored.

4. **Orientation from evidence, in strength order.**
   SYN/SYN+ACK → well-known email service ports (25/587/465/143/993/110/995 — never "lower
   port wins") → protocol greeting direction (email servers speak first). When nothing
   applies, `orientation: "unknown"` is recorded and endpoints are reported in canonical
   order with a warning.

5. **Detection combines signatures and reports its evidence.**
   SMTP/IMAP/POP3 detection scores server greetings, client command sets, SMTP banner hints,
   and port agreement — each match becomes a human-readable evidence line. A service port
   alone yields LOW confidence and never names a protocol. Ambiguous ties resolve to UNKNOWN.
   Confidence is the enum unknown/low/medium/high — no fabricated percentages.

6. **Reconstruction stops at the TLS boundary.**
   STARTTLS/STLS is recorded as `advertised / requested / response_seen` plus a
   `tls_transition` event with packet number and timestamp. Bytes after the boundary are
   ciphertext: plaintext parsing stops and a warning says so. No TLS handshake analysis
   happens in this stage (Stage 3).

7. **Credentials are redacted at the parser boundary.**
   USER/PASS/AUTH/LOGIN/AUTHENTICATE arguments are replaced with the literal `redacted`
   before any event object exists. Message bodies and multi-line data content (SMTP DATA,
   RETR/LIST responses) are skipped entirely. SMTP envelope addresses (MAIL FROM / RCPT TO)
   are forensic metadata, sanitized and length-bounded, not credentials. Events carry only
   sanitized structured fields — raw packet lines never enter evidence, logs, or API
   responses. A regression test asserts secret values are absent from API responses,
   persisted SQLite rows, and the session object graph.

8. **Timelines are observations, in arrival order.**
   Events carry the real packet timestamp(s) and the packet numbers that carried the bytes
   (byte-offset → packet mapping from the reassembler), e.g. "STARTTLS requested — packets
   12, 13".

9. **Analysis results are replaceable, captures are not touched.**
   `sessions` / `session_events` / `analysis` tables live beside `captures` in SQLite.
   Re-analysis atomically replaces a capture's sessions. The synchronous runner is bounded
   by the capture size cap; the service boundary is designed so an asynchronous runner can
   replace it without API changes (no queues in this stage).

## Limitations (recorded honestly)

- IPv6, VLAN tags, IP fragmentation, and non-Ethernet link layers are counted as skipped,
  not parsed.
- Session ids merge repeated connections that reuse one 5-tuple.
- Sequence wraparound on streams > 4 GiB per direction is not modeled.
- Packet metadata extraction (Stage 1) uses tshark when installed; packet parsing for
  session reconstruction currently uses the pure-Python source regardless of tshark.
