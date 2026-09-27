# ADR 003 — TLS Handshake Reconstruction & X.509 Evidence

- **Status:** Accepted (Stage 3)
- **Date:** 2026-09-27
- **Scope:** `engine/crypto`, session reconstruction integration, API, frontend

## Context

Stage 2 reconstructs email sessions and records the STARTTLS transition boundary. Stage 3
turns the ciphertext byte stream that follows that boundary into structured TLS evidence:
negotiated version, cipher suites, key exchange, hello extensions, and the visible
certificate chain. The stage boundary is strict: **facts only** — no version scoring, no
cipher weakness ratings, no certificate verdicts, no findings. Those belong to Stage 4+.

## Decisions

1. **Pure-Python TLS parsing, scoped to what passive evidence supports.**
   `engine/crypto` parses TLS record headers, defragments handshake messages across records
   (ClientHello routinely spans records), and decodes ClientHello/ServerHello including the
   well-known extensions. Parsing is defensive and bounded: truncation, garbage, and
   encryption boundaries produce warnings and partial evidence — never fabricated structures
   and never crashes.

2. **Facts from wire positions, in strength order.**
   The negotiated version comes from the ServerHello `supported_versions` extension (TLS 1.3)
   or its legacy version field; without a ServerHello, the client's highest offered version
   is recorded and the handshake is marked incomplete. The selected cipher suite comes from
   the ServerHello; offered suites from the ClientHello in offer order. The key-exchange
   family is derived from the selected suite's standard name (TLS 1.3 suites are always
   ephemeral). A service port alone still never identifies a protocol (ADR 002), and an
   implicit-TLS port plus a successfully parsed handshake raises protocol attribution to
   medium confidence with an explicit warning.

3. **Certificates via the `cryptography` library.**
   The TLS 1.2 Certificate message's DER entries are parsed with `cryptography`
   (subject, issuer, serial, validity, signature algorithm, public-key type/size, SANs,
   SHA-256 fingerprint) into the Stage 0 `CertificateEvidence` model. Chain position is
   recorded (0 = leaf). Certificate ids are deterministic — `cert_<fingerprint[:12]>` — so
   the same certificate observed in different captures shares one identity. Malformed DER
   entries are skipped with warnings; partial chains stay partial.

4. **TLS 1.3 limitations are recorded, not hidden.**
   From the ServerHello onward, TLS 1.3 encrypts handshake messages — the server certificate
   is invisible to a passive capture. The evidence records `handshake_complete: true` (the
   handshake progressed: CCS/application data observed) with `certificates: []` and a
   warning explaining the encryption. Negotiated version, cipher suite, and key-exchange
   facts remain available from the plaintext hello exchange.

5. **The boundary offset is captured at parse time.**
   The Stage 2 conversation parsers record the exact stream offset where each direction
   switches to ciphertext (just after the STARTTLS command and its acceptance response).
   `StreamSlice` wraps the reassembled stream so TLS parsing uses relative offsets while
   evidence lookups (packet numbers, timestamps) map back to the full stream. Implicit-TLS
   sessions (465/993/995) parse from offset 0.

6. **Persistence and API shape.**
   The handshake travels as a JSON column on the session row; certificates get their own
   `session_certificates` table (queryable inventory for later stages). The session detail
   API returns the full handshake (version, suite, key exchange, extensions, completeness,
   warnings) and the certificate chain; session summaries include the handshake without the
   chain.

## Consequences

- The engine gains its first third-party cryptographic dependency (`cryptography`), used
  only for X.509 parsing — TLS record parsing stays dependency-free.
- `TLSVersion.is_deprecated` and `KeyExchange.provides_forward_secrecy` exist as domain
  facts but are deliberately not surfaced as verdicts in this stage.
- Cross-record handshake defragmentation assumes the TCP stream was reassembled correctly
  first; capture gaps inside a handshake message surface as parse warnings.
