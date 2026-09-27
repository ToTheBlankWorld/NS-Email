"""Standalone HTML forensic report renderer (Stage 9).

Renders the deterministic report document as a self-contained HTML file:
no external assets, no JavaScript, print-friendly CSS. Every dynamic
value is escaped with ``html.escape`` — evidence fields are untrusted
data and must never inject markup.
"""

import html
from typing import Any

_BRANDING_TITLE = "SecureMailScope Forensic Report"
_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  font-size: 13px; line-height: 1.5; color: #1a202c; margin: 0;
  background: #f5f6f8;
}
.page { max-width: 960px; margin: 0 auto; padding: 24px 28px 48px; background: #fff; }
header.report-header {
  border-bottom: 3px solid #1a365d; padding-bottom: 12px; margin-bottom: 20px;
}
header.report-header h1 { font-size: 20px; margin: 0 0 2px; color: #1a365d; letter-spacing: 0.3px; }
header.report-header .subtitle { color: #4a5568; font-size: 12px; }
section { margin-bottom: 26px; }
section > h2 {
  font-size: 14px; text-transform: uppercase; letter-spacing: 1px;
  color: #1a365d; border-bottom: 1px solid #cbd5e0; padding-bottom: 4px; margin: 0 0 10px;
}
section > h3 { font-size: 12.5px; margin: 14px 0 6px; color: #2d3748; }
table { width: 100%; border-collapse: collapse; margin: 6px 0 12px; font-size: 12px; }
th { text-align: left; background: #edf2f7; color: #2d3748; border: 1px solid #cbd5e0;
     padding: 4px 8px; font-weight: 600; }
td { border: 1px solid #cbd5e0; padding: 4px 8px; vertical-align: top; }
tr { page-break-inside: avoid; }
.meta-grid { display: grid; grid-template-columns: 220px 1fr; gap: 2px 16px; font-size: 12.5px; }
.meta-grid dt { color: #4a5568; }
.meta-grid dd { margin: 0; font-family: Consolas, monospace; word-break: break-all; }
.badge { display: inline-block; padding: 1px 8px; border: 1px solid; border-radius: 2px;
         font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.sev-critical { color: #742a2a; border-color: #742a2a; background: #fff5f5; }
.sev-high { color: #9b2c2c; border-color: #9b2c2c; background: #fff5f5; }
.sev-medium { color: #975a16; border-color: #975a16; background: #fffff0; }
.sev-low { color: #2f855a; border-color: #2f855a; background: #f0fff4; }
.sev-info { color: #2a4365; border-color: #2a4365; background: #ebf8ff; }
.state-good { color: #22543d; border-color: #22543d; background: #f0fff4; }
.state-fair { color: #975a16; border-color: #975a16; background: #fffff0; }
.state-poor, .state-critical { color: #742a2a; border-color: #742a2a; background: #fff5f5; }
.state-unknown { color: #4a5568; border-color: #a0aec0; background: #edf2f7; }
ul.plain { margin: 4px 0; padding-left: 18px; }
ul.plain li { margin-bottom: 3px; }
.ai-entry { border: 1px solid #cbd5e0; border-left: 4px solid #805ad5; padding: 8px 12px;
            margin-bottom: 10px; background: #faf5ff; page-break-inside: avoid; }
.ai-entry .query { font-weight: 600; margin-bottom: 2px; }
.ai-entry .label { font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.6px;
                   color: #6b46c1; font-weight: 700; }
.note { color: #4a5568; font-style: italic; }
footer { border-top: 1px solid #cbd5e0; margin-top: 28px; padding-top: 10px;
         color: #718096; font-size: 11px; }
@media print {
  body { background: #fff; font-size: 11px; }
  .page { max-width: none; padding: 0; }
  section { page-break-inside: auto; }
  h2 { page-break-after: avoid; }
  table { page-break-inside: auto; }
}
"""


def _esc(value: Any) -> str:
    """Escape any value for safe HTML inclusion."""
    return html.escape(str(value), quote=True)


def _badge(kind: str, value: Any) -> str:
    return f'<span class="badge {kind}">{_esc(value)}</span>'


def _sev_badge(value: Any) -> str:
    return _badge(f"sev-{_esc(value)}", value)


def _render_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return '<p class="note">None recorded.</p>'
    head = "".join(f"<th>{h}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _kv(label: str, value: Any) -> str:
    return f"<dt>{_esc(label)}</dt><dd>{_esc(value if value is not None else '—')}</dd>"


def render_html_report(report: dict[str, Any]) -> str:
    """Render the report document into a complete standalone HTML page."""
    meta = report.get("report", {})
    capture = report.get("capture", {})
    summary = report.get("executive_summary", {})
    posture = report.get("posture", {})
    findings = report.get("findings", [])
    anomalies = report.get("anomalies", {})
    tls = report.get("tls_summary", {})
    graph = report.get("graph_summary", {})
    ai = report.get("ai_analyst", {})
    limitations = report.get("limitations", {}).get("items", [])
    methodology = report.get("methodology", [])

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>{_esc(_BRANDING_TITLE)}</title>")
    parts.append(f"<style>{_CSS}</style></head><body>")
    parts.append('<div class="page">')

    # Header ------------------------------------------------------------
    parts.append('<header class="report-header">')
    parts.append(f"<h1>{_esc(_BRANDING_TITLE)}</h1>")
    parts.append(
        '<div class="subtitle">NS-Email · AI-Assisted Cryptographic Security '
        "Posture Assessment for Secure Email Communications</div>"
    )
    parts.append("</header>")

    # Report metadata ----------------------------------------------------
    posture_state = (posture or {}).get("posture_state") or "unknown"
    parts.append("<section><h2>Report Information</h2><dl class='meta-grid'>")
    parts.append(_kv("Report ID", meta.get("report_id")))
    parts.append(_kv("Report schema version", meta.get("schema_version")))
    parts.append(_kv("Application", meta.get("application", {}).get("name")))
    parts.append(_kv("Application version", meta.get("application", {}).get("version")))
    parts.append(_kv("Generated at", meta.get("generated_at")))
    parts.append(_kv("Analysis status", meta.get("analysis_status")))
    parts.append(
        "<dt>Posture state</dt><dd>"
        + _badge(f"state-{_esc(posture_state)}", posture_state)
        + "</dd>"
    )
    parts.append("</dl></section>")

    # Executive summary ---------------------------------------------------
    parts.append("<section><h2>Executive Summary</h2><dl class='meta-grid'>")
    parts.append(_kv("Posture score", summary.get("posture_score")))
    parts.append(_kv("Total sessions", summary.get("total_sessions")))
    parts.append(_kv("Affected sessions", summary.get("affected_sessions")))
    parts.append(_kv("Affected hosts", summary.get("affected_hosts")))
    parts.append(_kv("Total findings", summary.get("findings_total")))
    parts.append(_kv("Total anomalies", summary.get("anomalies_total")))
    parts.append("</dl>")
    by_sev = summary.get("findings_by_severity", {})
    parts.append(
        _render_table(
            ["Severity", "Findings"],
            [
                [(_sev_badge(sev)), str(by_sev.get(sev, 0))]
                for sev in ("critical", "high", "medium", "low", "info")
                if by_sev.get(sev)
            ],
        )
    )
    by_band = summary.get("anomalies_by_band", {})
    parts.append(
        _render_table(
            ["Anomaly band", "Sessions"],
            [[_esc(band), str(by_band.get(band, 0))] for band in by_band if by_band.get(band)],
        )
    )
    proto = summary.get("protocol_distribution", {})
    parts.append(
        _render_table(
            ["Protocol", "Sessions"],
            [[_esc(p), str(c)] for p, c in proto.items()],
        )
    )
    coverage = summary.get("tls_coverage", {})
    parts.append(
        _render_table(
            ["TLS coverage", "Count"],
            [
                ["Sessions total", coverage.get("sessions_total", 0)],
                ["With TLS handshake", coverage.get("sessions_with_tls_handshake", 0)],
                ["With STARTTLS negotiation", coverage.get("sessions_with_starttls", 0)],
                ["Handshakes complete", coverage.get("handshakes_complete", 0)],
            ],
        )
    )
    parts.append("</section>")

    # Capture information --------------------------------------------------
    parts.append("<section><h2>Capture Information</h2><dl class='meta-grid'>")
    parts.append(_kv("Capture ID", capture.get("capture_id")))
    parts.append(_kv("Filename", capture.get("filename")))
    parts.append(_kv("Format", capture.get("format")))
    parts.append(_kv("Size (bytes)", capture.get("size_bytes")))
    parts.append(_kv("SHA-256", capture.get("sha256")))
    parts.append(_kv("Packets", capture.get("packet_count")))
    parts.append(_kv("Link type", capture.get("link_type")))
    parts.append(_kv("Ingested at", capture.get("ingested_at")))
    parts.append("</dl></section>")

    # Security posture -----------------------------------------------------
    parts.append("<section><h2>Security Posture</h2>")
    if not posture.get("available"):
        parts.append('<p class="note">Posture analysis not available for this capture.</p>')
    else:
        parts.append("<dl class='meta-grid'>")
        parts.append(_kv("Posture state", posture.get("posture_state")))
        parts.append(_kv("Overall score", posture.get("overall_score")))
        parts.append(_kv("Confidence", posture.get("confidence")))
        parts.append(_kv("Policy", posture.get("policy_id")))
        parts.append(_kv("Explanation", posture.get("explanation")))
        parts.append("</dl>")
        factors = posture.get("factors", [])
        parts.append(
            _render_table(
                ["Factor", "Status", "Contribution", "Affected sessions", "Explanation"],
                [
                    [
                        _esc(f.get("factor")),
                        _esc(f.get("status")),
                        _esc(f.get("score_contribution")),
                        _esc(f.get("affected_sessions")),
                        _esc(f.get("explanation")),
                    ]
                    for f in factors
                ],
            )
        )
    parts.append("</section>")

    # Findings ---------------------------------------------------------------
    parts.append("<section><h2>Security Findings</h2>")
    if not findings:
        parts.append('<p class="note">No findings recorded.</p>')
    else:
        rows = []
        for f in findings:
            remediation = f.get("remediation") or {}
            reference = f.get("standard_reference") or {}
            evidence = "; ".join(
                _esc(r.get("detail") or r.get("source") or "") for r in f.get("evidence_refs", [])
            )
            rows.append(
                [
                    _esc(f.get("rule_id")),
                    _sev_badge(f.get("severity")),
                    _esc(f.get("confidence")),
                    _esc(f.get("title")),
                    evidence,
                    _esc(remediation.get("action") or ""),
                    _esc(reference.get("name") or ""),
                ]
            )
        parts.append(
            _render_table(
                ["Rule", "Severity", "Confidence", "Title", "Evidence", "Remediation", "Reference"],
                rows,
            )
        )
    parts.append("</section>")

    # Anomalies ------------------------------------------------------------
    parts.append("<section><h2>Behavioral Anomalies</h2>")
    if not anomalies.get("available"):
        parts.append('<p class="note">Anomaly analysis not available for this capture.</p>')
    else:
        parts.append(
            '<p class="note">Anomaly bands describe statistical deviation from the '
            "capture-local baseline. They are not indicators of compromise.</p>"
        )
        rows = [
            [
                _esc(a.get("anomaly_id")),
                _esc(a.get("session_id")),
                _esc(a.get("protocol")),
                _esc(a.get("band") or a.get("status")),
                _esc(a.get("score")),
                _esc("; ".join(str(d.get("feature")) for d in a.get("top_deviations", [])[:3])),
            ]
            for a in anomalies.get("items", [])
        ]
        parts.append(
            _render_table(
                ["Anomaly", "Session", "Protocol", "Band", "Score", "Top deviating features"],
                rows,
            )
        )
    parts.append("</section>")

    # TLS summary ------------------------------------------------------------
    parts.append("<section><h2>TLS &amp; Certificate Analysis</h2>")
    parts.append(
        _render_table(
            ["TLS version", "Handshakes"],
            [[_esc(v), str(c)] for v, c in tls.get("versions_observed", {}).items()],
        )
    )
    parts.append(
        _render_table(
            ["Cipher family", "Handshakes"],
            [[_esc(c), str(n)] for c, n in tls.get("cipher_families", {}).items()],
        )
    )
    cert_rows = [
        [
            _esc(c.get("subject")),
            _esc(c.get("issuer")),
            _esc(c.get("not_after")),
            _esc(c.get("signature_algorithm")),
            _esc(c.get("public_key_algorithm")),
            _esc(c.get("public_key_size_bits")),
        ]
        for c in tls.get("certificates", [])
    ]
    parts.append(
        _render_table(
            ["Subject", "Issuer", "Valid until", "Signature", "Public key", "Bits"],
            cert_rows,
        )
    )
    parts.append("</section>")

    # Evidence graph summary ---------------------------------------------------
    parts.append("<section><h2>Evidence Graph Summary</h2><dl class='meta-grid'>")
    parts.append(_kv("Nodes", graph.get("node_count")))
    parts.append(_kv("Edges", graph.get("edge_count")))
    parts.append(_kv("Correlated certificates", graph.get("correlated_certificate_count")))
    parts.append("</dl>")
    node_types = graph.get("node_types", {})
    parts.append(
        _render_table(
            ["Node type", "Count"],
            [[_esc(t), str(c)] for t, c in node_types.items()],
        )
    )
    edge_types = graph.get("edge_types", {})
    parts.append(
        _render_table(
            ["Relationship", "Count"],
            [[_esc(t), str(c)] for t, c in edge_types.items()],
        )
    )
    parts.append("</section>")

    # AI analyst ------------------------------------------------------------
    parts.append("<section><h2>AI Analyst Observations</h2>")
    if not ai.get("configured"):
        parts.append('<p class="note">AI analyst not configured.</p>')
    elif not ai.get("observations"):
        parts.append(f'<p class="note">{_esc(ai.get("note"))}</p>')
    else:
        parts.append(
            '<p class="note">The following entries are AI-generated interpretive '
            "assistance derived from structured evidence. They are never a source "
            "of security truth and never override deterministic findings.</p>"
        )
        for entry in ai.get("observations", []):
            parts.append('<div class="ai-entry">')
            parts.append(f'<div class="query">{_esc(entry.get("query"))}</div>')
            parts.append(f"<p>{_esc(entry.get('answer'))}</p>")
            for key, label in (
                ("observations", "Observed evidence"),
                ("interpretations", "Interpretation"),
                ("uncertainties", "Uncertainty"),
            ):
                items = entry.get(key) or []
                if items:
                    parts.append(f'<div><span class="label">{_esc(label)}</span><ul class="plain">')
                    parts.extend(f"<li>{_esc(item)}</li>" for item in items)
                    parts.append("</ul></div>")
            citations = entry.get("citations") or []
            if citations:
                parts.append('<div><span class="label">Citations</span><ul class="plain">')
                for citation in citations:
                    if not isinstance(citation, dict):
                        continue
                    desc = (
                        citation.get("description")
                        or citation.get("source_id")
                        or citation.get("source")
                    )
                    parts.append(f"<li>{_esc(desc)}</li>")
                parts.append("</ul></div>")
            parts.append(
                f'<div class="note">{_esc(entry.get("provider"))} · '
                f"{_esc(entry.get('model'))} · "
                f"validation: {_esc(entry.get('validation_status'))}</div>"
            )
            parts.append("</div>")
    parts.append("</section>")

    # Limitations ------------------------------------------------------------
    parts.append("<section><h2>Limitations</h2><ul class='plain'>")
    parts.extend(f"<li>{_esc(item)}</li>" for item in limitations)
    parts.append("</ul></section>")

    # Methodology ------------------------------------------------------------
    parts.append("<section><h2>Methodology</h2><ul class='plain'>")
    parts.extend(f"<li>{_esc(item)}</li>" for item in methodology)
    parts.append("</ul></section>")

    parts.append(
        "<footer>Generated deterministically by SecureMailScope from persisted "
        "forensic evidence. Evidence fields are treated as untrusted data and "
        "are escaped in this document.</footer>"
    )
    parts.append("</div></body></html>")
    return "\n".join(parts)
