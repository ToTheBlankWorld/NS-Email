"""Standalone HTML case report renderer (Stage 11).

Renders the deterministic case report document as a self-contained HTML
file: no external assets, no JavaScript, print-friendly CSS. Every
dynamic value is escaped with ``html.escape`` — capture metadata,
analyst notes, tags, and bookmark labels are untrusted data and must
never inject markup. The three content classes (forensic evidence,
analyst-authored work, AI interpretation) are rendered under explicit
labeled headings.
"""

import html
from typing import Any

_BRANDING_TITLE = "SecureMailScope Case Report"
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
ul.plain { margin: 4px 0; padding-left: 18px; }
ul.plain li { margin-bottom: 3px; }
.analyst { border: 1px solid #cbd5e0; border-left: 4px solid #2b6cb0; padding: 8px 12px;
           margin-bottom: 10px; background: #ebf8ff; page-break-inside: avoid; }
.ai-entry { border: 1px solid #cbd5e0; border-left: 4px solid #805ad5; padding: 8px 12px;
            margin-bottom: 10px; background: #faf5ff; page-break-inside: avoid; }
.note { color: #4a5568; font-style: italic; }
footer { border-top: 1px solid #cbd5e0; margin-top: 28px; padding-top: 10px;
         color: #718096; font-size: 11px; }
@media print {
  body { background: #fff; font-size: 11px; }
  .page { max-width: none; padding: 0; }
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


def render_case_html_report(report: dict[str, Any]) -> str:
    """Render the case report document into a complete standalone HTML page."""
    meta = report.get("report", {})
    case = report.get("case", {})
    evidence = report.get("evidence", {})
    correlation = report.get("correlation", {})
    work = report.get("analyst_work", {})
    ai = report.get("ai_interpretation", {})
    provenance = report.get("provenance", {})
    limitations = report.get("limitations", {}).get("items", [])
    methodology = report.get("methodology", [])

    captures = evidence.get("captures", [])
    postures = evidence.get("posture_summaries", [])
    findings = evidence.get("findings", [])
    anomalies = evidence.get("anomalies", {})

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(f"<title>{_esc(_BRANDING_TITLE)}</title>")
    parts.append(f"<style>{_CSS}</style></head><body>")
    parts.append('<div class="page">')

    parts.append('<header class="report-header">')
    parts.append(f"<h1>{_esc(_BRANDING_TITLE)}</h1>")
    parts.append(
        '<div class="subtitle">NS-Email · AI-Assisted Cryptographic Security '
        "Posture Assessment for Secure Email Communications</div>"
    )
    parts.append("</header>")

    parts.append("<section><h2>Case Information</h2><dl class='meta-grid'>")
    parts.append(_kv("Case number", case.get("case_number")))
    parts.append(_kv("Case ID", case.get("case_id")))
    parts.append(_kv("Title", case.get("title")))
    parts.append(_kv("Description", case.get("description")))
    parts.append(_kv("Status", case.get("status")))
    parts.append(_kv("Priority", case.get("priority")))
    parts.append(_kv("Created", case.get("created_at")))
    parts.append(_kv("Updated", case.get("updated_at")))
    parts.append(_kv("Closed", case.get("closed_at")))
    parts.append(_kv("Report ID", meta.get("report_id")))
    parts.append(_kv("Report schema version", meta.get("schema_version")))
    parts.append(_kv("Evidence digest", meta.get("evidence_digest")))
    parts.append("</dl></section>")

    # Forensic evidence -------------------------------------------------
    parts.append("<section><h2>Forensic Evidence</h2>")
    parts.append(
        '<p class="note">Deterministic analysis output quoted from the '
        "underlying captures. Case metadata never alters these values.</p>"
    )
    parts.append("<h3>Attached captures</h3>")
    parts.append(
        _render_table(
            ["Capture ID", "Filename", "SHA-256", "Sessions", "Analyzed at"],
            [
                [
                    _esc(c.get("capture_id")),
                    _esc(c.get("filename")),
                    _esc(c.get("sha256")),
                    _esc(c.get("session_count")),
                    _esc(c.get("analyzed_at")),
                ]
                for c in captures
            ],
        )
    )
    parts.append("<h3>Posture summaries (authoritative per-capture values)</h3>")
    parts.append(
        _render_table(
            ["Capture ID", "Posture state", "Score", "Confidence", "Sessions", "Affected"],
            [
                [
                    _esc(p.get("capture_id")),
                    _sev_badge("info"),
                    _esc(p.get("overall_score")),
                    _esc(p.get("confidence")),
                    _esc(p.get("total_sessions")),
                    _esc(p.get("affected_sessions")),
                ]
                for p in postures
            ],
        )
    )
    parts.append("<h3>Findings</h3>")
    rows = []
    for f in findings:
        rows.append(
            [
                _esc(f.get("capture_id")),
                _esc(f.get("rule_id")),
                _sev_badge(f.get("severity")),
                _esc(f.get("title")),
                _esc(f.get("session_id")),
            ]
        )
    parts.append(_render_table(["Capture", "Rule", "Severity", "Title", "Session"], rows))
    parts.append("<h3>Anomalies</h3>")
    anomaly_items = anomalies.get("items", []) if isinstance(anomalies, dict) else []
    parts.append(
        _render_table(
            ["Anomaly", "Session", "Band", "Score"],
            [
                [
                    _esc(a.get("anomaly_id")),
                    _esc(a.get("session_id")),
                    _esc(a.get("band") or a.get("status")),
                    _esc(a.get("score")),
                ]
                for a in anomaly_items
            ],
        )
    )
    parts.append("</section>")

    # Correlation -----------------------------------------------------
    parts.append("<section><h2>Correlation — Repeated Evidence Across Captures</h2>")
    parts.append(f'<p class="note">{_esc(correlation.get("notice"))}</p>')
    summary = correlation.get("summary", {})
    parts.append("<dl class='meta-grid'>")
    parts.append(_kv("Correlations", summary.get("correlation_count")))
    parts.append(_kv("Captures correlated", summary.get("capture_count")))
    parts.append(_kv("Sessions scanned", summary.get("sessions_scanned")))
    parts.append("</dl>")
    by_type = summary.get("by_type", {})
    parts.append(
        _render_table(
            ["Correlation type", "Count"],
            [[_esc(t), str(by_type.get(t, 0))] for t in sorted(by_type)],
        )
    )
    parts.append(
        _render_table(
            ["Correlation", "Type", "Strength", "Occurrences", "Captures", "Evidence key"],
            [
                [
                    _esc(c.get("correlation_id")),
                    _esc(c.get("correlation_type")),
                    _esc(c.get("strength")),
                    _esc(c.get("occurrence_count")),
                    _esc(", ".join(str(x) for x in c.get("source_capture_ids", []))),
                    _esc(c.get("evidence_key")),
                ]
                for c in correlation.get("correlations", [])
            ],
        )
    )
    parts.append("</section>")

    # Analyst work -------------------------------------------------------
    parts.append("<section><h2>Analyst Notes, Tags &amp; Bookmarks</h2>")
    parts.append(f'<p class="note">{_esc(work.get("notice"))}</p>')
    parts.append("<h3>Tags</h3>")
    tags = work.get("tags", [])
    parts.append(f"<p>{', '.join(_esc(t) for t in tags) if tags else 'None recorded.'}</p>")
    parts.append("<h3>Bookmarks (references, not copies)</h3>")
    parts.append(
        _render_table(
            ["Target type", "Target ID", "Label", "Note"],
            [
                [
                    _esc(b.get("target_type")),
                    _esc(b.get("target_id")),
                    _esc(b.get("label")),
                    _esc(b.get("note")),
                ]
                for b in work.get("bookmarks", [])
            ],
        )
    )
    parts.append("<h3>Analyst notes (analyst-authored, not evidence)</h3>")
    notes = work.get("notes", [])
    if not notes:
        parts.append('<p class="note">No analyst notes recorded.</p>')
    else:
        for note in notes:
            parts.append('<div class="analyst">')
            parts.append(
                f"<div><strong>{_esc(note.get('target_type'))}</strong> "
                f"{_esc(note.get('target_id'))}</div>"
            )
            parts.append(f"<p>{_esc(note.get('content'))}</p>")
            parts.append(f"<div class='note'>{_esc(note.get('created_at'))}</div>")
            parts.append("</div>")
    parts.append("<h3>Case timeline (investigation events)</h3>")
    parts.append(
        _render_table(
            ["Event", "Detail", "Recorded at"],
            [
                [_esc(e.get("event_type")), _esc(e.get("detail")), _esc(e.get("created_at"))]
                for e in work.get("timeline", [])
            ],
        )
    )
    parts.append("</section>")

    # AI interpretation ---------------------------------------------------
    parts.append("<section><h2>AI Interpretation</h2>")
    parts.append(f'<p class="note">{_esc(ai.get("notice"))}</p>')
    observations = ai.get("observations", [])
    if not observations:
        parts.append(f'<p class="note">{_esc(ai.get("detail", "No AI observations."))}</p>')
    else:
        for entry in observations:
            parts.append('<div class="ai-entry">')
            parts.append(f"<div><strong>{_esc(entry.get('query'))}</strong></div>")
            parts.append(f"<p>{_esc(entry.get('answer'))}</p>")
            parts.append(
                f"<div class='note'>{_esc(entry.get('provider'))} · "
                f"{_esc(entry.get('model'))} · "
                f"validation: {_esc(entry.get('validation_status'))}</div>"
            )
            parts.append("</div>")
    parts.append("</section>")

    # Provenance ----------------------------------------------------------
    parts.append("<section><h2>Technical Provenance Metadata</h2>")
    parts.append(
        '<p class="note">Technical provenance records what was processed, '
        "when, and by which application version. It is not a legal "
        "chain-of-custody certification.</p>"
    )
    prov_captures = provenance.get("captures", [])
    parts.append(
        _render_table(
            ["Capture ID", "SHA-256", "Ingested at", "Analyzed at", "Attached at"],
            [
                [
                    _esc(c.get("capture_id")),
                    _esc(c.get("sha256")),
                    _esc(c.get("ingested_at")),
                    _esc(c.get("analyzed_at")),
                    _esc(c.get("attached_at")),
                ]
                for c in prov_captures
            ],
        )
    )
    parts.append("<dl class='meta-grid'>")
    parts.append(_kv("Application version", provenance.get("application_version")))
    parts.append(_kv("Export/report timestamp", provenance.get("generated_at")))
    parts.append("</dl></section>")

    parts.append("<section><h2>Limitations</h2><ul class='plain'>")
    parts.extend(f"<li>{_esc(item)}</li>" for item in limitations)
    parts.append("</ul></section>")

    parts.append("<section><h2>Methodology</h2><ul class='plain'>")
    parts.extend(f"<li>{_esc(item)}</li>" for item in methodology)
    parts.append("</ul></section>")

    parts.append(
        "<footer>Generated deterministically by SecureMailScope from persisted "
        "forensic evidence and recorded analyst metadata. Analyst content is "
        "treated as untrusted data and is escaped in this document.</footer>"
    )
    parts.append("</div></body></html>")
    return "\n".join(parts)
