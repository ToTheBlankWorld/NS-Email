"""Structured PDF case report renderer (Stage 11).

Builds a real, structured PDF (fpdf2) from the deterministic case
report document. Every dynamic value is sanitized to Latin-1 and
stripped of control characters; analyst notes, tags, and bookmark
labels are untrusted data and never interpreted as markup. Content
classes (forensic evidence, analyst work, AI interpretation) are kept
under explicit labeled headings.
"""

from datetime import UTC, datetime
from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos

_PAGE_MARGIN = 16
_ACCENT = (26, 54, 93)  # deep navy
_MUTED = (74, 85, 104)
_LIGHT = (237, 242, 247)


class _CasePDF(FPDF):
    """PDF with a branded footer and page numbering."""

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("helvetica", "", 7.5)
        self.set_text_color(*_MUTED)
        self.cell(
            0,
            8,
            f"SecureMailScope case report - page {self.page_no()} of {{nb}}",
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
            align="C",
        )


def _clean(value: Any) -> str:
    """Sanitize any value for safe single-byte PDF text output."""
    if value is None:
        return "-"
    text = str(value)
    replacements = {
        "\u2014": "-",
        "\u2013": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2192": "->",
        "\u00b7": "-",
        "\u2026": "...",
        "\u00a0": " ",
    }
    for source, target in replacements.items():
        text = text.replace(source, target)
    text = text.encode("latin-1", "replace").decode("latin-1")
    return "".join(ch for ch in text if ch.isprintable())


def _section_title(pdf: _CasePDF, title: str) -> None:
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 8, _clean(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*_ACCENT)
    pdf.set_line_width(0.4)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(3)
    pdf.set_text_color(0, 0, 0)


def _sub_title(pdf: _CasePDF, title: str) -> None:
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 6, _clean(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    pdf.set_text_color(0, 0, 0)


def _key_values(pdf: _CasePDF, pairs: list[tuple[str, Any]]) -> None:
    pdf.set_font("helvetica", "", 9.5)
    for label, value in pairs:
        pdf.set_font("helvetica", "B", 9.5)
        pdf.cell(52, 5.5, _clean(label), new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("helvetica", "", 9.5)
        pdf.multi_cell(0, 5.5, _clean(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _table(pdf: _CasePDF, headers: list[str], rows: list[list[Any]], widths: list[float]) -> None:
    if not rows:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*_MUTED)
        pdf.cell(0, 5.5, "None recorded.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)
        return

    def draw_header() -> None:
        pdf.set_font("helvetica", "B", 8.5)
        pdf.set_fill_color(*_LIGHT)
        pdf.set_draw_color(160, 174, 192)
        for header, width in zip(headers, widths, strict=True):
            pdf.cell(width, 6, _clean(header), border=1, fill=True)
        pdf.ln()

    draw_header()
    pdf.set_font("helvetica", "", 8.5)
    pdf.set_draw_color(160, 174, 192)
    for row in rows:
        if pdf.get_y() > pdf.page_break_trigger - 14:
            pdf.add_page()
            draw_header()
            pdf.set_font("helvetica", "", 8.5)
        y_start = pdf.get_y()
        x = pdf.l_margin
        max_bottom = y_start
        for value, width in zip(row, widths, strict=True):
            pdf.set_xy(x, y_start)
            pdf.multi_cell(width, 5, _clean(value), border=1)
            max_bottom = max(max_bottom, pdf.get_y())
            x += width
        pdf.set_xy(pdf.l_margin, max_bottom)
    pdf.ln(3)


def _bullets(pdf: _CasePDF, items: list[str]) -> None:
    pdf.set_font("helvetica", "", 9.5)
    for item in items:
        pdf.cell(5, 5.2, "-", new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.multi_cell(0, 5.2, _clean(item), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _note(pdf: _CasePDF, text: str) -> None:
    pdf.set_font("helvetica", "I", 9)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(0, 5.2, _clean(text), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(2)


def render_case_pdf_report(report: dict[str, Any]) -> bytes:
    """Render the case report document into a structured PDF."""
    meta = report.get("report", {})
    case = report.get("case", {})
    evidence = report.get("evidence", {})
    correlation = report.get("correlation", {})
    remediation = report.get("remediation", {})
    verification = report.get("verification", {})
    longitudinal = report.get("longitudinal", {})
    work = report.get("analyst_work", {})
    ai = report.get("ai_interpretation", {})
    provenance = report.get("provenance", {})
    limitations = report.get("limitations", {}).get("items", [])
    methodology = report.get("methodology", [])

    captures = evidence.get("captures", [])
    postures = evidence.get("posture_summaries", [])
    findings = evidence.get("findings", [])
    anomalies = evidence.get("anomalies", {})

    pdf = _CasePDF()
    pdf.set_margins(_PAGE_MARGIN, _PAGE_MARGIN, _PAGE_MARGIN)
    pdf.set_auto_page_break(True, margin=18)
    pdf.set_title(_clean(meta.get("report_id") or "SecureMailScope Case Report"))
    generated_at = meta.get("generated_at")
    if isinstance(generated_at, str) and generated_at:
        try:
            pdf.set_creation_date(datetime.fromisoformat(generated_at))
        except ValueError:
            pdf.set_creation_date(datetime(1970, 1, 1, tzinfo=UTC))
    else:
        pdf.set_creation_date(datetime(1970, 1, 1, tzinfo=UTC))

    # Cover ---------------------------------------------------------------
    pdf.add_page()
    pdf.ln(24)
    pdf.set_font("helvetica", "B", 22)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 10, "SecureMailScope", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.set_font("helvetica", "", 12)
    pdf.set_text_color(*_MUTED)
    pdf.cell(0, 8, "Forensic Case Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)
    _key_values(
        pdf,
        [
            ("Case number", case.get("case_number")),
            ("Title", case.get("title")),
            ("Status", case.get("status")),
            ("Priority", case.get("priority")),
            ("Report ID", meta.get("report_id")),
            ("Evidence digest", meta.get("evidence_digest")),
            ("Generated at", meta.get("generated_at")),
        ],
    )

    # Case metadata ---------------------------------------------------------
    pdf.add_page()
    _section_title(pdf, "Case Information")
    _key_values(
        pdf,
        [
            ("Case ID", case.get("case_id")),
            ("Case number", case.get("case_number")),
            ("Title", case.get("title")),
            ("Description", case.get("description")),
            ("Status", case.get("status")),
            ("Priority", case.get("priority")),
            ("Created", case.get("created_at")),
            ("Updated", case.get("updated_at")),
            ("Closed", case.get("closed_at")),
        ],
    )

    # Forensic evidence ------------------------------------------------------
    _section_title(pdf, "Forensic Evidence")
    _note(
        pdf,
        "Deterministic analysis output quoted from the underlying captures. "
        "Case metadata never alters these values.",
    )
    _sub_title(pdf, "Attached captures")
    _table(
        pdf,
        ["Capture ID", "Filename", "SHA-256"],
        [[c.get("capture_id"), c.get("filename"), c.get("sha256")] for c in captures],
        [52, 52, 74],
    )
    _sub_title(pdf, "Posture summaries (authoritative per-capture values)")
    _table(
        pdf,
        ["Capture", "State", "Score", "Sessions"],
        [
            [
                p.get("capture_id"),
                p.get("posture_state"),
                p.get("overall_score"),
                p.get("total_sessions"),
            ]
            for p in postures
        ],
        [58, 44, 30, 46],
    )
    _sub_title(pdf, "Findings")
    _table(
        pdf,
        ["Capture", "Rule", "Severity", "Title"],
        [
            [f.get("capture_id"), f.get("rule_id"), f.get("severity"), f.get("title")]
            for f in findings
        ],
        [44, 48, 28, 58],
    )
    _sub_title(pdf, "Anomalies")
    anomaly_items = anomalies.get("items", []) if isinstance(anomalies, dict) else []
    _table(
        pdf,
        ["Anomaly", "Session", "Band", "Score"],
        [
            [
                a.get("anomaly_id"),
                a.get("session_id"),
                a.get("band") or a.get("status"),
                a.get("score"),
            ]
            for a in anomaly_items
        ],
        [52, 52, 44, 30],
    )

    # Correlation ---------------------------------------------------------------
    _section_title(pdf, "Correlation - Repeated Evidence Across Captures")
    _note(
        pdf,
        str(correlation.get("notice") or "Derived shared-evidence relationships."),
    )
    corr_summary = correlation.get("summary", {})
    _key_values(
        pdf,
        [
            ("Correlations", corr_summary.get("correlation_count")),
            ("Captures correlated", corr_summary.get("capture_count")),
            ("Sessions scanned", corr_summary.get("sessions_scanned")),
        ],
    )
    _table(
        pdf,
        ["Type", "Strength", "Occurrences", "Evidence key"],
        [
            [
                c.get("correlation_type"),
                c.get("strength"),
                c.get("occurrence_count"),
                c.get("evidence_key"),
            ]
            for c in correlation.get("correlations", [])
        ],
        [52, 30, 30, 66],
    )

    # Remediation workflow --------------------------------------------------------
    _section_title(pdf, "Remediation Workflow")
    _note(pdf, str(remediation.get("notice") or ""))
    _table(
        pdf,
        ["Remediation", "Target", "Rule", "Status", "Verification"],
        [
            [
                r.get("remediation_id"),
                f"{r.get('target_type')}: {r.get('target_id')}",
                r.get("rule_id"),
                r.get("status"),
                r.get("verification_status"),
            ]
            for r in remediation.get("remediations", [])
        ],
        [46, 62, 34, 28, 28],
    )

    # Verification evidence ---------------------------------------------------------
    _section_title(pdf, "Verification Evidence")
    _note(pdf, str(verification.get("notice") or ""))
    _table(
        pdf,
        ["Verification", "Method", "Rule", "Result"],
        [
            [v.get("verification_id"), v.get("method"), v.get("rule_id"), v.get("result")]
            for v in verification.get("results", [])
        ],
        [52, 40, 44, 42],
    )
    for v in verification.get("results", []):
        comparison = v.get("comparison", {})
        if comparison.get("statement"):
            _sub_title(pdf, f"Verification {v.get('verification_id')}")
            pdf.set_font("helvetica", "", 9.5)
            pdf.multi_cell(
                0,
                5.5,
                _clean(comparison.get("statement")),
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
            )
            pdf.ln(2)

    # Longitudinal analysis -------------------------------------------------------
    _section_title(pdf, "Longitudinal Analysis")
    _note(pdf, str(longitudinal.get("notice") or ""))
    drift_summary = longitudinal.get("drift_summary", {})
    _table(
        pdf,
        ["Observations", "Baseline", "Posture changes", "New", "Resolved", "Recurring"],
        [
            [
                drift_summary.get("observations"),
                drift_summary.get("baseline_capture_id"),
                drift_summary.get("posture_changes"),
                drift_summary.get("new_findings"),
                drift_summary.get("resolved_findings"),
                drift_summary.get("recurring_findings"),
            ]
        ]
        if longitudinal.get("drift")
        else [],
        [28, 44, 30, 22, 24, 24],
    )
    _sub_title(pdf, "Posture trend")
    _table(
        pdf,
        ["Capture", "Score", "State", "Change"],
        [
            [
                t.get("capture_id"),
                t.get("posture_score"),
                t.get("posture_state"),
                t.get("score_change_points"),
            ]
            for t in longitudinal.get("posture_trend", [])
        ],
        [52, 26, 52, 30],
    )
    _sub_title(pdf, "Drift records")
    _table(
        pdf,
        ["Type", "Baseline", "Comparison", "Statement"],
        [
            [
                d.get("drift_type"),
                d.get("baseline_capture_id"),
                d.get("comparison_capture_id"),
                d.get("statement"),
            ]
            for d in longitudinal.get("drift", [])
        ],
        [44, 44, 44, 58],
    )

    # Analyst work ------------------------------------------------------------
    pdf.add_page()
    _section_title(pdf, "Analyst Notes, Tags & Bookmarks")
    _note(pdf, str(work.get("notice") or ""))
    _sub_title(pdf, "Tags")
    tags = work.get("tags", [])
    _bullets(pdf, [str(t) for t in tags] or ["None recorded."])
    _sub_title(pdf, "Bookmarks (references, not copies)")
    _table(
        pdf,
        ["Target type", "Target ID", "Label"],
        [
            [b.get("target_type"), b.get("target_id"), b.get("label")]
            for b in work.get("bookmarks", [])
        ],
        [44, 66, 68],
    )
    _sub_title(pdf, "Analyst notes (analyst-authored, not evidence)")
    notes = work.get("notes", [])
    if not notes:
        _note(pdf, "No analyst notes recorded.")
    for entry in notes:
        pdf.set_font("helvetica", "B", 9.5)
        pdf.multi_cell(
            0,
            5.5,
            _clean(f"{entry.get('target_type')}: {entry.get('target_id')}"),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        pdf.set_font("helvetica", "", 9.5)
        pdf.multi_cell(0, 5.5, _clean(entry.get("content")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)
    _sub_title(pdf, "Case timeline (investigation events)")
    _table(
        pdf,
        ["Event", "Recorded at"],
        [[e.get("event_type"), e.get("created_at")] for e in work.get("timeline", [])],
        [100, 78],
    )

    # AI interpretation ---------------------------------------------------------
    _section_title(pdf, "AI Interpretation")
    _note(pdf, str(ai.get("notice") or ""))
    observations = ai.get("observations", [])
    if not observations:
        _note(pdf, str(ai.get("detail", "No validated AI observations.")))
    for entry in observations:
        pdf.set_font("helvetica", "B", 9.5)
        pdf.multi_cell(0, 5.5, _clean(entry.get("query")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("helvetica", "", 9.5)
        pdf.multi_cell(0, 5.5, _clean(entry.get("answer")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

    # Provenance ------------------------------------------------------------------
    pdf.add_page()
    _section_title(pdf, "Technical Provenance Metadata")
    _note(
        pdf,
        "Technical provenance records what was processed, when, and by which "
        "application version. It is not a legal chain-of-custody certification.",
    )
    _table(
        pdf,
        ["Capture", "SHA-256", "Analyzed at"],
        [
            [c.get("capture_id"), c.get("sha256"), c.get("analyzed_at")]
            for c in provenance.get("captures", [])
        ],
        [52, 74, 52],
    )
    _key_values(
        pdf,
        [
            ("Application version", provenance.get("application_version")),
            ("Generated at", provenance.get("generated_at")),
        ],
    )

    _section_title(pdf, "Limitations")
    _bullets(pdf, [str(item) for item in limitations])
    _section_title(pdf, "Methodology")
    _bullets(pdf, [str(item) for item in methodology])

    output: bytes = bytes(pdf.output())
    return output
