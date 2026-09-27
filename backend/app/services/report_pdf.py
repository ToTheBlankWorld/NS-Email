"""Structured PDF forensic report renderer (Stage 9).

Builds a real, structured PDF (fpdf2) — not a screenshot. Sections use
explicit page breaks and print-safe core fonts. Every dynamic value is
sanitized to Latin-1 and stripped of control characters; evidence fields
are untrusted data and never interpreted as markup.
"""

from datetime import UTC, datetime
from typing import Any

from fpdf import FPDF
from fpdf.enums import XPos, YPos

_PAGE_MARGIN = 16
_ACCENT = (26, 54, 93)  # deep navy
_MUTED = (74, 85, 104)
_LIGHT = (237, 242, 247)

_SEVERITIES = ("critical", "high", "medium", "low", "info")


class _ReportPDF(FPDF):
    """PDF with a branded footer and page numbering."""

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("helvetica", "", 7.5)
        self.set_text_color(*_MUTED)
        self.cell(
            0,
            8,
            f"SecureMailScope forensic report - page {self.page_no()} of {{nb}}",
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


def _new_page(pdf: _ReportPDF, title: str) -> None:
    pdf.add_page()
    _section_title(pdf, title)


def _section_title(pdf: _ReportPDF, title: str) -> None:
    pdf.set_font("helvetica", "B", 13)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 8, _clean(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_draw_color(*_ACCENT)
    pdf.set_line_width(0.4)
    pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
    pdf.ln(3)
    pdf.set_text_color(0, 0, 0)


def _sub_title(pdf: _ReportPDF, title: str) -> None:
    pdf.set_font("helvetica", "B", 10.5)
    pdf.set_text_color(*_ACCENT)
    pdf.cell(0, 6, _clean(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1)
    pdf.set_text_color(0, 0, 0)


def _key_values(pdf: _ReportPDF, pairs: list[tuple[str, Any]]) -> None:
    pdf.set_font("helvetica", "", 9.5)
    for label, value in pairs:
        pdf.set_font("helvetica", "B", 9.5)
        pdf.cell(52, 5.5, _clean(label), new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("helvetica", "", 9.5)
        pdf.multi_cell(0, 5.5, _clean(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def _table(pdf: _ReportPDF, headers: list[str], rows: list[list[Any]], widths: list[float]) -> None:
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


def _bullets(pdf: _ReportPDF, items: list[str]) -> None:
    pdf.set_font("helvetica", "", 9.5)
    for item in items:
        pdf.cell(5, 5.2, "-", new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.multi_cell(0, 5.2, _clean(item), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)


def render_pdf_report(report: dict[str, Any]) -> bytes:
    """Render the report document into a structured PDF."""
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

    pdf = _ReportPDF()
    pdf.set_margins(_PAGE_MARGIN, _PAGE_MARGIN, _PAGE_MARGIN)
    pdf.set_auto_page_break(True, margin=18)
    pdf.set_title(_clean(meta.get("report_id") or "SecureMailScope Forensic Report"))
    # Determinism: the Info dict must not carry wall-clock time. The PDF
    # creation date mirrors the report's own deterministic generated_at.
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
    pdf.cell(
        0,
        8,
        "Forensic Security Posture Report",
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
        align="C",
    )
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)
    _key_values(
        pdf,
        [
            ("Report ID", meta.get("report_id")),
            ("Report schema version", meta.get("schema_version")),
            ("Application", meta.get("application", {}).get("name")),
            ("Application version", meta.get("application", {}).get("version")),
            ("Generated at", meta.get("generated_at")),
            ("Analysis status", meta.get("analysis_status")),
            ("Capture", capture.get("capture_id")),
            ("Filename", capture.get("filename")),
            ("SHA-256", capture.get("sha256")),
            ("Posture state", summary.get("posture_state") or "unknown"),
            ("Posture score", summary.get("posture_score")),
        ],
    )

    # Executive summary ------------------------------------------------------
    _new_page(pdf, "Executive Summary")
    _key_values(
        pdf,
        [
            ("Total sessions", summary.get("total_sessions")),
            ("Affected sessions", summary.get("affected_sessions")),
            ("Affected hosts", summary.get("affected_hosts")),
            ("Total findings", summary.get("findings_total")),
            ("Total anomalies", summary.get("anomalies_total")),
        ],
    )
    by_sev = summary.get("findings_by_severity", {})
    _table(
        pdf,
        ["Severity", "Findings"],
        [[sev, by_sev.get(sev, 0)] for sev in _SEVERITIES if by_sev.get(sev)],
        [60, 40],
    )
    by_band = summary.get("anomalies_by_band", {})
    _table(
        pdf,
        ["Anomaly band", "Sessions"],
        [[band, count] for band, count in by_band.items() if count],
        [80, 40],
    )
    _sub_title(pdf, "Protocol distribution")
    proto = summary.get("protocol_distribution", {})
    _table(pdf, ["Protocol", "Sessions"], [[p, c] for p, c in proto.items()], [60, 40])
    coverage = summary.get("tls_coverage", {})
    _sub_title(pdf, "TLS coverage")
    _table(
        pdf,
        ["Coverage", "Count"],
        [
            ["Sessions total", coverage.get("sessions_total", 0)],
            ["With TLS handshake", coverage.get("sessions_with_tls_handshake", 0)],
            ["With STARTTLS negotiation", coverage.get("sessions_with_starttls", 0)],
            ["Handshakes complete", coverage.get("handshakes_complete", 0)],
        ],
        [80, 40],
    )

    # Security posture ---------------------------------------------------------
    if posture.get("available"):
        _new_page(pdf, "Security Posture")
        _key_values(
            pdf,
            [
                ("Posture state", posture.get("posture_state")),
                ("Overall score", posture.get("overall_score")),
                ("Confidence", posture.get("confidence")),
                ("Policy", posture.get("policy_id")),
                ("Explanation", posture.get("explanation")),
            ],
        )
        _table(
            pdf,
            ["Factor", "Status", "Contribution", "Affected", "Explanation"],
            [
                [
                    f.get("factor"),
                    f.get("status"),
                    f.get("score_contribution"),
                    f.get("affected_sessions"),
                    f.get("explanation"),
                ]
                for f in posture.get("factors", [])
            ],
            [34, 24, 26, 18, 82],
        )

    # Findings -------------------------------------------------------------------
    _new_page(pdf, "Security Findings")
    _table(
        pdf,
        ["Rule", "Severity", "Confidence", "Title", "Remediation"],
        [
            [
                f.get("rule_id"),
                f.get("severity"),
                f.get("confidence"),
                f.get("title"),
                (f.get("remediation") or {}).get("action"),
            ]
            for f in findings
        ],
        [38, 20, 22, 54, 50],
    )

    # Anomalies --------------------------------------------------------------------
    _new_page(pdf, "Behavioral Anomalies")
    pdf.set_font("helvetica", "I", 9)
    pdf.set_text_color(*_MUTED)
    pdf.multi_cell(
        0,
        5,
        _clean(
            "Anomaly bands describe statistical deviation from the capture-local "
            "baseline. They are not indicators of compromise."
        ),
        new_x=XPos.LMARGIN,
        new_y=YPos.NEXT,
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(1)
    _table(
        pdf,
        ["Anomaly", "Session", "Protocol", "Band", "Score"],
        [
            [
                a.get("anomaly_id"),
                a.get("session_id"),
                a.get("protocol"),
                a.get("band") or a.get("status"),
                a.get("score"),
            ]
            for a in anomalies.get("items", [])
        ],
        [40, 42, 22, 40, 20],
    )

    # TLS summary ---------------------------------------------------------------------
    _new_page(pdf, "TLS & Certificate Analysis")
    _sub_title(pdf, "TLS versions observed")
    _table(
        pdf,
        ["TLS version", "Handshakes"],
        [[v, c] for v, c in tls.get("versions_observed", {}).items()],
        [60, 40],
    )
    _sub_title(pdf, "Cipher families")
    _table(
        pdf,
        ["Cipher family", "Handshakes"],
        [[c, n] for c, n in tls.get("cipher_families", {}).items()],
        [60, 40],
    )
    _sub_title(pdf, "Certificates observed")
    _table(
        pdf,
        ["Subject", "Issuer", "Valid until", "Signature"],
        [
            [
                c.get("subject"),
                c.get("issuer"),
                c.get("not_after"),
                c.get("signature_algorithm"),
            ]
            for c in tls.get("certificates", [])
        ],
        [50, 50, 34, 40],
    )

    # Evidence graph summary ------------------------------------------------------------
    _new_page(pdf, "Evidence Graph Summary")
    _key_values(
        pdf,
        [
            ("Nodes", graph.get("node_count")),
            ("Edges", graph.get("edge_count")),
            ("Correlated certificates", graph.get("correlated_certificate_count")),
        ],
    )
    _sub_title(pdf, "Node types")
    _table(
        pdf,
        ["Node type", "Count"],
        [[t, c] for t, c in graph.get("node_types", {}).items()],
        [70, 40],
    )
    _sub_title(pdf, "Relationships")
    _table(
        pdf,
        ["Relationship", "Count"],
        [[t, c] for t, c in graph.get("edge_types", {}).items()],
        [70, 40],
    )

    # AI analyst ---------------------------------------------------------------------------
    _new_page(pdf, "AI Analyst Observations")
    if not ai.get("configured"):
        pdf.set_font("helvetica", "I", 9.5)
        pdf.set_text_color(*_MUTED)
        pdf.cell(0, 6, "AI analyst not configured.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
    elif not ai.get("observations"):
        pdf.set_font("helvetica", "I", 9.5)
        pdf.set_text_color(*_MUTED)
        pdf.cell(0, 6, _clean(ai.get("note")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)
    else:
        pdf.set_font("helvetica", "I", 9)
        pdf.set_text_color(*_MUTED)
        pdf.multi_cell(
            0,
            5,
            _clean(
                "AI-generated interpretive assistance derived from structured "
                "evidence; never a source of security truth."
            ),
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
        pdf.set_text_color(0, 0, 0)
        pdf.ln(1)
        for entry in ai.get("observations", []):
            if pdf.get_y() > pdf.page_break_trigger - 40:
                pdf.add_page()
                _section_title(pdf, "AI Analyst Observations (continued)")
            pdf.set_font("helvetica", "B", 9.5)
            pdf.multi_cell(0, 5, _clean(entry.get("query")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_font("helvetica", "", 9)
            pdf.multi_cell(0, 5, _clean(entry.get("answer")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            for key, label in (
                ("observations", "Observed evidence"),
                ("interpretations", "Interpretation"),
                ("uncertainties", "Uncertainty"),
            ):
                items = entry.get(key) or []
                if items:
                    pdf.set_font("helvetica", "B", 8.5)
                    pdf.cell(0, 5, _clean(label), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    pdf.set_font("helvetica", "", 8.5)
                    _bullets(pdf, [str(item) for item in items])
            pdf.ln(2)

    # Limitations + methodology --------------------------------------------------------------
    _new_page(pdf, "Limitations")
    _bullets(pdf, limitations)
    _sub_title(pdf, "Methodology")
    _bullets(pdf, methodology)

    return bytes(pdf.output())
