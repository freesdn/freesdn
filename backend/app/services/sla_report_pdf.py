# SPDX-License-Identifier: AGPL-3.0-only
"""Render a real, paginated SLA PDF without interpreting operator text as markup."""

from __future__ import annotations

from html import escape
from pathlib import Path
from threading import Lock
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Flowable, Paragraph, SimpleDocTemplate, Spacer

_FONT_LOCK = Lock()


def write_sla_pdf(filepath: Path, data: dict[str, Any], title: str) -> None:
    # PDF's standard CJK font support preserves Chinese policy names. Rendering
    # those glyphs depends on the viewer's CJK font support; this is not PDF/A.
    with _FONT_LOCK:
        if "STSong-Light" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))

    styles = {
        "title": ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=21,
            leading=27,
            spaceAfter=16,
            textColor=colors.HexColor("#15334A"),
        ),
        "heading": ParagraphStyle(
            "heading",
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=17,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True,
        ),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=10, leading=15, spaceAfter=5),
    }

    def paragraph(value: object, style: str = "body") -> Paragraph:
        raw = str(value)
        text = escape(raw).replace("\n", "<br/>")
        selected = styles[style]
        if any("\u2e80" <= char <= "\uffef" for char in raw):
            selected = ParagraphStyle(
                style + "-cjk", parent=selected, fontName="STSong-Light", wordWrap="CJK"
            )
        return Paragraph(text, selected)

    def percent(value: object) -> str:
        return "Not measured" if value is None else f"{value}%"

    story: list[Flowable] = [
        paragraph("FreeSDN | SLA compliance", "title"),
        paragraph(title, "heading"),
        paragraph(f"Period: {data['period_start']} to {data['period_end']} (end exclusive)"),
        paragraph("Historical compliance", "heading"),
    ]
    compliance = data.get("compliance", {})
    for label, key in [
        ("Average", "avg_compliance_percent"),
        ("Minimum", "min_compliance_percent"),
        ("Maximum", "max_compliance_percent"),
    ]:
        story.append(paragraph(f"{label}: {percent(compliance.get(key))}"))
    story.append(paragraph(f"Snapshots: {compliance.get('snapshot_count', 0)}"))
    story.append(paragraph("Policies in this report", "heading"))
    policies = data.get("policies", [])
    if not policies:
        story.append(paragraph("No policies matched this report's scope."))
    for policy in policies:
        story.extend(
            [
                paragraph(policy.get("name", "Unnamed policy"), "heading"),
                paragraph(
                    f"Scope: {policy.get('scope', 'Unknown')} | Current status: {policy.get('status', 'Unknown')}"
                ),
                paragraph(
                    f"Current compliance (not the historical average): {percent(policy.get('current_compliance_percent'))}"
                ),
            ]
        )
    breaches = data.get("breaches", {})
    story.append(paragraph("Breaches overlapping the period", "heading"))
    story.append(paragraph(f"Total: {breaches.get('total', 0)}"))
    for category in ["by_severity", "by_status"]:
        for label, count in sorted(breaches.get(category, {}).items()):
            story.append(paragraph(f"{label}: {count}"))
    story.extend(
        [
            Spacer(1, 12),
            paragraph(
                "This report summarizes stored observations. No measurements means unavailable, not 100% compliance."
            ),
        ]
    )

    def footer(canvas: Canvas, document: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#536675"))
        canvas.drawString(42, 25, "FreeSDN SLA report")
        canvas.drawRightString(A4[0] - 42, 25, f"Page {document.page}")
        canvas.restoreState()

    document = SimpleDocTemplate(
        str(filepath),
        pagesize=A4,
        rightMargin=42,
        leftMargin=42,
        topMargin=40,
        bottomMargin=42,
        title=title,
        author="FreeSDN",
    )
    document.build(story, onFirstPage=footer, onLaterPages=footer)
