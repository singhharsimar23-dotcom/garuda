"""
Air-Gapped PDF Report Generator
Produces executive PDF reports using reportlab for air-gapped forensic triage.
"""

from datetime import datetime, timezone, timedelta
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("garuda.analyst.report")


def generate_pdf_report(
    output_path: str,
    hostname: str,
    alerts: List[Dict[str, Any]],
    observation_summary: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Builds a structured PDF report from local air-gapped alerts and telemetry history.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "TitleStyle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0D1521"),
        )
        heading2_style = ParagraphStyle(
            "Heading2Style",
            parent=styles["Heading2"],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#FF6B00"),
        )
        body_style = ParagraphStyle(
            "BodyStyle",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#222222"),
        )

        story = []

        # 1. Header
        now_str = datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime("%d-%b-%Y %H:%M:%S IST")
        story.append(Paragraph("<b>GARUDA DEFENSE INTELLIGENCE // AIR-GAPPED FORENSIC REPORT</b>", title_style))
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>Asset Monitored:</b> {hostname} | <b>Date:</b> {now_str} | <b>Version:</b> 0.3.0", body_style))
        story.append(Spacer(1, 14))

        # 2. Executive Summary (Deterministic — No External LLM)
        story.append(Paragraph("1. Executive Summary", heading2_style))
        critical_count = sum(1 for a in alerts if a.get("level") == "CRITICAL")
        medium_count = sum(1 for a in alerts if a.get("level") == "MEDIUM")
        
        summary_text = (
            f"Forensic triage completed for endpoint <b>{hostname}</b>. A total of <b>{len(alerts)} physical anomalies</b> "
            f"were identified during offline air-gapped monitoring ({critical_count} CRITICAL, {medium_count} MEDIUM). "
            f"Physical microarchitectural deviations indicate execution patterns consistent with dormant implants, "
            f"process hollowing, or unauthorized cryptographic activity."
        )
        story.append(Paragraph(summary_text, body_style))
        story.append(Spacer(1, 14))

        # 3. Alerts Breakdown Table
        story.append(Paragraph("2. Physics-Layer Anomaly Findings", heading2_style))
        story.append(Spacer(1, 6))

        table_data = [["Alert ID", "Timestamp (IST)", "Severity", "IAS Score", "Top Divergent Channel"]]
        for a in alerts[:15]:
            top_ch = a.get("top_channels", [{}])[0].get("channel", "N/A") if a.get("top_channels") else "N/A"
            table_data.append([
                a.get("alert_id", "N/A"),
                a.get("timestamp_ist", "N/A"),
                a.get("level", "N/A"),
                f"{a.get('ias_score', 0.0):.2f} σ",
                top_ch,
            ])

        if len(table_data) == 1:
            table_data.append(["NO ALERTS", "-", "CLEAN", "0.00 σ", "None"])

        t = Table(table_data, colWidths=[80, 120, 80, 80, 180])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D1521")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#FFFFFF")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D5DD")),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F9FA")]),
        ]))
        story.append(t)
        story.append(Spacer(1, 14))

        # 4. Recommendation
        story.append(Paragraph("3. Air-Gapped Hardening & Remediation", heading2_style))
        remediation_text = (
            "1. Inspect processes with elevated RAPL/cache divergence signatures using EPPI kprobe logs.<br/>"
            "2. Ensure memory dumps are preserved for processes with IAS &gt; 5.0.<br/>"
            "3. Export STIX 2.1 bundle for submission to national defense SOC."
        )
        story.append(Paragraph(remediation_text, body_style))

        doc.build(story)
        logger.info(f"PDF report generated at {output_path}")
        return True

    except ImportError:
        logger.warning("reportlab not installed. Writing plain-text markdown fallback report.")
        txt_path = output_path.replace(".pdf", ".txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"GARUDA DEFENSE INTELLIGENCE FORENSIC REPORT\nHostname: {hostname}\nTotal Alerts: {len(alerts)}\n")
        return True
    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")
        return False
