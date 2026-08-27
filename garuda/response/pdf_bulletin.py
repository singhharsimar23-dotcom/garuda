from datetime import datetime, timezone, timedelta
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from garuda.config import settings
from garuda.database import get_supabase_client
from garuda.response.alerts import dispatch_alert

logger = logging.getLogger("garuda.response.pdf_bulletin")


def generate_daily_bulletin_pdf(
    alerts: List[Dict[str, Any]],
    campaigns: List[Dict[str, Any]],
    tension_index: float,
    output_path: Optional[Path] = None,
) -> Path:
    """
    Generate an executive defense intelligence PDF bulletin using ReportLab.

    Sections:
        1. Executive Threat Summary & Geopolitical Tension Gauge
        2. New Critical & High Alerts (Past 24h)
        3. Active APT36 Campaign Clusters & Attack Window Forecasts
        4. Blocklist Submissions & Forensic IOC Matrix

    Args:
        alerts: List of recent alert records.
        campaigns: List of active campaign clusters.
        tension_index: Current measured tension score (0.0 - 1.0).
        output_path: Optional destination file path.

    Returns:
        Path: Absolute path to the generated PDF document.
    """
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    if output_path is None:
        bulletin_dir = Path(__file__).resolve().parent.parent / "data" / "bulletins"
        bulletin_dir.mkdir(parents=True, exist_ok=True)
        output_path = bulletin_dir / f"GARUDA_Bulletin_{date_str}.pdf"

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1A365D"),
    )

    sub_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4A5568"),
    )

    heading2_style = ParagraphStyle(
        "Heading2Custom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#2C5282"),
        spaceBefore=10,
        spaceAfter=6,
    )

    body_style = ParagraphStyle(
        "BodyCustom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#2D3748"),
    )

    elements = []

    # Title & Header
    elements.append(Paragraph("🛡️ GARUDA CYBER THREAT INTELLIGENCE DAILY BULLETIN", title_style))
    elements.append(
        Paragraph(
            f"Classification: <b>RESTRICTED / DEFENCE SOVEREIGN</b> | Published: {datetime.now(timezone.utc).strftime('%d %B %Y %H:%M UTC')}",
            sub_style,
        )
    )
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1A365D")))
    elements.append(Spacer(1, 10))

    # Section 1: Executive Tension & Posture
    conflict_state = "ELEVATED (CONFLICT MODE ACTIVE)" if tension_index >= settings.TENSION_THRESHOLD else "NOMINAL MONITORING"
    tension_summary = (
        f"<b>Current Geopolitical Tension Index:</b> {tension_index:.2f}/1.00 "
        f"| <b>Operational Posture:</b> <font color='{'red' if tension_index >= settings.TENSION_THRESHOLD else 'green'}'>{conflict_state}</font><br/>"
        f"<b>Total Monitored Indicators (24h):</b> {len(alerts)} | <b>Active Correlated Campaigns:</b> {len(campaigns)}"
    )
    elements.append(Paragraph(tension_summary, body_style))
    elements.append(Spacer(1, 12))

    # Section 2: Recent Threat Alerts Table
    elements.append(Paragraph("1. High & Critical Priority Alerts (Past 24 Hours)", heading2_style))

    table_data = [["Target Domain", "Score", "Target Sector", "Registrar", "Status"]]
    for a in alerts[:10]:
        table_data.append([
            a.get("domain", "N/A"),
            f"{a.get('score', 0)}/100",
            a.get("sector", "Critical Sector")[:24],
            str(a.get("registrar", "Unknown"))[:16],
            a.get("status", "pending"),
        ])

    if len(table_data) == 1:
        table_data.append(["No new high-severity alerts detected in this window.", "-", "-", "-", "nominal"])

    alert_table = Table(table_data, colWidths=[180, 50, 140, 100, 70])
    alert_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2B6CB0")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7FAFC")]),
        ])
    )
    elements.append(alert_table)
    elements.append(Spacer(1, 15))

    # Section 3: Active Campaigns
    elements.append(Paragraph("2. Correlated APT36 Attack Campaigns (DBSCAN Clusters)", heading2_style))
    camp_table_data = [["Cluster ID", "Domains", "Hosting ASN", "Target Sectors", "Est. Attack Window"]]
    for c in campaigns[:5]:
        camp_table_data.append([
            c.get("cluster_id", "N/A"),
            str(c.get("domain_count", 1)),
            f"AS{c.get('hosting_asn', 0)}",
            ", ".join(c.get("sectors", []))[:25] or "Defence",
            f"{c.get('estimated_attack_window_days', 15)} days",
        ])

    if len(camp_table_data) == 1:
        camp_table_data.append(["No multi-domain campaign clusters detected.", "-", "-", "-", "-"])

    camp_table = Table(camp_table_data, colWidths=[140, 55, 85, 160, 100])
    camp_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2D3748")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#EDF2F7")]),
        ])
    )
    elements.append(camp_table)
    elements.append(Spacer(1, 15))

    # Section 4: Recommended Actions
    elements.append(Paragraph("3. Operational Guidance for Defense CISOs", heading2_style))
    guidance = (
        "• Apply automated DNS sinkholing for all listed domains across boundary resolvers.<br/>"
        "• Cross-reference authentication telemetry for hits against AS16276, AS24940, and AS63949.<br/>"
        "• Execute YARA rule updates on Linux and Windows endpoints monitoring BOSS distribution paths."
    )
    elements.append(Paragraph(guidance, body_style))

    doc.build(elements)
    logger.info(f"[pdf_bulletin] Generated daily intelligence bulletin at {output_path}")
    return output_path


async def run_daily_bulletin_task() -> Optional[Path]:
    """Scheduled task to generate daily bulletin PDF and dispatch link to Telegram."""
    client = get_supabase_client()
    alerts: List[Dict[str, Any]] = []
    campaigns: List[Dict[str, Any]] = []

    if client:
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
            res_alerts = client.table("alerts").select("*").gte("created_at", cutoff).execute()
            alerts = res_alerts.data or []
            res_camp = client.table("campaigns").select("*").limit(10).execute()
            campaigns = res_camp.data or []
        except Exception as e:
            logger.warning(f"[pdf_bulletin] Database query error: {e}")

    pdf_path = generate_daily_bulletin_pdf(alerts, campaigns, tension_index=0.55)

    # Dispatch notification to Telegram
    await dispatch_alert({
        "domain": f"GARUDA Daily Intelligence Bulletin ({datetime.now(timezone.utc).strftime('%d-%b-%Y')})",
        "score": 50,
        "sector": "National Defense Cyber Command",
        "signals": {"bulletin_generated": True, "path": str(pdf_path)},
    }, level="INFO")

    return pdf_path
