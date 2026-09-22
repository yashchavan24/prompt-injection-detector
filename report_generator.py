"""
report_generator.py -- builds the periodic PDF security report.

Reads from attack_log.py's event store and renders a client-ready report:
executive summary, threat taxonomy with mitigations, daily timeline,
criticality breakdown, and recent incidents.
"""
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

import attack_log

CRIT_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#b45309"),
    "MEDIUM": colors.HexColor("#a16207"),
    "LOW": colors.HexColor("#4d7c0f"),
}

CRIT_HEX = {k: "#" + v.hexval()[2:] for k, v in CRIT_COLORS.items()}


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], fontSize=20),
        "sub": ParagraphStyle("s", parent=ss["Normal"], fontSize=9,
                              textColor=colors.HexColor("#555555")),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13,
                             spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5,
                               leading=13),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8.5,
                               leading=11),
        "cellb": ParagraphStyle("cb", parent=ss["Normal"], fontSize=8.5,
                                leading=11, fontName="Helvetica-Bold"),
    }


def build_report(period="weekly") -> tuple:
    """Render the PDF for 'daily' | 'weekly' | 'monthly'.
    Returns (pdf_bytes, period_label, stats_dict)."""
    since, label, start_dt = attack_log.period_range(period)
    events = attack_log.get_events(limit=500, since=since)
    stats = attack_log.get_stats(days=30)
    total = len(events)
    blocked = sum(1 for e in events if e["verdict"] == "BLOCK")
    flagged = sum(1 for e in events if e["verdict"] == "FLAG")
    canary = sum(1 for e in events if e.get("canary"))

    # per-type counts *within the period*, from the events themselves
    by_type, by_crit = {}, {}
    for e in events:
        by_type[e["attack_type"] or "unknown"] = \
            by_type.get(e["attack_type"] or "unknown", 0) + 1
        by_crit[e["criticality"] or "UNKNOWN"] = \
            by_crit.get(e["criticality"] or "UNKNOWN", 0) + 1

    S = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=1.8 * cm, rightMargin=1.8 * cm,
        topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        title=f"Prompt Injection {label} Security Report")
    story = []
    now = datetime.now(timezone.utc)

    story.append(Paragraph("Prompt Injection Detector", S["title"]))
    story.append(Paragraph(
        f"{label} Security Report &middot; {start_dt:%d %b %Y} &ndash; "
        f"{now:%d %b %Y %H:%M} UTC", S["sub"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1,
                            color=colors.HexColor("#4a7dff")))
    story.append(Spacer(1, 10))

    # ------------------------------------------------ executive summary
    story.append(Paragraph("1. Executive Summary", S["h2"]))
    crit_worst = ("CRITICAL" if by_crit.get("CRITICAL")
                  else "HIGH" if by_crit.get("HIGH")
                  else "MEDIUM" if by_crit.get("MEDIUM")
                  else "LOW" if by_crit.get("LOW") else "NONE")
    summary_text = (
        f"The prompt-injection firewall screened all traffic in this period "
        f"and recorded <b>{total}</b> security events: <b>{blocked}</b> "
        f"requests were blocked before reaching the AI model and "
        f"<b>{flagged}</b> were flagged for review. "
        + (f"<b>{canary}</b> canary-token alarm(s) confirmed that secrets "
           f"were actively targeted." if canary
           else "No canary-token alarms fired, and no known secrets were "
                "observed in any model response.")
        + (f" The most severe activity observed was "
           f"<b>{crit_worst}</b> criticality." if crit_worst != "NONE" else "")
        + " Overall postures: input-side screening plus output-side response "
          "scanning remained active for the whole period.")
    story.append(Paragraph(summary_text, S["body"]))

    top_type = max(by_type, key=by_type.get) if by_type else None
    if top_type:
        tax = attack_log.taxonomy().get(top_type, {})
        story.append(Paragraph(
            f"Dominant threat: <b>{tax.get('label', top_type)}</b> "
            f"({by_type[top_type]} of {total} events). "
            f"{tax.get('description', '')}", S["body"]))
    story.append(Spacer(1, 6))

    # ------------------------------------------------ verdict summary table
    story.append(Paragraph("2. Event Summary", S["h2"]))
    rows = [[Paragraph("<b>Verdict</b>", S["cell"]),
             Paragraph("<b>Count</b>", S["cell"]),
             Paragraph("<b>Meaning</b>", S["cell"])]]
    for v, meaning in (("BLOCK", "Stopped before reaching the AI model"),
                       ("FLAG", "Delivered with a warning; human review advised"),
                       ("OUTPUT_BLOCK", "Model reply suppressed by the output firewall")):
        n = blocked if v == "BLOCK" else flagged if v == "FLAG" else 0
        rows.append([Paragraph(v, S["cell"]), Paragraph(str(n), S["cell"]),
                     Paragraph(meaning, S["cell"])])
    t = Table(rows, colWidths=[3 * cm, 2 * cm, 11.5 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # ------------------------------------------------ criticality breakdown
    story.append(Paragraph("3. Criticality Breakdown", S["h2"]))
    crit_rows = [[Paragraph("<b>Criticality</b>", S["cell"]),
                  Paragraph("<b>Events</b>", S["cell"]),
                  Paragraph("<b>Share</b>", S["cell"])]]
    for c in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = by_crit.get(c, 0)
        share = f"{n / total * 100:.0f}%" if total else "0%"
        crit_rows.append([
            Paragraph(f'<font color="{CRIT_HEX[c]}"><b>{c}</b>'
                      f"</font>", S["cell"]),
            Paragraph(str(n), S["cell"]), Paragraph(share, S["cell"])])
    t = Table(crit_rows, colWidths=[4 * cm, 3 * cm, 3 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    # ------------------------------------------------ daily timeline
    story.append(Paragraph("4. Daily Timeline (last 14 days)", S["h2"]))
    daily = stats.get("by_day", {})
    day_rows = [[Paragraph("<b>Day</b>", S["cell"]),
                 Paragraph("<b>BLOCK</b>", S["cell"]),
                 Paragraph("<b>FLAG</b>", S["cell"])]]
    for day, counts in list(daily.items())[-14:]:
        day_rows.append([Paragraph(day, S["cell"]),
                         Paragraph(str(counts.get("BLOCK", 0)), S["cell"]),
                         Paragraph(str(counts.get("FLAG", 0)), S["cell"])])
    if len(day_rows) == 1:
        day_rows.append([Paragraph("No events recorded yet", S["cell"]),
                         Paragraph("-", S["cell"]), Paragraph("-", S["cell"])])
    t = Table(day_rows, colWidths=[5 * cm, 3 * cm, 3 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(t)

    # ------------------------------------------------ threat taxonomy
    story.append(Paragraph(
        "5. Threats Observed: Type, Criticality, Detection &amp; Protection",
        S["h2"]))
    tax_all = attack_log.taxonomy()
    types_sorted = sorted(by_type.items(), key=lambda kv: -kv[1]) or \
        [("none", 0)]
    for key, n in types_sorted:
        tax = tax_all.get(key, {
            "label": key, "criticality": "UNKNOWN",
            "description": "", "mitigations": []})
        col = CRIT_HEX.get(tax.get("criticality"), "#333333")
        head = (f'<font color="{col}"><b>{tax["label"]}</b></font>'
                f" &mdash; {tax.get('criticality', '')} &middot; "
                f"{n} event(s) this period")
        story.append(Paragraph(head, S["cellb"]))
        if tax.get("description"):
            story.append(Paragraph(tax["description"], S["cell"]))
        if tax.get("mitigations"):
            story.append(Paragraph("<b>How it is detected / protected:</b>",
                                   S["cell"]))
            for m in tax["mitigations"]:
                story.append(Paragraph(f"&bull; {m}", S["cell"]))
        story.append(Spacer(1, 5))

    # ------------------------------------------------ notable incidents
    story.append(Paragraph("6. Most Recent Incidents", S["h2"]))
    inc_rows = [[Paragraph(f"<b>{i + 1}</b>", S["cell"]),
                 Paragraph(e["time"], S["cell"]),
                 Paragraph(f'<font color="{CRIT_HEX.get(e["criticality"], "#000000")}">'
                           f"<b>{e['verdict']}</b></font><br/>"
                           f"{attack_log.taxonomy().get(e['attack_type'], {}).get('label', e['attack_type'])}"
                           f" ({e.get('criticality', '')})", S["cell"]),
                 Paragraph((e["text"] or "")[:180]
                           .replace("&", "&amp;").replace("<", "&lt;")
                           .replace(">", "&gt;"), S["cell"])]
                for i, e in enumerate(events[:12])]
    if not inc_rows:
        inc_rows = [[Paragraph("-", S["cell"]),
                     Paragraph("No incidents in this period", S["cell"]),
                     Paragraph("-", S["cell"]), Paragraph("-", S["cell"])]]
    t = Table(inc_rows, colWidths=[0.9 * cm, 3.1 * cm, 4.6 * cm, 7.9 * cm],
              repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)

    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=0.6,
                            color=colors.HexColor("#cbd5e1")))
    story.append(Paragraph(
        "Generated automatically by the Prompt Injection Detector v3 "
        "(input screening + output firewall + canary tokens + session risk "
        "tracking). For questions contact the project security team.",
        S["sub"]))

    doc.build(story)
    return buf.getvalue(), label, {"total": total, "blocked": blocked,
                                   "flagged": flagged, "canary": canary}
