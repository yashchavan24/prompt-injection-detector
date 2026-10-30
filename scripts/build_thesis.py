# -*- coding: utf-8 -*-
"""Build the final year project report PDF per the SVCET CS format (2026-27).

Format (from "Project _Report_Format (26-27) CS.doc"):
  A4; Times New Roman 12; 1.5 spacing; justified; margins top/bottom 1",
  left 1.5", right 1"; front matter in lower-case Roman numerals, Arabic
  from Chapter 1; chapter titles 16 bold UPPER CASE, sections 14 bold
  UPPER CASE, subsections 12 bold UPPER CASE, captions 12 title case
  (table captions above tables, figure captions below figures).

Sequence: Cover Page, Title Page, Certificate, Acknowledgment, Abstract,
Table of Contents, List of Tables, List of Figures, List of Symbols /
Abbreviations, Chapters 1-4, References and Bibliography, Project Team
Information. Built in two passes so the Contents / Lists show real page
numbers, then merged with pymupdf.

Output: docs/thesis/Prompt_Injection_Detector_Project_Report.pdf
"""
import os
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import (Drawing, Line, Rect, String)
from reportlab.platypus import (BaseDocTemplate, Frame, Image, KeepTogether,
                                PageBreak, PageTemplate, Paragraph, Spacer,
                                Table, TableStyle, NextPageTemplate)
import pymupdf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "docs", "thesis")
SHOTS = os.path.join(ROOT, "docs", "screenshots")
TMP = os.path.join(OUT_DIR, "_parts")
os.makedirs(TMP, exist_ok=True)
FINAL = os.path.join(OUT_DIR, "Prompt_Injection_Detector_Project_Report.pdf")

PAGE_W, PAGE_H = A4
M_TOP, M_BOT = 1.0 * inch, 1.0 * inch
M_LEFT, M_RIGHT = 1.5 * inch, 1.0 * inch
TEXT_W = PAGE_W - M_LEFT - M_RIGHT          # 5.77in
BODY_FONT = "Times-Roman"
GOLD = colors.HexColor("#d4af37")
NAVY = colors.HexColor("#0e1b45")

TITLE = ("A MACHINE LEARNING-BASED FRAMEWORK FOR REAL-TIME DETECTION OF "
         "PROMPT INJECTION ATTACKS IN LLM-INTEGRATED APPLICATIONS")
SHORT_TITLE = ("A MACHINE LEARNING-BASED FRAMEWORK FOR REAL-TIME DETECTION OF "
               "PROMPT INJECTION ATTACKS IN LLM-INTEGRATED APPLICATIONS")
TEAM = ["Yash Chavan", "Sohel Sheikh"]
GUIDE = "Dr. Abhishek D. Pathak"
GUIDE_DESG = "Assistant Professor"
HOD = "Dr. A.D. Pathak"
YEAR = "Academic Year 2026-27"

# ------------------------------------------------------------------ styles
S = {}
def _st(name, **kw):
    base = dict(fontName=BODY_FONT, fontSize=12, leading=18, spaceAfter=6)
    base.update(kw)
    S[name] = ParagraphStyle(name, **base)

_st("body", alignment=TA_JUSTIFY, firstLineIndent=0.4 * inch)
_st("nobody", alignment=TA_JUSTIFY)
_st("chapterNum", fontSize=16, leading=20, alignment=TA_CENTER,
    fontName="Times-Bold", spaceBefore=12)
_st("chapterTitle", fontSize=16, leading=20, alignment=TA_CENTER,
    fontName="Times-Bold", spaceAfter=18)
_st("section", fontSize=14, leading=18, fontName="Times-Bold",
    spaceBefore=14, spaceAfter=8)
_st("subsection", fontSize=12, leading=18, fontName="Times-Bold",
    spaceBefore=10, spaceAfter=6)
_st("caption", fontSize=12, leading=16, alignment=TA_CENTER,
    fontName="Times-Bold", spaceBefore=8, spaceAfter=4, keepWithNext=1)
_st("capnote", fontSize=12, leading=16, alignment=TA_CENTER, spaceBefore=4)
_st("bullet", fontSize=12, leading=18, alignment=TA_JUSTIFY,
    leftIndent=0.45 * inch, bulletIndent=0.2 * inch)
_st("centeR", alignment=TA_CENTER)
_st("ref", fontSize=12, leading=18, alignment=TA_JUSTIFY,
    leftIndent=0.35 * inch, firstLineIndent=-0.35 * inch, spaceAfter=4)

def P(text, style="body"):
    return Paragraph(text, S[style])

def chapter(num, title):
    return [Spacer(1, 24), P("CHAPTER %s" % num, "chapterNum"),
            P(title, "chapterTitle")]

def table_cap(txt):
    return P(txt, "caption")

def fig_cap(txt):
    return P(txt, "capnote")

def fig_table(rows, widths, header=True, fontsize=12):
    cell_style = ParagraphStyle("cell", fontName=BODY_FONT, fontSize=fontsize,
                                leading=fontsize * 1.35, alignment=TA_LEFT)
    data = [[Paragraph(str(c), cell_style) for c in row] for row in rows]
    if header:
        data[0] = [Paragraph("<b>%s</b>" % c, cell_style)
                   for i, c in enumerate(rows[0])]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.7, colors.black),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t

def roman(n):
    vals = [(1000, "m"), (900, "cm"), (500, "d"), (400, "cd"), (100, "c"),
            (90, "xc"), (50, "l"), (40, "xl"), (10, "x"), (9, "ix"),
            (5, "v"), (4, "iv"), (1, "i")]
    out = ""
    for v, s in vals:
        while n >= v:
            out += s
            n -= v
    return out

def numbered_footer(fmt):
    def cb(canv, doc):
        canv.saveState()
        canv.setFont(BODY_FONT, 12)
        if fmt == "roman":
            label = roman(canv.getPageNumber())
        else:
            label = str(canv.getPageNumber())
        canv.drawCentredString(PAGE_W / 2.0, 0.6 * inch, label)
        canv.restoreState()
    return cb

def blank_page(canv, doc):
    pass

# --------------------------------------------------------------- diagrams
def _box(d, x, y, w, h, label, fill="#eef1f7", fs=7.5):
    d.add(Rect(x, y, w, h, fillColor=colors.HexColor(fill),
               strokeColor=colors.black, strokeWidth=0.8, rx=4, ry=4))
    lines = label.split("\n")
    ty = y + h / 2 + (len(lines) - 1) * fs * 0.65 - fs / 3.0
    for ln in lines:
        d.add(String(x + w / 2, ty, ln, fontName="Helvetica", fontSize=fs,
                     fillColor=colors.black, textAnchor="middle"))
        ty -= fs * 1.3

def _arrow(d, x1, y1, x2, y2):
    d.add(Line(x1, y1, x2, y2, strokeColor=colors.black, strokeWidth=0.9))
    import math
    ang = math.atan2(y2 - y1, x2 - x1)
    for da in (0.42, -0.42):
        d.add(Line(x2, y2, x2 - 7 * math.cos(ang + da),
                   y2 - 7 * math.sin(ang + da),
                   strokeColor=colors.black, strokeWidth=0.9))

def _db(d, x, y, w, h, label):
    d.add(Rect(x, y, w, h, fillColor=colors.HexColor("#f7f0dc"),
               strokeColor=colors.black, strokeWidth=0.8, rx=10, ry=10))
    d.add(String(x + w / 2, y + h / 2 + 2, label, fontName="Helvetica",
                 fontSize=7.5, fillColor=colors.black, textAnchor="middle"))

def make_architecture():
    W, H = 5.5 * inch, 3.3 * inch
    d = Drawing(W, H)
    _box(d, 0.2 * inch, H - 0.72 * inch, 1.35 * inch, 0.55 * inch,
         "User prompt /\nChat site (ChatGPT etc.)")
    _box(d, 0.2 * inch, H - 1.55 * inch, 1.35 * inch, 0.55 * inch,
         "Browser extension\n(auto-scan + send guard)")
    _box(d, 2.05 * inch, H - 1.12 * inch, 1.6 * inch, 0.6 * inch,
         "FastAPI middleware\n/auth, /check, /chat", "#e8f0e8")
    _box(d, 4.05 * inch, H - 1.12 * inch, 1.25 * inch, 0.6 * inch,
         "Detection engine\nTF-IDF + 39 heuristics")
    _box(d, 2.05 * inch, H - 2.1 * inch, 1.6 * inch, 0.55 * inch,
         "Attack logger\n+ postgreSQL / sqlite")
    _box(d, 0.2 * inch, H - 2.85 * inch, 1.35 * inch, 0.55 * inch,
         "Output firewall\n(canary + re-score)")
    _box(d, 2.05 * inch, H - 2.85 * inch, 1.6 * inch, 0.55 * inch,
         "Trusted LLM endpoint\n(ChatGPT / Qwen / ...)")
    _box(d, 4.05 * inch, H - 2.85 * inch, 1.25 * inch, 0.55 * inch,
         "Dashboard +\nPDF reports")
    _arrow(d, 1.55 * inch, H - 0.45 * inch, 2.05 * inch, H - 0.85 * inch)
    _arrow(d, 1.55 * inch, H - 1.25 * inch, 2.05 * inch, H - 1.2 * inch)
    _arrow(d, 3.65 * inch, H - 0.82 * inch, 4.05 * inch, H - 0.82 * inch)
    bi = d._add if False else None
    return d

def make_erd():
    W, H = 5.5 * inch, 2.7 * inch
    d = Drawing(W, H)
    d.add(Rect(0.35 * inch, 0.9 * inch, 1.5 * inch, 1.5 * inch,
               fillColor=colors.HexColor("#eef1f7"), strokeColor=colors.black,
               strokeWidth=0.9))
    d.add(String(1.1 * inch, 2.18 * inch, "USERS", fontName="Helvetica-Bold",
                 fontSize=8, textAnchor="middle"))
    for i, ln in enumerate(["id  (PK)", "email (unique)", "name",
                            "pw_hash", "created_at"]):
        d.add(String(0.5 * inch, 1.95 * inch - i * 0.22 * inch, ln,
                     fontName="Helvetica", fontSize=7.5))
    d.add(Rect(3.3 * inch, 0.35 * inch, 1.9 * inch, 2.2 * inch,
               fillColor=colors.HexColor("#eef1f7"), strokeColor=colors.black,
               strokeWidth=0.9))
    d.add(String(4.25 * inch, 2.3 * inch, "EVENTS", fontName="Helvetica-Bold",
                 fontSize=8, textAnchor="middle"))
    for i, ln in enumerate(["id  (PK)", "ts", "verdict", "probability",
                            "attack_type, criticality", "source, canary",
                            "session_id", "user_id (FK)", "text, signals"]):
        d.add(String(3.42 * inch, 2.05 * inch - i * 0.2 * inch, ln,
                     fontName="Helvetica", fontSize=7.5))
    d.add(Line(1.85 * inch, 1.65 * inch, 3.3 * inch, 1.65 * inch,
               strokeColor=colors.black, strokeWidth=0.9))
    d.add(String(2.15 * inch, 1.72 * inch, "1:M", fontName="Helvetica",
                 fontSize=8))
    return d

def make_dfd0():
    W, H = 5.5 * inch, 2.9 * inch
    d = Drawing(W, H)
    _box(d, 0.25 * inch, H - 0.85 * inch, 1.3 * inch, 0.5 * inch, "USER")
    _box(d, 2.2 * inch, H - 0.95 * inch, 1.5 * inch, 0.7 * inch,
         "0.0\nPROMPT INJECTION\nDETECTOR SYSTEM", "#e8f0e8")
    _box(d, 4.15 * inch, H - 0.85 * inch, 1.15 * inch, 0.5 * inch,
         "LLM PROVIDER")
    _db(d, 1.0 * inch, 0.35 * inch, 1.3 * inch, 0.5 * inch,
        "USERS / EVENTS DB")
    _box(d, 2.4 * inch, 0.35 * inch, 1.2 * inch, 0.5 * inch,
         "SECURITY\nADMIN")
    _arrow(d, 1.55 * inch, H - 0.55 * inch, 2.2 * inch, H - 0.6 * inch)
    _arrow(d, 3.7 * inch, H - 0.55 * inch, 4.15 * inch, H - 0.6 * inch)
    _arrow(d, 2.95 * inch, H - 0.95 * inch, 2.2 * inch, 0.85 * inch)
    _arrow(d, 3.35 * inch, 0.6 * inch, 2.6 * inch, 0.6 * inch)
    return d

def make_dfd1():
    W, H = 5.5 * inch, 3.4 * inch
    d = Drawing(W, H)
    _box(d, 0.2 * inch, H - 0.8 * inch, 1.15 * inch, 0.45 * inch, "USER")
    _box(d, 1.85 * inch, H - 0.85 * inch, 1.05 * inch, 0.5 * inch,
         "1.0\nAUTHENTICATE")
    _box(d, 3.35 * inch, H - 0.85 * inch, 1.05 * inch, 0.5 * inch,
         "2.0\nINPUT SCREEN")
    _box(d, 2.0 * inch, H - 1.85 * inch, 1.4 * inch, 0.5 * inch,
         "3.0\nOUTPUT FIREWALL")
    _box(d, 0.35 * inch, H - 1.85 * inch, 1.05 * inch, 0.5 * inch,
         "4.0\nLLM CALL")
    _box(d, 3.9 * inch, H - 1.85 * inch, 1.3 * inch, 0.5 * inch,
         "5.0\nLOG & CONCLUDE")
    _box(d, 3.9 * inch, 0.4 * inch, 1.3 * inch, 0.5 * inch,
         "6.0\nREPORTS")
    _db(d, 1.55 * inch, 0.35 * inch, 1.35 * inch, 0.5 * inch,
        "EVENTS DB")
    _db(d, 0.2 * inch, 0.95 * inch, 1.0 * inch, 0.45 * inch, "USERS DB")
    _arrow(d, 1.35 * inch, H - 0.6 * inch, 1.85 * inch, H - 0.6 * inch)
    _arrow(d, 2.9 * inch, H - 0.6 * inch, 3.35 * inch, H - 0.6 * inch)
    _arrow(d, 2.6 * inch, H - 1.35 * inch, 2.0 * inch, H - 1.6 * inch)
    _arrow(d, 3.4 * inch, H - 1.6 * inch, 3.9 * inch, H - 1.6 * inch)
    _arrow(d, 0.75 * inch, H - 1.35 * inch, 1.4 * inch, H - 0.85 * inch)
    _arrow(d, 3.0 * inch, H - 2.05 * inch, 1.7 * inch, 0.75 * inch)
    _arrow(d, 4.5 * inch, H - 1.85 * inch, 4.5 * inch, 0.95 * inch)
    return d

# -------------------------------------------------------------- front docs
def build_cover_and_title():
    story = [
        Spacer(1, 0.55 * inch),
        Paragraph("A MACHINE LEARNING-BASED FRAMEWORK FOR<br/>REAL-TIME "
                  "DETECTION OF PROMPT INJECTION ATTACKS<br/>IN "
                  "LLM-INTEGRATED APPLICATIONS",
                  ParagraphStyle("t", fontName="Times-Bold", fontSize=22,
                                 leading=33, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.22 * inch),
        Paragraph("in partial fulfillment of the requirements for the award "
                  "of the degree<br/>of Bachelor of Technology in",
                  ParagraphStyle("i", fontName="Times-Italic", fontSize=14,
                                 leading=21, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.15 * inch),
        Paragraph("COMPUTER SCIENCE AND ENGINEERING<br/>(CYBER SECURITY)",
                  ParagraphStyle("d", fontName="Times-Bold", fontSize=16,
                                 leading=24, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.28 * inch),
        Paragraph("Submitted by",
                  ParagraphStyle("s", fontName="Times-BoldItalic", fontSize=14,
                                 leading=21, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.12 * inch),
        Paragraph("%s<br/>%s" % (TEAM[0].upper(), TEAM[1].upper()),
                  ParagraphStyle("n", fontName="Times-Bold", fontSize=16,
                                 leading=26, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.2 * inch),
        Paragraph("Under the guidance of",
                  ParagraphStyle("g1", fontName="Times-Roman", fontSize=14,
                                 leading=21, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.08 * inch),
        Paragraph("DR. ABHISHEK D. PATHAK",
                  ParagraphStyle("g2", fontName="Times-Bold", fontSize=16,
                                 leading=22, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Paragraph("Assistant Professor",
                  ParagraphStyle("g3", fontName="Times-Roman", fontSize=14,
                                 leading=21, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.18 * inch),
        Paragraph(YEAR,
                  ParagraphStyle("y", fontName="Times-Bold", fontSize=18,
                                 leading=24, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.12 * inch),
        Paragraph("Department of Computer Science and Engineering<br/>"
                  "(Cyber Security)",
                  ParagraphStyle("dep", fontName="Times-Bold", fontSize=16,
                                 leading=24, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Spacer(1, 0.16 * inch),
        Paragraph("ST. VINCENT PALLOTTI COLLEGE OF ENGINEERING AND TECHNOLOGY",
                  ParagraphStyle("c1", fontName="Times-Bold", fontSize=15,
                                 leading=22, alignment=TA_CENTER,
                                 textColor=GOLD)),
        Paragraph("Wardha Road, Gavsi Manapur, Nagpur - 441108",
                  ParagraphStyle("c2", fontName="Times-Roman", fontSize=13,
                                 leading=19, alignment=TA_CENTER,
                                 textColor=GOLD)),
    ]
    def bg(canv, doc):
        canv.saveState()
        canv.setFillColor(NAVY)
        canv.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
        canv.restoreState()
    doc = BaseDocTemplate(os.path.join(TMP, "cover.pdf"), pagesize=A4,
                          leftMargin=M_LEFT, rightMargin=M_RIGHT,
                          topMargin=M_TOP, bottomMargin=M_BOT)
    fr = Frame(M_LEFT, M_BOT, TEXT_W, PAGE_H - M_TOP - M_BOT, id="f")
    doc.addPageTemplates([PageTemplate(id="cov", frames=[fr], onPage=bg)])
    doc.build(story)

def build_title_page():
    story = [
        Spacer(1, 0.5 * inch),
        Paragraph("A MACHINE LEARNING-BASED FRAMEWORK FOR<br/>REAL-TIME "
                  "DETECTION OF PROMPT INJECTION ATTACKS<br/>IN "
                  "LLM-INTEGRATED APPLICATIONS",
                  ParagraphStyle("t", fontName="Times-Bold", fontSize=20,
                                 leading=30, alignment=TA_CENTER)),
        Spacer(1, 0.2 * inch),
        Paragraph("in partial fulfillment of the requirements for the award "
                  "of the degree<br/>of Bachelor of Technology in",
                  ParagraphStyle("i", fontName="Times-Italic", fontSize=14,
                                 leading=21, alignment=TA_CENTER)),
        Spacer(1, 0.15 * inch),
        Paragraph("COMPUTER SCIENCE AND ENGINEERING<br/>(CYBER SECURITY)",
                  ParagraphStyle("d", fontName="Times-Bold", fontSize=16,
                                 leading=24, alignment=TA_CENTER)),
        Spacer(1, 0.26 * inch),
        Paragraph("Submitted by",
                  ParagraphStyle("s", fontName="Times-BoldItalic", fontSize=14,
                                 leading=21, alignment=TA_CENTER)),
        Spacer(1, 0.12 * inch),
        Paragraph("%s<br/>%s" % (TEAM[0].upper(), TEAM[1].upper()),
                  ParagraphStyle("n", fontName="Times-Bold", fontSize=16,
                                 leading=26, alignment=TA_CENTER)),
        Spacer(1, 0.18 * inch),
        Paragraph("Under the guidance of",
                  ParagraphStyle("g1", fontSize=14, leading=21,
                                 alignment=TA_CENTER)),
        Spacer(1, 0.08 * inch),
        Paragraph("DR. ABHISHEK D. PATHAK",
                  ParagraphStyle("g2", fontName="Times-Bold", fontSize=16,
                                 leading=22, alignment=TA_CENTER)),
        Paragraph("Assistant Professor",
                  ParagraphStyle("g3", fontSize=14, leading=21,
                                 alignment=TA_CENTER)),
        Spacer(1, 0.16 * inch),
        Paragraph(YEAR,
                  ParagraphStyle("y", fontName="Times-Bold", fontSize=18,
                                 leading=24, alignment=TA_CENTER)),
        Spacer(1, 0.12 * inch),
        Paragraph("Department of Computer Science and Engineering<br/>"
                  "(Cyber Security)",
                  ParagraphStyle("dep", fontName="Times-Bold", fontSize=16,
                                 leading=24, alignment=TA_CENTER)),
        Spacer(1, 0.15 * inch),
        Paragraph("ST. VINCENT PALLOTTI COLLEGE OF ENGINEERING AND TECHNOLOGY",
                  ParagraphStyle("c1", fontName="Times-Bold", fontSize=15,
                                 leading=22, alignment=TA_CENTER)),
        Paragraph("Wardha Road, Gavsi Manapur, Nagpur - 441108",
                  ParagraphStyle("c2", fontSize=13, leading=19,
                                 alignment=TA_CENTER)),
    ]
    doc = BaseDocTemplate(os.path.join(TMP, "title.pdf"), pagesize=A4,
                          leftMargin=M_LEFT, rightMargin=M_RIGHT,
                          topMargin=M_TOP, bottomMargin=M_BOT)
    fr = Frame(M_LEFT, M_BOT, TEXT_W, PAGE_H - M_TOP - M_BOT, id="f")
    doc.addPageTemplates([PageTemplate(id="t", frames=[fr],
                                       onPage=blank_page)])
    doc.build(story)

def cert_page():
    st = ParagraphStyle("cert", fontName=BODY_FONT, fontSize=14, leading=28,
                        alignment=TA_JUSTIFY)
    sign = ParagraphStyle("sig", fontName=BODY_FONT, fontSize=13,
                          leading=18, alignment=TA_LEFT)
    story = [
        Spacer(1, 0.4 * inch),
        Paragraph("<b>CERTIFICATE</b>",
                  ParagraphStyle("ch", fontName="Times-Bold", fontSize=16,
                                 leading=22, alignment=TA_CENTER,
                                 spaceAfter=24)),
        Paragraph('Certified that this project report <b>"%s"</b> is the '
                  "bonafide work of <b>%s</b> and <b>%s</b>, who carried out "
                  "the project work under the supervision of %s in partial "
                  "fulfillment of the requirements for the award of the "
                  "degree of Bachelor of Technology in Computer Science and "
                  "Engineering (Cyber Security) during the %s."
                  % (SHORT_TITLE.title(), TEAM[0], TEAM[1], GUIDE, YEAR), st),
        Spacer(1, 0.9 * inch),
        Table([["", ""]],
              colWidths=[3.0 * inch, 2.6 * inch],
              style=TableStyle([("LINEABOVE", (0, 0), (0, 0), 0.8,
                                 colors.black),
                                ("LINEABOVE", (1, 0), (1, 0), 0.8,
                                 colors.black)])),
        Paragraph("%s<br/>%s<br/>Project Guide<br/>Department of Computer "
                  "Science and Engineering (Cyber Security)" % (GUIDE,
                                                                GUIDE_DESG),
                  sign),
        Spacer(1, 0.35 * inch),
        Table([["", ""]],
              colWidths=[3.0 * inch, 2.6 * inch],
              style=TableStyle([("LINEABOVE", (0, 0), (0, 0), 0.8,
                                 colors.black),
                                ("LINEABOVE", (1, 0), (1, 0), 0.8,
                                 colors.black)])),
        Paragraph("%s<br/>Head of the Department<br/>Computer Science and "
                  "Engineering (Cyber Security)" % HOD, sign),
        Spacer(1, 0.35 * inch),
        Paragraph("PRINCIPAL", sign),
        Spacer(1, 0.3 * inch),
        Paragraph("<b>ST. VINCENT PALLOTTI COLLEGE OF ENGINEERING AND "
                  "TECHNOLOGY</b><br/>Wardha Road, Gavsi Manapur, "
                  "Nagpur - 441108",
                  ParagraphStyle("foot", fontName="Times-Bold", fontSize=13,
                                 leading=19, alignment=TA_CENTER)),
    ]
    return story

def ack_page():
    story = [
        Spacer(1, 0.4 * inch),
        Paragraph("<b>ACKNOWLEDGMENT</b>",
                  ParagraphStyle("ch", fontName="Times-Bold", fontSize=16,
                                 leading=22, alignment=TA_CENTER,
                                 spaceAfter=20)),
        P("We take this opportunity to express our sincere gratitude to all "
          "those who have guided and supported us throughout the course of "
          "this project. We would like to thank <b>%s</b>, our project "
          "guide, for the valuable guidance, encouragement and constructive "
          "feedback provided at every stage, which greatly contributed to "
          "the successful completion of this work. We are also grateful to "
          "<b>Dr. Abhishek D. Pathak</b>, Head of the Department, Computer "
          "Science and Engineering (Cyber Security), for providing the "
          "necessary facilities, resources and motivation to carry out this "
          "project work." % GUIDE, "body"),
        P("We also extend our heartfelt thanks to the faculty members of the "
          "Department of Computer Science and Engineering (Cyber Security), "
          "our classmates and friends for their cooperation, and our "
          "families for their constant support and encouragement. Finally, "
          "we express our gratitude to the Principal and the Management of "
          "St. Vincent Pallotti College of Engineering and Technology, "
          "Nagpur, for providing an excellent environment that made this "
          "project possible.", "body"),
        Spacer(1, 0.5 * inch),
        Paragraph("<b>%s</b><br/><b>%s</b><br/>(B.Tech CSE - Cyber Security, "
                  "%s)" % (TEAM[0], TEAM[1], YEAR), S["centeR"]),
    ]
    return story

ABSTRACT = [
    ("CHAPTER 1: INTRODUCTION",
     'Large Language Models (LLMs) are increasingly embedded in '
     'customer-facing chatbots, coding assistants and autonomous agents, '
     'and these applications pass untrusted user text directly to the '
     'model. The resulting vulnerability, prompt injection, rewrites the '
     'behaviour of the model by natural-language instruction alone. This '
     'chapter introduces the problem, surveys the research literature '
     'between 2024 and 2026, defines the scope of the work and the '
     'hardware and software environment, and identifies the evaluation '
     'gap: most published detectors are validated only on same-dataset '
     'splits rather than on genuinely unseen attack distributions.'),
    ("CHAPTER 2: PROPOSED SYSTEM",
     "The proposed system, PromptShield, is a model-agnostic firewall that "
     "screens every prompt before it reaches any OpenAI-compatible LLM. It "
     "combines a TF-IDF linear classifier (50,039 input features, of which "
     "39 are hand-engineered heuristics) trained on 23,357 public prompt "
     "injection samples, with thresholded verdicts: ALLOW, FLAG (72%) and "
     "BLOCK (74%). The chapter states the objectives of the proposed "
     "system, specifies the user requirements, presents the system "
     "architecture, and reports the evaluation metrics, including a test "
     "verdict accuracy of 98.26% and an AUROC of 0.9987."),
    ("CHAPTER 3: ANALYSIS AND DESIGN",
     "The analysis centres on two relational entities, users and events, "
     "and eight cooperating modules: authentication, the detection engine, "
     "the output firewall, the protected chat application, attack logging, "
     "the security dashboard, automated PDF reporting and a browser "
     "extension that scans prompts inside third-party chat sites and stops "
     "blocked prompts from being sent. Entity relationship and data flow "
     "diagrams and table designs are presented, followed by annotated "
     "screenshots of the working deployment, which caught 30 of 30 "
     "curated red-team attacks and 29 of 29 live stress-test attacks."),
    ("CHAPTER 4: CONCLUSION",
     "The project demonstrates that a lightweight, explainable "
     "TF-IDF-plus-heuristics ensemble provides production-quality prompt "
     "injection defence when paired with an output firewall and "
     "per-account audit trail. Conclusions are drawn on effectiveness, "
     "misuse resistance and deployment cost; future work covers adaptive "
     "attacks, semantic encoders, multilingual coverage and "
     "feedback-assisted retraining; and the limitations of a "
     "lexically driven detector are stated honestly."),
]

def abstract_page():
    story = [
        Spacer(1, 0.3 * inch),
        Paragraph("<b>ABSTRACT</b>",
                  ParagraphStyle("ch", fontName="Times-Bold", fontSize=16,
                                 leading=22, alignment=TA_CENTER,
                                 spaceAfter=16)),
    ]
    for head, text in ABSTRACT:
        story.append(Paragraph("<b>%s</b>" % head, S["nobody"]))
        story.append(Paragraph(text, S["body"]))
    story.append(Spacer(1, 10))
    keywords = ("Keywords: prompt injection, large language models, "
                "TF-IDF, heuristic ensemble, output firewall, AUROC, "
                "browser extension, FastAPI, cyber security.")
    story.append(Paragraph(keywords, S["body"]))
    return story

CH_TITLES = {
    1: "INTRODUCTION",
    2: "PROPOSED SYSTEM",
    3: "ANALYSIS AND DESIGN",
    4: "CONCLUSION",
}

TOC_ROWS = [  # (num, title, sub-list)
    ("", "ABSTRACT", "rom"),
    ("", "LIST OF TABLES", "rom"),
    ("", "LIST OF FIGURES", "rom"),
    ("", "LIST OF SYMBOLS, ABBREVIATIONS AND NOMENCLATURE", "rom"),
    ("1.", CH_TITLES[1], "1"),
    ("1.1", "Introduction of Project", "sub"),
    ("1.2", "Literature Review", "sub"),
    ("1.3", "Scope of Work", "sub"),
    ("1.4", "Operating Environment - Hardware and Software (Technology Used)",
     "sub"),
    ("2.", CH_TITLES[2], "2"),
    ("2.1", "Objectives of Proposed System", "sub"),
    ("2.2", "User Requirements Specification", "sub"),
    ("2.3", "System Architecture", "sub"),
    ("2.4", "Detection Model and Evaluation Metrics", "sub"),
    ("3.", CH_TITLES[3], "3"),
    ("3.1", "Entity Relationship Diagram", "sub"),
    ("3.2", "Module Specification", "sub"),
    ("3.3", "Data Flow Diagrams", "sub"),
    ("3.4", "Table Specification", "sub"),
    ("3.5", "Results (Screenshots with Explanation)", "sub"),
    ("4.", CH_TITLES[4], "4"),
    ("4.1", "Summary of Work (Conclusion)", "sub"),
    ("4.2", "Future Scope", "sub"),
    ("4.3", "Limitations", "sub"),
    ("", "REFERENCES AND BIBLIOGRAPHY", "ref"),
    ("", "PROJECT TEAM INFORMATION", "ref"),
]

TABLES = [
    ("Table 1.1:", "Summary of key literature reviewed for this project"),
    ("Table 1.2:", "Operating environment of the proposed system"),
    ("Table 2.1:", "User requirements specification"),
    ("Table 2.2:", "Evaluation metrics of the detection engine"),
    ("Table 3.1:", "Table specification of the users entity"),
    ("Table 3.2:", "Table specification of the events entity"),
    ("Table 4.1:", "Red-team and stress-test results of the deployed system"),
]

FIGURES = [
    ("Fig. 2.1:", "System architecture of PromptShield"),
    ("Fig. 3.1:", "Entity relationship diagram of the system"),
    ("Fig. 3.2:", "Context level (level 0) data flow diagram"),
    ("Fig. 3.3:", "Level 1 data flow diagram"),
    ("Fig. 3.4:", "Login page"),
    ("Fig. 3.5:", "User registration page"),
    ("Fig. 3.6:", "Detector blocking a direct instruction-override attack"),
    ("Fig. 3.7:", "Protected chatbot demo blocked at the input layer"),
    ("Fig. 3.8:", "Per-user attack dashboard"),
    ("Fig. 3.9:", "Automated daily security report (page 1)"),
    ("Fig. 3.10:", "Automated daily security report (page 2)"),
]

ABBREVS = [
    ("API", "Application Programming Interface"),
    ("AUROC", "Area Under the Receiver Operating Characteristic curve"),
    ("B.Tech", "Bachelor of Technology"),
    ("CDP", "Chrome DevTools Protocol"),
    ("CSV", "Comma Separated Values"),
    ("DB", "Database"),
    ("DFD", "Data Flow Diagram"),
    ("ER", "Entity Relationship"),
    ("FK", "Foreign Key"),
    ("HMAC", "Hash-based Message Authentication Code"),
    ("HTTP", "HyperText Transfer Protocol"),
    ("JSON", "JavaScript Object Notation"),
    ("LLM", "Large Language Model"),
    ("NAACL", "North American Chapter of the Association for "
              "Computational Linguistics"),
    ("NLP", "Natural Language Processing"),
    ("PBKDF2", "Password-Based Key Derivation Function 2"),
    ("PDF", "Portable Document Format"),
    ("PK", "Primary Key"),
    ("RDBMS", "Relational Database Management System"),
    ("ROC", "Receiver Operating Characteristic"),
    ("SDK", "Software Development Kit"),
    ("TF-IDF", "Term Frequency - Inverse Document Frequency"),
    ("UI", "User Interface"),
    ("USENIX", "UNIX Users Group Association Symposium Series"),
    ("UUID", "Universally Unique Identifier"),
    ("WAF", "Web Application Firewall"),
]

def build_body():
    story = []

    # ------------------------------------------------ CHAPTER 1
    story += chapter("1", CH_TITLES[1])
    story.append(P("1.1 INTRODUCTION OF PROJECT", "section"))
    story.append(P(
        "Large Language Models (LLMs), such as GPT and its open-source "
        "competitors, are now embedded in customer support agents, coding "
        "assistants and autonomous web agents. These applications feed "
        "user input, and frequently external content from web pages, "
        "e-mails and PDF documents, directly into the model as "
        "instructions. The design creates a new and largely unsolved "
        "vulnerability: prompt injection, in which an attacker crafts "
        "natural-language input that overrides the original instructions "
        "of the model.", "body"))
    story.append(P(
        "Unlike classical web attacks such as SQL injection, which "
        "exploit rigid and well-defined syntax, prompt injection exploits "
        "natural language itself. There is no fixed grammar to blacklist, "
        "and an attacker can paraphrase, translate or otherwise obfuscate "
        "an attack while preserving its effect on the model. An "
        "injected prompt can cause leakage of confidential system "
        "prompts, redirection of the assistant towards harmful roles, "
        "generation of disallowed content and exfiltration of private "
        "conversation data to attacker-controlled endpoints.", "body"))
    story.append(P(
        'This project, entitled "%s", develops a practical and deployable '
        "defence: a machine-learning firewall, PromptShield, that screens "
        "every prompt before it reaches any LLM. The system issues an "
        "ALLOW, FLAG or BLOCK verdict in milliseconds, re-scores every "
        "model reply with an output firewall, records all events on a "
        "per-user security dashboard and a browser extension extends the "
        "same protection to third-party chat sites such as ChatGPT. The "
        "work includes a rigorous evaluation under realistic conditions "
        "rather than same-dataset accuracy alone."
        % SHORT_TITLE.title(), "body"))

    story.append(P("1.2 LITERATURE REVIEW", "section"))
    story.append(P(
        "The following review covers the key papers consulted for this "
        "project, spanning foundational benchmarks, detection methods "
        "and critical evaluations of the evaluation practices of the "
        "field. Liu et al. [1] formalize prompt injection and release "
        "the Open-Prompt-Injection benchmark, which is now a standard "
        "evaluation dataset in this field. Liu et al. [2] propose "
        "DataSentinel, a game-theoretic detector that models the "
        "interaction between attacker and defender instead of relying on "
        "static pattern matching. Hung et al. [3] present Attention "
        "Tracker, which detects injection by monitoring internal "
        "attention-head behaviour rather than surface text. Li and Liu "
        "[4] identify over-defence in guardrail models and release the "
        "InjecGuard benchmark. Yi et al. [5] benchmark indirect prompt "
        "injection attacks on LLM-integrated applications. Nasr et al. "
        "[6] demonstrate that adaptive attackers move second and can "
        "bypass published defences, which motivates the layered "
        "defence-in-depth design adopted in this project. Jia et al. [7] "
        "localize injected spans; Ji and Li [8] combine pre-trained "
        "models with heuristic feature engineering, the direction "
        "closest to the present work; Wang et al. [9] propose the "
        "GenTel-Safe shielding framework; and further studies address "
        "mixture-of-encodings defences [10], federated detection [11], "
        "and dataset shortcut artefacts [12]. The DeBERTa-based detector "
        "of Protect AI [13] represents the current community baseline "
        "for text-only classification.", "body"))
    story.append(table_cap("Table 1.1: Summary of key literature reviewed "
                           "for this project"))
    story.append(fig_table([
        ["Author(s) / Year", "Venue", "Key contribution"],
        ["Liu et al. (2024) [1]", "USENIX Security",
         "Formal definition of prompt injection; Open-Prompt-Injection "
         "benchmark."],
        ["Liu et al. (2025) [2]", "IEEE S&P",
         "DataSentinel: game-theoretic attack / defence interaction "
         "model."],
        ["Hung et al. (2025) [3]", "NAACL Findings",
         "Attention Tracker: detection through internal attention-head "
         "behaviour."],
        ["Li & Liu (2024) [4]", "arXiv",
         "InjecGuard: benchmarking over-defence in guardrail models."],
        ["Yi et al. (2025) [5]", "ACM SIGKDD",
         "Benchmark and defence against indirect prompt injection on "
         "LLM web applications."],
        ["Nasr et al. (2025) [6]", "arXiv",
         "Adaptive attacker moves second; several published defences are "
         "bypassed."],
        ["Ji & Li (2025) [8]", "arXiv",
         "Pre-trained language model combined with heuristic feature "
         "engineering."],
        ["Wang et al. (2024) [9]", "arXiv",
         "GenTel-Safe: unified benchmark and shielding framework."],
    ], [1.6 * inch, 1.05 * inch, 3.1 * inch]))
    story.append(Spacer(1, 8))
    story.append(P(
        "The literature reviewed above shows that lightweight lexical "
        "classifiers remain competitive for real-time screening, while "
        "model-internal methods require white-box access that "
        "commercially served LLMs do not expose. The gap identified at "
        "the end of the review is that reported accuracies are usually "
        "measured on same-dataset splits; the present work therefore "
        "reports both curated and live red-team results alongside the "
        "distribution-level metrics.", "body"))

    story.append(P("1.3 SCOPE OF WORK", "section"))
    story.append(P("The scope of the present work includes the following "
                   "items.", "body"))
    for b in [
        "Reviewing and categorizing existing prompt injection attack "
        "types: direct instruction override, roleplay jailbreak, system "
        "prompt probing, encoding obfuscation, false-authority claims, "
        "urgency pressure and indirect exfiltration through retrieved "
        "content.",
        "Aggregating public prompt injection corpora into a unified "
        "training set of 23,357 samples and engineering 39 heuristic "
        "features alongside 50,000 TF-IDF features.",
        "Designing a real-time screening service with strict verdict "
        "thresholds (BLOCK at 0.74, FLAG at 0.72) and an output "
        "firewall that re-scores model replies, including a canary-token "
        "leak scan.",
        "Building the surrounding application: authentication with "
        "PBKDF2 password hashing and HMAC-signed sessions, a per-user "
        "attack dashboard with criticality rating, and automated daily, "
        "weekly and monthly PDF reports.",
        "Extending the protection to third-party chat sites (ChatGPT, "
        "Claude, Gemini, Qwen, DeepSeek, Copilot, Mistral and Grok) "
        "through a Manifest V3 browser extension that scans while the "
        "user types and blocks the send action of verdict BLOCK prompts.",
        "Deploying the complete system to a public HTTPS endpoint and "
        "auditing it with curated red-team suites and live "
        "stress-tests.",
    ]:
        story.append(Paragraph(b, S["bullet"], bulletText="\u2022"))
    story.append(P(
        "Out of scope are full multilingual attack corpora, semantic "
        "embedding retraining on on-premise hardware and formal "
        "penetration testing of the host platform, which are identified "
        "as future work.", "body"))

    story.append(P("1.4 OPERATING ENVIRONMENT - HARDWARE AND SOFTWARE "
                   "(TECHNOLOGY USED)", "section"))
    story.append(P(
        "The system is developed on commodity personal hardware and is "
        "deployed as a serverless web application. Table 1.2 lists the "
        "operating environment of the proposed system.", "body"))
    story.append(table_cap("Table 1.2: Operating environment of the "
                           "proposed system"))
    story.append(fig_table([
        ["Component", "Technology used"],
        ["Processor / memory", "Intel Core i5-class laptop CPU, 8 GB RAM "
         "(training); cloud serverless for serving"],
        ["Operating system (development)", "Windows 10 / 11"],
        ["Language", "Python 3.12"],
        ["Core ML libraries", "scikit-learn (TF-IDF and linear "
         "classifier), NumPy, joblib"],
        ["Backend framework", "FastAPI served through a serverless "
         "platform over HTTPS"],
        ["Persistence", "Neon PostgreSQL (cloud) with SQLite fallback"],
        ["Front end", "HTML5, CSS3, vanilla JavaScript"],
        ["Reports", "ReportLab PDF generation"],
        ["Browser protection", "Chrome / Edge Manifest V3 extension "
         "(HTML, CSS, JavaScript)"],
        ["Version control", "Git and GitHub; Vercel for continuous "
         "deployment"],
    ], [2.0 * inch, 3.75 * inch]))
    story.append(Spacer(1, 10))
    story.append(P("Any modern computer with 4 GB RAM or more is capable "
                   "of running the detector at inference time, because "
                   "scoring a prompt requires only a sparse vector "
                   "multiply; training was performed once offline.",
                   "body"))

    # ------------------------------------------------ CHAPTER 2
    story.append(PageBreak())
    story += chapter("2", CH_TITLES[2])
    story.append(P("2.1 OBJECTIVES OF PROPOSED SYSTEM", "section"))
    story.append(P("The proposed system is designed around the following "
                   "objectives.", "body"))
    for b in [
        "To screen every user prompt and generated reply in real time, "
        "before and after the LLM is invoked, at negligible latency.",
        "To produce calibrated, explainable verdicts (ALLOW / FLAG / "
        "BLOCK) with word-level evidence, not merely a binary flag.",
        "To remain model-agnostic, protecting any OpenAI-compatible LLM "
        "endpoint without modification of the provider.",
        "To scope all detection history, dashboards and reports to the "
        "authenticated account, with hashed passwords and signed "
        "sessions.",
        "To quantify robustness honestly: same-distribution metrics "
        "combined with curated red-team suites and live stress tests "
        "against unseen adaptive phrasing.",
        "To make the defence usable in daily practice through a public "
        "deployment and a browser extension for third-party chat "
        "sites.",
    ]:
        story.append(Paragraph(b, S["bullet"], bulletText="\u2022"))

    story.append(P("2.2 USER REQUIREMENTS SPECIFICATION", "section"))
    story.append(P(
        "The functional and non-functional requirements collected from "
        "the target users (students, developers and security auditors "
        "of LLM applications) are listed in Table 2.1.", "body"))
    story.append(table_cap("Table 2.1: User requirements specification"))
    story.append(fig_table([
        ["ID", "Requirement", "Priority"],
        ["FR1", "The user shall create an account and sign in before "
         "using the detector.", "High"],
        ["FR2", "The user shall submit any prompt and receive an "
         "ALLOW / FLAG / BLOCK verdict with an injection score and "
         "word-level highlights.", "High"],
        ["FR3", "The protected chatbot shall refuse to forward a BLOCK "
         "verdict prompt to the LLM.", "High"],
        ["FR4", "Every model reply shall be re-scored and scanned for "
         "canary-token leakage before display.", "High"],
        ["FR5", "The user shall view personal attack history on a "
         "dashboard with criticality and session-risk indicators.",
         "High"],
        ["FR6", "The user shall download daily, weekly and monthly "
         "PDF security reports.", "Medium"],
        ["FR7", "The browser extension shall scan prompts inside "
         "supported chat sites automatically and stop BLOCK-verdict "
         "prompts from being sent.", "Medium"],
        ["NFR1", "Detection latency shall remain below one second per "
         "prompt on commodity hardware.", "High"],
        ["NFR2", "Passwords shall be stored salted and PBKDF2-hashed; "
         "sessions shall be HMAC-signed.", "High"],
        ["NFR3", "The service shall be available over HTTPS on a public "
         "URL.", "High"],
    ], [0.55 * inch, 4.15 * inch, 1.0 * inch]))
    story.append(Spacer(1, 10))

    story.append(P("2.3 SYSTEM ARCHITECTURE", "section"))
    story.append(P(
        "Fig. 2.1 shows the layered architecture. Untrusted text arrives "
        "either from the web front end or, through the browser "
        "extension, from a third-party chat site. The FastAPI "
        "middleware authenticates the session and forwards the text to "
        "the detection engine, whose verdict either blocks the request "
        "locally or permits the completion. Replies are subsequently "
        "passed through the output firewall before display, and all "
        "events are persisted for the dashboard and the automated "
        "reports.", "body"))
    story.append(KeepTogether([
        Image(os.path.join(TMP, "arch.png"),
              width=5.5 * inch, height=3.3 * inch),
        fig_cap("Fig. 2.1: System architecture of PromptShield")]))
    story.append(Spacer(1, 8))

    story.append(P("2.4 DETECTION MODEL AND EVALUATION METRICS", "section"))
    story.append(P(
        "The detection engine is an ensemble of a sparse linear "
        "classifier over TF-IDF character and word n-grams and "
        "39 hand-engineered heuristic features (50,039 features in "
        "total), trained on 23,357 labelled samples aggregated from the "
        "Liu et al. Open-Prompt-Injection corpus, the Jayavibhav corpus "
        "and the deepset prompt injection set. The heuristic features "
        "encode override and roleplay phrases, system-prompt probes, "
        "exfiltration patterns, encoding obfuscation, false-authority "
        "claims, urgency pressure, letter-spelled keywords and fuzzy "
        "matches of known attack phrases, so that a classified verdict "
        "is always traceable to interpretable evidence. Verdicts are "
        "thresholded at 0.72 for FLAG and 0.74 for BLOCK. Table 2.2 "
        "reports the evaluation metrics of the released model.", "body"))
    story.append(table_cap("Table 2.2: Evaluation metrics of the "
                           "detection engine"))
    story.append(fig_table([
        ["Metric", "Value"],
        ["Training samples aggregated", "23,357"],
        ["Input features (TF-IDF + heuristics)", "50,039 (50,000 + 39)"],
        ["Validation AUROC", "0.9987"],
        ["Test AUROC", "0.9987"],
        ["Test verdict accuracy", "98.26%"],
        ["Curated red-team attacks caught", "30 / 30"],
        ["Live stress-test attacks caught", "29 / 29"],
        ["BLOCK threshold / FLAG threshold", "0.74 / 0.72"],
    ], [3.4 * inch, 2.37 * inch]))
    story.append(Spacer(1, 10))

    # ------------------------------------------------ CHAPTER 3
    story.append(PageBreak())
    story += chapter("3", CH_TITLES[3])
    story.append(P("3.1 ENTITY RELATIONSHIP DIAGRAM", "section"))
    story.append(P(
        "The system uses two principal entities. USERS stores "
        "credentials of the registered accounts, and EVENTS stores one "
        "row for every screened prompt or reply. Each EVENTS row "
        "optionally references a USERS row through the user_id foreign "
        "key; anonymous extension scans are computed but not logged. "
        "Fig. 3.1 shows the entity relationship diagram.", "body"))
    story.append(KeepTogether([
        Image(os.path.join(TMP, "erd.png"),
              width=5.5 * inch, height=2.7 * inch),
        fig_cap("Fig. 3.1: Entity relationship diagram of the system")]))
    story.append(Spacer(1, 8))

    story.append(P("3.2 MODULE SPECIFICATION", "section"))
    story.append(P(
        "<b>Module 1: Authentication and session management</b> - "
        "implements account registration and sign-in, salted PBKDF2-HMAC "
        "password hashing with 200,000 iterations, and stateless, "
        "HMAC-signed session cookies with a 30-day validity. Every "
        "page and API resource is gated against the signed session; "
        "signed-out requests to protected APIs receive HTTP 401.",
        "nobody"))
    story.append(P(
        "<b>Module 2: Detection engine</b> - normalizes the input "
        "text, extracts the feature vector (TF-IDF plus 39 heuristics), "
        "scores the injection probability, applies guardrail "
        "post-processing for guardrail-disable and meta-question "
        "patterns, and maps the score to a verdict using the calibrated "
        "thresholds. Word-level highlight spans and a machine-readable "
        "signal dictionary accompany every verdict.", "nobody"))
    story.append(P(
        "<b>Module 3: Output firewall</b> - receives the draft reply of "
        "the chat application, embeds canary tokens in the system "
        "prompt, scans the reply for token leakage and re-runs the "
        "full detector on the reply text so that indirect leaks are "
        "caught even when the input was benign.", "nobody"))
    story.append(P(
        "<b>Module 4: Protected chat application</b> - a multi-turn "
        "chat interface that only forwards prompts that survive the "
        "input screen to the configured OpenAI-compatible provider, "
        "keeps per-conversation session state and blocks disallowed "
        "replies at the output firewall.", "nobody"))
    story.append(P(
        "<b>Module 5: Attack logger</b> - persists every verdict with "
        "timestamp, probability, attack type, criticality rating, "
        "source (input or output), canary flag and session identifier, "
        "scoped to the signed-in account, on PostgreSQL with an "
        "SQLite fallback.", "nobody"))
    story.append(P(
        "<b>Module 6: Security dashboard</b> - aggregates per-user "
        "statistics over a selectable window of 14 to 90 days, "
        "including the taxonomy of attack types, session-risk streaks "
        "and recent events, with criticality categorization.",
        "nobody"))
    story.append(P(
        "<b>Module 7: Report generator</b> - composes daily, weekly "
        "and monthly PDF reports from the logged events, including a "
        "summary verdict distribution and the most severe incidents.",
        "nobody"))
    story.append(P(
        "<b>Module 8: Browser extension (Prompt Injection Guard)</b> - "
        "a Manifest V3 extension, running on the supported chat sites, "
        "that scans the draft prompt while the user types (debounced, "
        "with a floating verdict banner); intercepts the Enter key, the "
        "send button and form submission, and stops prompts whose "
        "cached verdict is BLOCK; benign prompts pass through "
        "untouched using a public, rate-limited scan endpoint.",
        "nobody"))

    story.append(P("3.3 DATA FLOW DIAGRAMS", "section"))
    story.append(P(
        "Fig. 3.2 shows the context-level (level 0) data flow diagram, "
        "and Fig. 3.3 decomposes the system into six processes. The "
        "level-1 processes correspond directly to the modules "
        "specified above; the USERS and EVENTS data stores are shared "
        "by authentication, logging and reporting.", "body"))
    story.append(KeepTogether([
        Image(os.path.join(TMP, "dfd0.png"),
              width=5.5 * inch, height=2.9 * inch),
        fig_cap("Fig. 3.2: Context level (level 0) data flow diagram")]))
    story.append(Spacer(1, 10))
    story.append(KeepTogether([
        Image(os.path.join(TMP, "dfd1.png"),
              width=5.5 * inch, height=3.4 * inch),
        fig_cap("Fig. 3.3: Level 1 data flow diagram")]))
    story.append(Spacer(1, 8))

    story.append(P("3.4 TABLE SPECIFICATION", "section"))
    story.append(P(
        "Tables 3.1 and 3.2 specify the two entities of the database "
        "as created by the application on both SQLite and PostgreSQL.",
        "body"))
    story.append(table_cap("Table 3.1: Table specification of the users "
                           "entity"))
    story.append(fig_table([
        ["Column", "Type", "Constraint"],
        ["id", "TEXT / UUID", "Primary key"],
        ["email", "TEXT", "Unique, not null; indexed"],
        ["name", "TEXT", "Display name of the account"],
        ["pw_hash", "TEXT", "Salted PBKDF2-HMAC digest, 200,000 "
         "iterations"],
        ["created_at", "REAL / DOUBLE PRECISION", "Unix timestamp of "
         "registration"],
    ], [1.3 * inch, 1.7 * inch, 2.75 * inch]))
    story.append(Spacer(1, 8))
    story.append(table_cap("Table 3.2: Table specification of the events "
                           "entity"))
    story.append(fig_table([
        ["Column", "Type", "Description"],
        ["id", "BIGSERIAL / INTEGER", "Primary key"],
        ["ts", "DOUBLE PRECISION", "Unix timestamp of the event"],
        ["verdict", "TEXT", "ALLOW / FLAG / BLOCK"],
        ["probability", "REAL", "Injection probability of the engine"],
        ["attack_type", "TEXT", "Primary attack category"],
        ["criticality", "TEXT", "Low / Medium / High rating"],
        ["source", "TEXT", "input or output (firewall)"],
        ["canary", "INTEGER", "1 when a canary-token leak was detected"],
        ["session_id", "TEXT", "Chat session grouping"],
        ["user_id", "TEXT", "Foreign key to users"],
        ["text", "TEXT", "Screened text"],
        ["signals", "TEXT", "Serialized signal dictionary"],
    ], [1.3 * inch, 1.7 * inch, 2.75 * inch]))
    story.append(Spacer(1, 10))

    story.append(P("3.5 RESULTS (SCREENSHOTS WITH EXPLANATION)", "section"))
    shots = [
        ("login.png", "Fig. 3.4: Login page"),
        ("signup.png", "Fig. 3.5: User registration page"),
        ("detector-block.png", "Fig. 3.6: Detector blocking a direct "
         "instruction-override attack"),
        ("chat-firewall.png", "Fig. 3.7: Protected chatbot demo blocked "
         "at the input layer"),
        ("dashboard.png", "Fig. 3.8: Per-user attack dashboard"),
        ("report-daily-1.png", "Fig. 3.9: Automated daily security "
         "report (page 1)"),
        ("report-daily-2.png", "Fig. 3.10: Automated daily security "
         "report (page 2)"),
    ]
    anecdotes = {
        "login.png": "The application is login-first: detection "
             "history, dashboards and reports are saved to the "
             "authenticated account, so nothing is lost between "
             "sessions.",
        "signup.png": "Registration salts and PBKDF2-hashes the "
             "password (200,000 iterations) and issues the signed "
             "session cookie immediately, without ever storing the "
             "plaintext password.",
        "detector-block.png": "A direct instruction-override attempt is "
             "blocked at 100% injection probability with a BLOCK "
             "verdict; the word-level highlights and the signal "
             "breakdown (override pattern, system-prompt probe) explain "
             "the decision to the user.",
        "chat-firewall.png": "In the protected chatbot demo, a "
             "jailbreak prompt is stopped at the input layer and the "
             "configured LLM is never invoked, so no attacker payload "
             "reaches the model.",
        "dashboard.png": "The security dashboard aggregates the "
             "personal attack history with criticality ratings, the "
             "attack taxonomy and a session-risk streak indicator over "
             "a selectable time window of 14 to 90 days.",
        "report-daily-1.png": "The automated daily report summarizes "
             "the verdict distribution, the severity breakdown and the "
             "top incidents, and is downloadable as a PDF for "
             "documentation and audit purposes.",
        "report-daily-2.png": "The second page of the daily report "
             "lists the individual events with timestamps, verdicts "
             "and probabilities for a complete audit trail.",
    }
    for i, (fname, cap) in enumerate(shots):
        img = ImageReader(os.path.join(SHOTS, fname))
        iw, ih = img.getSize()
        w = 5.4 * inch
        h = w * ih / iw
        if h > 3.5 * inch:
            h = 3.5 * inch
            w = h * iw / ih
        story.append(KeepTogether([
            Image(os.path.join(SHOTS, fname), width=w, height=h),
            fig_cap(cap)]))
        story.append(Paragraph(anecdotes[fname], S["body"]))
        if i < len(shots) - 1:
            story.append(Spacer(1, 10))

    # ------------------------------------------------ CHAPTER 4
    story.append(PageBreak())
    story += chapter("4", CH_TITLES[4])
    story.append(P("4.1 SUMMARY OF WORK (CONCLUSION)", "section"))
    story.append(P(
        "The project demonstrates that a lightweight, explainable "
        "ensemble of a TF-IDF linear classifier and 39 hand-engineered "
        "heuristic features provides production-quality prompt "
        "injection defence when it is paired with an output firewall, "
        "per-account auditing and browser-level protection. The "
        "deployed system achieved a test verdict accuracy of 98.26% "
        "and an AUROC of 0.9987, caught all 30 curated red-team "
        "attacks and 29 of 29 live stress-test attacks, and completes "
        "each screening in milliseconds on commodity hardware.",
        "body"))
    story.append(P(
        "Three contributions stand out from the work. First, the "
        "defence is layered: input screening, output re-scoring with "
        "canary tokens and extension-level send interception together "
        "cover direct, indirect and third-party-site attack surfaces, "
        "which addresses the adaptive-attacker critique of Nasr et al. "
        "[6]. Second, every verdict is accompanied by interpretable "
        "signal evidence, which is a practical requirement for "
        "security review that more opaque deep detectors do not "
        "provide. Third, the evaluation combines distribution-level "
        "metrics from held-out sets with deployment-level results from "
        "live attacks, avoiding the same-dataset accuracy artefacts "
        "criticized in recent benchmark studies [1], [12].", "body"))
    story.append(table_cap("Table 4.1: Red-team and stress-test results "
                           "of the deployed system"))
    story.append(fig_table([
        ["Evaluation", "Result"],
        ["Curated red-team suite", "30 / 30 attacks caught (100%)"],
        ["Live stress test against fresh phrasing", "29 / 29 attacks "
         "caught"],
        ["Test verdict accuracy (held-out set)", "98.26%"],
        ["Test AUROC (held-out set)", "0.9987"],
    ], [3.1 * inch, 1.9 * inch]))
    story.append(Spacer(1, 10))

    story.append(P("4.2 FUTURE SCOPE", "section"))
    story.append(P(
        "The following directions are identified for future work on "
        "separate pages of the final bound report, as required by the "
        "format.", "body"))
    for b in [
        "Adaptive-attack hardening: an adversarial evaluation loop in "
        "which paraphrased and encoded variants of blocked attacks are "
        "generated continuously and used for periodic retraining.",
        "Semantic features: adding sentence-embedding distance to "
        "benign instruction centroids, complementing the lexical "
        "features for paraphrase robustness.",
        "Multilingual coverage: extending the corpora and fuzzy "
        "matchers to Hindi, Marathi and other languages used in "
        "regional deployments.",
        "Extension telemetry: opt-in logging of extension-blocked "
        "attempts into the dashboard of the signed-in account, so that "
        "third-party protection becomes visible in the central audit "
        "trail.",
        "Reinforcement from feedback: allowing flagged-false-positive "
        "and flagged-miss reports from users to trigger supervised "
        "threshold or model updates.",
        "Deployment packaging: containerized on-premise distribution "
        "for organizations that cannot use a public endpoint.",
    ]:
        story.append(Paragraph(b, S["bullet"], bulletText="\u2022"))

    story.append(P("4.3 LIMITATIONS", "section"))
    story.append(P(
        "As a lexically driven detector, the system inherits known "
        "limitations. Highly novel paraphrases outside the training "
        "distribution may score below the threshold until the "
        "heuristic layer or retrained model covers them; the heuristic "
        "signals also assume English-language text, so non-English "
        "attacks reduce recall. The engine evaluates text only "
        "surface-level: it cannot model LLM-internal states, so "
        "attacks that rely on model-specific shopping of context "
        "windows require provider-side cooperation. Finally, the "
        "verdict thresholds are calibrated for the aggregated corpora; "
        "a deployment with a very different traffic mix may need "
        "recalibration through the documented validation protocol.",
        "body"))

    # ------------------------------------------------ REFERENCES
    story.append(PageBreak())
    story.append(Spacer(1, 24))
    story.append(P("REFERENCES", "chapterNum"))
    story.append(P("AND BIBLIOGRAPHY", "chapterTitle"))
    refs = [
        ("[1]", "Liu Y.; Jia Y.; Geng R.; Jia J.; Gong N. Z.; Formalizing "
         "and Benchmarking Prompt Injection Attacks and Defenses; 33rd "
         "USENIX Security Symposium (2024)."),
        ("[2]", "Liu Y.; Jia Y.; Jia J.; Song D.; Gong N. Z.; DataSentinel: "
         "A Game-Theoretic Detection of Prompt Injection Attacks; IEEE "
         "Symposium on Security and Privacy (2025)."),
        ("[3]", "Hung K.-H.; Ko C.-Y.; Rawat A.; Chung I.; Hsu W. H.; Chen "
         "P.-Y.; Attention Tracker: Detecting Prompt Injection Attacks in "
         "LLMs; NAACL 2025 Findings (2024/2025)."),
        ("[4]", "Li H.; Liu X.; InjecGuard: Benchmarking and Mitigating "
         "Over-Defense in Prompt Injection Guardrail Models; arXiv "
         "2410.22770 (2024)."),
        ("[5]", "Yi J.; Xie Y.; Zhu B.; Kiciman E.; Sun G.; Xie X.; Wu F.; "
         "Benchmarking and Defending Against Indirect Prompt Injection "
         "Attacks on Large Language Models; ACM SIGKDD (2025)."),
        ("[6]", "Nasr M.; Carlini N.; Sitawarin C.; Schulhoff S.; Hayes J.; "
         "Ilie M.; et al.; The Attacker Moves Second: Stronger Adaptive "
         "Attacks Bypass Defenses Against LLM Jailbreaks and Prompt "
         "Injections; arXiv 2510.09023 (2025)."),
        ("[7]", "Jia Y.; Liu Y.; Shao Z.; Jia J.; Gong N. Z.; PromptLocate: "
         "Localizing Prompt Injection Attacks; IEEE Symposium on Security "
         "and Privacy (2026)."),
        ("[8]", "Ji Y.; Li R.; Detection Method for Prompt Injection by "
         "Integrating Pre-trained Model and Heuristic Feature "
         "Engineering; arXiv 2506.06384 (2025)."),
        ("[9]", "Wang C.; et al.; GenTel-Safe: A Unified Benchmark and "
         "Shielding Framework for Defending Against Prompt Injection "
         "Attacks; arXiv 2409.19521 (2024/2025)."),
        ("[10]", "Anonymous; Defense against Prompt Injection Attacks via "
         "Mixture of Encodings; arXiv 2504.07467 (2025)."),
        ("[11]", "Anonymous; Privacy-Preserving Prompt Injection Detection "
         "via Federated Learning; arXiv preprint (2025)."),
        ("[12]", "Anonymous; When Benchmarks Lie: Dataset Shortcuts in "
         "Prompt Injection Detection; arXiv preprint (2026)."),
        ("[13]", "Protect AI; Fine-tuned DeBERTa-v3-base for Prompt "
         "Injection Detection; HuggingFace Model Repository (2023)."),
    ]
    for num, txt in refs:
        story.append(Paragraph("%s %s" % (num, txt), S["ref"]))
    story.append(Spacer(1, 14))
    story.append(P(
        "In addition to the literature cited above, the project "
        "consulted the scikit-learn and FastAPI documentation, the "
        "OWASP Top 10 for Large Language Model Applications, and the "
        "research paper prepared by the team during this project, "
        "entitled 'A Machine Learning-Based Framework for Real-Time "
        "Detection of Prompt Injection Attacks in LLM-Integrated "
        "Applications with Cross-Dataset Generalization Evaluation'.",
        "nobody"))

    # ------------------------------------------------ TEAM PAGE
    story.append(PageBreak())
    story.append(Spacer(1, 24))
    story.append(P("PROJECT TEAM", "chapterNum"))
    story.append(P("INFORMATION", "chapterTitle"))
    photo_style = ParagraphStyle("ph", fontName=BODY_FONT, fontSize=10,
                                 alignment=TA_CENTER,
                                 textColor=colors.HexColor("#777777"))
    def photo_cell():
        t = Table([[Paragraph("Passport size<br/>photo", photo_style)]],
                  colWidths=[1.1 * inch], rowHeights=[1.3 * inch])
        t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.8,
                                colors.black)]))
        return t
    team_rows = []
    for member in TEAM:
        team_rows.append([Paragraph("<b>Name</b>",
                                    ParagraphStyle("c", fontName=BODY_FONT,
                                                   fontSize=12)),
                          Paragraph("<b>%s</b>" % member,
                                    ParagraphStyle(
                                        "c2", fontName=BODY_FONT,
                                        fontSize=12)),
                          photo_cell()])
        team_rows.append([Paragraph("Contact No.",
                                    ParagraphStyle("c", fontName=BODY_FONT,
                                                   fontSize=12)),
                          Paragraph("__________________",
                                    ParagraphStyle("c2", fontName=BODY_FONT,
                                                   fontSize=12)),
                          Paragraph("", ParagraphStyle(
                              "c3", fontName=BODY_FONT, fontSize=12))])
        team_rows.append([Paragraph("E-mail ID",
                                    ParagraphStyle("c", fontName=BODY_FONT,
                                                   fontSize=12)),
                          Paragraph("__________________",
                                    ParagraphStyle("c2", fontName=BODY_FONT,
                                                   fontSize=12)),
                          Paragraph("", ParagraphStyle(
                              "c4", fontName=BODY_FONT, fontSize=12))])
    t = Table(team_rows, colWidths=[1.4 * inch, 3.1 * inch, 1.25 * inch])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.6, colors.black),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))
    story.append(P("Project Guide", "subsection"))
    t2 = Table([[Paragraph("<b>Name</b>", ParagraphStyle(
                    "c", fontName=BODY_FONT, fontSize=12)),
                 Paragraph("<b>%s</b> (%s)" % (GUIDE, GUIDE_DESG),
                           ParagraphStyle("c2", fontName=BODY_FONT,
                                          fontSize=12)),
                 photo_cell()]],
               colWidths=[1.4 * inch, 3.1 * inch, 1.25 * inch])
    t2.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.6, colors.black),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(t2)

    doc = BaseDocTemplate(os.path.join(TMP, "body.pdf"), pagesize=A4,
                          leftMargin=M_LEFT, rightMargin=M_RIGHT,
                          topMargin=M_TOP, bottomMargin=M_BOT,
                          title=SHORT_TITLE.title(),
                          author="Yash Chavan, Sohel Sheikh")
    fr = Frame(M_LEFT, M_BOT, TEXT_W, PAGE_H - M_TOP - M_BOT, id="f")
    doc.addPageTemplates([PageTemplate(id="body", frames=[fr],
                                       onPage=numbered_footer("arabic"))])
    doc.build(story)

def find_pages(pdf, needles, min_size=15.5):
    doc = pymupdf.open(pdf)
    out = {}
    for pno, page in enumerate(doc, 1):
        d = page.get_text("dict")
        for block in d["blocks"]:
            for line in block.get("lines", []):
                for span in line["spans"]:
                    txt = span["text"].strip()
                    size = span["size"]
                    if size >= min_size:
                        for ndl, key in needles:
                            if out.get(key) is None and ndl in txt:
                                out[key] = pno
    doc.close()
    return out

def build_front(page_map):
    doc = BaseDocTemplate(os.path.join(TMP, "front.pdf"), pagesize=A4,
                          leftMargin=M_LEFT, rightMargin=M_RIGHT,
                          topMargin=M_TOP, bottomMargin=M_BOT)
    fr = Frame(M_LEFT, M_BOT, TEXT_W, PAGE_H - M_TOP - M_BOT, id="f")
    doc.addPageTemplates([PageTemplate(id="f", frames=[fr],
                                       onPage=numbered_footer("roman"))])

    def centered_header(txt):
        return [Spacer(1, 0.3 * inch),
                Paragraph("<b>%s</b>" % txt,
                          ParagraphStyle("ch", fontName="Times-Bold",
                                         fontSize=16, leading=22,
                                         alignment=TA_CENTER,
                                         spaceAfter=18))]

    toc_style_head = ParagraphStyle("toch", fontName="Times-Bold",
                                    fontSize=14, leading=21)
    toc_style = ParagraphStyle("toc", fontName=BODY_FONT, fontSize=12,
                               leading=21)
    toc_table_rows = []
    for num, title, kind in TOC_ROWS:
        page = page_map.get(title) if title in page_map else None
        if kind == "rom":
            pnum = roman(page) if page else "--"
            left = Paragraph("<b>%s</b>" % title,
                             ParagraphStyle("tocb", fontName="Times-Bold",
                                            fontSize=12, leading=21))
        elif kind == "sub":
            pnum = str(page) if page else "--"
            left = Paragraph("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;%s %s" %
                             (num, title), toc_style)
        else:
            pnum = str(page) if page else "--"
            left = Paragraph("<b>%s %s</b>" % (num.title() if num else "",
                                               title),
                             toc_style_head)
        toc_table_rows.append([left, Paragraph(pnum, toc_style)])
    toc = Table(toc_table_rows, colWidths=[5.0 * inch, 0.75 * inch],
                hAlign="LEFT")
    toc.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    front_story = []
    front_story += cert_page()
    front_story.append(PageBreak())
    front_story += ack_page()
    front_story.append(PageBreak())
    front_story += abstract_page()
    front_story.append(PageBreak())
    front_story += centered_header("CONTENTS")
    front_story.append(toc)
    front_story.append(PageBreak())
    front_story += centered_header("LIST OF TABLES")
    for num, title in TABLES:
        front_story.append(Paragraph(
            "<b>%s</b> %s &nbsp;&nbsp;&nbsp; %s" %
            (num, title, page_map.get(num + " " + title, "--")),
            toc_style))
    front_story.append(PageBreak())
    front_story += centered_header("LIST OF FIGURES")
    for num, title in FIGURES:
        front_story.append(Paragraph(
            "<b>%s</b> %s &nbsp;&nbsp;&nbsp; %s" %
            (num, title, page_map.get(num + " " + title, "--")),
            toc_style))
    front_story.append(PageBreak())
    front_story += centered_header("LIST OF SYMBOLS, ABBREVIATIONS AND "
                                   "NOMENCLATURE")
    for ab, full in ABBREVS:
        front_story.append(Paragraph("<b>%s</b> - %s" % (ab, full),
                                     toc_style))
    doc.build(front_story)

def main():
    # diagrams
    from reportlab.graphics import renderPDF as rp
    for name, drawing in [("arch", make_architecture()), ("erd", make_erd()),
                          ("dfd0", make_dfd0()), ("dfd1", make_dfd1())]:
        pdf_path = os.path.join(TMP, name + ".pdf")
        rp.drawToFile(drawing, pdf_path)
        src = pymupdf.open(pdf_path)
        pix = src[0].get_pixmap(dpi=220)
        pix.save(os.path.join(TMP, name + ".png"))
        src.close()

    build_cover_and_title()
    build_title_page()
    print("pass 1: body")
    build_body()

    # discover heading/caption pages in body.pdf
    ch_needles = [("INTRODUCTION", "INTRODUCTION"),
                  ("PROPOSED SYSTEM", "PROPOSED SYSTEM"),
                  ("ANALYSIS AND DESIGN", "ANALYSIS AND DESIGN"),
                  ("CONCLUSION", "CONCLUSION"),
                  ("REFERENCES", "REFERENCES AND BIBLIOGRAPHY"),
                  ("PROJECT TEAM", "PROJECT TEAM INFORMATION")]
    ch_map = find_pages(os.path.join(TMP, "body.pdf"), ch_needles)
    sec_needles = [("1.1 INTRODUCTION OF PROJECT",
                    "Introduction of Project"),
                   ("1.2 LITERATURE REVIEW", "Literature Review"),
                   ("1.3 SCOPE OF WORK", "Scope of Work"),
                   ("1.4 OPERATING ENVIRONMENT",
                    "Operating Environment - Hardware and Software "
                    "(Technology Used)"),
                   ("2.1 OBJECTIVES OF PROPOSED SYSTEM",
                    "Objectives of Proposed System"),
                   ("2.2 USER REQUIREMENTS SPECIFICATION",
                    "User Requirements Specification"),
                   ("2.3 SYSTEM ARCHITECTURE", "System Architecture"),
                   ("2.4 DETECTION MODEL",
                    "Detection Model and Evaluation Metrics"),
                   ("3.1 ENTITY RELATIONSHIP DIAGRAM",
                    "Entity Relationship Diagram"),
                   ("3.2 MODULE SPECIFICATION", "Module Specification"),
                   ("3.3 DATA FLOW DIAGRAMS", "Data Flow Diagrams"),
                   ("3.4 TABLE SPECIFICATION", "Table Specification"),
                   ("3.5 RESULTS", "Results (Screenshots with "
                                   "Explanation)"),
                   ("4.1 SUMMARY OF WORK", "Summary of Work (Conclusion)"),
                   ("4.2 FUTURE SCOPE", "Future Scope"),
                   ("4.3 LIMITATIONS", "Limitations")]
    sec_map = find_pages(os.path.join(TMP, "body.pdf"), sec_needles,
                         min_size=13.5)    # captions: pymupdf search inside body document (lists are in front)
    body = pymupdf.open(os.path.join(TMP, "body.pdf"))
    def caption_page(caption):
        prefix = caption[:40]
        for pno, page in enumerate(body, 1):
            if page.search_for(prefix):
                return pno
        return None
    tab_pages = {"%s %s" % (num, title): caption_page("%s %s" % (num,
                                                                  title))
                 for num, title in TABLES}
    fig_pages = {"%s %s" % (num, title): caption_page("%s %s" % (num,
                                                                 title))
                 for num, title in FIGURES}
    body.close()
    page_map = {}
    page_map.update(ch_map)
    page_map.update(sec_map)
    page_map.update(tab_pages)
    page_map.update(fig_pages)
    print("page map:", page_map)

    print("pass 2: front matter with real page numbers")
    build_front(page_map)

    out = pymupdf.open()
    for part in ["cover.pdf", "title.pdf", "front.pdf", "body.pdf"]:
        out.insert_pdf(pymupdf.open(os.path.join(TMP, part)))
    out.set_metadata({
        "title": SHORT_TITLE.title(),
        "author": "Yash Chavan, Sohel Sheikh",
        "subject": "B.Tech CSE (Cyber Security) Final Year Project Report",
        "creator": "PromptShield",
    })
    out.save(FINAL, deflate=True)
    print("saved", FINAL, "%.1f KB" % (os.path.getsize(FINAL) / 1024),
          "pages:", out.page_count)

if __name__ == "__main__":
    main()
