# -*- coding: utf-8 -*-
"""Build the editable Word (.docx) version of the project report.

Reuses the exact content of build_thesis.py by monkey-patching
BaseDocTemplate.build so the platypus stories are captured instead of
rendered, then converts each flowable (Paragraph / Table / Image /
Spacer / PageBreak / KeepTogether) into python-docx members.

Format: A4, 1"/1"/1.5"/1" margins, Times New Roman 12, 1.5 line
spacing, justified body; cover + title (unnumbered), front matter
(lower-case Roman page numbers), body (Arabic, restarting at 1).

Output: docs/thesis/Prompt_Injection_Detector_Project_Report.docx
"""
import os
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import build_thesis as bt

from docx import Document
from docx.shared import Pt, Inches, RGBColor, Emu
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

ROOT = bt.ROOT
OUT = os.path.join(ROOT, "docs", "thesis",
                   "Prompt_Injection_Detector_Project_Report.docx")

# --------------------------------------------------------------- capture
CAPTURED = []


def _capture_build(self, story, *args, **kwargs):
    CAPTURED.append(list(story))


bt.BaseDocTemplate.build = _capture_build


def capture_stories():
    bt.build_cover_and_title()
    bt.build_title_page()
    bt.build_body()

    # page map, same logic as build_thesis.main() but reusing the
    # _parts/*.pdf left behind by the last real PDF build
    ch_needles = [("INTRODUCTION", "INTRODUCTION"),
                  ("PROPOSED SYSTEM", "PROPOSED SYSTEM"),
                  ("ANALYSIS AND DESIGN", "ANALYSIS AND DESIGN"),
                  ("CONCLUSION", "CONCLUSION"),
                  ("REFERENCES", "REFERENCES AND BIBLIOGRAPHY"),
                  ("PROJECT TEAM", "PROJECT TEAM INFORMATION")]
    sec_needles = [("1.1 INTRODUCTION OF PROJECT", "Introduction of Project"),
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
    ch_map = bt.find_pages(os.path.join(bt.TMP, "body.pdf"), ch_needles)
    sec_map = bt.find_pages(os.path.join(bt.TMP, "body.pdf"), sec_needles,
                            min_size=13.5)
    body = bt.pymupdf.open(os.path.join(bt.TMP, "body.pdf"))

    def caption_page(caption):
        prefix = caption[:40]
        for pno, page in enumerate(body, 1):
            if page.search_for(prefix):
                return pno
        return None

    tab_pages = {}
    fig_pages = {}
    for num, title in bt.TABLES:
        cap = "%s %s" % (num, title)
        tab_pages[cap] = caption_page(cap)
    for num, title in bt.FIGURES:
        cap = "%s %s" % (num, title)
        fig_pages[cap] = caption_page(cap)
    body.close()

    front_needles = [("ABSTRACT", "ABSTRACT"),
                     ("LIST OF TABLES", "LIST OF TABLES"),
                     ("LIST OF FIGURES", "LIST OF FIGURES"),
                     ("LIST OF SYMBOLS",
                      "LIST OF SYMBOLS, ABBREVIATIONS AND NOMENCLATURE")]
    fmap = bt.find_pages(os.path.join(bt.TMP, "front.pdf"), front_needles)

    page_map = {}
    page_map.update(ch_map)
    page_map.update(sec_map)
    page_map.update(tab_pages)
    page_map.update(fig_pages)
    page_map.update({k: bt.roman(v) for k, v in fmap.items()})

    bt.build_front(page_map)
    return CAPTURED


# --------------------------------------------------------------- helpers
TAG_RE = re.compile(r"(<[^>]+>)")

ENTITIES = {"&nbsp;": "\u00a0", "&amp;": "&", "&lt;": "<", "&gt;": ">",
            "&apos;": "'", "&quot;": '"'}


def _unent(s):
    for k, v in ENTITIES.items():
        s = s.replace(k, v)
    return re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), s)


def add_markup(par, text, base_size=None, base_color=None):
    """Append reportlab-style inline markup to a python-docx paragraph."""
    state = {"b": False, "i": False, "u": False, "sub": False, "sup": False}
    color = base_color
    for tok in TAG_RE.split(text):
        if not tok:
            continue
        if tok.startswith("<"):
            tag = tok.lower()
            if tag in ("<br/>", "<br>"):
                par.add_run().add_break()
                continue
            if tag in ("</b>", "</i>", "</u>", "</sub>", "</sup>",
                       "</strength>"):
                key = {"</b>": "b", "</i>": "i", "</u>": "u",
                       "</sub>": "sub", "</sup>": "sup"}[tag]
                state[key] = False
                continue
            if tag.startswith("</font"):
                color = base_color
                continue
            if tag.startswith("<sub"):
                state["sub"] = True
            elif tag.startswith("<sup"):
                state["sup"] = True
            elif tag.startswith("<u"):
                state["u"] = True
            elif tag.startswith("<i"):
                state["i"] = True
            elif tag.startswith("<b"):
                state["b"] = True
            elif tag.startswith("<font"):
                m = re.search(r'color\s*=\s*"?([#0-9a-zA-Z]+)"?', tag)
                if m:
                    cv = m.group(1)
                    try:
                        color = cv if cv.startswith("#") else "#" + cv
                    except ValueError:
                        color = base_color
            continue
        txt = _unent(tok)
        if not txt.strip():
            # keep spaces but avoid empty runs making odd breaks
            par.add_run(txt)
            continue
        run = par.add_run(txt)
        if state["b"]:
            run.bold = True
        if state["i"]:
            run.italic = True
        if state["u"]:
            run.underline = True
        if state["sub"]:
            run.font.subscript = True
        if state["sup"]:
            run.font.superscript = True
        if color:
            run.font.color.rgb = hexrgb(color)
    return par


def hexrgb(c):
    if isinstance(c, RGBColor):
        return c
    if not c.startswith("#"):
        c = "#" + c
    if len(c) == 7:
        return RGBColor(int(c[1:3], 16), int(c[3:5], 16), int(c[5:7], 16))
    return RGBColor(0, 0, 0)


def hl_color(reportlab_color):
    """reportlab Color -> docx RGBColor, or None."""
    if reportlab_color is None:
        return None
    return RGBColor(int(round(reportlab_color.red * 255)),
                    int(round(reportlab_color.green * 255)),
                    int(round(reportlab_color.blue * 255)))


def set_section(section, fmt=None, start=None, footer=True):
    if fmt or start:
        sectPr = section._sectPr
        pg = sectPr.find(qn("w:pgNumType"))
        if pg is None:
            pg = OxmlElement("w:pgNumType")
            sectPr.append(pg)
        if fmt:
            pg.set(qn("w:fmt"), fmt)
        if start is not None:
            pg.set(qn("w:start"), str(start))
    section.footer.is_linked_to_previous = False
    p = section.footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    if footer:
        r = p.add_run()
        el = r._r
        f1 = OxmlElement("w:fldChar")
        f1.set(qn("w:fldCharType"), "begin")
        instr = OxmlElement("w:instrText")
        instr.set(qn("xml:space"), "preserve")
        instr.text = " PAGE "
        f2 = OxmlElement("w:fldChar")
        f2.set(qn("w:fldCharType"), "end")
        el.append(f1)
        el.append(instr)
        el.append(f2)
        r.font.name = "Times New Roman"
        r.font.size = Pt(12)


def style_par(par, st):
    """Apply a reportlab ParagraphStyle to a docx paragraph."""
    pf = par.paragraph_format
    pf.line_spacing = Pt(st.leading)
    pf.space_after = Pt(st.spaceAfter)
    pf.space_before = Pt(getattr(st, "spaceBefore", 0) or 0)
    al = getattr(st, "alignment", None)
    if al == bt.TA_JUSTIFY:
        pf.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    elif al == bt.TA_CENTER:
        pf.alignment = WD_ALIGN_PARAGRAPH.CENTER
    else:
        pf.alignment = WD_ALIGN_PARAGRAPH.LEFT
    if getattr(st, "firstLineIndent", 0):
        pf.first_line_indent = Pt(st.firstLineIndent)
    if getattr(st, "leftIndent", 0):
        pf.left_indent = Pt(st.leftIndent)
    if getattr(st, "rightIndent", 0):
        pf.right_indent = Pt(st.rightIndent)
    bold = "Bold" in st.fontName
    return bold


def docx_paragraph(pflow):
    doc = _DOC
    st = pflow.style
    name = st.name
    par = doc.add_paragraph()
    bold_base = style_par(par, st)
    color = hl_color(getattr(st, "textColor", None))
    add_markup(par, pflow.text, base_size=st.fontSize, base_color=color)
    # normalize runs' font size
    for run in par.runs:
        run.font.name = "Times New Roman"
        run.font.size = Pt(st.fontSize)
        if "Bold" in st.fontName and run.bold is None:
            run.bold = True
        if run.bold is None:
            run.bold = False
    if name == "chapterNum":
        par.style = _DOC.styles["Heading 1"]
        par.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif name == "chapterTitle":
        par.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif name == "section":
        par.style = _DOC.styles["Heading 2"]
    elif name == "subsection":
        par.style = _DOC.styles["Heading 3"]
    elif name == "ref":
        pf = par.paragraph_format
        pf.left_indent = Pt(25)
        pf.first_line_indent = Pt(-25)
    # bullets keep their indent; everything else styled by style_par
    return par


def img_path(img):
    fn = getattr(img, "filename", None)
    if fn and os.path.exists(fn):
        return fn
    fn2 = getattr(img, "_filePath", None) or getattr(img, "_file", None)
    if isinstance(fn2, str) and os.path.exists(fn2):
        return fn2
    return None


def docx_table(tbl):
    cells = getattr(tbl, "_cellvalues", None)
    if cells is None:
        return
    widths = [w for w in (getattr(tbl, "_argW", None) or [])]
    ncols = max(len(r) for r in cells)
    sig_only = all((c == "" or c is None) for row in cells for c in row)
    if sig_only:
        # signature rule lines in the certificate -> underscore rules
        wsum = sum(w for w in widths if w) or 300
        par = _DOC.add_paragraph()
        n = int(wsum / 72 * 12)
        par.add_run("_" * max(10, n)).font.name = "Times New Roman"
        return
    t = _DOC.add_table(rows=len(cells), cols=ncols)
    t.style = _DOC.styles["Table Grid"]
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for row in cells:
        if len(row) < ncols:
            row += [""] * (ncols - len(row))
    for i, row in enumerate(cells):
        for j, c in enumerate(row):
            cell = t.cell(i, j)
            cp = cell.paragraphs[0]
            if j < len(widths) and widths[j]:
                try:
                    cell.width = Emu(int(widths[j] * 12700))
                except Exception:
                    pass
            if isinstance(c, bt.Paragraph):
                st = c.style
                cp.paragraph_format.space_after = Pt(2)
                cp.paragraph_format.line_spacing = Pt(st.fontSize * 1.15)
                add_markup(cp, c.text,
                           base_color=hl_color(
                               getattr(st, "textColor", None)))
                for run in cp.runs:
                    run.font.name = "Times New Roman"
                    run.font.size = Pt(st.fontSize - 1)
                    if "Bold" in st.fontName:
                        run.bold = True
            else:
                txt = _unent(str(c))
                cp.add_run(txt)
                for run in cp.runs:
                    run.font.name = "Times New Roman"
                    run.font.size = Pt(11)
                    if i == 0:
                        run.bold = True
    _DOC.add_paragraph()


def walk(flowables):
    for f in flowables:
        cls = f.__class__.__name__
        if isinstance(f, bt.KeepTogether):
            walk(f._content)
        elif isinstance(f, bt.Paragraph):
            docx_paragraph(f)
        elif isinstance(f, bt.Image):
            path = img_path(f)
            if path:
                w = getattr(f, "width", None)
                par = _DOC.add_paragraph()
                par.alignment = WD_ALIGN_PARAGRAPH.CENTER
                run = par.add_run()
                run.add_picture(path,
                                width=Emu(int(w * 12700)) if w else None)
            else:
                print("WARN: image path not found ->", f)
        elif isinstance(f, bt.Table):
            docx_table(f)
        elif isinstance(f, bt.Spacer):
            par = _DOC.add_paragraph()
            par.paragraph_format.line_spacing = Pt(min(f.height, 24))
            par.paragraph_format.space_after = Pt(0)
            if f.height == 0:
                par.add_run(" ")  # keep the spacer line
        elif isinstance(f, bt.PageBreak):
            _DOC.add_page_break()
        elif isinstance(f, bt.NextPageTemplate):
            pass
        else:
            print("WARN: unhandled flowable", cls)


_DOC = None


def main():
    global _DOC
    cover, title, body, front = capture_stories()
    doc = Document()
    _DOC = doc

    # Normal style: Times New Roman 12
    st = doc.styles["Normal"]
    st.font.name = "Times New Roman"
    st.font.size = Pt(12)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")
    # Tidy Heading styles to match the college format
    for hname, size, centre in (("Heading 1", 16, True),
                                ("Heading 2", 14, False),
                                ("Heading 3", 12, False)):
        h = doc.styles[hname]
        h.font.name = "Times New Roman"
        h.font.size = Pt(size)
        h.font.bold = True
        h.font.color.rgb = RGBColor(0, 0, 0)
        h.element.rPr.rFonts.set(qn("w:eastAsia"), "Times New Roman")

    s = doc.sections[0]
    s.page_width = Emu(int(bt.PAGE_W * 12700))
    s.page_height = Emu(int(bt.PAGE_H * 12700))
    s.top_margin = Emu(int(bt.M_TOP * 12700))
    s.bottom_margin = Emu(int(bt.M_BOT * 12700))
    s.left_margin = Emu(int(bt.M_LEFT * 12700))
    s.right_margin = Emu(int(bt.M_RIGHT * 12700))
    set_section(s, footer=False)          # cover + title: unnumbered
    walk(cover)
    walk(title)

    s2 = doc.add_section(WD_SECTION.NEW_PAGE)
    set_section(s2, fmt="lowerRoman", start=1)     # front matter
    walk(front)

    s3 = doc.add_section(WD_SECTION.NEW_PAGE)
    set_section(s3, fmt="decimal", start=1)        # body, restart at 1
    walk(body)

    cp = doc.core_properties
    cp.title = bt.TITLE_MIXED
    cp.author = ", ".join(bt.TEAM)
    cp.subject = "B.Tech CSE (Cyber Security) Final Year Project Report"
    doc.save(OUT)
    print("saved", OUT, "%.1f KB"
          % (os.path.getsize(OUT) / 1024))


if __name__ == "__main__":
    main()
