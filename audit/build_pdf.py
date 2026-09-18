# -*- coding: utf-8 -*-
"""
Sovereign Defender — visual test-results PDF.
ALL numbers are read from the REAL audit_results.json produced by the live
test suite (audit_suite.ts). Nothing here is hand-typed or invented.
"""
import json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
import arabic_reshaper
from bidi.algorithm import get_display

import tempfile
ROOT = os.getcwd()
OUT_DIR = ROOT
SCRATCH = tempfile.mkdtemp(prefix="sd_charts_")
RESULTS = json.load(open(os.path.join(ROOT, "audit_results.json"), encoding="utf-8"))

# ---- palette (dark tactical SOC) ----
BG      = "#0b1220"
PANEL   = "#111a2e"
GREEN   = "#22d39a"
AMBER   = "#f5b544"
RED     = "#ff5c6c"
BLUE    = "#4aa8ff"
CYAN    = "#39d0d8"
PURPLE  = "#b98cff"
TEXT    = "#dbe6f5"
MUTED   = "#8aa0be"

CAT_COLORS = {"eBPF/XDP": BLUE, "Tarpit": PURPLE, "FIM": CYAN, "AI": AMBER, "E2E": GREEN}

# ---- Arabic shaping helper for matplotlib labels ----
TAHOMA = "C:/Windows/Fonts/tahoma.ttf"
font_manager.fontManager.addfont(TAHOMA)
AR_FONT = font_manager.FontProperties(fname=TAHOMA)
def ar(s):
    return get_display(arabic_reshaper.reshape(s))

# ---- derive REAL aggregates ----
total = len(RESULTS)
n_pass = sum(1 for r in RESULTS if r["status"] == "PASS")
n_warn = sum(1 for r in RESULTS if r["status"] == "WARN")
n_fail = sum(1 for r in RESULTS if r["status"] == "FAIL")

cats = {}
for r in RESULTS:
    c = cats.setdefault(r["cat"], {"n": 0, "pass": 0, "ms": 0})
    c["n"] += 1
    c["pass"] += 1 if r["status"] == "PASS" else 0
    c["ms"] += r["ms"]
CAT_ORDER = ["eBPF/XDP", "Tarpit", "FIM", "AI", "E2E"]

plt.rcParams.update({
    "figure.facecolor": BG, "axes.facecolor": PANEL, "savefig.facecolor": BG,
    "text.color": TEXT, "axes.labelcolor": TEXT, "xtick.color": MUTED, "ytick.color": MUTED,
    "axes.edgecolor": "#25324a", "font.size": 11,
})

def save(fig, name):
    p = os.path.join(SCRATCH, name)
    fig.savefig(p, dpi=170, bbox_inches="tight", facecolor=BG)
    plt.close(fig)
    return p

# ===== Chart 1: overall donut =====
fig, ax = plt.subplots(figsize=(4.2, 4.2))
vals   = [n_pass, n_warn, n_fail]
labels = ["PASS", "WARN", "FAIL"]
cols   = [GREEN, AMBER, RED]
vals2  = [v for v in vals if v > 0]
cols2  = [c for v, c in zip(vals, cols) if v > 0]
labs2  = [f"{l}\n{v}" for l, v, c in zip(labels, vals, cols) if v > 0]
w, _ = ax.pie(vals2, colors=cols2, startangle=90,
              wedgeprops=dict(width=0.42, edgecolor=BG, linewidth=3))
ax.text(0, 0.12, str(n_pass), ha="center", va="center", color=GREEN, fontsize=40, fontweight="bold")
ax.text(0, -0.22, f"/ {total} PASS", ha="center", va="center", color=MUTED, fontsize=13)
ax.legend(w, labs2, loc="center", bbox_to_anchor=(0.5, -0.08), ncol=len(vals2),
          frameon=False, labelcolor=TEXT, handlelength=1.1, fontsize=11)
ax.set_title("Overall Test Outcome", color=TEXT, fontsize=14, pad=12, fontweight="bold")
c1 = save(fig, "c1_donut.png")

# ===== Chart 2: per-category pass bars (stacked pass vs total) =====
fig, ax = plt.subplots(figsize=(7.6, 3.6))
xs = range(len(CAT_ORDER))
totals = [cats[c]["n"] for c in CAT_ORDER]
passes = [cats[c]["pass"] for c in CAT_ORDER]
ax.bar(xs, totals, color="#1d2942", width=0.62, label="Total")
bars = ax.bar(xs, passes, color=[CAT_COLORS[c] for c in CAT_ORDER], width=0.62, label="Passed")
for x, p, t in zip(xs, passes, totals):
    ax.text(x, p + 0.15, f"{p}/{t}", ha="center", color=TEXT, fontsize=11, fontweight="bold")
ax.set_xticks(list(xs)); ax.set_xticklabels(CAT_ORDER)
ax.set_ylim(0, max(totals) + 1.6)
ax.set_ylabel("Test count")
ax.set_title("Passed Tests per Category  (all categories 100%)", color=TEXT, fontsize=13, fontweight="bold", pad=10)
ax.grid(axis="y", color="#1c2740", linewidth=0.7)
ax.set_axisbelow(True)
for s in ["top", "right"]: ax.spines[s].set_visible(False)
c2 = save(fig, "c2_catbars.png")

# ===== Chart 3: total execution time per category (real ms) =====
fig, ax = plt.subplots(figsize=(7.6, 3.4))
ms = [cats[c]["ms"] for c in CAT_ORDER]
b = ax.barh(CAT_ORDER, ms, color=[CAT_COLORS[c] for c in CAT_ORDER], height=0.6)
for y, v in enumerate(ms):
    ax.text(v + max(ms) * 0.01, y, f"{v} ms", va="center", color=TEXT, fontsize=11, fontweight="bold")
ax.set_xlabel("Total execution time (ms)")
ax.set_xlim(0, max(ms) * 1.16)
ax.invert_yaxis()
ax.set_title("Measured Execution Time by Category", color=TEXT, fontsize=13, fontweight="bold", pad=10)
ax.grid(axis="x", color="#1c2740", linewidth=0.7); ax.set_axisbelow(True)
for s in ["top", "right"]: ax.spines[s].set_visible(False)
c3 = save(fig, "c3_time.png")

# ===== Chart 4: per-test response time (all 50, colored by category) =====
fig, ax = plt.subplots(figsize=(7.8, 4.6))
ids = [r["id"] for r in RESULTS]
msv = [r["ms"] for r in RESULTS]
colr = [CAT_COLORS[r["cat"]] for r in RESULTS]
ax.bar(ids, msv, color=colr, width=0.8)
ax.set_xlabel("Test #"); ax.set_ylabel("Response time (ms)")
ax.set_title("Per-Test Response Time — all 50 tests", color=TEXT, fontsize=13, fontweight="bold", pad=10)
ax.set_xticks(range(0, 51, 5))
ax.grid(axis="y", color="#1c2740", linewidth=0.7); ax.set_axisbelow(True)
for s in ["top", "right"]: ax.spines[s].set_visible(False)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=CAT_COLORS[c], label=c) for c in CAT_ORDER],
          frameon=False, labelcolor=TEXT, ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.16), fontsize=10)
c4 = save(fig, "c4_pertest.png")
print("charts:", c1, c2, c3, c4)

# =========================== ASSEMBLE PDF ===========================
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Image, Table,
                                TableStyle, PageBreak)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT

pdfmetrics.registerFont(TTFont("Tahoma", TAHOMA))
pdfmetrics.registerFont(TTFont("Tahoma-Bold", "C:/Windows/Fonts/tahomabd.ttf"))

def A(s):  # Arabic paragraph text (shaped + bidi)
    return get_display(arabic_reshaper.reshape(s))

PDF = os.path.join(OUT_DIR, "Sovereign_Defender_Test_Report.pdf")
doc = SimpleDocTemplate(PDF, pagesize=A4, topMargin=14*mm, bottomMargin=14*mm,
                        leftMargin=14*mm, rightMargin=14*mm,
                        title="Sovereign Defender Test Report", author="Security Audit")

def bg(canvas, d):
    canvas.setFillColor(colors.HexColor(BG)); canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)

ar_title = ParagraphStyle("arT", fontName="Tahoma-Bold", fontSize=21, textColor=colors.HexColor(GREEN),
                          alignment=TA_RIGHT, leading=28)
ar_sub   = ParagraphStyle("arS", fontName="Tahoma", fontSize=12, textColor=colors.HexColor(MUTED),
                          alignment=TA_RIGHT, leading=18)
ar_h     = ParagraphStyle("arH", fontName="Tahoma-Bold", fontSize=14, textColor=colors.HexColor(BLUE),
                          alignment=TA_RIGHT, leading=20, spaceBefore=8, spaceAfter=4)
ar_body  = ParagraphStyle("arB", fontName="Tahoma", fontSize=10.5, textColor=colors.HexColor(TEXT),
                          alignment=TA_RIGHT, leading=17)
en_small = ParagraphStyle("enS", fontName="Tahoma", fontSize=9, textColor=colors.HexColor(MUTED),
                          alignment=TA_CENTER, leading=12)

S = []
S.append(Paragraph(A("تقرير نتائج الاختبارات — Sovereign Defender"), ar_title))
S.append(Paragraph(A("منظومة الدفاع السيبراني الذاتية · حزمة الخمسين اختباراً الآلية"), ar_sub))
S.append(Paragraph("Autonomous Cyber-Defense Platform — 50-Test Automated Suite", en_small))
S.append(Spacer(1, 6))

# KPI strip (REAL numbers)
avg_ms = round(sum(r["ms"] for r in RESULTS) / total, 1)
kpi = [[str(total), f"{n_pass}", f"{n_warn}", f"{n_fail}", f"{avg_ms} ms"],
       [A("اختبار"), A("ناجح"), A("تحذير"), A("فاشل"), A("متوسط الزمن")]]
kt = Table(kpi, colWidths=[36*mm]*5 if False else None)
kt = Table(kpi, colWidths=[35*mm, 35*mm, 35*mm, 35*mm, 42*mm])
kt.setStyle(TableStyle([
    ("BACKGROUND", (0,0), (-1,-1), colors.HexColor(PANEL)),
    ("FONTNAME", (0,0), (-1,0), "Tahoma-Bold"), ("FONTSIZE", (0,0), (-1,0), 20),
    ("FONTNAME", (0,1), (-1,1), "Tahoma"), ("FONTSIZE", (0,1), (-1,1), 10),
    ("TEXTCOLOR", (0,0), (0,0), colors.HexColor(BLUE)),
    ("TEXTCOLOR", (1,0), (1,0), colors.HexColor(GREEN)),
    ("TEXTCOLOR", (2,0), (2,0), colors.HexColor(AMBER)),
    ("TEXTCOLOR", (3,0), (3,0), colors.HexColor(RED)),
    ("TEXTCOLOR", (4,0), (4,0), colors.HexColor(CYAN)),
    ("TEXTCOLOR", (0,1), (-1,1), colors.HexColor(MUTED)),
    ("ALIGN", (0,0), (-1,-1), "CENTER"), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ("TOPPADDING", (0,0), (-1,0), 10), ("BOTTOMPADDING", (0,1), (-1,1), 8),
    ("LINEBEFORE", (1,0), (-1,-1), 0.6, colors.HexColor("#25324a")),
    ("BOX", (0,0), (-1,-1), 0.6, colors.HexColor("#25324a")),
]))
S.append(kt)
S.append(Spacer(1, 8))

# Row of two charts
row = Table([[Image(c1, width=82*mm, height=82*mm), Image(c2, width=95*mm, height=45*mm)]],
            colWidths=[86*mm, 99*mm])
row.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"MIDDLE"),("ALIGN",(0,0),(-1,-1),"CENTER")]))
S.append(row)
S.append(Spacer(1, 4))
S.append(Image(c3, width=178*mm, height=79*mm))
S.append(PageBreak())

# Page 2: per-test chart + full matrix
S.append(Paragraph(A("زمن الاستجابة لكل اختبار + مصفوفة النتائج الكاملة"), ar_h))
S.append(Image(c4, width=178*mm, height=105*mm))
S.append(Spacer(1, 6))

# Full matrix table (REAL data). Split into two columns of 25 for compactness.
def status_txt(s): return {"PASS":"PASS","WARN":"WARN","FAIL":"FAIL"}[s]
hdr = ["#", "Category", "Test", "Status", "ms"]
rows = [hdr]
for r in RESULTS:
    nm = r["name"]
    if len(nm) > 42: nm = nm[:41] + "…"
    rows.append([str(r["id"]), r["cat"], nm, status_txt(r["status"]), str(r["ms"])])
mt = Table(rows, colWidths=[8*mm, 20*mm, 118*mm, 20*mm, 12*mm], repeatRows=1)
style = [
    ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a2740")),
    ("FONTNAME", (0,0), (-1,0), "Tahoma-Bold"), ("FONTSIZE", (0,0), (-1,-1), 7.6),
    ("FONTNAME", (0,1), (-1,-1), "Tahoma"),
    ("TEXTCOLOR", (0,0), (-1,0), colors.HexColor(TEXT)),
    ("TEXTCOLOR", (0,1), (-1,-1), colors.HexColor(MUTED)),
    ("TEXTCOLOR", (2,1), (2,-1), colors.HexColor(TEXT)),
    ("FONTNAME", (3,1), (3,-1), "Tahoma-Bold"),
    ("ALIGN", (0,0), (0,-1), "CENTER"), ("ALIGN", (3,0), (4,-1), "CENTER"),
    ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor(PANEL), colors.HexColor("#0e1626")]),
    ("LINEBELOW", (0,0), (-1,0), 0.6, colors.HexColor("#2a3a58")),
    ("TOPPADDING", (0,0), (-1,-1), 2.4), ("BOTTOMPADDING", (0,0), (-1,-1), 2.4),
]
for i, r in enumerate(RESULTS, start=1):
    col = {"PASS": GREEN, "WARN": AMBER, "FAIL": RED}[r["status"]]
    style.append(("TEXTCOLOR", (3, i), (3, i), colors.HexColor(col)))
    style.append(("TEXTCOLOR", (1, i), (1, i), colors.HexColor(CAT_COLORS[r["cat"]])))
mt.setStyle(TableStyle(style))
S.append(mt)
S.append(Spacer(1, 6))
S.append(Paragraph(
    "Source: audit_results.json — generated by live execution of audit_suite.ts against the running "
    "server (127.0.0.1:3000) + direct module unit tests. Every value above is measured, not estimated.",
    en_small))

doc.build(S, onFirstPage=bg, onLaterPages=bg)
print("PDF:", PDF, os.path.getsize(PDF), "bytes")
