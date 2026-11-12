"""A minimal .xlsx reader (an .xlsx file is a zip of XML parts), enough for CryptoAPI-Bench's label sheet.

Standard library only. Cell values are returned as text; a cell whose style is a date format is marked, because
Excel turned some "9,12" line-number cells of the benchmark into dates (their serial numbers are not lines).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
# ECMA-376 Part 1, 18.8.30: built-in number formats that are dates or times.
DATE_FORMAT_IDS = set(range(14, 23)) | set(range(27, 37)) | set(range(45, 48)) | set(range(50, 59))


def _date_styles(styles_xml: bytes | None) -> set[int]:
    """Indices of cellXfs whose number format is a date (built-in id, or a custom code with y/m/d outside quotes)."""
    if not styles_xml:
        return set()
    root = ET.fromstring(styles_xml)
    custom: dict[int, bool] = {}
    for nf in root.iter(f"{NS}numFmt"):
        code = re.sub(r'"[^"]*"|\\.', "", nf.get("formatCode", ""))
        custom[int(nf.get("numFmtId", "0"))] = bool(re.search(r"[ymd]", code, re.I))
    xfs = root.find(f"{NS}cellXfs")
    out = set()
    for i, xf in enumerate(xfs.findall(f"{NS}xf") if xfs is not None else []):
        fid = int(xf.get("numFmtId", "0"))
        if fid in DATE_FORMAT_IDS or custom.get(fid):
            out.add(i)
    return out


def _first_sheet_path(z: zipfile.ZipFile) -> str:
    """The first worksheet in workbook order (workbook.xml + its relationships), not just sheet1.xml by name."""
    rel_ns = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
    pkg_ns = "{http://schemas.openxmlformats.org/package/2006/relationships}"
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    first = wb.find(f"{NS}sheets/{NS}sheet")
    rid = first.get(f"{rel_ns}id") if first is not None else None
    if rid and "xl/_rels/workbook.xml.rels" in z.namelist():
        for rel in ET.fromstring(z.read("xl/_rels/workbook.xml.rels")).iter(f"{pkg_ns}Relationship"):
            if rel.get("Id") == rid:
                target = rel.get("Target", "")
                return target.lstrip("/") if target.startswith("/") else "xl/" + target
    return "xl/worksheets/sheet1.xml"


def read_rows(path: Path) -> list[dict[str, dict]]:
    """Rows of the first worksheet: [{column letter: {"text", "date_styled", "formula"}}], in sheet order."""
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        shared: list[str] = []
        if "xl/sharedStrings.xml" in names:
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall(f"{NS}si"):
                shared.append("".join(t.text or "" for t in si.iter(f"{NS}t")))
        sheet = ET.fromstring(z.read(_first_sheet_path(z)))
        dates = _date_styles(z.read("xl/styles.xml") if "xl/styles.xml" in names else None)
    rows = []
    for row in sheet.iter(f"{NS}row"):
        cells: dict[str, dict] = {}
        for c in row.findall(f"{NS}c"):
            m = re.match(r"[A-Z]+", c.get("r", ""))
            if not m:
                continue
            v, f, kind = c.find(f"{NS}v"), c.find(f"{NS}f"), c.get("t")
            formula = (f.text or "") if f is not None else ""
            if kind == "s" and v is not None:
                text = shared[int(v.text or "0")]
            elif kind == "inlineStr":
                text = "".join(t.text or "" for t in c.iter(f"{NS}t"))
            elif kind == "b" and v is not None:
                text = "TRUE" if (v.text or "").strip() == "1" else "FALSE"
            elif v is not None:
                text = v.text or ""
            else:
                text = ""
            style = c.get("s")
            date_styled = bool(style and int(style) in dates and kind not in ("s", "inlineStr", "b", "str"))
            cells[m.group(0)] = {"text": text.strip(), "date_styled": date_styled, "formula": formula.strip()}
        rows.append(cells)
    return rows


def boolean_cell(cell: dict | None) -> bool | None:
    """TRUE/FALSE as Excel stores it: a boolean cell, a =TRUE()/=FALSE() formula, or the numbers 1/0."""
    if not cell:
        return None
    formula = cell.get("formula", "").upper().replace(" ", "")
    if formula in ("TRUE()", "=TRUE()", "TRUE"):
        return True
    if formula in ("FALSE()", "=FALSE()", "FALSE"):
        return False
    text = cell.get("text", "").upper()
    if text in ("TRUE", "1", "=TRUE()"):
        return True
    if text in ("FALSE", "0", "=FALSE()"):
        return False
    return None
