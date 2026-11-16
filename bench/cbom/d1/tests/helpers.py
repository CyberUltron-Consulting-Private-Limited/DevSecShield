"""Small builders for hermetic lane tests (no network, no product)."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

D1 = Path(__file__).resolve().parents[1]
REPO = D1.parents[2]
NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'


def write_xlsx(path: Path, rows: list[list[tuple]]) -> None:
    """rows: [[(column, kind, value, style)], ...]; kind: s (shared string), n (number), f (formula TRUE/FALSE)."""
    shared: list[str] = []
    xml_rows = []
    for i, row in enumerate(rows, start=1):
        cells = []
        for col, kind, value, style in row:
            s = f' s="{style}"' if style is not None else ""
            ref = f"{col}{i}"
            if kind == "s":
                shared.append(str(value))
                cells.append(f'<c r="{ref}" t="s"{s}><v>{len(shared) - 1}</v></c>')
            elif kind == "f":
                cells.append(f'<c r="{ref}" t="b"{s}><f>{value}()</f><v>{1 if value == "TRUE" else 0}</v></c>')
            else:
                cells.append(f'<c r="{ref}"{s}><v>{value}</v></c>')
        xml_rows.append(f'<row r="{i}">{"".join(cells)}</row>')
    sst = "".join(f"<si><t>{x}</t></si>" for x in shared)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/workbook.xml", f'<workbook {NS} xmlns:r="http://schemas.openxmlformats.org/officeDocument/'
                                      f'2006/relationships"><sheets><sheet name="V" sheetId="1" r:id="rId1"/></sheets>'
                                      f'</workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Target="worksheets/sheet1.xml" Type="ws"/></Relationships>')
        z.writestr("xl/sharedStrings.xml", f"<sst {NS}>{sst}</sst>")
        z.writestr("xl/styles.xml", f'<styleSheet {NS}><numFmts><numFmt numFmtId="164" formatCode="m/d/yyyy"/>'
                                    f'</numFmts><cellXfs><xf numFmtId="0"/><xf numFmtId="164"/><xf numFmtId="14"/>'
                                    f'</cellXfs></styleSheet>')
        z.writestr("xl/worksheets/sheet1.xml", f"<worksheet {NS}><sheetData>{''.join(xml_rows)}</sheetData></worksheet>")


def row(location: str, line: int | None, codes: list[str], algorithm: str = "", occurrences=None) -> dict:
    return {"location": location, "line": line, "occurrences": occurrences or ([line] if line else []),
            "codes": codes, "algorithm": algorithm, "asset_type": None}


def case(bench: str, cid: str, files: list[str], category: str, lane_category: str, vulnerable: bool, **kw) -> dict:
    return {"bench": bench, "case_id": cid, "files": files, "category": category, "lane_category": lane_category,
            "vulnerable": vulnerable, **kw}


def make_work(tmp: Path, benches: dict[str, tuple[list[dict], list[dict]]], libraries=None, osv=None) -> Path:
    """A work directory as `d1.py prepare` + `product` leave it: cases/<bench>.json, observed/<bench>.json, osv.json."""
    for bench, (cases, rows) in benches.items():
        src = {"scan_tree": {"sha256": f"tree-{bench}", "files": 1}}
        cdoc = {"schema": "zs-cbom-d1-cases/1", "bench": bench, "source": src,
                "labels": {"excluded": [], "anomalies": []}, "cases": cases}
        if bench == "corpus":
            cdoc["libraries"] = libraries or []
        (tmp / "cases").mkdir(parents=True, exist_ok=True)
        (tmp / "observed").mkdir(parents=True, exist_ok=True)
        (tmp / "cases" / f"{bench}.json").write_text(json.dumps(cdoc))
        (tmp / "observed" / f"{bench}.json").write_text(json.dumps({
            "schema": "zs-cbom-d1-observed/1", "bench": bench, "rows": rows,
            "product": {"entry": "test", "level": 4, "git_sha": "0" * 40, "kb_version": "t",
                        "scan_tree_sha256": f"tree-{bench}"}}))
    (tmp / "osv.json").write_text(json.dumps(osv or {"schema": "zs-cbom-d1-osv/1", "answers": {}, "error": None,
                                                      "asked_at": "2026-11-12T00:00:00Z"}))
    return tmp


def floors_doc(floors: list[dict]) -> dict:
    return {"schema": "zs-cbom-d1-floors/1", "version": 1, "floors": floors}
