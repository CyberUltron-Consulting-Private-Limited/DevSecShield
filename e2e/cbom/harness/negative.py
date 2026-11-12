"""Negative controls: deliberately wrong CBOMs that the gate must FAIL, on real evidence (review 5874859738).

    python3 -m harness.negative <run> [--ledger L] [--cases a,b,...] [--keep DIR]

For each case: a hardlinked copy of the run directory (a file is unlinked before it is rewritten, so the source run is
never touched), one mutation of the product's evidence, then the judge with the given ledger. The run as captured
(case ``A_correct``) must PASS; every other case must FAIL. Exit 0 when that holds, 1 otherwise, 2 on an error.

The cases are written against the CB-02 core lab (target ids z01, z02, z05, z05b, z16, sshd-pq, canary) and find the
product's asset for an oracle row through the judge's own oracle pairing, so they work on any run of that lab.
The 27 wrong CBOMs are the reviewer's, kept as permanent controls (``round6/rv-75-notes/bin/wrong_cboms.py``).
"""
from __future__ import annotations

import argparse
import copy
import csv
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from . import gate, join, oracle
from .checks import Checks
from .oracle import _address_of

JUDGE_OUTPUTS = ("report.json", "report.md", "canaries.txt", "SHA256SUMS")


def clone(src: Path, dst: Path) -> Path:
    """Hardlinked copy without the judge's outputs (cp -al)."""
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, copy_function=os.link)
    for name in JUDGE_OUTPUTS:
        (dst / name).unlink(missing_ok=True)
    if (dst / "diff").is_dir():
        shutil.rmtree(dst / "diff")
    (dst / "diff").mkdir()
    return dst


def _write(path: Path, text: str) -> None:
    path.unlink(missing_ok=True)  # break the hard link first: the source run keeps its bytes
    path.write_text(text, encoding="utf-8")


class Views:
    """The four views of run 1, edited together."""

    def __init__(self, run: Path):
        self.run = run
        self.api = json.loads((run / "api/assets-run1.json").read_text(encoding="utf-8"))
        self.ui = json.loads((run / "ui/assets-run1.json").read_text(encoding="utf-8"))
        self.exp = json.loads((run / "exports/run1.cdx.json").read_text(encoding="utf-8"))
        with open(run / "db/assets.csv", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            self.dbf, self.db = reader.fieldnames, list(reader)

    def item(self, aid: int) -> dict[str, Any]:
        return next(i for i in self.api["items"] if i["id"] == aid)

    def uirow(self, aid: int) -> dict[str, Any]:
        return next(r for r in self.ui["rows"] if r["id"] == aid)

    def dbrow(self, aid: int) -> dict[str, Any]:
        return next(r for r in self.db if int(r["id"]) == aid)

    def comp(self, aid: int) -> dict[str, Any]:
        return next(c for c in self.exp["components"] if c.get("bom-ref") == f"zs-asset-{aid}")

    def setprop(self, aid: int, name: str, value: str) -> None:
        props = self.comp(aid).setdefault("properties", [])
        for p in props:
            if p["name"] == name:
                p["value"] = value
                return
        props.append({"name": name, "value": value})

    def facts(self, row: dict[str, Any]) -> dict[str, Any]:
        f = row.get("facts")
        return json.loads(f) if isinstance(f, str) and f else (f or {})

    def set_facts(self, aid: int, fn: Callable[[dict[str, Any]], None]) -> None:
        for row in (self.item(aid), self.dbrow(aid)):
            f = self.facts(row)
            fn(f)
            row["facts"] = f if isinstance(row.get("facts"), dict) else json.dumps(f)

    def refacet(self) -> None:
        from collections import Counter
        items = self.api["items"]
        self.api["all_total"] = self.api["total"] = len(items)
        self.api["facets"] = {"type": dict(Counter(i.get("type") for i in items)),
                              "impact": dict(Counter(i.get("impact") or "none" for i in items)),
                              "quantum_vulnerable": sum(1 for i in items if i.get("quantum_vulnerable") is True)}
        self.ui["total_text"] = f"{len(items)} assets"

    def save(self, refacet: bool = True) -> None:
        if refacet:
            self.refacet()
        _write(self.run / "api/assets-run1.json", json.dumps(self.api, indent=1))
        _write(self.run / "ui/assets-run1.json", json.dumps(self.ui, indent=1))
        _write(self.run / "exports/run1.cdx.json", json.dumps(self.exp, indent=1))
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=self.dbf)
        w.writeheader()
        w.writerows(self.db)
        _write(self.run / "db/assets.csv", buf.getvalue())


def pairs_of(run: Path) -> dict[str, int]:
    """oracle_id -> product asset id, as the judge pairs them (no verdicts kept)."""
    views = join.load_views(run, "1")
    out: dict[str, int] = {}
    oracle.match(run, "1", Checks(), views["api"], views["export"], None, out)
    return out


def _qv(v: Views, aid: int, value: bool) -> None:
    v.item(aid)["quantum_vulnerable"] = value
    v.dbrow(aid)["quantum_vulnerable"] = "t" if value else "f"
    v.uirow(aid)["quantum"] = "Vulnerable" if value else "Safe"
    v.setprop(aid, "zs:quantum_vulnerable", "true" if value else "false")


def _drop(v: Views, aid: int) -> None:
    v.api["items"] = [i for i in v.api["items"] if i["id"] != aid]
    v.ui["rows"] = [r for r in v.ui["rows"] if r["id"] != aid]
    v.db = [r for r in v.db if int(r["id"]) != aid]
    v.exp["components"] = [c for c in v.exp["components"] if c.get("bom-ref") != f"zs-asset-{aid}"]
    meta = v.exp.setdefault("metadata", {})
    meta["properties"] = [p for p in meta.get("properties") or []
                          if not (p.get("name") == "zs:coverage_gap" and f'"zs-asset-{aid}"' in str(p.get("value")))]


def _add(v: Views, aid: int, src: int, loc: str, target: str, alg: str = "RSA", ks: int | None = 2048,
         qv: bool = True, typ: str = "tls_endpoint") -> None:
    it = copy.deepcopy(v.item(src))
    it.update(id=aid, location=loc, target=target, algorithm=alg, key_size=ks, quantum_vulnerable=qv, type=typ)
    v.api["items"].append(it)
    ui = copy.deepcopy(v.uirow(src))
    ui.update(id=aid, location=loc, target=target, algorithm=f"{alg} {ks}" if ks else alg,
              quantum="Vulnerable" if qv else "Safe")
    v.ui["rows"].append(ui)
    db = copy.deepcopy(v.dbrow(src))
    db.update(id=str(aid), location=loc, target=target, algorithm=alg, key_size=str(ks or ""),
              quantum_vulnerable="t" if qv else "f", asset_type=typ)
    v.db.append(db)
    c = copy.deepcopy(v.comp(src))
    c["bom-ref"] = f"zs-asset-{aid}"
    v.exp["components"].append(c)
    for name, val in (("zs:location", loc), ("zs:target", target), ("zs:algorithm", alg),
                      ("zs:quantum_vulnerable", "true" if qv else "false"), ("zs:asset_type", typ)):
        v.setprop(aid, name, val)


def _new_id(v: Views) -> int:
    return max(i["id"] for i in v.api["items"]) + 1


def _empty_address(v: Views) -> tuple[int, str]:
    cov = next(i for i in v.api["items"] if i["type"] == "coverage")
    return cov["id"], _address_of(cov["location"])


# ------------------------------------------------------------------------------------------------------- cases
# Each case: (run, pairs) -> None, mutating the run's evidence. Docstrings are the table's description.
def c_A_correct(run: Path, p: dict[str, int]) -> None:
    """positive control: the run as captured"""


def c_B_export_value(run, p):
    """the export says a TLS endpoint uses another suite than the API/DB"""
    v = Views(run)
    v.setprop(p["z01/tls"], "zs:algorithm", "TLS_RSA_WITH_RC4_128_MD5")
    v.save(refacet=False)


def c_C_consistent_wrong(run, p):
    """a z01 certificate says RSA in all four views (the lab served EC): only the oracle sees it"""
    v = Views(run)
    aid = p["z01/cert[0]"]
    alg = v.item(aid)["algorithm"]
    v.item(aid)["algorithm"] = v.dbrow(aid)["algorithm"] = "RSA"
    v.uirow(aid)["algorithm"] = v.uirow(aid)["algorithm"].replace(alg, "RSA", 1)
    v.setprop(aid, "zs:algorithm", "RSA")
    v.save(refacet=False)


def c_D_ui_lost_row(run, p):
    """the Results table lost a row"""
    v = Views(run)
    v.ui["rows"] = v.ui["rows"][:-1]
    v.save(refacet=False)


def c_1_dropped_asset(run, p):
    """a z05 certificate is gone from every view (consistently)"""
    v = Views(run)
    _drop(v, p["z05/cert[0]"])
    v.save()


def c_1b_dropped_unjudged_asset(run, p):
    """the coverage row of an empty address is gone from every view"""
    v = Views(run)
    aid, _ = _empty_address(v)
    _drop(v, aid)
    v.save()


def c_2_wrong_algorithm(run, p):
    """z16's certificate RSA-2048 -> EC-384 in all views"""
    v = Views(run)
    aid = p["z16/cert[0]"]
    for row in (v.item(aid), v.dbrow(aid)):
        row["algorithm"], row["key_size"] = "EC", 384
    v.uirow(aid)["algorithm"] = "EC 384"
    v.setprop(aid, "zs:algorithm", "EC")
    v.save()


def c_3_qv_flip_cert(run, p):
    """quantum verdict flipped on a certificate (z05 cert[0]: vulnerable -> safe)"""
    v = Views(run)
    _qv(v, p["z05/cert[0]"], False)
    v.save()


def c_3b_qv_flip_hybrid_endpoint(run, p):
    """quantum verdict flipped on the hybrid endpoint z05/tls (safe -> vulnerable)"""
    v = Views(run)
    _qv(v, p["z05/tls"], True)
    v.save()


def c_3c_qv_flip_legacy_endpoint(run, p):
    """quantum verdict flipped on the classical endpoint z02/tls (vulnerable -> safe)"""
    v = Views(run)
    _qv(v, p["z02/tls"], False)
    v.save()


def c_4_extra_asset_unclaimed_address(run, p):
    """a fabricated TLS asset at an empty address inside a scanned range, in all views"""
    v = Views(run)
    _, addr = _empty_address(v)
    _add(v, _new_id(v), p["z16/tls"], f"{addr}:443", addr)
    v.save()


def c_4b_extra_asset_outside_lab(run, p):
    """a fabricated TLS asset at 203.0.113.7:443 (not in the lab), in all views"""
    v = Views(run)
    _add(v, _new_id(v), p["z16/tls"], "203.0.113.7:443", "203.0.113.7")
    v.save()


def c_4c_extra_asset_closed_target(run, p):
    """a fabricated TLS asset at z01's address, port 8443 (closed world), in all views"""
    v = Views(run)
    addr = _address_of(v.item(p["z01/tls"])["location"])
    _add(v, _new_id(v), p["z01/tls"], f"{addr}:8443", addr)
    v.save()


def c_5_stale_timestamps(run, p):
    """export metadata.timestamp and every DB created_at a year old"""
    v = Views(run)
    v.exp.setdefault("metadata", {})["timestamp"] = "2025-11-12T12:16:18Z"
    for r in v.db:
        r["created_at"] = "2025-11-12 12:14:00"
    v.save(refacet=False)


def c_5b_stale_cert_date_api_db(run, p):
    """z05b cert[0] not_after a year off in the API and DB only"""
    v = Views(run)
    v.set_facts(p["z05b/cert[0]"], lambda f: f.__setitem__("not_after", "2025-01-01T00:00:00Z"))
    v.save(refacet=False)


def c_5c_new_defect_in_ledgered_target(run, p):
    """a NEW defect on a ledgered target, all four views: z01 cert[0] not_after a year off (KF-18 pins only z01/tls's
    /complete checks). Was z05b's certificate (KF-3); since CB-02 v7.1 every z05b key is unverified, so a change there
    is NOT-JUDGED by design (O-3) and can no longer serve as a control."""
    v = Views(run)
    aid = p["z01/cert[0]"]
    v.set_facts(aid, lambda f: f.__setitem__("not_after", "2025-12-14T12:13:02Z"))
    cert = v.comp(aid).get("cryptoProperties", {}).get("certificateProperties")
    if cert is not None:
        cert["notValidAfter"] = "2025-12-14T12:13:02Z"
    v.save(refacet=False)


def c_5d_new_defect_sshd_pq(run, p):
    """a NEW defect on a ledgered target: sshd-pq reports a classic-only KEX list (KF-6 is the host key)"""
    v = Views(run)
    v.set_facts(p["sshd-pq/ssh"], lambda f: f.__setitem__("kex", ["curve25519-sha256"]))
    v.save(refacet=False)


def c_6_ui_count_only(run, p):
    """the Results header shows one asset more than the API, DB and export"""
    v = Views(run)
    n = len(v.api["items"])
    v.ui["total_text"] = str(v.ui.get("total_text") or f"{n} assets").replace(str(n), str(n + 1), 1)
    v.save(refacet=False)


def c_6b_ui_duplicate_row(run, p):
    """the UI shows a row twice"""
    v = Views(run)
    v.ui["rows"].append(copy.deepcopy(v.ui["rows"][0]))
    v.save(refacet=False)


def c_7_api_duplicate_item(run, p):
    """the API serves an asset twice (paging overlap); the facets count it twice"""
    v = Views(run)
    v.api["items"].append(copy.deepcopy(v.item(p["z01/tls"])))
    items = v.api["items"]
    v.refacet()
    v.ui["total_text"] = f"{len(items) - 1} assets"
    v.save(refacet=False)


def c_8_weak_cipher_regression(run, p):
    """the weak-cipher probe regressed: z02 and z16 report only the negotiated suite"""
    v = Views(run)
    for oid in ("z02/tls", "z16/tls"):
        v.set_facts(p[oid], lambda f: f.__setitem__("weak_ciphers_accepted", {"cbc": [], "static_rsa": []}))
    v.save(refacet=False)


def c_9_canary_asset(run, p):
    """never-scan violated: a TLS endpoint stored at the canary's address, all views"""
    v = Views(run)
    lab = json.loads((run / "lab/lab.json").read_text(encoding="utf-8"))
    canary = next(x for x in lab.get("listeners") or [] if x.get("role") == "canary")
    _add(v, _new_id(v), p["z16/tls"], f"{canary['address']}:443", canary["address"])
    v.save()


def c_10_export_wrong_key_size(run, p):
    """the export carries a key size, but the wrong one (1024 where the API says 256)"""
    v = Views(run)
    v.setprop(p["z01/cert[0]"], "zs:key_size", "1024")
    v.save(refacet=False)


def c_11_har_gone(run, p):
    """the HAR recording is lost (har/ empty)"""
    for f in (run / "har").glob("*.har"):
        f.unlink()


def c_12_no_assets_stored_lines(run, p):
    """the backend no longer logs 'assets stored' lines"""
    for f in (run / "logs").glob("*.log"):
        text = f.read_text(encoding="utf-8", errors="replace")
        new = "\n".join(ln for ln in text.splitlines() if "assets stored" not in ln) + "\n"
        if new != text:
            _write(f, new)


def c_13_export_missing(run, p):
    """the export lane is missing"""
    (run / "exports/run1.cdx.json").unlink()


def c_14_ui_lane_missing(run, p):
    """the UI lane is missing"""
    (run / "ui/assets-run1.json").unlink()


def c_15_case_location_export(run, p):
    """the export's location for a TLS endpoint carries a trailing dot"""
    v = Views(run)
    aid = p["z01/tls"]
    v.setprop(aid, "zs:location", v.item(aid)["location"] + ".")
    v.save(refacet=False)


CASES: dict[str, Callable[[Path, dict[str, int]], None]] = {
    k[2:]: f for k, f in sorted(globals().items(), key=lambda kv: kv[0]) if k.startswith("c_")}
WRONG = [k for k in CASES if k != "A_correct"]


def run_cases(src: Path, ledger_path: Path, names: list[str] | None = None, work: Path | None = None
              ) -> list[dict[str, Any]]:
    names = names or list(CASES)
    work = Path(work or tempfile.mkdtemp(prefix="cbom-neg-"))
    base = clone(src, work / "_base")
    pairs = pairs_of(base)
    out = []
    for name in names:
        run = clone(src, work / name)
        CASES[name](run, pairs)
        passed, rep = gate.judge(run, ledger_path)
        blocking = [(c["id"], c.get("reason")) for c in rep["blocking"]]
        moved = [r["row"] for r in rep["ledger"] if r["status"] not in ("holds", "not-run-ok")]
        out.append({"case": name, "doc": (CASES[name].__doc__ or "").strip(), "gate": "PASS" if passed else "FAIL",
                    "expected": "PASS" if name == "A_correct" else "FAIL", "blocking": blocking[:6],
                    "ledger_rows_moved": moved})
        shutil.rmtree(run, ignore_errors=True)
    shutil.rmtree(base, ignore_errors=True)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="harness.negative")
    ap.add_argument("run", type=Path)
    ap.add_argument("--ledger", type=Path, default=gate.DEFAULT_LEDGER)
    ap.add_argument("--cases", default="")
    ap.add_argument("--out", type=Path, help="write the table as JSON here")
    args = ap.parse_args(argv)
    if not args.run.is_dir():
        print(f"no such run directory: {args.run}", file=sys.stderr)
        return 2
    names = [n for n in args.cases.split(",") if n] or None
    rows = run_cases(args.run, args.ledger, names)
    bad = [r for r in rows if r["gate"] != r["expected"]]
    for r in rows:
        mark = "ok " if r["gate"] == r["expected"] else "BAD"
        print(f"{mark} {r['case']:36s} gate {r['gate']:4s} (want {r['expected']}) {r['blocking'][:2]} moved={r['ledger_rows_moved']}")
    killed = sum(1 for r in rows if r["case"] != "A_correct" and r["gate"] == "FAIL")
    print(f"negative controls: {killed}/{sum(1 for r in rows if r['case'] != 'A_correct')} wrong CBOMs FAIL; "
          f"correct run {'PASS' if any(r['case'] == 'A_correct' and r['gate'] == 'PASS' for r in rows) else 'not PASS'}")
    if args.out:
        args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
