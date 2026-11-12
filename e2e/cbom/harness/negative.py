"""Negative controls: deliberately wrong CBOMs that the gate must FAIL, on real evidence (review 5874859738).

    python3 -m harness.negative <run> [--ledger L] [--cases a,b,...] [--keep DIR]

For each case: a hardlinked copy of the run directory (a file is unlinked before it is rewritten, so the source run is
never touched), one mutation of the product's evidence, then the judge with the given ledger. The run as captured
(case ``A_correct``) must PASS; every other case must FAIL. Exit 0 when that holds, 1 otherwise, 2 on an error.

The cases are written against the CB-02 core lab (target ids z01, z02, z04, z05, z05b, z16, sshd-legacy, sshd-pq,
canary) and work on any run of that lab. 47 wrong CBOMs, kept as permanent controls: the first reviewer's 27
(``round6/rv-75-notes/bin/wrong_cboms.py``; they find the asset through the judge's oracle pairing) and, from review
5878413538 (``round6/rv-75-r2/bin/wrong6.py``; asset found by type and location), the original 5c on z05b and 19 cases
aimed at the second round's code. Each case names the check that must catch it (``INTENDED``): a wrong CBOM that
fails for an incidental reason is a hole, so the case counts only when that check blocks or moves its ledger row.
"""
from __future__ import annotations

import argparse
import copy
import csv
import datetime as dt
import io
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from . import fieldmap as F
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


# ------------------------------------------------- review 5878413538: the original 5c and the reviewer's 19 new cases
# Ported from round6/rv-75-r2/bin/wrong6.py: the asset is found by type and location in the API capture (independent of
# the judge's pairing), and times are relative to the run's own G9/G10 steps, so the cases work on any core-lab run.
def _loc(v: Views, typ: str, loc: str) -> int:
    hits = [i["id"] for i in v.api["items"] if i["type"] == typ and i["location"] == loc]
    assert len(hits) == 1, (typ, loc, hits)
    return hits[0]


def _addr(run: Path, target: str) -> str:
    doc = json.loads((run / "oracle/run1.json").read_text(encoding="utf-8"))
    return next(str(t["address"]) for t in doc["targets"] if t["target_id"] == target)


def _tls(v: Views, run: Path, target: str) -> int:
    return _loc(v, "tls_endpoint", f"{_addr(run, target)}:443")


def _cert0(v: Views, run: Path, target: str) -> int:
    return _loc(v, "certificate", f"{_addr(run, target)}:443#chain[0]")


def _ssh(v: Views, run: Path, target: str) -> int:
    return _loc(v, "ssh_endpoint", f"{_addr(run, target)}:22")


def _step(run: Path, step: str, key: str):
    from .rundir import parse_ts
    return parse_ts(json.loads((run / "steps" / step / "step.json").read_text(encoding="utf-8")).get(key))


def _year_back(text: str) -> str:
    return str(int(text[:4]) - 1) + text[4:]


def _codes_in_views(v: Views, aid: int, codes: list[str], impact: str | None, finding: str | None) -> None:
    v.item(aid).update(finding_codes=codes, impact=impact, finding=finding)
    v.dbrow(aid).update(finding_codes=json.dumps(codes), impact=impact or "", finding=finding or "")
    v.uirow(aid).update(impact=impact or "Info", finding=finding or "—")
    c = v.comp(aid)
    c["properties"] = [p for p in c.get("properties") or [] if p["name"] not in ("zs:finding_code", "zs:impact", "zs:finding")]
    c["properties"] += [{"name": "zs:finding_code", "value": code} for code in codes]
    if impact:
        c["properties"].append({"name": "zs:impact", "value": impact})
    if finding:
        c["properties"].append({"name": "zs:finding", "value": finding})


def _refreeze(run: Path, edit: Callable[[dict[str, Any]], None]) -> None:
    """A lab run whose oracle says something else: edit oracle/run1.json and freeze it again (O-5 still holds)."""
    from . import manifest
    path = run / "oracle/run1.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    edit(doc)
    _write(path, json.dumps(doc, indent=1))
    manifest.freeze_oracle(run)


def _oracle_asset(doc: dict[str, Any], oid: str) -> dict[str, Any]:
    return next(a for t in doc["targets"] for a in t.get("assets") or [] if a["oracle_id"] == oid)


def c_5c_orig_z05b_cert_all_views(run, p):
    """5c as the earlier reviewer wrote it: z05b cert[0] not_after a year off in ALL four views (an unverified key)"""
    v = Views(run)
    aid = _cert0(v, run, "z05b")
    after = _year_back(v.facts(v.item(aid))["not_after"])
    v.set_facts(aid, lambda f: f.__setitem__("not_after", after))
    cert = v.comp(aid).get("cryptoProperties", {}).get("certificateProperties")
    if cert is not None:
        cert["notValidAfter"] = after
    v.save(refacet=False)


def c_N1_derived_qv_lab_silent_flip(run, p):
    """N1 the lab states no endpoint verdict (re-frozen); z02/tls vulnerable -> safe and z05/tls safe -> vulnerable"""
    def edit(doc):
        for t in doc["targets"]:
            for a in t.get("assets") or []:
                if a.get("asset_type") in ("tls_endpoint", "ssh_endpoint"):
                    (a.get("expect") or {}).pop("quantum_vulnerable", None)
    _refreeze(run, edit)
    v = Views(run)
    _qv(v, _tls(v, run, "z02"), False)
    _qv(v, _tls(v, run, "z05"), True)
    v.save()


def c_N1b_derived_qv_iana_group_outside_table(run, p):
    """N1b z05 accepts only MLKEM1024X448 (IANA 4591, a PQ hybrid), the lab is silent on the verdict, the product calls
    the endpoint quantum-vulnerable (reads the hybrid as classical)"""
    def edit(doc):
        a = _oracle_asset(doc, "z05/tls")
        a["expect"]["groups"] = ["MLKEM1024X448"]
        a["expect"].pop("quantum_vulnerable", None)
    _refreeze(run, edit)
    v = Views(run)
    aid = _tls(v, run, "z05")
    v.set_facts(aid, lambda f: f.__setitem__("negotiated_group", "MLKEM1024X448"))
    _qv(v, aid, True)
    v.save()


def c_N2_derived_ssh_key_size(run, p):
    """N2 sshd-legacy reports its host key as ssh-rsa 4096 (the server's RSA key is 1024)"""
    v = Views(run)
    aid = _ssh(v, run, "sshd-legacy")
    for row in (v.item(aid), v.dbrow(aid)):
        row["algorithm"] = "ssh-rsa"
    v.item(aid)["key_size"], v.dbrow(aid)["key_size"] = 4096, "4096"
    v.uirow(aid)["algorithm"] = "ssh-rsa 4096"
    v.setprop(aid, "zs:algorithm", "ssh-rsa")
    v.setprop(aid, "zs:key_size", "4096")
    v.save(refacet=False)


def c_N3_unverified_z05_suite(run, p):
    """N3 z05/tls (verified TLS 1.3 only) reports TLS_RSA_WITH_RC4_128_MD5 as its suite, all views"""
    v = Views(run)
    aid = _tls(v, run, "z05")
    suite = "TLS_RSA_WITH_RC4_128_MD5"
    for row in (v.item(aid), v.dbrow(aid)):
        row["algorithm"] = suite
    v.uirow(aid)["algorithm"] = suite
    v.setprop(aid, "zs:algorithm", suite)
    v.set_facts(aid, lambda f: f.__setitem__("negotiated_cipher", suite))
    v.save(refacet=False)


def c_N4_unverified_z05b_qv_flip(run, p):
    """N4 z05b/tls (ML-KEM hybrid offered, verdict unverified) safe -> vulnerable in all views"""
    v = Views(run)
    _qv(v, _tls(v, run, "z05b"), True)
    v.save()


def c_N5_z05b_reports_another_certificate(run, p):
    """N5 the product reports z05's RSA certificate (subject, issuer, serial, fingerprint, dates) as z05b's leaf"""
    v = Views(run)
    src, dst = _cert0(v, run, "z05"), _cert0(v, run, "z05b")
    facts = v.facts(v.item(src))
    keys = ("subject", "issuer", "serial", "fingerprint_sha256", "not_after", "not_before")
    v.set_facts(dst, lambda f: f.update({k: facts.get(k) for k in keys}))
    sp = v.comp(src).get("cryptoProperties", {}).get("certificateProperties") or {}
    cp = v.comp(dst).setdefault("cryptoProperties", {}).setdefault("certificateProperties", {})
    for k in ("subjectName", "issuerName", "notValidBefore", "notValidAfter"):
        if k in sp:
            cp[k] = sp[k]
    v.save(refacet=False)


def c_N6_must_report_further_loss_z02(run, p):
    """N6 z02 alone loses its weak-suite probe results: a further loss under a check that already fails"""
    v = Views(run)
    v.set_facts(_tls(v, run, "z02"), lambda f: f.__setitem__("weak_ciphers_accepted", {"cbc": [], "static_rsa": []}))
    v.save(refacet=False)


def c_N7_coverage_beyond_range(run, p):
    """N7 the coverage row of an empty address moves to the range's broadcast address (no target, not empty)"""
    v = Views(run)
    aid, addr = _empty_address(v)
    new = addr.rsplit(".", 1)[0] + ".31"
    for row in (v.item(aid), v.dbrow(aid), v.uirow(aid)):
        row["location"], row["target"] = f"{new}#no answer", new
    for prop in (v.exp.get("metadata") or {}).get("properties") or []:
        if prop.get("name") == "zs:coverage_gap" and f'"zs-asset-{aid}"' in str(prop.get("value")):
            gap = json.loads(prop["value"])
            gap["location"], gap["target"] = f"{new}#no answer", new
            prop["value"] = json.dumps(gap)
    v.save(refacet=False)


def c_N7b_cert_at_empty_address(run, p):
    """N7b a certificate asset at an empty address, next to its coverage row, all views"""
    v = Views(run)
    _, addr = _empty_address(v)
    _add(v, _new_id(v), _cert0(v, run, "z16"), f"{addr}:443#chain[0]", addr, typ="certificate")
    v.save()


def c_N8_ledger_swap_export_versions(run, p):
    """N8 the export writes TLSv1.2 for TLS-1.3-only z05 (new mismatch) while z02's export versions are fixed: the
    count of protocol-version mismatches stays the same"""
    v = Views(run)
    v.comp(_tls(v, run, "z05"))["cryptoProperties"]["protocolProperties"]["version"] = "TLSv1.2"
    z02 = _tls(v, run, "z02")
    api = F.view_value("protocol_versions", "api", v.item(z02)) or []
    v.comp(z02)["cryptoProperties"]["protocolProperties"]["version"] = ",".join(api)
    v.save(refacet=False)


def c_N8b_ledger_swap_export_missing(run, p):
    """N8b the API invents curve P-384 on z16's RSA certificate (export-missing +1) while the export gains z01 cert[0]'s
    key size (export-missing -1)"""
    v = Views(run)
    v.set_facts(_cert0(v, run, "z16"), lambda f: f.__setitem__("curve", "P-384"))
    z01 = _cert0(v, run, "z01")
    v.setprop(z01, "zs:key_size", str(v.item(z01)["key_size"]))
    v.save(refacet=False)


def c_N9_one_db_row_before_start(run, p):
    """N9 one DB asset row created an hour before Start"""
    v = Views(run)
    t = _step(run, "G9", "started") - dt.timedelta(hours=1)
    v.dbrow(_tls(v, run, "z01"))["created_at"] = t.strftime("%Y-%m-%d %H:%M:%S.000000")
    v.save(refacet=False)


def c_N9b_run_record_dates(run, p):
    """N9b the run's own record (API run document, DB runs.csv and jobs.csv) says created/finished a year ago"""
    state = json.loads((run / "flow-state.json").read_text(encoding="utf-8"))
    rid = str(state["runs"][0])
    path = run / "api" / f"run-{rid}.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    for obj in [doc["run"], *(doc["run"].get("jobs") or [])]:
        for key in ("created_at", "finished_at", "claimed_at"):
            if obj.get(key):
                obj[key] = _year_back(obj[key])
    _write(path, json.dumps(doc, indent=1))
    for name, idkey in (("runs.csv", "id"), ("jobs.csv", "run_id")):
        with open(run / "db" / name, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            fields, rows = reader.fieldnames, list(reader)
        for row in rows:
            if str(row.get(idkey)) == rid:
                for key in ("created_at", "finished_at", "claimed_at"):
                    if row.get(key):
                        row[key] = _year_back(row[key])
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
        _write(run / "db" / name, buf.getvalue())


def c_N9c_export_serial_nil(run, p):
    """N9c the export's serialNumber is the nil UUID (one constant serial in every BOM)"""
    v = Views(run)
    v.exp["serialNumber"] = "urn:uuid:00000000-0000-0000-0000-000000000000"
    v.save(refacet=False)


def c_N10_ui_total_second_number(run, p):
    """N10 the Results header reads '25 of 26 assets found' (claims an asset the table does not show)"""
    v = Views(run)
    n = len(v.api["items"])
    v.ui["total_text"] = f"{n} of {n + 1} assets found"
    v.save(refacet=False)


def c_N11_canary_hit_after_g10(run, p):
    """N11 the sealed canary log holds a connection from the node after the G10 read"""
    state = json.loads((run / "flow-state.json").read_text(encoding="utf-8"))
    lab = json.loads((run / "lab/lab.json").read_text(encoding="utf-8"))
    canary = next(x for x in lab["listeners"] if x.get("role") == "canary" and x.get("name") == "canary")
    path = run / (canary.get("log") or "lab/listeners/canary.jsonl")
    when = (_step(run, "G10", "ended") + dt.timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = json.dumps({"ts": when, "peer": f"{state['node']['addresses'][0]}:40100", "local": f"{canary['address']}:443"})
    _write(path, path.read_text(encoding="utf-8") + line + "\n")


def c_N11b_canary_log_gone(run, p):
    """N11b the canary listener's log is missing from the bundle"""
    lab = json.loads((run / "lab/lab.json").read_text(encoding="utf-8"))
    canary = next(x for x in lab["listeners"] if x.get("role") == "canary" and x.get("name") == "canary")
    (run / (canary.get("log") or "lab/listeners/canary.jsonl")).unlink()


def c_N12_expired_cert_not_flagged(run, p):
    """N12 z04's expired certificate is no longer flagged (CERT_EXPIRED dropped, impact High -> none, finding cleared)"""
    v = Views(run)
    aid = _cert0(v, run, "z04")
    codes = [c for c in v.item(aid).get("finding_codes") or [] if c != "CERT_EXPIRED"]
    _codes_in_views(v, aid, codes, None, None)
    v.save()


def c_N12b_weak_endpoint_not_flagged(run, p):
    """N12b z02/tls no longer flags TLS 1.0/1.1, static RSA or CBC (codes, finding, impact High -> Low); facts kept"""
    v = Views(run)
    _codes_in_views(v, _tls(v, run, "z02"), ["NO_PQ_KEX"], "Low", "Endpoint has no post-quantum key exchange")
    v.save()


# The check each wrong CBOM must be caught by (review 5878413538 minor): a regex over check ids, found among the
# blocking checks or among the identities of a ledger row it moved (unexpected / missing). A case that fails for an
# incidental reason does not count.
INTENDED: dict[str, str] = {
    "B_export_value": r"/asset/[^/]+/algorithm/export$",
    "C_consistent_wrong": r"/z01/cert\[0\]/algorithm$",
    "D_ui_lost_row": r"/presence/ui$",
    "1_dropped_asset": r"/z05/cert\[0\]/present$",
    "1b_dropped_unjudged_asset": r"/oracle/run1/empty/[\d.]+$",
    "2_wrong_algorithm": r"/z16/cert\[0\]/(algorithm|key_size)$",
    "3_qv_flip_cert": r"/z05/cert\[0\]/quantum_vulnerable$",
    "3b_qv_flip_hybrid_endpoint": r"/z05/tls/quantum_vulnerable$",
    "3c_qv_flip_legacy_endpoint": r"/z02/tls/quantum_vulnerable$",
    "4_extra_asset_unclaimed_address": r"/oracle/run1/empty/[\d.]+$",
    "4b_extra_asset_outside_lab": r"/oracle/run1/unattributed/",
    "4c_extra_asset_closed_target": r"/z01/extra/",
    "5_stale_timestamps": r"/(db_created_in_run_window|timestamps_on_run_day)/run1$",
    "5b_stale_cert_date_api_db": r"/asset/[^/]+/not_after/export$",
    "5c_new_defect_in_ledgered_target": r"/z01/cert\[0\]/not_after$",
    "5c_orig_z05b_cert_all_views": r"/z05b/cert\[0\]/not_after$",
    "5d_new_defect_sshd_pq": r"/sshd-pq/ssh/kex_algorithms$",
    "6_ui_count_only": r"/join/run1/ui_total$",
    "6b_ui_duplicate_row": r"/duplicates/ui$",
    "7_api_duplicate_item": r"/duplicates/api$",
    "8_weak_cipher_regression": r"/(z02|z16)/tls/cipher_suites/must_report$",
    "9_canary_asset": r"/canary/(extra/|must-not-appear/)",
    "10_export_wrong_key_size": r"/asset/[^/]+/key_size/export$",
    "11_har_gone": r"^G16/har$",
    "12_no_assets_stored_lines": r"^G16/assets-stored/job-",
    "13_export_missing": r"/join/run1/export$",
    "14_ui_lane_missing": r"/join/run1/ui$",
    "15_case_location_export": r"/asset/[^/]+/location/export$",
    "N1_derived_qv_lab_silent_flip": r"/(z02|z05)/tls/quantum_vulnerable$",
    "N1b_derived_qv_iana_group_outside_table": r"/z05/tls/quantum_vulnerable$",
    "N2_derived_ssh_key_size": r"/sshd-legacy/ssh/key_size$",
    "N3_unverified_z05_suite": r"/z05/tls/algorithm(/tls13_suite)?$",
    "N4_unverified_z05b_qv_flip": r"/z05b/tls/quantum_vulnerable$",
    "N5_z05b_reports_another_certificate": r"/z05b/(cert\[0\]/present|extra/)",
    "N6_must_report_further_loss_z02": r"/z02/tls/cipher_suites/must_report$",
    "N7_coverage_beyond_range": r"/oracle/run1/(unattributed/|empty/)",
    "N7b_cert_at_empty_address": r"/oracle/run1/empty/[\d.]+$",
    "N8_ledger_swap_export_versions": r"/asset/[^/]+/protocol_versions/export$",
    "N8b_ledger_swap_export_missing": r"/asset/[^/]+/(curve|key_size)/export$",
    "N9_one_db_row_before_start": r"/db_created_in_run_window/run1$",
    "N9b_run_record_dates": r"/run_record_in_run_window/run1$",
    "N9c_export_serial_nil": r"/serial_number/run1$",
    "N10_ui_total_second_number": r"/join/run1/ui_total$",
    "N11_canary_hit_after_g10": r"^G10/sealed/canary_accepts/canary$",
    "N11b_canary_log_gone": r"^G10/sealed/canary_(accepts|log_path)/canary$",
    "N12_expired_cert_not_flagged": r"/z04/cert\[0\]/(code/CERT_EXPIRED|finding_codes|impact|impact_min)$",
    "N12b_weak_endpoint_not_flagged": r"/z02/tls/(code/(PROTO_TLS10|PROTO_TLS11|STATIC_RSA_KEX)|finding_codes|impact|impact_min)$",
}


def intended_hit(case: str, report: dict[str, Any]) -> str | None:
    """The blocking check or moved-row identity that matches the case's intended check, or None."""
    rx = re.compile(INTENDED[case])
    for c in report.get("blocking") or []:
        if rx.search(c["id"]):
            return f"blocking {c['id']} ({c.get('reason')})"
    for r in report.get("ledger") or []:
        if r["status"] in ("holds", "not-run-ok"):
            continue
        for side in ("unexpected", "missing"):
            for ident in r.get(side) or []:
                if rx.search(ident.get("id", "")):
                    return f"row {r['row']} {r['status']}: {side} {ident['id']}"
    return None


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
                    "ledger_rows_moved": moved, "intended": INTENDED.get(name),
                    "caught_by": intended_hit(name, rep) if name in INTENDED else None})
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
    bad = [r for r in rows if r["gate"] != r["expected"] or (r["case"] != "A_correct" and not r["caught_by"])]
    for r in rows:
        mark = "ok " if r not in bad else "BAD"
        print(f"{mark} {r['case']:42s} gate {r['gate']:4s} (want {r['expected']}) caught by: {r['caught_by']}")
    killed = sum(1 for r in rows if r["case"] != "A_correct" and r["gate"] == "FAIL")
    print(f"negative controls: {killed}/{sum(1 for r in rows if r['case'] != 'A_correct')} wrong CBOMs FAIL; "
          f"correct run {'PASS' if any(r['case'] == 'A_correct' and r['gate'] == 'PASS' for r in rows) else 'not PASS'}")
    if args.out:
        args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
