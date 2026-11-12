"""One-line mutants of the judge, matchers and ledger; a mutant is killed when the harness's own unit suite fails.

Started from the reviewer's set for #75 (review 5874859738: 43 mutants, 25 killed) with the anchors moved to the
v2 code, plus mutants for the code added in that round (ledger v2, timing, sampled/derived oracle rules, G16 positive
controls, trace.zip redaction); review 5878413538 added the second reviewer's 15 (R1-R15, anchors moved to the round-3
code) and round 3's own (U compare-first, V codes/impact, I identities, N never-scan, T5-T7, J12, K1). Every surviving
mutant is a hole in the suite: add the test that kills it.

    python3 e2e/cbom/tools/mutants.py [--only L1,O3] [--out results.json]

Exit 0 when every mutant is killed and every anchor is found exactly once.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CBOM = Path(__file__).resolve().parents[1]

LED, JOIN, ORA, LOGS = "harness/ledger.py", "harness/join.py", "harness/oracle.py", "harness/logs.py"
M = [  # (id, file, exact old text (must occur once), new text, what it breaks)
    # ---- ledger (major 5, 6)
    ("L1", LED, '        elif not actual:\n            res.status = "stale"', '        elif not actual:\n            res.status = "holds"',
     "stale rows never reported"),
    ("L2", LED, "        if have == want:", "        if True:", "moved identities are not detected"),
    ("L3", LED, 'if row.get("not_run_ok"):\n                    covered.add(check.id)',
     'if True:\n                    covered.add(check.id)', "NOT-RUN covered by a row without not_run_ok"),
    ("L4", LED, 'return not blocking and all(r.status in ("holds", "not-run-ok") for r in results)',
     "return not blocking", "row statuses ignored in the verdict"),
    ("L5", LED, '    if check.gate not in row["gate"]:\n        return False',
     '    if check.gate not in row["gate"]:\n        pass', "rows match outside their gate"),
    ("L6", LED, "wanted = [str(w) for w in (want if isinstance(want, list) else [want])]",
     "wanted = [str(w) for w in (want if isinstance(want, list) else [want])] + ([str(got)] if isinstance(want, list) "
     "else [])", "list values in match are wildcards"),
    ("L7", LED, "if str(got) not in wanted:", "if not any(w in str(got) for w in wanted):",
     "exact match becomes substring"),
    ("L8", LED, "missing = [k for k in REQUIRED if k not in row", "missing = [k for k in REQUIRED[:3] if k not in row",
     "issue/owner/why/expect_failing no longer required"),
    ("L9", LED, "if check.verdict in (FAIL, NOT_JUDGED):\n                actual.append",
     "if check.verdict in (FAIL,):\n                actual.append", "NOT-JUDGED can no longer be ledgered"),
    ("L10", LED, "if not NARROWING & set(match):", "if False:", "a row need not name a narrowing key"),
    ("L11", LED, 'if n_run and not row.get("not_run_ok"):', "if False:", "a pinned NOT-RUN without not_run_ok"),
    ("L12", LED, 'row[k] in (None, "", [], {}) and not (pinning', 'row[k] in (None, "", {}) and not (pinning',
     "a row may pin nothing (empty expect)"),
    ("L13", LED, "        if got is None:\n            return False", "        if got is None:\n            continue",
     "a key the check does not carry matches anything"),
    ("L14", LED, 'k.endswith("_prefix") or k not in MATCH_KEYS', 'k.endswith("_prefix")',
     "any match key allowed"),
    # ---- join (minor 1)
    ("J1", JOIN, 'if view == "export" and not _is_empty(a):', "if False:", "export-missing becomes a skip (O-7)"),
    ("J2", JOIN, "        for aid in extra:\n            checks.fail(", "        for aid in extra[:0]:\n            checks.fail(",
     "rows only in DB/export/UI not reported"),
    ("J3", JOIN, 'checks.verdict(cid, GATE, "join", a_cmp == o_cmp, "mismatch"',
     'checks.verdict(cid, GATE, "join", True, "mismatch"', "API vs DB/export values never compared"),
    ("J4", JOIN, '"join", want == got, "mismatch",', '"join", True, "mismatch",', "UI cells never compared"),
    ("J5", JOIN, 'checks.verdict(cid, GATE, "join", prop in p, "export-missing"',
     'checks.verdict(cid, GATE, "join", True, "export-missing"', "zs:pqc_class presence never checked"),
    ("J6", JOIN, "extra = sorted(set(other) - set(api))", "extra = []", "rows only in DB/export/UI ignored"),
    ("J7", JOIN, "shown is not None and shown == want", "True", "UI header total not judged"),
    ("J8", JOIN, 'not dups, f"duplicate-in-{view}"', 'True, f"duplicate-in-{view}"', "duplicate rows not judged"),
    ("J9", JOIN, "and len(raw[view] or []) == len(raw[\"api\"] or []), \"count-mismatch\"", ", \"count-mismatch\"",
     "row counts compared as id sets only (duplicates hide)"),
    # ---- oracle (majors 1-3, minor 5, nit 1)
    ("O1", ORA, "            for aid in extras:", "            for aid in extras[:0]:", "closed-world extras never fail"),
    ("O2", ORA, "ok = got_raw is not F.MISSING and got == want", "ok = got_raw is not F.MISSING",
     "oracle values never compared"),
    ("O3", ORA, "ok = bool(reported) and reported <= accepted", "ok = bool(reported)",
     "sampled keys: anything reported passes"),
    ("O3b", ORA, 'checks.verdict(f"{cid}/must_report", GATE, "oracle", not missing,',
     'checks.verdict(f"{cid}/must_report", GATE, "oracle", True,', "must_report never fails"),
    ("O3c", ORA, "exact = reported == accepted", "exact = True", "a sample passes as the enumeration"),
    ("O4", ORA, "        if tid in lab_bugs:", "        if False:", "self-check disagreement ignored (O-3)"),
    ("O5", ORA, '    if not (Path(run) / "lab" / "selfcheck.json").is_file():', "    if False:",
     "missing self-check not reported"),
    ("O6", ORA, 'if aid not in consumed and item.get("type") == asset.get("asset_type")', "if aid not in consumed",
     "asset type not part of the match"),
    ("O7", ORA, 'checks.verdict(f"{prefix}/{tid}/must-not-appear/{i}", GATE, "oracle", not hits,',
     'checks.verdict(f"{prefix}/{tid}/must-not-appear/{i}", GATE, "oracle", True,', "must_not_appear never fails"),
    ("O8", ORA, "    if scope is None:\n        return True", "    if True:\n        return True",
     "every target in scope (NOT-RUN never used)"),
    ("O9", ORA, "scored = sorted((-_score(asset, api_items[a], components.get(a)), a) for a in candidates)",
     "scored = sorted((0, a) for a in candidates)", "chain certificates matched by id order"),
    ("O10", ORA, 'for code in asset.get("codes_include") or []:', 'for code in (asset.get("codes_include") or [])[:0]:',
     "codes_include never judged"),
    ("O11", ORA, "        if aid in claimed:\n            continue", "        if True:\n            continue",
     "unattributed assets pass (major 1)"),
    ("O12", ORA, 'len(cov) == 1 and not other, "empty-address"', 'True, "empty-address"',
     "anything at a declared-empty address passes"),
    ("O13", ORA, "ok = _derived_ok(key, want, item, asset)", "ok = True", "derived expectations never compared"),
    ("O14", ORA, 'elif item.get(key) not in (None, ""):', "elif False:",
     "an unstated visible field passes silently (major 2)"),
    ("O15", ORA, 'if (oid.split("[", 1)[0], key) in weak_keys:', "if False:",
     "independent:false self-checks judged as product passes"),
    ("O16", ORA, "scored = [(s, a) for s, a in scored if s <= 0]", "scored = scored",
     "a candidate contradicting the fingerprint is paired"),
    ("O17", ORA, "            for aid, item in sorted(mine.items()):  # the customer did not ask for this target",
     "            for aid, item in sorted(mine.items())[:0]:  # the customer did not ask for this target",
     "assets at an unconfigured target pass"),
    ("O18", ORA, "if derived is not None and F.norm_bool(expect[key]) is not derived[0]:", "if False:",
     "a lab verdict contradicting its own groups/KEX is not reported"),
    ("O19", ORA, "unverified |= {(str(oid).split(\"[\", 1)[0], str(key)) for key in keys or []}", "pass",
     "selfcheck unverified_keys ignored (v7.1 #5)"),
    # ---- canary, logs, manifest
    ("C1", "harness/canary.py",
     "found_control = any(_allowed(rel, [control]) for rel, _ in hits[cid]) if control else False",
     "found_control = True", "positive control always satisfied"),
    ("C2", "harness/canary.py", "    for pad in range(3):", "    for pad in range(1):", "base64 needles one alignment"),
    ("C3", "harness/canary.py",
     'leaks = sorted({f"{rel} [{enc}]" for rel, enc in hits[cid] if not _allowed(rel, allowed)})', "leaks = []",
     "leaks never reported"),
    ("C4", "harness/canary.py", '        if path.suffix == ".zip":', "        if False:", "trace.zip members not searched"),
    ("G1", LOGS, 'ok = kv.get("rejected") == "0" and kv.get("dropped") == "0"', 'ok = kv.get("rejected") == "0"',
     "dropped assets ignored"),
    ("G2", LOGS, "abs(ts - when) <= WINDOW", "True", "any nginx 5xx line explains any 5xx"),
    ("G3", LOGS, 'REQUIRED_LOGS = ("backend", "cbom-cloud-worker", "nginx", "postgres")', 'REQUIRED_LOGS = ("backend",)',
     "core logs not required"),
    ("G4", LOGS, 'explained = kv.get("ref") in seen_refs', "explained = True", "FAILED lines always explained"),
    ("G5", LOGS, 'str(j["id"]) in stored_jobs,\n                           "assets-stored-line-missing"',
     'True,\n                           "assets-stored-line-missing"', "a job's missing 'assets stored' line passes"),
    ("G6", LOGS, '        out.append("zs-scan-node-*")', "        pass", "node log not required"),
    ("B1", "harness/bundle.py", '        missing.append("harness.commit")', "        pass",
     "MANIFEST without the harness commit passes"),
    ("B2", "harness/bundle.py", '        missing.append("node_image.id")', "        pass", "MANIFEST without the node image id"),
    ("P1", "harness/preflight.py", "    if image_paths:\n        return False", "    if False:\n        return False",
     "a code change passes as the same build"),
    ("W1", "harness/rundir.py", '    tmp = path.with_suffix(path.suffix + ".tmp")\n    with open(tmp, "w", encoding="utf-8", newline="")',
     '    tmp = path\n    with open(tmp, "w", encoding="utf-8", newline="")', "judge rewrites a hard-linked bundle"),
    ("O20", ORA, "                    if (oid.split(\"[\", 1)[0], source) in weak_keys:", "                    if False:",
     "a derivation from an unverified oracle key is judged"),
    ("M1", "harness/manifest.py", "return frozen == now, (", "return True, (", "oracle changed after Start (O-5)"),
    ("M2", "harness/manifest.py",
     "        if path.is_file() and path.name != SUMS and path.relative_to(run).as_posix() not in listed:",
     "        if False:", "unlisted files not detected"),
    # ---- derived, timing, gate, fieldmap
    ("D1", "harness/derived.py", 'dict(by_type) == dict(facets.get("type") or {}), "mismatch"', 'True, "mismatch"',
     "facet by type not checked"),
    ("D2", "harness/derived.py", 'doc.get("all_total") == len(items), "mismatch"', 'True, "mismatch"',
     "served total not checked"),
    ("D3", "harness/derived.py", 'want_q == got_q, "mismatch"', 'True, "mismatch"',
     "closed-world quantum count not checked"),
    ("T1", "harness/timing.py", "ok_meta = meta_ts is not None and lo <= meta_ts <= hi and meta_ts.date() == start.date()",
     "ok_meta = True", "export timestamp from another day passes (O-10)"),
    ("T2", "harness/timing.py", '"G11", "timing", not bad, "outside-run-window"', '"G11", "timing", True, '
     '"outside-run-window"', "DB rows from before the run pass"),
    ("T3", "harness/timing.py", "    if not UUID_URN.match(serial.lower()):\n        problems", "    if False:\n        problems",
     "export serial not judged"),
    ("T4", "harness/timing.py", 'not disagree, "mismatch"', 'True, "mismatch"', "re-judged run verdict not compared"),
    ("X1", "harness/gate.py", '            for gate_name in part.get("gate") or []:',
     '            for gate_name in (part.get("gate") or [])[:0]:', "deferred lab parts dropped silently"),
    ("X2", "harness/gate.py",
     'FLOW_STEPS = ["G0", "G1", "G2", "G3", "G4", "G5", "G5b", "G6", "G7", "G8", "G9", "G10",',
     'FLOW_STEPS = ["G0", "G1", "G2", "G3", "G4", "G5", "G5b", "G6", "G7", "G8", "G10",',
     "G9 (Review & Run) never loaded"),
    ("X3", "harness/gate.py", '    if (run / "oracle").is_dir() and any((run / "oracle").iterdir()):', "    if False:",
     "O-5 check never added"),
    ("X4", "harness/gate.py", "            new = redact.scrub_text(text)", "            new = text",
     "trace.zip members not scrubbed"),
    ("F1", "harness/fieldmap.py", '"key_size": norm_int, "job_id": norm_int,', '"key_size": lambda v: None, '
     '"job_id": norm_int,', "key_size equal in every view join"),
    ("F2", "harness/fieldmap.py", 'SAMPLED = {"cipher_suites", "groups"}',
     'SAMPLED = {"cipher_suites", "groups", "protocol_versions"}', "protocol versions judged as a sample"),
    ("S1", "harness/standards.py", '    if kinds == {"pq"}:\n        return False', '    if kinds == {"pq"}:\n'
     "        return True", "all-PQ key exchange called vulnerable"),
    ("S2", "harness/standards.py", '    if kinds == {"classical"}:\n        return True', '    if kinds == {"classical"}:\n'
     "        return None", "classical-only key exchange not derived"),
    # ---- review 5878413538: the reviewer's 15 mutants (rv-75-r2/bin/mymutants.py), anchors moved to the round-3 code
    ("R1", "harness/timing.py", 'if str(k) == "1" else end) + SLACK', 'if str(k) == "1" else end) + dt.timedelta(days=1)',
     "DB rows up to a day after G10 pass (no upper bound)"),
    ("R2", "harness/timing.py", "SLACK = dt.timedelta(seconds=120)", "SLACK = dt.timedelta(hours=6)",
     "six hours of clock slack"),
    ("R3", "harness/timing.py", "ok_meta = meta_ts is not None and lo <= meta_ts <= hi and meta_ts.date() == start.date()",
     "ok_meta = meta_ts is not None and lo <= meta_ts and meta_ts.date() == start.date()",
     "export metadata.timestamp after the run passes"),
    ("R4", "harness/timing.py", "    if not UUID_URN.match(serial.lower()):\n        problems", '    if not serial.startswith("urn:uuid:"):\n        problems',
     "any urn:uuid: prefix is a serial number"),
    ("R5", LOGS, 'if int(j.get("asset_count") or 0) > 0:', 'if int(j.get("asset_count") or 0) > 1:',
     "a job that stored exactly one asset needs no 'assets stored' line"),
    ("R6", JOIN, 'and (db_n is None or db_n == want), "count-mismatch"', 'and True, "count-mismatch"',
     "ui_total no longer compares the DB row count"),
    ("R7", "harness/rundir.py", 'found |= {str(i + 1) for i in range(len(state.get("runs") or []))}', "pass",
     "a run the flow started with no oracle/API files is skipped"),
    ("R8", JOIN, 'if run_id is None or str(r.get("run_id")) == str(run_id)]', "]",
     "DB rows of other runs join this run's view"),
    ("R9", LED, 'if row.get("not_run_ok") and not n_run and not pinning:', "if False:",
     "not_run_ok without a pinned NOT-RUN accepted"),
    ("R10", "harness/standards.py", '    "SecP256r1MLKEM768", "X25519MLKEM768", "SecP384r1MLKEM1024",',
     '    "X25519MLKEM768", "SecP384r1MLKEM1024",', "SecP256r1MLKEM768 dropped from the PQ table"),
    ("R11", "harness/standards.py", '"export": lambda s: "_EXPORT" in s,', '"export": lambda s: False,',
     "EXPORT suites not a weak class"),
    ("R12", ORA, 'return (bits.get(alg), f"derived: bits of the {alg or \'?\'} host key") if alg in bits else None',
     'return (max(b or 0 for b in bits.values()), "derived: largest host key") if alg in bits else None',
     "SSH key size derived from the largest host key"),
    ("R13", ORA, 'return bool(got) and (F.norm_suites([got]) or [""])[0] in allowed', "return bool(got)",
     "derived TLS suite: any reported suite passes"),
    ("R14", ORA, 'len(cov) == 1 and not other, "empty-address"', 'len(cov) <= 1 and not other, "empty-address"',
     "an empty address with no coverage row passes"),
    ("R15", ORA, 'unverified |= {(str(oid).split("[", 1)[0], str(key)) for key in keys or []}',
     'unverified |= {(str(oid).split("[", 1)[0], str(key)) for key in (keys or [])[:1]}',
     "only the first unverified key per oracle row is NOT-JUDGED"),
    # ---- round 3's own new code (compare-first, verdict fields, identities, never-scan, timing, G17)
    ("U1", ORA, "                        same = got_raw is not F.MISSING and got == want", "                        same = True",
     "an unverified key passes NOT-JUDGED whatever the product says (5c, N4)"),
    ("U2", ORA, "same = got_raw is not F.MISSING and bool(got) and set(got) <= set(want or [])", "same = True",
     "an unverified sampled list passes NOT-JUDGED whatever the product says"),
    ("U3", ORA, "    if same:\n        checks.not_judged(", "    if True:\n        checks.not_judged(",
     "disagreement with an unverified lab value is NOT-JUDGED, not FAIL"),
    ("U4", ORA, 'bool(got) and (F.norm_suites([got]) or [""])[0] in STD.TLS13_SUITES', "True",
     "a TLS 1.3-only endpoint may report any suite (N3)"),
    ("V1", ORA, 'the lab states no codes_include"},\n                       observed=sorted(codes))',
     'the lab states no codes_include"})', "unjudged codes carry no shown value, so a pinned row cannot see them change (N12)"),
    ("V2", ORA, 'F.IMPACT_RANK.get(got, 4) <= F.IMPACT_RANK.get(asset["impact_min"], 4), "impact-too-low"',
     'True, "impact-too-low"', "impact_min never judged"),
    ("V3", ORA, '    if not asset.get("codes_include"):\n        checks.not_run(', "    if False:\n        checks.not_run(",
     "the lab's silence on codes is not named"),
    ("I1", "harness/identity.py", '        out["observed"] = normalise_value(check.observed, maps, field)\n    elif',
     "    elif", "pins ignore the product's value (N6: a worse regression under one check)"),
    ("I2", "harness/identity.py", 'out: dict[str, Any] = {"id": normalise_id(check.id, maps), "verdict": check.verdict}',
     'out: dict[str, Any] = {"id": normalise_id(check.id, maps).split("/asset/")[0], "verdict": check.verdict}',
     "pins ignore which asset failed (N8, N8b: swaps)"),
    ("N1", "harness/neverscan.py", 'node = [x for x in after if str(x.get("peer", "")).rsplit(":", 1)[0] in node_ips]',
     "node = []", "the sealed canary log is not recounted (N11)"),
    ("N2", "harness/neverscan.py", "missing = lines is None", "missing = False", "a missing listener log reads as zero (N11b)"),
    ("N3", "harness/neverscan.py", 'if (parse_ts(x.get("ts")) or start) >= start]', "]",
     "node connections before Start (CB-05's G4 tests) count"),
    ("T5", "harness/timing.py", "outside_rec = sorted(name for name, t in record.items() if t is None or not lo <= t <= stored_by)",
     "outside_rec = []", "the run record's dates are not judged (N9b)"),
    ("T6", "harness/timing.py", 'problems += [f"same as run {kk}\'s export" for kk, s in others.items() if s and s == serial]',
     "problems += []", "run 1 and run 2 may share a serial number"),
    ("T7", "harness/timing.py", '    else:\n        checks.not_run(f"G11/db_created_in_run_window/run{k}"',
     '    elif False:\n        checks.not_run(f"G11/db_created_in_run_window/run{k}"', "no DB row for the run passes silently"),
    ("J12", JOIN, "if len(numbers) == 1 else None", "if numbers else None", "a header with two numbers reads the first (N10)"),
    ("K1", "harness/bundle.py", 'return bool(h.get("commit")) and h.get("dirty") is False and not h.get("untracked")',
     'return bool(h.get("commit"))', "a dirty or untracked judge passes G17"),
]


def run_suite(root: Path) -> tuple[bool, str]:
    p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "-o", "addopts=", "tests"],
                       cwd=root, capture_output=True, text=True, timeout=600)
    last = (p.stdout.strip().splitlines() or [""])[-1]
    return p.returncode == 0, last


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)
    only = {x for x in args.only.split(",") if x}
    results = []
    with tempfile.TemporaryDirectory(prefix="cbom-mut-") as tmp:
        for mid, rel, old, new, what in M:
            if only and mid not in only:
                continue
            root = Path(tmp) / "cbom"
            shutil.rmtree(root, ignore_errors=True)
            shutil.copytree(CBOM, root, ignore=shutil.ignore_patterns("__pycache__", "node_modules", "tools"))
            f = root / rel
            text = f.read_text(encoding="utf-8")
            n = text.count(old)
            if n != 1:
                results.append({"id": mid, "file": rel, "status": f"INVALID (anchor found {n}x)", "what": what})
                print(f"{mid:4s} INVALID  {rel:22s} anchor found {n}x", flush=True)
                continue
            f.write_text(text.replace(old, new), encoding="utf-8")
            passed, last = run_suite(root)
            status = "SURVIVED" if passed else "killed"
            results.append({"id": mid, "file": rel, "status": status, "what": what, "pytest": last})
            print(f"{mid:4s} {status:8s} {rel:22s} {what}  [{last}]", flush=True)
    killed = sum(r["status"] == "killed" for r in results)
    print(f"score: {killed}/{len(results)} killed")
    if args.out:
        args.out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    return 0 if killed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
