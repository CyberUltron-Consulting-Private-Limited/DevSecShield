"""CB-06 scale exit (S): the run CycloneDX export of 50,000 components, p95 time, before vs after.

    # 1. one SQLite database with a 50k-asset run (rows classified by the product's own classifier, as ingest does)
    PYTHONPATH=<repo> python bench/cb06_export/bench.py make-db /tmp/cb06.db --assets 50000
    # 2. time the export with one code tree (one JSON line per iteration: build, +json.dumps, +to_xml)
    PYTHONPATH=<repo> python bench/cb06_export/bench.py time /tmp/cb06.db --iterations 1
    # 3. A/B, interleaved so machine noise hits both sides alike: A = base tree, B = head tree
    python bench/cb06_export/bench.py ab /tmp/cb06.db --a <base repo> --b <head repo> --rounds 10 --out result.json

One export = what the route does: ``inventory.cyclonedx`` then ``json.dumps`` (format json) or ``cdx_xml.to_xml``
(format xml); each iteration builds once and times both serialisations of that build. The database is read-only during timing. The mix (certificates, TLS and SSH endpoints, private keys,
libraries, KMS keys, coverage rows) follows what the lab and a mid-size estate produce; every certificate and endpoint
carries the facts the collectors write, so the new per-component work (nested certificate parts, groups, provenance)
is exercised at full size. Each record has wall time and process CPU time: on a shared host the wall time includes
waiting for a CPU, so the report gives the head/base p95 ratio of both.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import resource
import statistics
import subprocess
import sys
import time

MIX = (("certificate", 0.30), ("tls_endpoint", 0.25), ("ssh_endpoint", 0.10), ("private_key", 0.10),
       ("crypto_library", 0.10), ("kms_key", 0.10), ("coverage", 0.05))


def _asset(kind: str, i: int) -> dict:
    host = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
    if kind == "certificate":
        ec = i % 3 == 0
        facts = {"subject": f"CN=h{i}.bank.local", "issuer": "CN=Bank Issuing CA 2", "not_before": "2026-01-01T00:00:00Z",
                 "not_after": "2027-12-31T00:00:00Z", "sig_alg": "ecdsa-with-SHA256" if ec else "sha256WithRSAEncryption",
                 "key_alg": "EC" if ec else "RSA", "key_size": 256 if ec else (2048 if i % 2 else 3072),
                 "fingerprint_sha256": f"{i:064x}", "serial": f"{i:x}", "san": [f"h{i}.bank.local"]}
        if ec:
            facts["curve"] = "secp256r1"
        return {"type": kind, "target": host, "location": f"{host}:443#cert", "name": f"h{i}", "algorithm": facts["key_alg"],
                "key_size": facts["key_size"], "facts": facts}
    if kind == "tls_endpoint":
        hybrid = i % 4 == 0
        return {"type": kind, "target": host, "location": f"{host}:443", "protocol": "TLSv1.3",
                "facts": {"versions": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
                          "negotiated_version": "TLSv1.3", "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
                          "negotiated_group": "X25519MLKEM768" if hybrid else "X25519", "pq_hybrid": hybrid,
                          "pq_group": "X25519MLKEM768" if hybrid else None, "fallback_scsv": True}}
    if kind == "ssh_endpoint":
        return {"type": kind, "target": host, "location": f"{host}:22",
                "facts": {"kex": ["curve25519-sha256", "diffie-hellman-group14-sha256"], "host_key_algs": ["ssh-ed25519"],
                          "ciphers_c2s": ["aes256-gcm@openssh.com"], "ciphers_s2c": ["aes256-gcm@openssh.com"],
                          "macs_c2s": ["hmac-sha2-256-etm@openssh.com"], "macs_s2c": ["hmac-sha2-256-etm@openssh.com"]}}
    if kind == "private_key":
        return {"type": kind, "target": host, "location": f"/etc/ssl/private/k{i}.key", "algorithm": "RSA",
                "key_size": 2048, "facts": {"format": "pem", "encrypted": False}}
    if kind == "crypto_library":
        return {"type": kind, "target": host, "location": "package:openssl", "name": "openssl",
                "facts": {"name": "openssl", "version": "3.0.13-0ubuntu3.4", "source": "package", "ecosystem": "deb"}}
    if kind == "kms_key":
        return {"type": kind, "target": "111122223333", "location": f"arn:aws:kms:ap-south-1:111122223333:key/{i:08x}",
                "name": f"alias/k{i}", "algorithm": "SYMMETRIC_DEFAULT",
                "facts": {"key_spec": "SYMMETRIC_DEFAULT", "key_state": "Enabled", "rotation_enabled": i % 2 == 0}}
    return {"type": "coverage", "target": "111122223333", "location": f"arn:aws:kms:region-{i}:111122223333:kms",
            "facts": {"check": f"kms in region-{i}", "status": "denied", "detail": "AccessDeniedException"}}


def make_db(path: str, assets: int) -> None:
    from sqlmodel import Session, SQLModel, create_engine

    from backend.new_models import (CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource,
                                    CbomScanNode, Team)
    from backend.utilities.cbom_sources.classify import classify

    if os.path.exists(path):
        os.remove(path)
    engine = create_engine(f"sqlite:///{path}")
    SQLModel.metadata.create_all(engine)
    now = dt.datetime(2026, 11, 12, 12, 0, 0)
    with Session(engine) as s:
        s.add(Team(id=1, name="Bench", credit_balance=0.0))
        s.add(CbomScanNode(id=1, team_id=1, owner_user_id=1, name="node-1", enrolled_at=now - dt.timedelta(days=30),
                           node_version="1.0.0+0123456789ab", signing_public_key="A" * 43 + "="))
        s.add(CbomCollectionSource(id=1, team_id=1, owner_user_id=1, kind="linux_servers", name="dc", name_lower="dc",
                                   node_id=1))
        s.add(CbomCollectionSource(id=2, team_id=1, owner_user_id=1, kind="aws_account", name="aws", name_lower="aws"))
        s.add(CbomCollectionRun(id=1, team_id=1, owner_user_id=1, client_request_id="bench", status="done",
                                kb_version="bench", classifier_version="bench", engine_version="bench"))
        s.add(CbomCollectionJob(id=1, team_id=1, run_id=1, source_id=1, node_id=1, kind="collect", status="success",
                                attempts=1, result={"node_version": "1.0.0+0123456789ab"}, outcome="ok"))
        s.add(CbomCollectionJob(id=2, team_id=1, run_id=1, source_id=2, node_id=None, kind="collect", status="success",
                                attempts=1, result={"node_version": "cloud-worker-1.0"}, outcome="partial"))
        s.commit()
        rows, i = [], 0
        for kind, share in MIX:
            for _ in range(int(assets * share)):
                a = _asset(kind, i)
                v = classify(a["type"], a.get("algorithm"), a.get("key_size"), a.get("protocol"), a["facts"], now)
                rows.append({"team_id": 1, "run_id": 1, "job_id": 2 if kind in ("kms_key", "coverage") else 1,
                             "source_id": 2 if kind in ("kms_key", "coverage") else 1, "attempt": 1,
                             "asset_key": f"{i:064x}", "asset_type": a["type"], "cdx_type": v["cdx_type"],
                             "target": a["target"], "location": a["location"], "name": a.get("name"),
                             "algorithm": a.get("algorithm"), "key_size": a.get("key_size"), "protocol": a.get("protocol"),
                             "quantum_vulnerable": v["quantum_vulnerable"], "impact": v["impact"],
                             "finding_codes": v["finding_codes"], "finding": v["finding"], "facts": a["facts"],
                             "created_at": now})
                i += 1
        for start in range(0, len(rows), 2000):
            s.execute(CbomCollectedAsset.__table__.insert(), rows[start:start + 2000])
        s.commit()
    print(json.dumps({"db": path, "assets": len(rows)}))


def time_export(path: str, iterations: int) -> None:
    """One ``cyclonedx`` build per iteration, then both serialisations of it: json = build + json.dumps,
    xml = build + to_xml (each is exactly what one download of that format costs)."""
    from sqlmodel import Session, create_engine

    from backend.new_models import CbomCollectionRun
    from backend.utilities.cbom_sources import cdx_xml, inventory

    engine = create_engine(f"sqlite:///{path}")
    now = dt.datetime(2026, 11, 12, 13, 0, 0)
    for _ in range(iterations):
        with Session(engine) as s:
            run = s.get(CbomCollectionRun, 1)
            t0, c0 = time.perf_counter(), time.process_time()
            doc = inventory.cyclonedx(s, run, now)
            t1, c1 = time.perf_counter(), time.process_time()
            as_json = json.dumps(doc).encode()
            t2, c2 = time.perf_counter(), time.process_time()
            as_xml = cdx_xml.to_xml(doc)
            t3, c3 = time.perf_counter(), time.process_time()
        print(json.dumps({"build_s": round(t1 - t0, 4), "build_cpu_s": round(c1 - c0, 4),
                          "json": {"seconds": round(t2 - t0, 4), "cpu": round(c2 - c0, 4), "bytes": len(as_json)},
                          "xml": {"seconds": round(t1 - t0 + t3 - t2, 4), "cpu": round(c1 - c0 + c3 - c2, 4),
                                  "bytes": len(as_xml)},
                          "maxrss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024,
                          "components": len(doc["components"])}), flush=True)


def _p95(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, int(round(0.95 * len(ordered))) - 1)]


def ab(path: str, a: str, b: str, rounds: int, out: str | None) -> None:
    """Alternate A and B (one export each per step, both formats), ``rounds`` steps; p50/p95 per side and format."""
    results: dict[str, dict[str, list]] = {side: {"json": [], "xml": [], "json_cpu": [], "xml_cpu": []}
                                           for side in ("a", "b")}
    meta: dict[str, dict] = {"a": {}, "b": {}}
    for step in range(rounds):
        for side, tree in (("a", a), ("b", b)) if step % 2 == 0 else (("b", b), ("a", a)):
            env = {**os.environ, "PYTHONPATH": tree}
            line = subprocess.run([sys.executable, __file__, "time", path, "--iterations", "1"],
                                  env=env, capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
            rec = json.loads(line)
            for fmt in ("json", "xml"):
                results[side][fmt].append(rec[fmt]["seconds"])
                results[side][f"{fmt}_cpu"].append(rec[fmt]["cpu"])
                meta[side][fmt] = meta[side][f"{fmt}_cpu"] = {"bytes": rec[fmt]["bytes"], "components": rec["components"],
                                                              "maxrss_mb": rec["maxrss_mb"]}
            print(json.dumps({"step": step, "side": side, **rec}), file=sys.stderr, flush=True)
    report = {"rounds": rounds, "db": path, "a": a, "b": b, "sides": {}}
    for side in ("a", "b"):
        report["sides"][side] = {fmt: {"p50": round(statistics.median(v), 3), "p95": round(_p95(v), 3),
                                       "min": round(min(v), 3), "max": round(max(v), 3), "n": len(v), **meta[side][fmt]}
                                 for fmt, v in results[side].items()}
    # wall time on a shared host includes waiting for a CPU; process CPU time is the code's own cost
    report["ratio_p95"] = {fmt: round(report["sides"]["b"][fmt]["p95"] / report["sides"]["a"][fmt]["p95"], 3)
                           for fmt in ("json", "xml", "json_cpu", "xml_cpu")}
    report["loadavg_end"] = os.getloadavg()
    report["raw"] = results
    text = json.dumps(report, indent=1)
    if out:
        with open(out, "w") as fh:
            fh.write(text + "\n")
    print(text)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make-db")
    m.add_argument("db")
    m.add_argument("--assets", type=int, default=50_000)
    t = sub.add_parser("time")
    t.add_argument("db")
    t.add_argument("--iterations", type=int, default=1)
    c = sub.add_parser("ab")
    c.add_argument("db")
    c.add_argument("--a", required=True)
    c.add_argument("--b", required=True)
    c.add_argument("--rounds", type=int, default=10)
    c.add_argument("--out")
    args = p.parse_args()
    if args.cmd == "make-db":
        make_db(args.db, args.assets)
    elif args.cmd == "time":
        time_export(args.db, args.iterations)
    else:
        ab(args.db, args.a, args.b, args.rounds, args.out)


if __name__ == "__main__":
    main()
