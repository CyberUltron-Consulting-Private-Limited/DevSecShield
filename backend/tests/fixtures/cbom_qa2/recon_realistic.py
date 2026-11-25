"""PR #496 review: reconciliation chain on a realistic team.

usage: python recon_realistic.py <worktree> <out_dir>
Seeds a SQLite team with: a certificate read in two places (lab-mssql master/msdb), an AWS account collected twice
(the first collection superseded), a cross-source duplicate certificate (ACM + Kubernetes secret, same fingerprint),
two network probes of one endpoint, a deleted source with a last collection, a repository scanned twice (superseded),
a second repository whose scan repeats one row, and a failed scan. Prints the view headline, the reconciliation block,
whether each document prints it, the dashboard card + block, and independent counts for each bucket.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

WT = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2]).resolve()
OUT.mkdir(parents=True, exist_ok=True)
sys.path[:0] = [str(WT), str(WT / "backend"), str(WT / "backend" / "tests")]

from sqlmodel import Session, select  # noqa: E402

from test_cbom_cb20_estate import World, _sqlite, cert  # noqa: E402
from test_cbom_deliverable_pqc_roadmap import pdf_full_text  # noqa: E402

from backend.new_models import CbomCollectionSource, CbomEstateAsset, Scan  # noqa: E402
from backend.utilities.cbom_sources import reconciliation as RECON  # noqa: E402
from backend.utilities.cbom_sources import risk_register as REG  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import DELIVERABLES  # noqa: E402

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 11, 20, 9, tzinfo=UTC)


def squash(t: str) -> str:
    return re.sub(r"\s+", " ", t)


def c(location, fp, size=1024, alg="RSA", name="CN=x", qv=True, impact="High", codes=("QUANTUM_VULNERABLE",),
      target=None, sig=None):
    row = cert(target or location.split("/")[0], location, serial=fp[:16].upper(), not_after="2028-01-31T00:00:00Z",
               fingerprint_sha256=fp * (64 // len(fp)), subject=name, issuer=name, key_alg=alg, key_size=size,
               **({"signature_algorithm": sig} if sig else {}))
    return {**row, "name": name, "qv": qv, "impact": impact, "codes": list(codes)}


def key(arn, name, alg, qv, impact=None, codes=("QUANTUM_VULNERABLE",), facts=None, typ="kms_key"):
    return {"type": typ, "target": arn, "location": "kms", "name": name, "algorithm": alg, "qv": qv,
            "impact": impact, "codes": list(codes), "facts": facts or {}}


def ep(host):
    return {"type": "tls_endpoint", "target": host, "location": f"{host}:443", "name": "TLS", "algorithm": "ECDHE-RSA",
            "qv": True, "impact": "High", "codes": ["PROTO_TLS10", "QUANTUM_VULNERABLE"],
            "facts": {"protocol": "TLSv1.0", "negotiated_group": "secp256r1", "port": 443}}


def code_row(title, ref, qv, size=1024, loc=None):
    return {"title": title, "algorithm_name": title.split("-")[0], "asset_type": "algorithm", "algorithm_type": "pke",
            "location": loc or f"src/{ref}.py:1", "bom_ref": ref, "impact": "High", "key_size": size,
            "finding_codes": ["QUANTUM_VULNERABLE"], "quantum_vulnerable": qv, "quantum_safe": None if qv is None else not qv}


def scan(engine, sid, created, repo, rows, status="success"):
    with Session(engine) as s:
        s.add(Scan(id=sid, team_id=1, owner_user_id=1, scan_type="cbom", title=repo, scan_status=status,
                   scan_metadata={"repo_url": f"https://github.com/acme/{repo}", "branch": "main"}, created_at=created,
                   last_updated=created, scan_data={"results": rows}))
        s.commit()


def seed(db: Path) -> World:
    w = World(_sqlite(db))
    mssql = w.source("database", "lab-mssql")
    aws = w.source("aws_account", "aws-prod")
    k8s = w.source("kubernetes", "k8s-prod")
    na, nb = w.source("network_range", "dmz-a"), w.source("network_range", "dmz-b")
    vault = w.source("vault", "old-vault")
    acm_fp = "a1"
    aws_rows_1 = [key("arn:k/a", "legacy-3des", "DES-EDE3", None, "High", ["WEAK_ALGORITHM"], typ="managed_key"),
                  key("arn:k/b", "aes-128", "AES", True, "Low", facts={"key_size": 128}, typ="managed_key"),
                  key("arn:k/c", "signer", "RSA_2048", True, facts={"key_spec": "RSA_2048", "key_usage": "SIGN_VERIFY"}),
                  key("arn:k/d", "aes-256", "AES", False, codes=(), facts={"key_size": 256}, typ="managed_key"),
                  {"type": "appliance_config", "target": "fw-1", "location": "fw-1#policy", "name": "unknown policy",
                   "algorithm": None, "qv": True, "impact": None, "codes": ["QUANTUM_VULNERABLE"], "facts": {}},
                  c("acm/pay", acm_fp, 2048, name="CN=pay.example.com", impact="Medium", target="acm")]
    r1 = w.run({mssql: {"rows": [c("lab-mssql:1433/master", "9f"), c("lab-mssql:1433/msdb", "9f")]},
                aws: {"rows": aws_rows_1},
                k8s: {"rows": [c("ns/pay-tls", acm_fp, 2048, name="CN=pay.example.com", impact="Medium", target="k8s"),
                               c("ns/legacy", "b7", 2048, name="CN=legacy", sig="sha1WithRSAEncryption",
                                 codes=("WEAK_SIGNATURE", "QUANTUM_VULNERABLE"), target="k8s")]},
                na: {"rows": [ep("pay.example.com")]}, nb: {"rows": [ep("pay.example.com")]},
                vault: {"rows": [key("vault:k/1", "v1", "RSA_2048", True, facts={"key_spec": "RSA_2048"}),
                                 key("vault:k/2", "v2", "RSA_2048", True, facts={"key_spec": "RSA_2048"}),
                                 key("vault:k/3", "v3", "EC_P256", True, facts={"key_spec": "ECC_NIST_P256"})]}})
    w.finalise(r1)
    # aws collected again: the policy is gone, an RSA-3072 key is new (the first collection is superseded)
    aws_rows_2 = [r for r in aws_rows_1 if r["target"] != "fw-1"] + [
        key("arn:k/e", "rsa3072", "RSA_3072", True, facts={"key_spec": "RSA_3072", "key_usage": "ENCRYPT_DECRYPT"})]
    r2 = w.run({aws: {"rows": aws_rows_2}})
    w.finalise(r2)
    with Session(w.engine) as s:  # old-vault deleted after its collection (staging Q1-01)
        s.delete(s.get(CbomCollectionSource, vault))
        s.commit()
    scan(w.engine, 901, dt.datetime(2026, 11, 1, 9), "pay", [code_row("RSA-1024", "rsa", True), code_row("RSA-512", "old", True)])
    scan(w.engine, 902, dt.datetime(2026, 11, 10, 9), "pay", [code_row("RSA-1024", "rsa", True)])
    scan(w.engine, 903, dt.datetime(2026, 11, 11, 9), "api", [code_row("ECDSA-256", "ec", True, 256),
                                                               code_row("ECDSA-256", "ec", True, 256),
                                                               code_row("ML-KEM-768", "mlkem", False, 768)])
    scan(w.engine, 904, dt.datetime(2026, 11, 12, 9), "api", [code_row("RSA-2048", "r2", True, 2048)], status="failure")
    return w


def main() -> None:
    db = OUT / "realistic.db"
    if db.exists():
        db.unlink()
    w = seed(db)
    view = load_team_cbom_view(w.engine, 1, now=NOW)
    pop = RECON.from_view(view)
    lines = RECON.lines(pop)
    report: dict = {"headline": {"asset_occurrences": view.asset_occurrences, "pqc_vulnerable": view.pqc_vulnerable,
                                 "readiness_pct": view.readiness_pct},
                    "collections": [(col.label, col.source_kind, col.asset_count) for col in view.collections],
                    "population": {k: v for k, v in pop.__dict__.items() if k != "register"},
                    "register_summary": {k: (pop.register or {}).get(k) for k in ("total", "q_grades", "sow_classes", "presence")},
                    "lines": lines, "documents": {}}
    for slug, n in (("scope-baseline-register", 1), ("quantum-risk-register", 12), ("pqc-migration-roadmap", 13),
                    ("board-executive-report", 14)):
        pdf = DELIVERABLES[slug].build(view)
        (OUT / f"D{n}.pdf").write_bytes(pdf)
        text = squash(pdf_full_text(pdf))
        report["documents"][f"D{n}"] = {"all_lines": all(squash(ln) in text for ln in lines),
                                        "missing": [ln[:60] for ln in lines if squash(ln) not in text]}
    from backend.utilities.cbom_sources.collections_view import load_sources_result
    from backend.utilities.dashboard import scan_list
    scan_list.get_findings_for_scan_id = lambda **_kw: []
    with Session(w.engine) as s:
        scans = s.exec(select(Scan).where(Scan.team_id == 1)).all()
        summary = REG.summary(s, 1, NOW.replace(tzinfo=None))
        board = scan_list.generate_cbom_dashboard_data(list(scans), load_sources_result(s, 1, NOW), team_id=1,
                                                       register_summary=summary, now=NOW)
        estate = s.exec(select(CbomEstateAsset).where(CbomEstateAsset.team_id == 1)).all()
    card = board["card_data"]
    report["dashboard"] = {"total_crypto_assets": card["total_crypto_assets"],
                           "total_quantum_vulnerable": card["total_quantum_vulnerable"],
                           "quantum_readiness_score": card["quantum_readiness_score"],
                           "steps": [st["text"] for st in (board.get("population") or {}).get("steps", [])]}
    # independent counts, not residuals
    live_src = [a for a in view.assets if a.current and a.source_key.startswith("sources:")]
    deleted = [col for col in view.collections if not col.source_kind]
    report["independent"] = {
        "deleted_source_collections": [(col.label, col.asset_count) for col in deleted],
        "deleted_source_current_assets": sum(1 for a in live_src if any(a.source_key == col.key for col in deleted)),
        "estate_assets": len(estate), "estate_by_presence": {p: sum(1 for e in estate if e.presence == p)
                                                              for p in {e.presence for e in estate}},
        "code_occurrences_current": sum(1 for a in view.assets if a.current and not a.source_key.startswith("sources:")),
    }
    (OUT / "recon_realistic.json").write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps(report, indent=1, default=str))


if __name__ == "__main__":
    main()
