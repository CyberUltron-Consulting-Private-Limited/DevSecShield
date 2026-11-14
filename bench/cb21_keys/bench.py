"""CB-21 PR-1 bench: the team view's Sources side (``collections_view.load_sources_result`` + ``resolve``) at N
assets (default 50,000), SQLite, dev vs branch (run the same file with PYTHONPATH at each tree).

One team, 20 sources (prober, Linux, Windows, AWS kinds), N assets in their latest successful collect jobs:
40 % certificates (prober chains, files, Windows store rows without serials, ACM rows with Issuer "Amazon"; the same
certificate seen by up to four sources, a lab CA in every fourth chain, SAN-only leaves), 20 % TLS / SSH endpoints
(IPv4 and IPv6), 40 % keys, libraries and configuration. Measured p50 / max of REPS repetitions:

* ``load_sources_result``  the DB read + rows + certificate correlation (what every team view calls);
* ``resolve``              "latest observation wins" over those rows with 2,000 code-scan certificate keys;
* ``counted``              certificates counted after resolve (branch < dev: Windows rows now join).

Usage (repo root): PYTHONPATH=<tree> python bench/cb21_keys/bench.py [N] [REPS]
"""
from __future__ import annotations

import datetime as dt
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource
from backend.utilities.cbom_sources import collections_view as CV

N = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
REPS = int(sys.argv[2]) if len(sys.argv) > 2 else 5
KINDS = ["network", "linux_servers", "windows_servers", "aws_account"]


def cert_facts(c: int, kind: str) -> dict:
    serial = format(0x9F00000000000000000000000000000 + c * 7919, "x")
    after = (dt.datetime(2027, 1, 1) + dt.timedelta(seconds=c * 37)).strftime("%Y-%m-%dT%H:%M:%SZ")
    subject = "" if c % 23 == 0 else f"CN=host-{c}.example.com,O=Example Corp"
    issuer = "CN=Example Issuing CA 2,O=Example Corp,C=US"
    if c % 4 == 3:  # the lab CA, chain[1] everywhere
        return {"subject": "CN=Lab CA", "issuer": "CN=Lab CA", "serial": "3e8", "not_after": "2036-01-01T00:00:00Z",
                "fingerprint_sha256": "5a" * 32, "is_ca": True}
    if kind == "windows_servers":
        return {"subject": subject.replace(",", ", "), "issuer": issuer.replace(",", ", "),
                "thumbprint": format(c, "040x").upper(), "not_after": after.replace("Z", ".0000000Z"),
                "source": "windows-store"}
    if kind == "aws_account":
        colon = ":".join(serial.zfill(32)[i:i + 2] for i in range(0, 32, 2))
        return {"subject": subject.split(",")[0], "issuer": "Example Corp", "serial": colon,
                "not_before": "2026-01-01T00:00:00Z", "not_after": after, "source": "aws"}
    return {"subject": subject, "issuer": issuer, "serial": serial, "not_before": "2026-01-01T00:00:00Z",
            "not_after": after, "fingerprint_sha256": format(c, "064x"), "san": [f"host-{c}.example.com"]}


def seed(engine) -> None:
    with Session(engine) as s:
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="bench", status="success")
        s.add(run)
        s.flush()
        jobs = []
        for n in range(20):
            kind = KINDS[n % 4]
            src = CbomCollectionSource(team_id=1, owner_user_id=1, kind=kind, name=f"{kind}-{n}", name_lower=f"{kind}-{n}",
                                       config={})
            s.add(src)
            s.flush()
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                    attempts=1, finished_at=dt.datetime(2026, 11, 1) + dt.timedelta(minutes=n), params={})
            s.add(job)
            s.flush()
            jobs.append((job, src, kind))
        rows = []
        for i in range(N):
            job, src, kind = jobs[i % 20]
            bucket = i % 10
            common = dict(team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1, finding_codes=[])
            if bucket < 4:
                c = i // 40 * 4 + (i % 4)  # the same certificate is seen by up to four sources
                rows.append(CbomCollectedAsset(**common, asset_key=f"c{i}", asset_type="certificate", cdx_type="certificate",
                                               target=f"10.1.{i % 250}.{i % 200}", location=f"loc-{i}#chain[{i % 2}]",
                                               name="cert", algorithm="RSA", key_size=2048, facts=cert_facts(c, kind)))
            elif bucket < 6:
                host = f"[2001:db8::{i:x}]" if i % 3 == 0 else f"10.2.{i // 250 % 250}.{i % 250}"
                rows.append(CbomCollectedAsset(**common, asset_key=f"e{i}", asset_type="tls_endpoint" if i % 2 else "ssh_endpoint",
                                               cdx_type="protocol", target=host.strip("[]"), location=f"{host}:{443 if i % 2 else 22}",
                                               name="ep", protocol="TLSv1.3", facts={"protocols": ["TLSv1.3"]}))
            else:
                rows.append(CbomCollectedAsset(**common, asset_key=f"k{i}", asset_type="private_key" if bucket < 8 else "crypto_library",
                                               cdx_type="related-crypto-material" if bucket < 8 else "library",
                                               target=f"h{i % 300}", location=f"/etc/k/{i}", name="k", algorithm="RSA",
                                               key_size=2048, facts={"key_alg": "RSA", "key_size": 2048}))
        s.add_all(rows)
        s.commit()


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        engine = create_engine(f"sqlite:///{Path(tmp) / 'b.db'}")
        SQLModel.metadata.create_all(engine)
        seed(engine)
        code_keys = []
        try:
            from backend.utilities.cbom_sources.asset_keys import code_certificate_key as code_key
        except ImportError:  # dev
            code_key = CV.cert_identity
        for c in range(0, 8000, 4):
            f = cert_facts(c, "network")
            code_keys.append((1, dt.datetime(2026, 10, 1), code_key(f["subject"].split(",")[0].split("=")[-1],
                                                                      "Example Issuing CA 2", f["not_before"], f["not_after"])))
        code_keys = [o for o in code_keys if o[2]]
        load, res = [], []
        counted = None
        for _ in range(REPS):
            with Session(engine) as s:
                t0 = time.perf_counter()
                result = CV.load_sources_result(s, 1, now=dt.datetime(2026, 11, 14))
                load.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            resolution = CV.resolve(code_keys, result.rows)
            res.append(time.perf_counter() - t0)
            counted = sum(1 for item in resolution.sources_rows if item.row.get("algorithm_type") == "certificate")
        print(json.dumps({"n": N, "reps": REPS, "rows": len(result.rows),
                          "load_sources_result_p50_s": round(statistics.median(load), 3), "load_max_s": round(max(load), 3),
                          "resolve_p50_s": round(statistics.median(res), 4), "resolve_max_s": round(max(res), 4),
                          "certificates_counted": counted, "code_rows_dropped": len(resolution.dropped_code)}))


if __name__ == "__main__":
    main()
