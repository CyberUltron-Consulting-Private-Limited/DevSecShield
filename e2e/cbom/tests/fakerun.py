"""A complete, internally consistent run directory for the harness's own tests.

Every view is rendered from one list of asset specs in the shapes the product serves (API items as
``inventory.public_asset``, DB rows as ``cbomcollectedasset`` columns, CycloneDX components with ``zs-asset-<id>``,
DOM rows as the Results table renders them), and the oracle is written from the same specs, so a fresh FakeRun judges
PASS. Each test then breaks exactly one thing ("a deliberately wrong CBOM") and checks the gate notices.

The export written here is the *complete* one (with the fields CB-06 will add); ``legacy_export=True`` writes the
export as dev 83b570b does (no key size on certificates, no curve, signature algorithm, groups, pqc class or
provenance), which is what KF-9 records.
"""
from __future__ import annotations

import copy
import csv
import json
from pathlib import Path
from typing import Any

from harness import manifest
from harness.gate import FLOW_STEPS

PROVENANCE = {"zs:collector": "network", "zs:node_id": "7", "zs:node_build": "abc1234", "zs:job_id": None,
              "zs:attempt": "1", "zs:method": "agentless", "zs:collected_at": "2026-11-12T09:00:00Z",
              "zs:signed": "true"}

ASSETS: list[dict[str, Any]] = [
    {"id": 101, "type": "certificate", "cdx": "certificate", "target": "10.231.0.17",
     "location": "10.231.0.17:443", "name": "CN=z01.lab", "algorithm": "EC", "key_size": 256, "protocol": None,
     "qv": True, "impact": "Medium", "codes": ["QUANTUM_VULNERABLE"], "finding": "Quantum-vulnerable key",
     "facts": {"key_alg": "EC", "curve": "secp256r1", "sig_alg": "ecdsa-with-SHA256", "subject": "CN=z01.lab",
               "issuer": "CN=cbom-e2e lab CA", "not_before": "2026-11-12T08:00:00Z",
               "not_after": "2027-11-12T08:00:00Z", "serial": "1a"},
     "pqc": "vulnerable",
     "oracle": {"target": "z01", "expect": {"algorithm": "EC", "key_size": 256, "curve": "P-256",
                                            "signature_algorithm": "ecdsa-with-SHA256", "subject": "CN=z01.lab",
                                            "not_after": "2027-11-12T08:00:00Z", "quantum_vulnerable": True,
                                            "pqc_class": "vulnerable"},
                "codes_include": ["QUANTUM_VULNERABLE"], "codes_exclude": ["CERT_EXPIRED"], "impact_max": "Medium"}},
    {"id": 102, "type": "tls_endpoint", "cdx": "protocol", "target": "10.231.0.17", "location": "10.231.0.17:443",
     "name": "https 10.231.0.17:443", "algorithm": "TLS_AES_256_GCM_SHA384", "key_size": None, "protocol": "https",
     "qv": True, "impact": "Low", "codes": ["NO_PQ_KEX"], "finding": "No post-quantum key exchange",
     "facts": {"protocols": ["TLSv1.3"], "negotiated_version": "TLSv1.3", "negotiated_group": "x25519",
               "groups": ["x25519", "secp256r1"], "ciphers": ["TLS_AES_256_GCM_SHA384"]},
     "pqc": "vulnerable",
     "oracle": {"target": "z01", "expect": {"protocol_versions": ["TLSv1.3"], "groups": ["X25519", "P-256"],
                                            "cipher_suites": ["TLS_AES_256_GCM_SHA384"], "quantum_vulnerable": True},
                "codes_include": ["NO_PQ_KEX"], "codes_exclude": ["PROTO_TLS10"]}},
    {"id": 103, "type": "certificate", "cdx": "certificate", "target": "10.231.0.18", "location": "10.231.0.18:443",
     "name": "CN=z02.lab", "algorithm": "RSA", "key_size": 3072, "protocol": None, "qv": True, "impact": "High",
     "codes": ["CERT_SELF_SIGNED", "QUANTUM_VULNERABLE"], "finding": "Self-signed certificate",
     "facts": {"key_alg": "RSA", "sig_alg": "sha256WithRSAEncryption", "subject": "CN=z02.lab",
               "issuer": "CN=z02.lab", "not_before": "2026-11-12T08:00:00Z", "not_after": "2027-11-12T08:00:00Z",
               "serial": "2b"},
     "pqc": "vulnerable",
     "oracle": {"target": "z02", "expect": {"algorithm": "RSA", "key_size": 3072,
                                            "signature_algorithm": "sha256WithRSAEncryption",
                                            "quantum_vulnerable": True},
                "codes_include": ["CERT_SELF_SIGNED"]}},
]


class FakeRun:
    def __init__(self, root: Path, *, legacy_export: bool = False, run_id: int = 55, team: int = 9,
                 ui_attrs: bool = False) -> None:
        self.dir = Path(root) / "L-abc123456789-20261112T090000Z"
        self.assets = copy.deepcopy(ASSETS)
        self.legacy_export = legacy_export
        self.ui_attrs = ui_attrs  # CB-38: DOM rows as the gate reads them from the data attributes
        self.run_id = run_id
        self.team = team
        self.canary_value = "zs-canary-7f3a9c1e5b2d4a6f8e0c"

    # ------------------------------------------------------------------------------------------- render views
    def api_item(self, a: dict[str, Any]) -> dict[str, Any]:
        return {"id": a["id"], "type": a["type"], "cdx_type": a["cdx"], "job_id": 900, "source_id": 31,
                "source_name": "S-zoo", "target": a["target"], "location": a["location"], "name": a["name"],
                "algorithm": a["algorithm"], "key_size": a["key_size"], "protocol": a["protocol"],
                "quantum_vulnerable": a["qv"], "impact": a["impact"], "finding": a["finding"],
                "finding_codes": list(a["codes"]), "as_of_run": None, "facts": dict(a["facts"])}

    def db_row(self, a: dict[str, Any]) -> dict[str, Any]:
        return {"id": a["id"], "team_id": self.team, "run_id": self.run_id, "job_id": 900, "source_id": 31,
                "attempt": 1, "asset_key": f"k{a['id']}", "asset_type": a["type"], "cdx_type": a["cdx"],
                "target": a["target"], "location": a["location"], "name": a["name"], "algorithm": a["algorithm"] or "",
                "key_size": "" if a["key_size"] is None else a["key_size"], "protocol": a["protocol"] or "",
                "quantum_vulnerable": {True: "t", False: "f", None: ""}[a["qv"]], "impact": a["impact"] or "",
                "finding_codes": json.dumps(a["codes"]), "finding": a["finding"] or "",
                "facts": json.dumps(a["facts"]), "created_at": "2026-11-12 09:00:00"}

    def component(self, a: dict[str, Any]) -> dict[str, Any]:
        props = [{"name": "zs:location", "value": a["location"]}, {"name": "zs:asset_type", "value": a["type"]},
                 {"name": "zs:target", "value": a["target"]}, {"name": "zs:source", "value": "S-zoo"},
                 {"name": "zs:impact", "value": a["impact"] or "Info"},
                 {"name": "zs:quantum_vulnerable", "value": "unknown" if a["qv"] is None else str(a["qv"]).lower()},
                 {"name": "zs:finding", "value": a["finding"]}]
        props += [{"name": "zs:finding_code", "value": c} for c in a["codes"]]
        if a["algorithm"]:
            props.append({"name": "zs:algorithm", "value": a["algorithm"]})
        crypto: dict[str, Any]
        f = a["facts"]
        if a["cdx"] == "certificate":
            crypto = {"assetType": "certificate", "certificateProperties": {
                "subjectName": f["subject"], "issuerName": f["issuer"], "notValidBefore": f["not_before"],
                "notValidAfter": f["not_after"], "certificateFormat": "X.509", "certificateExtension": "pem"}}
        elif a["cdx"] == "algorithm":
            crypto = {"assetType": "algorithm"}
        else:
            crypto = {"assetType": "protocol", "protocolProperties": {
                "type": "tls", "version": ",".join(f["protocols"]),
                "cipherSuites": [{"name": c} for c in f["ciphers"]]}}
        if not self.legacy_export:
            if a["key_size"]:
                props.append({"name": "zs:key_size", "value": str(a["key_size"])})
            if f.get("curve"):
                props.append({"name": "zs:curve", "value": f["curve"]})
            if f.get("sig_alg"):
                props.append({"name": "zs:signature_algorithm", "value": f["sig_alg"]})
            if f.get("groups"):
                props.append({"name": "zs:groups", "value": ",".join(f["groups"])})
            props.append({"name": "zs:pqc_class", "value": a["pqc"]})
            props += [{"name": k, "value": "900" if k == "zs:job_id" else v} for k, v in PROVENANCE.items()]
        return {"type": "cryptographic-asset", "bom-ref": f"zs-asset-{a['id']}", "name": a["name"],
                "cryptoProperties": crypto, "evidence": {"occurrences": [{"location": a["location"]}]},
                "properties": props}

    def ui_row(self, a: dict[str, Any]) -> dict[str, Any]:
        if self.ui_attrs:
            return self.ui_attr_row(a)
        labels = {"certificate": "Certificate", "tls_endpoint": "TLS endpoint", "coverage": "Not collected"}
        head = a["algorithm"] or a["protocol"] or "—"
        return {"id": a["id"], "impact": a["impact"] or "Info", "type": labels.get(a["type"], a["type"]), "location": a["location"],
                "target": a["target"], "algorithm": f"{head} {a['key_size']}" if a["key_size"] else head,
                "finding": a["finding"] or "—",
                "quantum": "Vulnerable" if a["qv"] is True else "Safe" if a["qv"] is False else "—"}

    @staticmethod
    def ui_attr_row(a: dict[str, Any]) -> dict[str, Any]:
        """A results-page row as gate.mjs reads it from data-* attributes (raw API values, "" for none)."""
        return {"id": a["id"], "reader": "data-attributes", "impact": a["impact"] or "", "type": a["type"],
                "location": a["location"] or "", "target": a["target"] or "",
                "algorithm": a["algorithm"] or a["protocol"] or "",
                "key_size": "" if a["key_size"] is None else str(a["key_size"]), "finding": a["finding"] or "",
                "quantum": "vulnerable" if a["qv"] is True else "safe" if a["qv"] is False else "",
                "status": "not_started"}

    def oracle(self) -> dict[str, Any]:
        targets: dict[str, dict[str, Any]] = {}
        for a in self.assets:
            o = a["oracle"]
            t = targets.setdefault(o["target"], {"target_id": o["target"], "address": a["target"], "source": "S-zoo",
                                                 "world": "closed", "extras_ceiling": 0, "assets": [],
                                                 "must_not_appear": []})
            t["assets"].append({"oracle_id": f"{o['target']}/{a['type']}", "asset_type": a["type"],
                                "location": a["location"], "expect": o["expect"],
                                "codes_include": o.get("codes_include", []),
                                "codes_exclude": o.get("codes_exclude", []),
                                **({"impact_max": o["impact_max"]} if o.get("impact_max") else {}),
                                "provenance": {"source": "gen.py", "detail": "fake", "captured_at": "2026-11-12T08:59:00Z"}})
        targets["z01"]["must_not_appear"] = [{"asset_type": "tls_endpoint", "location": "10.231.0.33:443"}]
        return {"schema": "zs-cbom-oracle/1", "run_step": "run1", "generated_at": "2026-11-12T08:59:00Z",
                "generator": {"name": "gen.py", "commit": "fake", "wave": "core"}, "targets": list(targets.values())}

    # ------------------------------------------------------------------------------------------------ write
    def write(self) -> Path:
        d = self.dir
        for sub in ("oracle", "lab", "steps", "har", "ui", "api", "db", "exports", "logs", "diff"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        items = [self.api_item(a) for a in self.assets]
        facets_type: dict[str, int] = {}
        facets_impact: dict[str, int] = {}
        for i in items:
            facets_type[i["type"]] = facets_type.get(i["type"], 0) + 1
            facets_impact[i["impact"] or "none"] = facets_impact.get(i["impact"] or "none", 0) + 1
        self._json("api/assets-run1.json", {
            "run_id": self.run_id, "total": len(items), "all_total": len(items), "pages": 1, "items": items,
            "facets": {"type": facets_type, "impact": facets_impact,
                       "quantum_vulnerable": sum(1 for i in items if i["quantum_vulnerable"] is True)}})
        rows = [self.db_row(a) for a in self.assets]
        with open(d / "db" / "assets.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        self._json("exports/run1.cdx.json", {"bomFormat": "CycloneDX", "specVersion": "1.6",
                                             "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
                                             "version": 1, "metadata": {"timestamp": "2026-11-12T09:01:00Z",
                                                                        "properties": []},
                                             "components": [self.component(a) for a in self.assets],
                                             "vulnerabilities": []})
        self._json("ui/assets-run1.json", {"run_id": self.run_id, "total_text": f"{len(self.assets)} assets",
                                           "rows": [self.ui_row(a) for a in self.assets]})
        with open(d / "db" / "jobs.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["id", "team_id", "run_id", "kind", "status", "outcome", "asset_count"])
            w.writeheader()
            w.writerow({"id": 900, "team_id": self.team, "run_id": self.run_id, "kind": "collect", "status": "success",
                        "outcome": "ok", "asset_count": len(self.assets)})
        self._json("oracle/run1.json", self.oracle())
        self._json("oracle/canaries.json", {"schema": "zs-cbom-canaries/1", "canaries": [
            {"id": "ssh-pass", "kind": "string", "value": self.canary_value, "allowed": ["oracle/canaries.json"],
             "control": "lab/ubuntu/zs-canary"}]})
        (d / "lab" / "ubuntu").mkdir(parents=True, exist_ok=True)
        (d / "lab" / "ubuntu" / "zs-canary").write_text(self.canary_value + "\n", encoding="utf-8")
        self._json("lab/selfcheck.json", {"schema": "zs-cbom-selfcheck/1", "checked_at": "2026-11-12T08:59:30Z",
                                          "targets": [{"target_id": t, "agree": True, "checks": []}
                                                      for t in ("z01", "z02")]})
        for extra in ("cbom-cloud-worker", "nginx", "postgres"):
            (d / "logs" / f"{extra}.log").write_text("", encoding="utf-8")
        (d / "logs" / "backend.log").write_text(
            "2026-11-12T09:00:01.123456789Z cbom sources assets stored team=9 run=55 job=900 attempt=1 accepted=3 "
            "duplicate=0 rejected=0 dropped=0 total=3 cap_reached=False\n", encoding="utf-8")
        self._json("har/G9.har", {"log": {"version": "1.2", "entries": [{
            "startedDateTime": "2026-11-12T09:00:00Z",
            "request": {"method": "POST", "url": "https://api.dss.test/9/cbom/sources/runs", "headers": []},
            "response": {"status": 200, "headers": [], "content": {"mimeType": "application/json", "text": "{}"}}}]}})
        times = {"G9": ("2026-11-12T08:59:00Z", "2026-11-12T08:59:30Z"), "G10": ("2026-11-12T08:59:30Z", "2026-11-12T09:00:30Z"),
                 "G11": ("2026-11-12T09:00:30Z", "2026-11-12T09:00:50Z"), "G12": ("2026-11-12T09:00:50Z", "2026-11-12T09:01:30Z")}
        for step in FLOW_STEPS:
            started, ended = times.get(step, ("2026-11-12T08:58:00Z", "2026-11-12T08:58:30Z"))
            self._json(f"steps/{step}/step.json", {"gate": step, "status": "ran", "started": started, "ended": ended,
                                                   "checks": []})
        manifest.update(d, teams={"A": self.team})
        manifest.freeze_oracle(d)
        return d

    def _json(self, rel: str, data: Any) -> None:
        path = self.dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=1), encoding="utf-8")

    def edit_json(self, rel: str, fn) -> None:
        path = self.dir / rel
        data = json.loads(path.read_text(encoding="utf-8"))
        fn(data)
        path.write_text(json.dumps(data, indent=1), encoding="utf-8")
