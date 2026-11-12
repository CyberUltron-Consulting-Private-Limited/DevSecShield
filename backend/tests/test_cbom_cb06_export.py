"""CB-06: the run's CycloneDX export carries what the collector read, and where each asset came from.

Failing-first tests from the round-7 CBOM plan (DEVILS-ADVOCATE.md CB-06; R4 probe p1, contradiction-4 OBS-1/OBS-11):
* RSA-3072 vs RSA-2048 certificates, P-384 vs P-256, hybrid vs classical TLS must export differently;
* a KMS AccessDenied coverage row is a gap, not an ``algorithm`` component;
* every component carries its provenance (collector, node, build, job, attempt, method, time, signed, transport);
* JSON valid against the PUBLISHED CycloneDX 1.6.2 JSON schema and XML against the published XSD, validated by test
  code (support/cyclonedx_schema.py), never by the product's own validator;
* the unsigned run export no longer says ``X-ZS-Signature-Scope: json``.

Oracle rule O-1: every expected value below comes from this file's own inputs (what the fake collector reported) or
from a cited standard (IANA TLS Supported Groups; CycloneDX 1.6 field definitions), never from product output.
The product is driven through its real paths: node API (enrol, claim, assets, result) for node rows, and the cloud
worker's own store calls (``jobs.add_assets`` / ``jobs.finish_job`` with no node) for cloud rows.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support.cyclonedx_schema import (all_bom_refs, all_references, is_rfc3339_date_time, json_errors,  # noqa: E402
                                      published_files, xml_errors)
from test_cbom_sources_api import _collect_job, api, world  # noqa: E402,F401  (shared fixtures)

from backend.new_models import CbomCollectionJob, CbomCollectionSource, CbomScanNode  # noqa: E402

PROVENANCE = ("zs:collector", "zs:node_id", "zs:node_build", "zs:job_id", "zs:attempt", "zs:method",
              "zs:collected_at", "zs:signed", "zs:transport")
NODE_BUILD = "1.0.0+0123456789ab"  # what this test's node reports with its result (CB-03 form)
CLOUD_BUILD = "cloud-worker-1.0"   # what the cloud worker reports (backend/workers/cbom_cloud_worker.py)
ROLE = "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader"  # AWS documentation account id


def _cert(name, location, alg, size, sig, *, curve=None, fp="00", not_before="2026-01-01T00:00:00Z",
          not_after="2027-11-12T00:00:00Z"):
    facts = {"subject": f"CN={name}.bank.local", "issuer": "CN=Lab Issuing CA", "not_before": not_before,
             "not_after": not_after, "sig_alg": sig, "key_alg": alg, "key_size": size, "fingerprint_sha256": fp * 32,
             "serial": "1f"}
    if curve:
        facts["curve"] = curve
    return {"type": "certificate", "target": "10.20.0.1", "location": location, "name": name, "algorithm": alg,
            "key_size": size, "facts": facts}


CERT_RSA3072 = _cert("rsa3072", "/etc/ssl/rsa3072.pem", "RSA", 3072, "sha256WithRSAEncryption", fp="a1")
CERT_RSA2048 = _cert("rsa2048", "/etc/ssl/rsa2048.pem", "RSA", 2048, "sha256WithRSAEncryption", fp="a2")
CERT_P384 = _cert("p384", "/etc/ssl/p384.pem", "EC", 384, "ecdsa-with-SHA384", curve="secp384r1", fp="a3")
CERT_P256 = _cert("p256", "/etc/ssl/p256.pem", "EC", 256, "ecdsa-with-SHA256", curve="secp256r1", fp="a4")
# the TLS facts the network collector writes (collectors/network.py _tls): a full handshake, then a PQ-only offer.
# X25519MLKEM768 (0x11EC) is a hybrid post-quantum group in the IANA TLS Supported Groups registry.
TLS_HYBRID = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:8443",
              "facts": {"versions": {"TLSv1.2": False, "TLSv1.3": True}, "negotiated_version": "TLSv1.3",
                        "negotiated_group": "X25519MLKEM768", "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
                        "pq_hybrid": True, "pq_group": "X25519MLKEM768"}}
TLS_CLASSICAL = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:9443",
                 "facts": {"versions": {"TLSv1.2": False, "TLSv1.3": True}, "negotiated_version": "TLSv1.3",
                           "negotiated_group": "X25519", "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
                           "pq_hybrid": False}}
# SSH KEXINIT facts (tlsprobe.ssh_kexinit names)
SSH = {"type": "ssh_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:22",
       "facts": {"kex": ["mlkem768x25519-sha256", "curve25519-sha256"], "host_key_algs": ["ssh-ed25519"],
                 "ciphers_c2s": ["chacha20-poly1305@openssh.com"], "ciphers_s2c": ["chacha20-poly1305@openssh.com"],
                 "macs_c2s": ["hmac-sha2-256-etm@openssh.com"], "macs_s2c": ["hmac-sha2-256-etm@openssh.com"],
                 "banner": "SSH-2.0-OpenSSH_10.0"}}
# every other shape a node or the cloud worker stores, so the schema test sees the whole vocabulary
OTHERS = [
    {"type": "private_key", "target": "10.20.0.1", "location": "/etc/ssl/private/old.key", "algorithm": "RSA",
     "key_size": 1024, "facts": {"format": "pem", "encrypted": False, "mode": "0644"}},
    {"type": "ssh_server_config", "target": "10.20.0.1", "location": "sshd -T",
     "facts": {"kexalgorithms": "curve25519-sha256,diffie-hellman-group14-sha1", "ciphers": "aes128-cbc,aes256-ctr",
               "macs": "hmac-sha1", "hostkeyalgorithms": "ssh-rsa"}},
    {"type": "crypto_library", "target": "10.20.0.1", "location": "package:openssl", "name": "openssl",
     "facts": {"name": "openssl", "version": "3.0.2-0ubuntu1.15", "source": "package", "ecosystem": "deb"}},
    {"type": "open_port", "target": "10.20.0.1", "location": "10.20.0.1:5900", "facts": {"service": "vnc"}},
    {"type": "keystore", "target": "10.20.0.1", "location": "/opt/app/keystore.jks", "facts": {"format": "JKS"}},
    # a certificate whose dates are not RFC 3339 (a node is untrusted input): the document must stay schema-valid
    _cert("odd", "/etc/ssl/odd.pem", "RSA", 2048, "sha256WithRSAEncryption", fp="a5",
          not_before="2026-01-01 00:00:00", not_after="next tuesday"),
]


def _props(component: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for prop in component.get("properties") or []:
        out.setdefault(prop["name"], []).append(prop.get("value"))
    return out


def _one(component: dict, name: str):
    values = _props(component).get(name)
    assert values is not None, f"{component.get('bom-ref')}: {name} absent"
    assert len(values) == 1, f"{component.get('bom-ref')}: {name} repeated {values}"
    return values[0]


def _refs_index(doc: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}

    def walk(items):
        for comp in items or []:
            out[comp["bom-ref"]] = comp
            walk(comp.get("components"))

    walk(doc.get("components"))
    return out


def _node_run(call, engine, assets, *, build=NODE_BUILD):
    """A linux source on a (legacy, unsigned) node: claim, store ``assets``, report the result. Returns ids."""
    src, run, claim, hdr = _collect_job(call, engine)
    job = claim["job"]
    r = call("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": assets})
    assert r.status_code == 200 and r.json()["accepted"] == len(assets), r.text
    done = call("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr, json={
        "lease_id": job["lease_id"], "status": "success",
        "result": {"counts": {"total": 1, "ok": 1, "failed": 0, "skipped": 0}, "asset_count": len(assets),
                   "targets": [{"target": "10.20.0.1", "status": "ok"}], "node_version": build}})
    assert done.status_code == 200, done.text
    with Session(engine) as s:
        node_id = s.get(CbomCollectionJob, job["id"]).node_id
    return {"source": src, "run": run, "job_id": job["id"], "node_id": node_id}


def _cloud_job(engine, run_id, assets, *, build=CLOUD_BUILD):
    """An AWS account job in ``run_id``, stored exactly as the cloud worker stores it (node None)."""
    from backend.utilities.cbom_sources import jobs as J

    now = dt.datetime.utcnow().replace(microsecond=0)
    with Session(engine) as s:
        src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="aws_account", name="aws-prod",
                                   name_lower="aws-prod", config={"role_arn": ROLE, "regions": ["ap-south-1"]},
                                   last_test_status="passed")
        s.add(src)
        s.commit()
        s.refresh(src)
        job = CbomCollectionJob(team_id=1, run_id=run_id, source_id=src.id, node_id=None, kind="collect",
                                status="claimed", lease_id="cloudlease0001", attempts=1, claimed_at=now,
                                lease_expires_at=now + dt.timedelta(minutes=10),
                                params={"source_name": src.name, "conn_v": J.connection_version(src),
                                        "source_uid": src.source_uid})
        s.add(job)
        s.commit()
        s.refresh(job)
        stored = J.add_assets(s, None, job.id, "cloudlease0001", assets, now, team_id=1)
        s.commit()
        assert stored["accepted"] == len(assets), stored
        J.finish_job(s, None, job.id, "cloudlease0001", "success",
                     {"targets": [{"target": "111122223333", "status": "partial"}], "asset_count": None,
                      "node_version": build, "counts": {"total": 1, "ok": 0, "partial": 1, "failed": 0}},
                     None, now, team_id=1)
        s.commit()
        return job.id, src.id


# a KMS key the AWS collector read, and the coverage row it writes when kms in a region answers AccessDenied
# (aws_collect._region_services.run: {"check": "<service> in <region>", "status": "denied", "detail": <code>})
KMS_KEY = {"type": "kms_key", "target": "111122223333", "location": "arn:aws:kms:ap-south-1:111122223333:key/1234abcd",
           "name": "alias/payments", "algorithm": "RSA_2048", "key_size": 2048,
           "facts": {"key_spec": "RSA_2048", "key_usage": "SIGN_VERIFY", "key_state": "Enabled", "source": "aws"}}
KMS_DENIED = {"type": "coverage", "target": "111122223333", "location": "arn:aws:kms:ap-south-1:111122223333:kms",
              "facts": {"check": "kms in ap-south-1", "status": "denied", "detail": "AccessDeniedException"}}


@pytest.fixture()
def exported(request):
    """One run with node rows (legacy node) and cloud rows; the JSON and XML downloads plus the ids."""
    call = request.getfixturevalue("api")
    engine, _ = request.getfixturevalue("world")
    ids = _node_run(call, engine, [CERT_RSA3072, CERT_RSA2048, CERT_P384, CERT_P256, TLS_HYBRID, TLS_CLASSICAL, SSH,
                                  *OTHERS])
    run_id = ids["run"]["id"]
    ids["cloud_job_id"], ids["cloud_source_id"] = _cloud_job(engine, run_id, [KMS_KEY, KMS_DENIED])
    r = call("GET", f"/1/cbom/sources/runs/{run_id}/cbom")
    assert r.status_code == 200, r.text
    x = call("GET", f"/1/cbom/sources/runs/{run_id}/cbom?format=xml")
    assert x.status_code == 200, x.text
    items = call("GET", f"/1/cbom/sources/runs/{run_id}/assets?page_size=200").json()["items"]
    by_location = {a["location"]: a["id"] for a in items}
    return {"doc": r.json(), "xml": x, "ids": ids, "asset_id": by_location, "engine": engine, "call": call}


def _component(exported, location):
    ref = f"zs-asset-{exported['asset_id'][location]}"
    found = [c for c in exported["doc"]["components"] if c["bom-ref"] == ref]
    assert len(found) == 1, f"{location}: {len(found)} top-level components with bom-ref {ref}"
    return found[0]


# ============================================================================== R4 p1: values that must differ
def test_rsa_3072_and_rsa_2048_certificates_export_their_own_key_size(exported):
    big, small = _component(exported, CERT_RSA3072["location"]), _component(exported, CERT_RSA2048["location"])
    assert _one(big, "zs:key_size") == "3072" and _one(small, "zs:key_size") == "2048"
    refs = _refs_index(exported["doc"])
    for comp, bits in ((big, 3072), (small, 2048)):
        cert = comp["cryptoProperties"]["certificateProperties"]
        key = refs[cert["subjectPublicKeyRef"]]  # CycloneDX 1.6: the subject's public key, a related-material asset
        material = key["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert key["cryptoProperties"]["assetType"] == "related-crypto-material"
        assert material["type"] == "public-key" and material["size"] == bits
        algorithm = refs[material["algorithmRef"]]["cryptoProperties"]
        assert algorithm["assetType"] == "algorithm"
        assert algorithm["algorithmProperties"]["parameterSetIdentifier"] == str(bits)
        assert _one(comp, "zs:signature_algorithm") == "sha256WithRSAEncryption"
    assert _strip(big) != _strip(small)


def test_p384_and_p256_certificates_export_their_own_curve(exported):
    p384, p256 = _component(exported, CERT_P384["location"]), _component(exported, CERT_P256["location"])
    refs = _refs_index(exported["doc"])
    for comp, curve, bits, sig in ((p384, "secp384r1", 384, "ecdsa-with-SHA384"),
                                   (p256, "secp256r1", 256, "ecdsa-with-SHA256")):
        assert _one(comp, "zs:curve") == curve and _one(comp, "zs:key_size") == str(bits)
        assert _one(comp, "zs:signature_algorithm") == sig
        cert = comp["cryptoProperties"]["certificateProperties"]
        signature = refs[cert["signatureAlgorithmRef"]]
        assert signature["name"] == sig
        assert signature["cryptoProperties"]["algorithmProperties"]["primitive"] == "signature"
        key = refs[cert["subjectPublicKeyRef"]]["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert key["size"] == bits
        assert refs[key["algorithmRef"]]["cryptoProperties"]["algorithmProperties"]["curve"] == curve
    assert _strip(p384) != _strip(p256)


def test_hybrid_and_classical_tls_endpoints_export_their_pqc_class_and_groups(exported):
    hybrid, classical = _component(exported, TLS_HYBRID["location"]), _component(exported, TLS_CLASSICAL["location"])
    # vocabulary of the product's PQC classes (posture.py docstring); the verdicts follow from the IANA registry:
    # X25519MLKEM768 is a hybrid ML-KEM group, X25519 alone is broken by Shor
    assert _one(hybrid, "zs:pqc_class") == "hybrid"
    assert _one(classical, "zs:pqc_class") == "quantum-vulnerable"
    assert _one(hybrid, "zs:groups").split(",") == ["X25519MLKEM768"]
    assert _one(hybrid, "zs:groups_negotiated") == "X25519MLKEM768"
    assert _one(classical, "zs:groups").split(",") == ["X25519"]
    assert _one(classical, "zs:groups_negotiated") == "X25519"
    assert _strip(hybrid) != _strip(classical)


def test_ssh_endpoints_export_the_algorithms_the_server_offered(exported):
    ssh = _component(exported, SSH["location"])
    assert _one(ssh, "zs:kex_algorithms").split(",") == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert _one(ssh, "zs:host_key_algorithms") == "ssh-ed25519"
    assert _one(ssh, "zs:ciphers") == "chacha20-poly1305@openssh.com"
    assert _one(ssh, "zs:macs") == "hmac-sha2-256-etm@openssh.com"
    config = _component(exported, "sshd -T")  # sshd -T writes comma-separated strings
    assert _one(config, "zs:kex_algorithms").split(",") == ["curve25519-sha256", "diffie-hellman-group14-sha1"]


def test_every_component_has_a_pqc_class(exported):
    for comp in exported["doc"]["components"]:
        assert _one(comp, "zs:pqc_class") in ("quantum-vulnerable", "hybrid", "quantum-safe", "grover-weakened",
                                              "not-applicable", "unknown")


def _strip(component: dict) -> dict:
    """The component without what always differs between two inputs (ref, location, name, times, provenance)."""
    c = json.loads(json.dumps(component))
    for key in ("bom-ref", "name", "evidence", "components"):
        c.pop(key, None)
    drop = {"zs:location", "zs:collected_at", "zs:job_id", *PROVENANCE}
    c["properties"] = [p for p in c.get("properties") or [] if p["name"] not in drop]
    cert = (c.get("cryptoProperties") or {}).get("certificateProperties") or {}
    for key in ("subjectName", "signatureAlgorithmRef", "subjectPublicKeyRef"):
        cert.pop(key, None)
    return c


# ============================================================================== coverage rows are gaps
def test_a_kms_access_denied_coverage_row_is_a_gap_not_an_algorithm(exported):
    doc, gap_id = exported["doc"], exported["asset_id"][KMS_DENIED["location"]]
    ref = f"zs-asset-{gap_id}"
    assert ref not in all_bom_refs(doc), "a coverage row is not a cryptographic asset"
    assert not [c for c in doc["components"] if _props(c).get("zs:asset_type") == ["coverage"]]
    meta = _props(doc["metadata"])
    gaps = [json.loads(v) for v in meta.get("zs:coverage_gap", [])]
    mine = [g for g in gaps if g["ref"] == ref]
    assert len(mine) == 1, gaps
    gap = mine[0]
    assert (gap["location"], gap["status"], gap["check"], gap["detail"]) == (
        KMS_DENIED["location"], "denied", "kms in ap-south-1", "AccessDeniedException")
    assert gap["source"] == "aws-prod" and gap["collector"] == "aws" and gap["method"] == "api"
    assert gap["job_id"] == exported["ids"]["cloud_job_id"] and gap["signed"] == "false"
    assert meta["zs:coverage_gap_count"] == ["1"]
    for vuln in doc.get("vulnerabilities") or []:
        assert ref not in [t["ref"] for t in vuln.get("affects") or []]
    # the KMS key the same job did read is still an asset
    assert _component(exported, KMS_KEY["location"])["cryptoProperties"]["assetType"] == "related-crypto-material"


# ============================================================================== provenance
def test_every_component_carries_its_provenance(exported):
    for comp in exported["doc"]["components"]:
        props = _props(comp)
        absent = [name for name in PROVENANCE if name not in props]
        assert not absent, f"{comp['bom-ref']}: {absent}"
        assert all(len(props[name]) == 1 and props[name][0] for name in PROVENANCE), comp["bom-ref"]
        assert is_rfc3339_date_time(props["zs:collected_at"][0]) and props["zs:collected_at"][0].endswith("Z")


def test_node_rows_name_the_node_its_build_and_the_job(exported):
    ids = exported["ids"]
    node = _component(exported, CERT_RSA3072["location"])
    assert _one(node, "zs:collector") == "linux_ssh" and _one(node, "zs:method") == "agentless"
    assert _one(node, "zs:transport") == "direct"
    assert _one(node, "zs:node_id") == str(ids["node_id"]) and _one(node, "zs:node_build") == NODE_BUILD
    assert _one(node, "zs:job_id") == str(ids["job_id"]) and _one(node, "zs:attempt") == "1"
    assert _one(node, "zs:signed") == "false"  # enrolled without a signing key (a legacy node)


def test_cloud_rows_are_unsigned_by_design_and_name_the_cloud_worker(exported):
    cloud = _component(exported, KMS_KEY["location"])
    assert _one(cloud, "zs:collector") == "aws" and _one(cloud, "zs:method") == "api"
    assert _one(cloud, "zs:transport") == "direct" and _one(cloud, "zs:node_id") == "cloud-worker"
    assert _one(cloud, "zs:node_build") == CLOUD_BUILD and _one(cloud, "zs:signed") == "false"
    assert _one(cloud, "zs:job_id") == str(exported["ids"]["cloud_job_id"])


def test_signed_reflects_the_node_key_held_since_before_the_row(exported):
    engine, call = exported["engine"], exported["call"]
    run_id, location = exported["ids"]["run"]["id"], CERT_P256["location"]

    def signed() -> str:
        doc = call("GET", f"/1/cbom/sources/runs/{run_id}/cbom").json()
        return _one(next(c for c in doc["components"] if c["bom-ref"] == f"zs-asset-{exported['asset_id'][location]}"),
                    "zs:signed")

    with Session(engine) as s:  # the node enrolled with an Ed25519 key long before it stored the row
        node = s.get(CbomScanNode, exported["ids"]["node_id"])
        node.signing_public_key, node.enrolled_at = "A" * 43 + "=", dt.datetime(2020, 1, 1)
        s.add(node)
        s.commit()
    assert signed() == "true"
    with Session(engine) as s:  # re-enrolled after the row: what signed the row is no longer known
        node = s.get(CbomScanNode, exported["ids"]["node_id"])
        node.enrolled_at = dt.datetime.utcnow() + dt.timedelta(days=1)
        s.add(node)
        s.commit()
    assert signed() == "unknown"


def test_provenance_survives_deleting_the_source_and_the_node(exported):
    engine, call, ids = exported["engine"], exported["call"], exported["ids"]
    run_id = ids["run"]["id"]
    assert call("DELETE", f"/1/cbom/sources/items/{ids['source']['id']}").status_code == 200
    assert call("DELETE", f"/1/cbom/sources/nodes/{ids['node_id']}").status_code == 200
    with Session(engine) as s:
        job = s.get(CbomCollectionJob, ids["job_id"])
        assert job.source_id is None and job.node_id is None  # the product unlinked both
    doc = call("GET", f"/1/cbom/sources/runs/{run_id}/cbom").json()
    comp = next(c for c in doc["components"] if c["bom-ref"] == f"zs-asset-{exported['asset_id'][CERT_P384['location']]}")
    assert _one(comp, "zs:collector") == "linux_ssh" and _one(comp, "zs:method") == "agentless"
    assert _one(comp, "zs:node_id") == "unknown" and _one(comp, "zs:signed") == "unknown"
    assert _one(comp, "zs:node_build") == NODE_BUILD and _one(comp, "zs:job_id") == str(ids["job_id"])
    assert json_errors(doc) == []


# ============================================================================== the documents are valid
def test_the_published_schema_files_are_the_ones_checked():
    files = published_files()  # raises when any file is not the published one
    assert set(files) == {"bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json", "bom-1.6.xsd", "spdx.xsd"}


def test_the_validators_reject_what_the_published_schemas_reject():
    """Positive control: the test validators are real (a broken document fails each of them)."""
    good = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"timestamp": "2026-11-12T00:00:00Z"},
            "components": [{"type": "cryptographic-asset", "bom-ref": "a", "name": "x",
                            "cryptoProperties": {"assetType": "certificate",
                                                 "certificateProperties": {"notValidAfter": "2027-01-01T00:00:00Z"}}}]}
    assert json_errors(good) == []
    bad_date = json.loads(json.dumps(good))
    bad_date["components"][0]["cryptoProperties"]["certificateProperties"]["notValidAfter"] = "2027-01-01 00:00:00"
    assert json_errors(bad_date)
    bad_key = json.loads(json.dumps(good))
    bad_key["components"][0]["cryptoProperties"]["zs"] = 1
    assert json_errors(bad_key)
    assert xml_errors(b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"/>') == []
    assert xml_errors(b'<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="x"/>')
    assert not is_rfc3339_date_time("2027-02-30T00:00:00Z") and is_rfc3339_date_time("2027-02-28T00:00:00+05:30")


def test_json_export_is_valid_against_the_published_schema(exported):
    assert json_errors(exported["doc"]) == []


def test_xml_export_is_valid_against_the_published_xsd_and_keeps_every_key(exported):
    from backend.utilities.cbom_sources.cdx_xml import to_xml

    assert xml_errors(exported["xml"].content) == []
    to_xml(exported["doc"], strict=True)  # raises when a key of the JSON has no place in the XML


def test_every_bom_ref_is_unique_and_every_reference_resolves(exported):
    doc = exported["doc"]
    refs = all_bom_refs(doc)
    assert len(refs) == len(set(refs))
    known = set(refs)
    dangling = [(where, ref) for where, ref in all_references(doc) if ref not in known]
    assert not dangling, dangling[:10]


def test_certificate_dates_that_are_not_rfc3339_never_break_the_document(exported):
    odd = _component(exported, "/etc/ssl/odd.pem")["cryptoProperties"]["certificateProperties"]
    # "2026-01-01 00:00:00" is a readable UTC time; "next tuesday" is not a date at all
    assert odd.get("notValidBefore") == "2026-01-01T00:00:00Z"
    assert "notValidAfter" not in odd


# ============================================================================== header
def test_the_unsigned_run_export_does_not_claim_a_signature_scope(exported):
    assert "x-zs-signature-scope" not in exported["xml"].headers
    call, run_id = exported["call"], exported["ids"]["run"]["id"]
    assert "x-zs-signature-scope" not in call("GET", f"/1/cbom/sources/runs/{run_id}/cbom").headers


# ============================================================================== the mapping covers every kind
def test_every_source_kind_has_a_collector_method_and_transport():
    from backend.utilities.cbom_sources import provenance as PV
    from backend.utilities.cbom_sources.kinds import KINDS

    for kind in KINDS:
        row = PV.kind_provenance(kind)
        assert row.collector != "unknown" and row.method in PV.METHODS and row.transport in PV.TRANSPORTS, kind
    assert PV.kind_provenance("no_such_kind").collector == "unknown"
