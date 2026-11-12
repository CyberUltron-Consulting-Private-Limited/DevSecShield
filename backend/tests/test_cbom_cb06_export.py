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
import re
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
# FIPS 204 ML-DSA-65 (no key size fact: the parameter set is the name)
CERT_MLDSA = _cert("mldsa", "/etc/ssl/mldsa.pem", "ML-DSA-65", None, "ML-DSA-65", fp="a7")
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
# a TLS 1.0-1.2 server as the network collector really writes it (stack run 26, asset 628, lab z02): the negotiated
# suite under openssl s_client's OpenSSL name, the weak-class probes' suites under their IANA names (tlsprobe.CIPHERS),
# so one suite (0xC0,0x13) arrives under two names (review 5879114669, major 1)
TLS_LEGACY = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:10443", "protocol": "tls",
              "facts": {"versions": {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": None, "TLSv1.2": True, "TLSv1.3": False},
                        "negotiated_version": "TLSv1.2", "negotiated_cipher": "ECDHE-RSA-AES128-SHA",
                        "negotiated_group": "prime256v1", "weak_ciphers_accepted": {
                            "obsolete": [], "static_rsa": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
                            "cbc": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"], "dhe": []}}}
# the same server once the collector stores IANA names (CB-12): the export must read the same
TLS_LEGACY_IANA = {**TLS_LEGACY, "location": "10.20.0.1:11443",
                   "facts": {**TLS_LEGACY["facts"], "negotiated_cipher": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}}
# IANA TLS Cipher Suites registry (tls-parameters-4): TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC0,0x13 (RFC 8422),
# TLS_RSA_WITH_AES_128_CBC_SHA = 0x00,0x2F (RFC 5246), TLS_AES_256_GCM_SHA384 = 0x13,0x02 (RFC 8446),
# TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC0,0x30 (RFC 5289)
LEGACY_SUITES = [{"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "identifiers": ["0xC0", "0x13"]},
                 {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "identifiers": ["0x00", "0x2F"]}]
# an address where nothing accepted TLS (stack run 26, assets 612/636): s_client still prints "group: <NULL>"
TLS_NONE = {"type": "tls_endpoint", "target": "10.20.0.2", "location": "10.20.0.2:443", "protocol": "tls",
            "facts": {"negotiated_version": None, "negotiated_cipher": None, "negotiated_group": "<NULL>", "tls": None,
                      "versions": {"SSLv3": False, "TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False,
                                   "TLSv1.3": False}}}
# a server that negotiates X25519 by default and also accepts the hybrid group the PQ probe offered (lab z05b)
TLS_PQ_PROBED = {"type": "tls_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:12443",
                 "facts": {"versions": {"TLSv1.2": False, "TLSv1.3": True}, "negotiated_version": "TLSv1.3",
                           "negotiated_group": "X25519", "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
                           "pq_hybrid": True, "pq_group": "X25519MLKEM768"}}
# what the database collector writes (collectors/database.py; stack run 26 asset 616 for PostgreSQL)
DB_PG_TLS = {"type": "database_tls", "target": "10.20.0.5", "location": "10.20.0.5:5432", "protocol": "TLSv1.3",
             "algorithm": "TLS_AES_256_GCM_SHA384", "name": "PostgreSQL connections",
             "facts": {"engine": "postgres",
                       "own_connection": {"version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "bits": 256},
                       "live_connections": [{"ssl": True, "version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "count": 1},
                                            {"ssl": True, "version": "TLSv1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "count": 2},
                                            {"ssl": False, "version": None, "cipher": None, "count": 4}]}}
DB_MYSQL_TLS = {"type": "database_tls", "target": "10.20.0.6", "location": "10.20.0.6:3306", "protocol": "TLSv1.2",
                "algorithm": "ECDHE-RSA-AES256-GCM-SHA384", "name": "MySQL connections",
                "facts": {"engine": "mysql",
                          "own_connection": {"Ssl_version": "TLSv1.2", "Ssl_cipher": "ECDHE-RSA-AES256-GCM-SHA384"},
                          "live_connections": [{"variable": "Ssl_cipher", "value": "ECDHE-RSA-AES256-GCM-SHA384", "count": 3},
                                               {"variable": "Ssl_cipher", "value": "", "count": 2},
                                               {"variable": "Ssl_version", "value": "TLSv1.2", "count": 3}]}}
DB_CONFIG = {"type": "database_config", "target": "10.20.0.5", "location": "10.20.0.5:5432#config",
             "protocol": "postgres", "name": "PostgreSQL 16", "facts": {"engine": "postgres", "settings": {"ssl": "on"}}}
# SSH KEXINIT facts (tlsprobe.ssh_kexinit names; the network collector stores protocol "ssh" and the banner)
SSH = {"type": "ssh_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:22", "protocol": "ssh",
       "facts": {"kex": ["mlkem768x25519-sha256", "curve25519-sha256"], "host_key_algs": ["ssh-ed25519"],
                 "ciphers_c2s": ["chacha20-poly1305@openssh.com"], "ciphers_s2c": ["aes256-gcm@openssh.com"],
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
    # xs:dateTime (XML Schema 1.1 Part 2, 3.3.7) allows offsets up to +/-14:00 only; RFC 3339 allows +14:30
    _cert("tz", "/etc/ssl/tz.pem", "RSA", 4096, "sha384WithRSAEncryption", fp="a6",
          not_before="2026-01-01T00:00:00+14:00", not_after="2027-01-01T00:00:00+14:30"),
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


ASSET_REF = re.compile(r"^zs-asset-(\d+)$")  # INTERFACES CB-06: the regex that selects exactly the assets


def _assets(doc: dict) -> list[dict]:
    return [c for c in doc.get("components") or [] if ASSET_REF.match(c.get("bom-ref", ""))]


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
MORE_GAPS = [{"type": "coverage", "target": "111122223333", "location": f"arn:aws:{svc}:{region}:111122223333:{svc}",
              "facts": {"check": f"{svc} in {region}", "status": status, "detail": detail}}
             for svc, region, status, detail in (("acm", "ap-south-1", "denied", "AccessDeniedException"),
                                                 ("kms", "us-east-1", "error", "ThrottlingException"))]


@pytest.fixture()
def exported(request):
    """One run with node rows (legacy node) and cloud rows; the JSON and XML downloads plus the ids."""
    call = request.getfixturevalue("api")
    engine, _ = request.getfixturevalue("world")
    ids = _node_run(call, engine, [CERT_RSA3072, CERT_RSA2048, CERT_P384, CERT_P256, CERT_MLDSA, TLS_HYBRID, TLS_CLASSICAL, SSH,
                                   TLS_LEGACY, TLS_LEGACY_IANA, TLS_NONE, TLS_PQ_PROBED, DB_PG_TLS, DB_MYSQL_TLS, DB_CONFIG,
                                   *OTHERS])
    run_id = ids["run"]["id"]
    ids["cloud_job_id"], ids["cloud_source_id"] = _cloud_job(engine, run_id, [KMS_KEY, KMS_DENIED, *MORE_GAPS])
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
    # [mutant I14] both directions: the server offered chacha20 client-to-server and AES-GCM server-to-client
    assert set(_one(ssh, "zs:ciphers").split(",")) == {"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"}
    assert _one(ssh, "zs:macs") == "hmac-sha2-256-etm@openssh.com"
    config = _component(exported, "sshd -T")  # sshd -T writes comma-separated strings
    assert _one(config, "zs:kex_algorithms").split(",") == ["curve25519-sha256", "diffie-hellman-group14-sha1"]


def test_protocols_export_the_versions_and_suites_the_collector_saw(exported):
    """Found by CB-01's G11 join on this branch (L probe): the network collector writes ``versions`` (a dict of
    probes), ``negotiated_cipher`` and ``weak_ciphers_accepted``; the export read only ``protocols`` / ``ciphers``,
    so a real TLS endpoint exported no version and no suite, and an sshd -T cipher string became one suite per
    character."""
    def proto(location):
        return _component(exported, location)["cryptoProperties"]["protocolProperties"]

    assert proto(TLS_HYBRID["location"])["version"] == "TLSv1.3"
    assert proto(TLS_HYBRID["location"])["cipherSuites"] == [{"name": "TLS_AES_256_GCM_SHA384",
                                                             "identifiers": ["0x13", "0x02"]}]
    legacy = proto(TLS_LEGACY["location"])
    assert legacy["version"].split(",") == ["TLSv1.0", "TLSv1.2"]  # True probes only; None = not read, not accepted
    assert legacy["cipherSuites"] == LEGACY_SUITES
    assert proto(SSH["location"])["version"] == "SSHv2"  # banner "SSH-2.0-OpenSSH_10.0" (RFC 4253 section 4.2)
    assert [c["name"] for c in proto("sshd -T")["cipherSuites"]] == ["aes128-cbc", "aes256-ctr"]
    assert all("identifiers" not in c for c in proto("sshd -T")["cipherSuites"])  # SSH ciphers have no TLS code


# ============================================================================== review 5879114669 (CB-06 fix round)
def test_one_suite_is_listed_once_under_its_iana_name_with_its_code(exported):
    """[major 1] The collector stores the negotiated suite under its OpenSSL name and the probes' suites under their
    IANA names, so 0xC0,0x13 was listed twice (3 entries for 2 accepted suites on z02/z16 of stack run 26). Each
    suite is listed once, by its IANA name, with its code; a row stored with IANA names exports the same."""
    for location in (TLS_LEGACY["location"], TLS_LEGACY_IANA["location"]):
        suites = _component(exported, location)["cryptoProperties"]["protocolProperties"]["cipherSuites"]
        assert suites == LEGACY_SUITES, location
    xml = exported["xml"].content.decode()
    assert xml.count("<name>TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</name>") == 2  # once per endpoint
    assert "ECDHE-RSA-AES128-SHA" not in json.dumps([(c.get("cryptoProperties") or {}).get("protocolProperties")
                                                    for c in _assets(exported["doc"])])
    assert "<identifier>0xC0</identifier>" in xml and "<identifier>0x13</identifier>" in xml


def test_the_suite_table_agrees_with_the_running_openssl_and_with_the_node():
    """The OpenSSL->IANA table against sources that share nothing with it: the OpenSSL library this Python runs on
    (its own name and code for every suite it knows) and the node's raw-probe table (code -> IANA name)."""
    import ssl

    from backend.utilities.cbom_sources import tls_suites

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")
    seen = 0
    for cipher in ctx.get_ciphers():
        code = cipher["id"] & 0xFFFF
        want = f"0x{code >> 8:02X},0x{code & 0xFF:02X}"
        iana, got = tls_suites.canonical(cipher["name"])
        assert got == want, (cipher["name"], got, want)
        assert tls_suites.canonical(iana) == (iana, want)
        seen += 1
    assert seen >= 30, seen  # positive control: the runtime really listed its suites
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scan_node"))
    from zs_scan_node import tlsprobe

    for code, name in tlsprobe.CIPHERS.items():
        assert tls_suites.canonical(name) == (name, f"0x{code >> 8:02X},0x{code & 0xFF:02X}"), name
    assert tls_suites.canonical("not-a-suite") == ("not-a-suite", None)


def test_an_endpoint_where_nothing_accepted_tls_reports_no_group(exported):
    """[minor] s_client prints "Negotiated TLS1.3 group: <NULL>" when no handshake completed; that is not a group."""
    props = _props(_component(exported, TLS_NONE["location"]))
    assert "zs:groups" not in props and "zs:groups_negotiated" not in props
    proto = _component(exported, TLS_NONE["location"])["cryptoProperties"]["protocolProperties"]
    assert "cipherSuites" not in proto


def test_database_tls_exports_the_suites_its_connections_used(exported):
    """[minor] The database collector reads the suite of its own connection and of every live connection
    (``own_connection`` / ``live_connections``); the export listed none of them."""
    pg = _component(exported, DB_PG_TLS["location"])["cryptoProperties"]["protocolProperties"]
    assert pg["cipherSuites"] == [{"name": "TLS_AES_256_GCM_SHA384", "identifiers": ["0x13", "0x02"]},
                                  {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "identifiers": ["0xC0", "0x30"]}]
    mysql = _component(exported, DB_MYSQL_TLS["location"])["cryptoProperties"]["protocolProperties"]
    assert mysql["cipherSuites"] == [{"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "identifiers": ["0xC0", "0x30"]}]


def test_certificate_dates_keep_only_offsets_xs_datetime_allows(exported):
    """[minor] xs:dateTime offsets stop at 14:00: +14:30 made the whole XML document invalid."""
    tz = _component(exported, "/etc/ssl/tz.pem")["cryptoProperties"]["certificateProperties"]
    assert tz["notValidBefore"] == "2026-01-01T00:00:00+14:00"
    assert "notValidAfter" not in tz
    assert xml_errors(exported["xml"].content) == []


def test_two_batches_of_one_job_keep_their_own_collected_at(request):
    """[minor] Rows of one job attempt share their provenance properties per stored batch: two batches stored at
    different times must keep two ``zs:collected_at`` values, each the row's own stored time."""
    from sqlmodel import select

    from backend.new_models import CbomCollectedAsset
    from backend.utilities.cbom_sources import jobs as J

    call = request.getfixturevalue("api")
    engine, _ = request.getfixturevalue("world")
    src, run, claim, hdr = _collect_job(call, engine)
    job = claim["job"]
    t1 = dt.datetime(2026, 11, 12, 9, 0, 0)
    t2 = t1 + dt.timedelta(minutes=7)
    with Session(engine) as s:  # the node's two upload batches, stored by the product's own store call
        node = s.get(CbomScanNode, s.get(CbomCollectionJob, job["id"]).node_id)
        for when, cert in ((t1, CERT_RSA2048), (t2, CERT_RSA3072)):
            assert J.add_assets(s, node, job["id"], job["lease_id"], [cert], when, team_id=1)["accepted"] == 1
            s.commit()
        stored = {r.location: r.created_at for r in s.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.job_id == job["id"])).all()}
    assert stored == {CERT_RSA2048["location"]: t1, CERT_RSA3072["location"]: t2}
    doc = call("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    got = {_one(c, "zs:location"): _one(c, "zs:collected_at") for c in _assets(doc)}
    assert got == {CERT_RSA2048["location"]: "2026-11-12T09:00:00Z", CERT_RSA3072["location"]: "2026-11-12T09:07:00Z"}


def test_the_kind_table_is_pinned():
    """[minor, mutant P9] Every source kind's collector, method and transport (the vocabulary of INTERFACES CB-06)."""
    from backend.utilities.cbom_sources import provenance as PV

    want = {
        "linux_servers": ("linux_ssh", "agentless", "direct"), "windows_servers": ("windows_winrm", "agentless", "direct"),
        "active_directory": ("active_directory", "agentless", "direct"),
        "kubernetes": ("kubernetes", "agentless", "direct"), "database": ("database", "agentless", "direct"),
        "network_range": ("network", "agentless", "direct"), "appliance": ("appliance", "agentless", "direct"),
        "container_images": ("container_images", "agentless", "direct"), "key_manager": ("key_manager", "api", "direct"),
        "ca_connector": ("ca", "api", "direct"), "aws_account": ("aws", "api", "direct"),
        "azure_subscription": ("azure", "api", "direct"), "gcp_project": ("gcp", "api", "direct"),
        "idp": ("idp", "api", "direct"), "host_agent": ("host_agent", "agent", "local"),
        "awx_hosts": ("zs_collect", "agentless", "awx"), "salt_hosts": ("zs_collect", "agentless", "salt"),
        "ssm_hosts": ("zs_collect", "agentless", "ssm"),
    }
    got = {kind: tuple(vars(PV.kind_provenance(kind)).values()) for kind in want}
    assert got == want


def test_the_pq_probe_group_is_listed_beside_the_negotiated_group(exported):
    """[minor, mutant I6] A server that negotiates X25519 and accepted the PQ probe's X25519MLKEM768."""
    comp = _component(exported, TLS_PQ_PROBED["location"])
    assert _one(comp, "zs:groups").split(",") == ["X25519", "X25519MLKEM768"]
    assert _one(comp, "zs:groups_negotiated") == "X25519"


def test_coverage_gaps_are_capped_but_all_counted(exported, monkeypatch):
    """[minor, mutants I2/I3] At most COVERAGE_GAP_CAP gaps are listed; the count is every coverage row."""
    from backend.utilities.cbom_sources import inventory as INV

    doc = exported["doc"]
    assert _props(doc["metadata"])["zs:coverage_gap_count"] == ["3"]
    monkeypatch.setattr(INV, "COVERAGE_GAP_CAP", 2)
    capped = exported["call"]("GET", f"/1/cbom/sources/runs/{exported['ids']['run']['id']}/cbom").json()
    meta = _props(capped["metadata"])
    assert meta["zs:coverage_gap_count"] == ["3"] and len(meta["zs:coverage_gap"]) == 2


def test_asset_count_counts_the_asset_components(exported):
    """[minor, mutant I12] ``zs:asset_count`` is the number of assets (``zs-asset-<id>`` components), coverage rows
    and shared certificate parts excluded (INTERFACES CB-06 v2)."""
    doc = exported["doc"]
    assets = _assets(doc)
    assert _props(doc["metadata"])["zs:asset_count"] == [str(len(assets))]
    assert len(assets) == len(exported["asset_id"]) - 3  # every API row but the 3 coverage rows


def test_key_algorithm_parts_carry_curve_or_size_and_the_quantum_level(exported):
    """[minor, mutants I7/I13] An EC key's algorithm names its curve and no parameter set; an RSA key's names its
    size; an algorithm a quantum computer breaks (Shor: RSA, ECDSA) has nistQuantumSecurityLevel 0, ML-DSA has none."""
    refs = _refs_index(exported["doc"])

    def key_alg(location):
        cert = _component(exported, location)["cryptoProperties"]["certificateProperties"]
        key = refs[cert["subjectPublicKeyRef"]]["cryptoProperties"]["relatedCryptoMaterialProperties"]
        return refs[key["algorithmRef"]]["cryptoProperties"]["algorithmProperties"], \
            refs[cert["signatureAlgorithmRef"]]["cryptoProperties"]["algorithmProperties"]

    ec, ec_sig = key_alg(CERT_P384["location"])
    assert ec["curve"] == "secp384r1" and "parameterSetIdentifier" not in ec
    assert ec["nistQuantumSecurityLevel"] == 0 and ec_sig["nistQuantumSecurityLevel"] == 0
    rsa, rsa_sig = key_alg(CERT_RSA3072["location"])
    assert rsa["parameterSetIdentifier"] == "3072" and "curve" not in rsa
    assert rsa["nistQuantumSecurityLevel"] == 0 and rsa_sig["nistQuantumSecurityLevel"] == 0
    pq, pq_sig = key_alg(CERT_MLDSA["location"])
    assert "nistQuantumSecurityLevel" not in pq and "nistQuantumSecurityLevel" not in pq_sig


def test_certificates_share_their_algorithm_and_key_parts_by_bom_ref(exported):
    """[major 2] Certificates reference shared signature-algorithm, public-key and key-algorithm components by
    bom-ref instead of carrying three nested copies each (an estate shares a handful of such tuples). Top-level
    components are the assets (``zs-asset-<id>``) followed by the parts; no asset nests components."""
    doc = exported["doc"]
    refs = _refs_index(doc)
    assert not [c["bom-ref"] for c in doc["components"] if c.get("components")]
    certs = {loc: _component(exported, loc)["cryptoProperties"]["certificateProperties"]
             for loc in (CERT_RSA2048["location"], "/etc/ssl/odd.pem", CERT_RSA3072["location"])}
    same_key, odd, big = certs[CERT_RSA2048["location"]], certs["/etc/ssl/odd.pem"], certs[CERT_RSA3072["location"]]
    # RSA-2048 + sha256WithRSAEncryption twice: one signature algorithm, one public key
    assert same_key["subjectPublicKeyRef"] == odd["subjectPublicKeyRef"]
    assert same_key["signatureAlgorithmRef"] == odd["signatureAlgorithmRef"] == big["signatureAlgorithmRef"]
    assert big["subjectPublicKeyRef"] != same_key["subjectPublicKeyRef"]
    parts = [c for c in doc["components"] if not ASSET_REF.match(c["bom-ref"])]
    assert parts and all(_one(p, "zs:part_of") == "certificate" for p in parts)
    assert all(ASSET_REF.match(c["bom-ref"]) for c in doc["components"][:len(_assets(doc))])  # assets first
    # the parts the inputs imply: one per distinct signature algorithm, (key algorithm, size, curve) and key algorithm
    cert_inputs = [CERT_RSA3072, CERT_RSA2048, CERT_P384, CERT_P256, CERT_MLDSA, *[a for a in OTHERS if a["type"] == "certificate"]]
    sigs = {a["facts"]["sig_alg"] for a in cert_inputs}
    keys = {(a["facts"]["key_alg"], a["facts"].get("key_size"), a["facts"].get("curve")) for a in cert_inputs}
    key_algs = {(alg, None if curve or not size else size, curve) for alg, size, curve in keys}
    assert len(parts) == len(sigs) + len(keys) + len(key_algs), [p["bom-ref"] for p in parts]
    for part in parts:
        assert refs[part["bom-ref"]] is part


def test_zs_protocol_is_the_stored_protocol_column(exported):
    """[minor, CB05-B2] The asset table's protocol column (``postgres`` on a database_config row) is exported as
    ``zs:protocol``; ``protocolProperties.type`` stays the CycloneDX enum."""
    assert _one(_component(exported, DB_CONFIG["location"]), "zs:protocol") == "postgres"
    assert _one(_component(exported, TLS_LEGACY["location"]), "zs:protocol") == "tls"
    assert "zs:protocol" not in _props(_component(exported, "sshd -T"))  # nothing stored, nothing claimed


def test_large_exports_wait_for_a_free_export_slot(exported, monkeypatch, tmp_path):
    """[major 2a] A large export holds one of a few host-wide slots while it is built; with every slot taken the
    route answers 503 with Retry-After instead of building another multi-GB document."""
    from backend.utilities.cbom_sources import export_slots as ES

    monkeypatch.setattr(ES, "LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(ES, "SLOTS", 1)
    assert ES.is_large(ES.LARGE_ASSETS) and not ES.is_large(ES.LARGE_ASSETS - 1)  # "large" = at least LARGE_ASSETS rows
    call, run_id = exported["call"], exported["ids"]["run"]["id"]
    monkeypatch.setattr(ES, "LARGE_ASSETS", 1)  # this run counts as large
    with ES.slot():  # another worker process is building a large export
        for fmt in ("json", "xml"):
            busy = call("GET", f"/1/cbom/sources/runs/{run_id}/cbom?format={fmt}")
            assert busy.status_code == 503, busy.text
            assert int(busy.headers["retry-after"]) > 0 and "busy" in busy.json()["detail"]
        monkeypatch.setattr(ES, "LARGE_ASSETS", 10_000)  # a small run is never held up
        assert call("GET", f"/1/cbom/sources/runs/{run_id}/cbom").status_code == 200
    monkeypatch.setattr(ES, "LARGE_ASSETS", 1)
    assert call("GET", f"/1/cbom/sources/runs/{run_id}/cbom?format=xml").status_code == 200  # the slot is free again
    assert call("GET", "/1/cbom/sources/runs/999999/cbom").status_code == 404  # ownership is checked first


def _import_with_the_product(doc: dict, tmp_path: Path) -> dict:
    """The product's "Analyze CBOM file" import (``aibom.cbom.ingest``) of ``doc``, run from source in a child process
    (the backend's environment carries its dependencies; the repo's top-level aibom/ is not the package)."""
    import subprocess

    src = Path(__file__).resolve().parents[2] / "aibom" / "src"
    path = tmp_path / "export.cdx.json"
    path.write_text(json.dumps(doc))
    code = ("import json,sys; sys.path.insert(0, sys.argv[1]); from aibom.cbom.ingest import components_from_cyclonedx as f; "
            "c, s = f(json.load(open(sys.argv[2]))); "
            "print(json.dumps({'stats': s.as_dict(), 'components': [x.properties for x in c]}))")
    out = subprocess.run([sys.executable, "-c", code, str(src), str(path)], capture_output=True, text=True, timeout=300)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_the_products_own_import_counts_each_certificate_once(exported, tmp_path):
    """[minor] Re-importing the export ("Analyze CBOM file") must not count certificate parts as assets; the
    certificate keeps its key size, curve and signature algorithm, resolved through its refs."""
    doc = exported["doc"]
    got = _import_with_the_product(doc, tmp_path)
    stats = got["stats"]
    crypto_assets = [c for c in _assets(doc) if c["type"] == "cryptographic-asset"]
    parts = [c for c in doc["components"] if not ASSET_REF.match(c["bom-ref"])]
    assert stats["crypto_assets"] == len(crypto_assets) and stats["certificate_parts"] == len(parts)
    by_source = {c.get("discovery:source"): c for c in got["components"]}
    p384 = by_source[CERT_P384["location"]]
    assert p384["crypto:assetType"] == "certificate" and p384["crypto:keySize"] == "384"
    assert p384["crypto:curve"] == "secp384r1" and p384["crypto:signatureAlgorithm"] == "ecdsa-with-SHA384"
    assert by_source[CERT_RSA3072["location"]]["crypto:keySize"] == "3072"


def test_every_component_has_a_pqc_class(exported):
    for comp in _assets(exported["doc"]):
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
    assert meta["zs:coverage_gap_count"] == ["3"]
    for vuln in doc.get("vulnerabilities") or []:
        assert ref not in [t["ref"] for t in vuln.get("affects") or []]
    # the KMS key the same job did read is still an asset
    assert _component(exported, KMS_KEY["location"])["cryptoProperties"]["assetType"] == "related-crypto-material"


# ============================================================================== provenance
def test_every_component_carries_its_provenance(exported):
    for comp in _assets(exported["doc"]):
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
    # [nit] reset through the product (enrolled_at cleared) and not enrolled again: also unknown
    assert call("POST", f"/1/cbom/sources/nodes/{exported['ids']['node_id']}/reset").status_code == 200
    with Session(engine) as s:
        assert s.get(CbomScanNode, exported["ids"]["node_id"]).enrolled_at is None
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


# ============================================================================== edge cases (hostile or partial input)
def _row(**kw):
    from backend.new_models import CbomCollectedAsset

    base = {"id": 9, "team_id": 1, "run_id": 1, "job_id": 4, "source_id": None, "attempt": 1, "asset_key": "k" * 64,
            "asset_type": "certificate", "cdx_type": "certificate", "target": "10.0.0.9", "location": "/x.pem",
            "name": "x", "algorithm": "RSA", "key_size": 2048, "protocol": None, "quantum_vulnerable": True,
            "impact": None, "finding_codes": ["QUANTUM_VULNERABLE"], "finding": None, "facts": {},
            "created_at": dt.datetime(2026, 11, 12, 10, 0, 0)}
    return CbomCollectedAsset(**{**base, **kw})


def _job(**kw):
    base = {"id": 4, "team_id": 1, "run_id": 1, "source_id": None, "node_id": None, "kind": "collect",
            "status": "success", "attempts": 1, "params": {}, "result": {}}
    return CbomCollectionJob(**{**base, **kw})


def test_hostile_facts_never_break_the_document():
    """A node is untrusted input: facts of the wrong type or size must give a schema-valid component."""
    from backend.utilities.cbom_sources import inventory as INV

    facts = {"subject": {"CN": "x"}, "issuer": ["a"], "not_before": 17, "not_after": "2027-13-45T99:00:00Z",
             "sig_alg": 1234, "curve": {"name": "P-256"}, "crv": "P-256", "key_size": True, "format": ["pem"],
             "groups": {"a": 1}, "negotiated_group": ["X25519"], "kex": "x" * 5000, "key_alg": None,
             "key_alg_oid": "not an oid", "algorithm_unknown": True}
    rows = [_row(facts=facts, key_size=None),
            _row(id=10, asset_type="tls_endpoint", cdx_type="protocol", location="10.0.0.9:443",
                 facts={"groups": [f"g{i}" for i in range(500)], "negotiated_group": 7, "protocols": ["TLSv1.3"]}),
            _row(id=11, asset_type="ssh_endpoint", cdx_type="protocol", location="10.0.0.9:22",
                 facts={"kex": ["a", "a", None, {"x": 1}, "b"], "ciphers_c2s": "c1,c2", "macs": 5}),
            # what tools print for "nothing" is never a suite or a group (s_client "(NONE)" / "<NULL>", Perl "undef")
            _row(id=12, asset_type="tls_endpoint", cdx_type="protocol", location="10.0.0.9:8443",
                 facts={"negotiated_cipher": "(NONE)", "weak_ciphers_accepted": {"cbc": ["<NULL>", "undef"]},
                        "negotiated_group": "(none)", "pq_group": "NULL"})]
    parts = INV.CertificateParts()
    comps = [INV._component(r, "src", parts=parts) for r in rows]
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "components": comps + parts.components()}
    assert json_errors(doc) == []
    from backend.utilities.cbom_sources.cdx_xml import to_xml

    assert xml_errors(to_xml(doc, strict=True)) == []
    cert = comps[0]
    assert _one(cert, "zs:curve") == "P-256"  # the JWK name when the curve fact is not text
    assert "zs:key_size" not in _props(cert)  # a boolean is not a size
    assert _one(cert, "zs:algorithm_unknown") == "true"
    assert "notValidAfter" not in cert["cryptoProperties"]["certificateProperties"]  # month 13 is not a date
    assert len(_one(comps[1], "zs:groups").split(",")) == 200  # capped
    assert _one(comps[2], "zs:kex_algorithms") == "a,b"
    assert _one(comps[2], "zs:ciphers") == "c1,c2"
    assert "cipherSuites" not in comps[3]["cryptoProperties"]["protocolProperties"]
    assert "zs:groups" not in _props(comps[3]) and "zs:groups_negotiated" not in _props(comps[3])
    for comp in comps:
        assert [p for p in PROVENANCE if p not in _props(comp)] == []  # no job known: every value "unknown"
        assert _one(comp, "zs:collector") == "unknown" and _one(comp, "zs:signed") == "unknown"


@pytest.mark.parametrize("job_kw, kind, attempt, expect", [
    # a running job has no report yet: its build is not known
    ({"status": "claimed", "node_id": 3, "result": {"progress": {"done": 1}}}, "linux_servers", 1,
     {"zs:node_build": "unknown", "zs:node_id": "3", "zs:collector": "linux_ssh"}),
    # a finished job's report holds only for its own attempt
    ({"status": "success", "node_id": 3, "attempts": 2, "result": {"node_version": "1.0.1"}}, "linux_servers", 1,
     {"zs:node_build": "unknown", "zs:attempt": "1"}),
    ({"status": "success", "node_id": 3, "attempts": 2, "result": {"node_version": "1.0.1"}}, "linux_servers", 2,
     {"zs:node_build": "1.0.1", "zs:attempt": "2"}),
    # source and node both deleted, nothing snapshotted: the node's name says a node ran it
    ({"node_id": None, "params": {"node_name": "dc-1"}, "result": {"node_version": "1.0.0"}}, None, 1,
     {"zs:collector": "unknown", "zs:node_id": "unknown", "zs:signed": "unknown", "zs:node_build": "1.0.0"}),
    # an unknown kind whose report says the cloud worker ran it
    ({"node_id": None, "result": {"node_version": "cloud-worker-1.0"}}, None, 1,
     {"zs:node_id": "cloud-worker", "zs:signed": "false"}),
    # a cloud kind is the cloud worker's whatever the report says
    ({"node_id": None, "params": {"source_kind": "gcp_project"}}, None, 1,
     {"zs:collector": "gcp", "zs:method": "api", "zs:node_id": "cloud-worker", "zs:node_build": "unknown"}),
    # agent mode reads its own host
    ({"node_id": 3, "params": {"source_kind": "host_agent"}, "result": {"node_version": "1.0.0"}}, None, 1,
     {"zs:collector": "host_agent", "zs:method": "agent", "zs:transport": "local"}),
])
def test_provenance_of_partial_and_orphaned_jobs(job_kw, kind, attempt, expect):
    from backend.utilities.cbom_sources import provenance as PV

    source = CbomCollectionSource(id=5, team_id=1, owner_user_id=1, kind=kind, name="s", name_lower="s") if kind else None
    job = _job(source_id=5 if kind else None, **job_kw)
    node = CbomScanNode(id=3, team_id=1, owner_user_id=1, name="n", enrolled_at=dt.datetime(2026, 1, 1),
                        signing_public_key=None) if job.node_id else None
    got = PV.values(_row(attempt=attempt), PV.job_provenance(job, source, node))
    assert list(got) == list(PV.NAMES)
    assert {k: got[k] for k in expect} == expect


def test_another_teams_node_or_source_is_never_used():
    from backend.utilities.cbom_sources import provenance as PV

    job = _job(source_id=5, node_id=3, result={"node_version": "1.0.0"})
    foreign_source = CbomCollectionSource(id=5, team_id=2, owner_user_id=1, kind="aws_account", name="s", name_lower="s")
    foreign_node = CbomScanNode(id=3, team_id=2, owner_user_id=1, name="n", enrolled_at=dt.datetime(2026, 1, 1),
                                signing_public_key="A" * 43 + "=")
    got = PV.values(_row(), PV.job_provenance(job, foreign_source, foreign_node))
    assert got["zs:collector"] == "unknown" and got["zs:signed"] == "unknown"
