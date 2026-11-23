"""FIX-B2 (SOW D7 / D8, audit lane B: B-02, B-03, B-04, B-05, B-06, B-09).

One fixture team, stored the way the scan node and the cloud worker store it (``CbomCollectedAsset`` rows of each
source's latest collect job), then loaded with the real ``load_team_cbom_view`` and rendered with the real renderers:

* network source "Lab network" probes four TLS endpoints (one with a two-certificate chain, one STARTTLS SMTP, one
  plaintext-only), one SSH endpoint, one IKE gateway, one OPC UA server and one Modbus port;
* a second network source "Lab network rescan" probes the SAME 10.0.0.10:443 later (D7 must print it once);
* an appliance source holds F5 TLS, Cisco SSH, Cisco IKEv2 proposal and IPsec transform settings;
* two AWS sources read the SAME AWS Private CA (no thumbprint: the role may not read its certificate) and the same
  ACM certificate, which the network probe also saw on 10.0.0.11:443 (same SHA-256 thumbprint);
* a Linux source reports a trust-store bundle file and a certificate whose subject is a spreadsheet formula;
* a source that was DELETED left a collection with one TLS endpoint and one certificate.

Oracles are literals worked out by hand from the fixture (never recomputed with the product functions).
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import re

import pytest
from pypdf import PdfReader
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource
from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view
from backend.utilities.pdf import cbom_cert_register_pdf as D8
from backend.utilities.pdf import cbom_network_tls_pdf as D7

NOW = dt.datetime(2026, 11, 23, 12, 0, tzinfo=dt.timezone.utc)
FP_ACM = "ab" * 32
FP_LEAF10 = "10" * 32
FP_ROOT = "cd" * 32
FP_DELETED = "ee" * 32
FP_FORMULA = "fa" * 32
PCA_ARN = "arn:aws:acm-pca:ap-south-1:111122223333:certificate-authority/ca429b08"
ACM_ARN = "arn:aws:acm:ap-south-1:111122223333:certificate/6508ffda"


def _tls(versions, suites, *, group="x25519", leaf=None, service="tls", weak=None, complete=True, label="HTTPS"):
    facts = {"protocol_label": label, "service": service, "mode": "full", "tls": True,
             "versions": {v: (v in versions) for v in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")},
             "cipher_suites": {v: [{"name": n} for n in names] for v, names in suites.items()},
             "cipher_suites_complete": {v: complete for v in suites},
             "negotiated_group": group, "negotiated_version": versions[-1],
             "negotiated_cipher": next(iter(suites.values()))[0], "weak_ciphers_accepted": weak or {},
             "enumeration": {"complete": complete, "not_complete": [] if complete else ["TLSv1.2 suites: budget (12)"]},
             "fallback_scsv": True}
    if leaf:
        facts["leaf"] = leaf
    return facts


LEAF10 = {"subject": "CN=web10.lab", "issuer": "CN=ZS Lab Root,O=ZS", "not_after": "2027-12-16T08:34:23Z",
          "key_alg": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption", "fingerprint_sha256": FP_LEAF10,
          "self_signed": False, "san": ["web10.lab"]}
CERT_LEAF10 = {"subject": "CN=web10.lab", "issuer": "CN=ZS Lab Root,O=ZS", "serial": "1a2b3c4d5e6f7081",
               "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-16T08:34:23Z", "key_alg": "RSA",
               "key_size": 2048, "sig_alg": "sha256WithRSAEncryption", "san": ["web10.lab", "www.web10.lab"],
               "is_ca": False, "self_signed": False, "fingerprint_sha256": FP_LEAF10, "source": "tls"}
CERT_ROOT = {"subject": "CN=ZS Lab Root,O=ZS", "issuer": "CN=ZS Lab Root,O=ZS", "serial": "3e8",
             "not_before": "2026-01-01T00:00:00Z", "not_after": "2036-01-01T00:00:00Z", "key_alg": "RSA",
             "key_size": 4096, "sig_alg": "sha256WithRSAEncryption", "san": [], "is_ca": True, "self_signed": True,
             "fingerprint_sha256": FP_ROOT, "source": "tls"}
CERT_ACM_NODE = {"subject": "CN=pay.bank.example", "issuer": "CN=Amazon RSA 2048 M02,O=Amazon,C=US",
                 "serial": "f3a1c2b4d5e6f708192a3b4c5d6e7f80", "not_before": "2026-06-01T00:00:00Z",
                 "not_after": "2026-12-10T23:59:59Z", "key_alg": "RSA", "key_size": 2048,
                 "sig_alg": "sha256WithRSAEncryption", "san": ["pay.bank.example"], "is_ca": False,
                 "self_signed": False, "fingerprint_sha256": FP_ACM, "source": "tls"}
CERT_ACM = {"subject": "CN=pay.bank.example", "issuer": "Amazon", "serial": "F3:A1:C2:B4:D5:E6:F7:08:19:2A:3B:4C:5D:6E:7F:80",
            "not_before": "2026-06-01T00:00:00Z", "not_after": "2026-12-10T23:59:59Z", "key_alg": "RSA",
            "key_size": 2048, "san": ["pay.bank.example"], "status": "ISSUED", "source": "aws", "identity": ACM_ARN}
PCA = {"subject": "CN=ZeroShield-AWS-PCA-Test,O=ZeroShield", "issuer": "CN=ZeroShield-AWS-PCA-Test,O=ZeroShield",
       "key_alg": "RSA_2048", "sig_alg": "SHA256WITHRSA", "status": "ACTIVE", "ca_type": "ROOT",
       "not_after": "2027-11-17T11:49:20Z", "not_before": "2026-11-17T10:49:20Z", "is_ca": True, "self_signed": True,
       "source": "aws", "identity": PCA_ARN, "certificate_read": "AccessDeniedException"}
BUNDLE = {"path": "/etc/ssl/certs/ca-certificates.crt", "trust_store": True, "count": 120, "sha1_signed": 3}
FORMULA = {"subject": "CN==HYPERLINK(\"http://x\")", "issuer": "CN=ZS Lab Root,O=ZS", "serial": "99aa",
           "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-12-01T00:00:00Z", "key_alg": "EC", "key_size": 256,
           "curve": "secp256r1", "sig_alg": "ecdsa-with-SHA256", "is_ca": False, "self_signed": False,
           "fingerprint_sha256": FP_FORMULA, "source": "file"}
DELETED_CERT = {"subject": "CN=gone.lab", "issuer": "CN=gone.lab", "serial": "77", "not_after": "2027-01-01T00:00:00Z",
                "key_alg": "RSA", "key_size": 2048, "self_signed": True, "fingerprint_sha256": FP_DELETED}
SSH = {"banner": "SSH-2.0-OpenSSH_9.6p1", "kex": ["diffie-hellman-group14-sha1", "curve25519-sha256", "ext-info-s"],
       "host_key_algs": ["rsa-sha2-512", "ssh-ed25519"], "ciphers_c2s": ["aes128-cbc", "aes256-gcm@openssh.com"],
       "ciphers_s2c": ["aes128-cbc", "aes256-gcm@openssh.com"], "macs_c2s": ["hmac-sha1", "hmac-sha2-256"],
       "macs_s2c": ["hmac-sha1", "hmac-sha2-256"],
       "host_keys": [{"type": "ssh-rsa", "bits": 1024, "fingerprint": "SHA256:ZdjQprnjztcKhjzT4mbNS7jAIupa8tIkb1DIMI9FxbY"},
                     {"type": "ssh-ed25519", "bits": 256, "fingerprint": "SHA256:lzKIsD0zuPFhjJOQAe9Qh+Pq1HO1vbFQ+ZQLvVPR7Ik"}]}
IKE = {"service": "ike", "port": 500, "nat_t": False,
       "ikev2": {"supported": True, "chosen": {"encryption": "AES-CBC-256", "prf": "PRF_HMAC_SHA2_256",
                                               "integrity": "AUTH_HMAC_SHA2_256_128", "group": "MODP-2048"},
                 "weak": {"group": {"accepted": ["MODP-1024"], "complete": False}},
                 "pq": {"supported": False, "method": None}},
       "ikev1": {"supported": False}, "unknown": []}
OPCUA = {"service": "opcua", "port": 4840, "application_name": "Line 3 PLC",
         "endpoints": [{"url": "opc.tcp://10.0.0.30:4840", "security_mode": "None",
                        "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#None",
                        "user_tokens": [{"type": "Anonymous"}]},
                       {"url": "opc.tcp://10.0.0.30:4840", "security_mode": "SignAndEncrypt",
                        "security_policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
                        "user_tokens": [{"type": "UserName"}]}],
         "policies": ["http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
                      "http://opcfoundation.org/UA/SecurityPolicy#None"], "modes": ["None", "SignAndEncrypt"]}
MODBUS = {"service": "modbus", "port": 502, "tls": False, "identified_by": "port",
          "detail": "TCP port accepts connections; no Modbus request was sent"}
APPLIANCE = [
    ("10.0.0.64:443#client-ssl /Common/legacy-vip",
     {"kind": "tls", "vendor": "f5_bigip", "vendor_label": "F5 BIG-IP", "appliance": "10.0.0.64",
      "section": "client-ssl profile /Common/legacy-vip", "ciphers": "DEFAULT:RC4-SHA:DES-CBC3-SHA",
      "protocols": ["SSLv3", "TLSv1.0", "TLSv1.2"], "weak_ciphers": ["RC4-SHA", "DES-CBC3-SHA"]}),
    ("10.0.0.60:22#ip ssh",
     {"kind": "ssh", "vendor": "cisco_ios", "vendor_label": "Cisco IOS", "appliance": "10.0.0.60", "section": "ip ssh",
      "versions": [2], "ciphers": ["aes128-ctr", "3des-cbc"], "macs": ["hmac-sha1"],
      "kex": ["diffie-hellman-group1-sha1"], "dh_min_bits": 1024}),
    ("10.0.0.60:22#crypto ikev2 proposal PROP-LEGACY",
     {"kind": "ike_policy", "vendor": "cisco_ios", "vendor_label": "Cisco IOS", "appliance": "10.0.0.60",
      "section": "crypto ikev2 proposal PROP-LEGACY", "version": 2, "encryption": ["AES-CBC-128", "3DES"],
      "integrity": ["SHA1", "MD5"], "groups": ["MODP-1024"]}),
    ("10.0.0.60:22#crypto ipsec transform-set TS-LEGACY",
     {"kind": "ipsec_policy", "vendor": "cisco_ios", "vendor_label": "Cisco IOS", "appliance": "10.0.0.60",
      "section": "crypto ipsec transform-set TS-LEGACY", "encryption": ["3DES"], "integrity": ["MD5"]}),
]


@pytest.fixture(scope="module")
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    with Session(eng) as s:
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="fixb2", status="success")
        s.add(run)
        s.flush()
        n = [0]

        def source(kind, name, *, deleted=False, hours_ago=2, owner=None):
            src_id = None
            if not deleted:
                src = CbomCollectionSource(team_id=1, owner_user_id=1, kind=kind, name=name, name_lower=name.lower(),
                                           config={"owner": owner} if owner else {},
                                           created_at=NOW.replace(tzinfo=None))
                s.add(src)
                s.flush()
                src_id = src.id
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src_id if src_id else 9999, kind="collect",
                                    status="success", attempts=1,
                                    finished_at=(NOW - dt.timedelta(hours=hours_ago)).replace(tzinfo=None),
                                    params={"source_uid": f"uid-{name}", "source_name": name})
            s.add(job)
            s.flush()
            return run.id, job.id, src_id

        def asset(where, asset_type, cdx, location, facts, *, name=None, target=None, algorithm=None, codes=()):
            n[0] += 1
            run_id, job_id, src_id = where
            s.add(CbomCollectedAsset(team_id=1, run_id=run_id, job_id=job_id, source_id=src_id, attempt=1,
                                     asset_key=f"k{n[0]}", asset_type=asset_type, cdx_type=cdx,
                                     target=target or location.split(":")[0], location=location,
                                     name=name or location, algorithm=algorithm, facts=facts,
                                     finding_codes=list(codes)))

        net = source("network", "Lab network", hours_ago=6, owner="Network team")
        asset(net, "tls_endpoint", "protocol", "10.0.0.10:443",
              _tls(["TLSv1.0", "TLSv1.2"], {"TLSv1.0": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"],
                                           "TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                       "TLS_RSA_WITH_AES_128_GCM_SHA256"]},
                   leaf=LEAF10, weak={"static_rsa": ["TLS_RSA_WITH_AES_128_GCM_SHA256"]}, complete=False),
              codes=("PROTO_TLS10", "STATIC_RSA_KEX"))
        asset(net, "certificate", "certificate", "10.0.0.10:443#chain[0]", CERT_LEAF10, name="CN=web10.lab")
        asset(net, "certificate", "certificate", "10.0.0.10:443#chain[1]", CERT_ROOT, name="CN=ZS Lab Root")
        asset(net, "tls_endpoint", "protocol", "10.0.0.11:443",
              _tls(["TLSv1.2", "TLSv1.3"], {"TLSv1.3": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
                                           "TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]},
                   group="X25519MLKEM768", leaf={**CERT_ACM_NODE, "key_size": 2048}))
        asset(net, "certificate", "certificate", "10.0.0.11:443#chain[0]", CERT_ACM_NODE, name="CN=pay.bank.example")
        asset(net, "tls_endpoint", "protocol", "10.0.0.12:25",
              _tls(["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_RC4_128_SHA"]},
                   service="starttls-smtp", label="SMTP"), codes=("WEAK_CIPHER",))
        asset(net, "tls_endpoint", "protocol", "10.0.0.13:1521",
              {"engine": "oracle", "tls_offered": False, "service": "oracle", "tls": False, "plaintext_only": True},
              codes=("NO_TLS",))
        asset(net, "ssh_endpoint", "protocol", "10.0.0.20:22", SSH, codes=("SSH_DH_SHA1", "SSH_HMAC_SHA1"))
        asset(net, "ike_endpoint", "protocol", "10.0.0.40:500", IKE, codes=("IKE_WEAK_DH",))
        asset(net, "ot_endpoint", "protocol", "10.0.0.30:4840", OPCUA, codes=("OPCUA_SECURITY_NONE",))
        asset(net, "ot_endpoint", "protocol", "10.0.0.31:502", MODBUS, codes=("OT_PLAINTEXT",))
        rescan = source("network", "Lab network rescan", hours_ago=1)
        asset(rescan, "tls_endpoint", "protocol", "10.0.0.10:443",
              _tls(["TLSv1.0", "TLSv1.2"], {"TLSv1.0": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"],
                                           "TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                       "TLS_RSA_WITH_AES_128_GCM_SHA256"]},
                   leaf=LEAF10, weak={"static_rsa": ["TLS_RSA_WITH_AES_128_GCM_SHA256"]}, complete=False),
              codes=("PROTO_TLS10", "STATIC_RSA_KEX"))
        app = source("network_appliance", "Lab appliances", hours_ago=3)
        for location, facts in APPLIANCE:
            asset(app, "appliance_config", "protocol", location, facts, target=facts["appliance"])
        for name, hours in (("AWS prod", 5), ("AWS prod (second role)", 4)):
            aws = source("aws_account", name, hours_ago=hours)
            asset(aws, "cloud_ca", "certificate", PCA_ARN, PCA, name=PCA["subject"], target="aws:111122223333",
                  algorithm="RSA")
            asset(aws, "certificate", "certificate", ACM_ARN, CERT_ACM, name="pay.bank.example",
                  target="aws:111122223333", algorithm="RSA")
        linux = source("servers", "Linux web", hours_ago=2)
        asset(linux, "certificate", "certificate", BUNDLE["path"], BUNDLE, target="web-1")
        asset(linux, "certificate", "certificate", "/srv/app/formula.crt", FORMULA, target="web-1",
              name=FORMULA["subject"])
        gone = source("network", "Rate test fleet", deleted=True, hours_ago=1)
        asset(gone, "tls_endpoint", "protocol", "10.0.0.99:443",
              _tls(["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}))
        asset(gone, "certificate", "certificate", "10.0.0.99:443#chain[0]", DELETED_CERT, name="CN=gone.lab")
        s.commit()
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def view(engine):
    return load_team_cbom_view(engine, 1, now=NOW)


@pytest.fixture(scope="module")
def d7_text(view):
    return _text(D7.build_pdf(view))


@pytest.fixture(scope="module")
def d8_pdf(view):
    return D8.build_pdf(view)


@pytest.fixture(scope="module")
def d8_csv(view):
    return D8.build_csv(view)


def _text(pdf: bytes) -> str:
    return " ".join((page.extract_text() or "") for page in PdfReader(io.BytesIO(pdf)).pages)


def _squash(text: str) -> str:
    return re.sub(r"\s+", "", text)


def _csv_rows(body: bytes) -> list[dict[str, str]]:
    assert body.startswith(b"\xef\xbb\xbf")
    return list(csv.DictReader(io.StringIO(body[3:].decode("utf-8"), newline="")))


# ----------------------------------------------------------------------------- D8: one unique set, CSV
# Unique certificates by hand: web10 leaf, ZS Lab Root, pay.bank.example (node + ACM x2 share serial/thumbprint),
# the AWS Private CA (two AWS sources, one ARN), the formula-named file certificate = 5. Not counted: the trust-store
# bundle (a file of 120 roots) and gone.lab (seen only by the deleted source).
UNIQUE = 5


def test_d8_csv_has_one_row_per_unique_certificate_and_the_pdf_says_the_same_number(d8_pdf, d8_csv):
    rows = _csv_rows(d8_csv)
    assert len(rows) == UNIQUE
    assert len({r["certificate_key"] for r in rows}) == UNIQUE
    text = _squash(_text(d8_pdf))
    assert _squash(f"Showing all {UNIQUE} unique certificates") in text
    assert "gone.lab" not in text and "ca-certificates.crt" not in text
    assert _squash("1 unique certificate seen only by deleted sources is not listed") in text
    assert _squash("1 trust-store bundle file row") in text


def test_d8_csv_is_rfc4180_utf8_bom_and_carries_every_sow_column(d8_csv):
    assert d8_csv.count(b"\r\n") == UNIQUE + 1 and b"\n" not in d8_csv.replace(b"\r\n", b"")
    header = d8_csv[3:].split(b"\r\n", 1)[0].decode()
    for column in ("sha256_thumbprint", "serial", "subject", "issuer", "subject_alt_names", "key_algorithm",
                   "key_size", "signature_algorithm", "not_before", "not_after", "days_to_expiry", "status",
                   "chain_position", "issuer_thumbprint", "self_signed", "where_seen", "seen_count", "owner",
                   "pqc_class"):
        assert column in header.split(","), column


def test_d8_rows_are_keyed_by_thumbprint_with_serial_sans_chain_and_where_seen(d8_csv):
    rows = {r["subject"]: r for r in _csv_rows(d8_csv)}
    leaf = rows["CN=web10.lab"]
    assert leaf["sha256_thumbprint"] == FP_LEAF10 and leaf["certificate_key"] == "sha256:" + FP_LEAF10
    assert leaf["serial"] == "1a2b3c4d5e6f7081"
    assert leaf["subject_alt_names"] == "web10.lab; www.web10.lab"
    assert leaf["chain_position"] == "leaf" and leaf["issuer_thumbprint"] == FP_ROOT
    assert leaf["owner"] == "Network team"
    assert leaf["pqc_class"] == "quantum-vulnerable"
    assert rows["CN=ZS Lab Root,O=ZS"]["chain_position"] == "root"
    pay = rows["CN=pay.bank.example"]
    assert pay["sha256_thumbprint"] == FP_ACM
    assert pay["seen_count"] == "3"  # the probe on 10.0.0.11:443 and ACM read by both AWS sources
    assert "10.0.0.11:443#chain[0]" in pay["where_seen"] and ACM_ARN in pay["where_seen"]
    assert pay["status"] == "expiring <=30 d" and pay["days_to_expiry"] == "17"


def test_d8_aws_private_ca_is_one_row_with_a_dn_subject_not_raw_json(d8_csv, d8_pdf):
    rows = [r for r in _csv_rows(d8_csv) if "ZeroShield-AWS-PCA-Test" in r["subject"]]
    assert len(rows) == 1
    assert rows[0]["subject"] == "CN=ZeroShield-AWS-PCA-Test,O=ZeroShield"
    assert rows[0]["sources"] == "Sources run #1 · AWS prod (second role); Sources run #1 · AWS prod"
    assert '{"CommonName"' not in _text(d8_pdf)


def test_d8_csv_cells_never_start_a_formula(d8_csv):
    row = next(r for r in _csv_rows(d8_csv) if "HYPERLINK" in r["subject"])
    assert row["subject"].startswith("CN==HYPERLINK")  # does not start with "=": safe as it is
    assert D8.csv_cell('=HYPERLINK("http://x")') == '\'=HYPERLINK("http://x")'
    assert D8.csv_cell(" +1") == "' +1" and D8.csv_cell("@SUM(A1)") == "'@SUM(A1)"
    assert D8.csv_cell("-2+3") == "'-2+3" and D8.csv_cell(-44) == -44 and D8.csv_cell("\tx") == "'\tx"
    assert D8.csv_cell("a\x00b\x1bc") == "abc"


def test_d8_pdf_has_thumbprint_and_serial_columns_and_the_sow_document_id(d8_pdf):
    text = _squash(_text(d8_pdf))
    assert "SHA-256thumbprint" in text and "Serial" in text
    assert _squash("10101010 10101010") in text  # the first 16 hex of web10's thumbprint, in groups of eight
    assert "CBOM-D08-" in text


# ----------------------------------------------------------------------------- D7
def test_d7_certificate_kpi_is_the_d8_unique_count(d7_text):
    assert _squash(f"{UNIQUE} unique certificates (D8)") in _squash(d7_text)


def test_d7_prints_every_sow_network_section(d7_text):
    text = _squash(d7_text)
    for heading in ("TLS endpoint grades", "Accepted cipher suites by endpoint", "Certificate chains presented",
                    "SSH endpoints", "Network appliance configuration (TLS, SSH, IKE, IPsec)",
                    "IKE / IPsec proposals", "STARTTLS services", "OPC UA endpoint security",
                    "Modbus/TCP (port open only)", "TLS grade rubric"):
        assert _squash(heading) in text, heading
    for needle in ("diffie-hellman-group14-sha1", "hmac-sha1", "ssh-rsa 1024", "F5 BIG-IP", "RC4-SHA:DES-CBC3-SHA",
                   "PROP-LEGACY", "MODP-1024", "Line 3 PLC", "SignAndEncrypt", "Basic256Sha256", "10.0.0.31:502",
                   "STARTTLS smtp", "TLS_CHACHA20_POLY1305_SHA256", "CBOM-D07-"):
        assert _squash(needle) in text, needle


def test_d7_endpoint_probed_by_two_sources_is_one_row_naming_both(view):
    _scoped, model = D7._scoped(view)
    keys = [e.key for e in model.tls]
    assert keys == ["10.0.0.10:443", "10.0.0.11:443", "10.0.0.12:25", "10.0.0.13:1521"]
    first = model.tls[0].observed
    assert first.source == "Sources run #1 · Lab network rescan"  # the newest observation wins
    assert first.also_seen == ("Sources run #1 · Lab network",)


def test_d7_leaves_deleted_sources_out_and_says_so(view, d7_text):
    _scoped, model = D7._scoped(view)
    assert all("10.0.0.99" not in e.key for e in model.tls)
    assert model.deleted_rows == 1
    text = _squash(d7_text)
    assert "10.0.0.99" not in text
    assert _squash("deleted source (1 network row): Sources run #1 · Rate test fleet") in text


def test_d7_grades_follow_the_rubric(view):
    _scoped, model = D7._scoped(view)
    grades = {e.key: e.grade for e in model.tls}
    # TLS 1.0 offered + static RSA accepted -> B cap; enumeration incomplete -> provisional
    assert grades["10.0.0.10:443"].text == "B*"
    # TLS 1.2 / 1.3, AEAD only, hybrid PQ group, 2048-bit leaf: no cap -> A
    assert grades["10.0.0.11:443"].text == "A"
    # RC4 accepted -> C
    assert grades["10.0.0.12:25"].letter == "C"
    # plaintext only -> not graded
    assert grades["10.0.0.13:1521"].text == "no TLS"


def test_d7_has_collapsible_bookmarks_for_the_suite_lists(view):
    reader = PdfReader(io.BytesIO(D7.build_pdf(view)))
    outline = reader.outline
    titles = [item.title for item in outline if not isinstance(item, list)]
    assert "Accepted cipher suites by endpoint" in titles
    children = next(item for item in outline if isinstance(item, list))
    assert [c.title for c in children][:2] == ["10.0.0.10:443 (B*)", "10.0.0.11:443 (A)"]


def test_d7_source_table_lists_every_current_network_source_and_no_deleted_one(view):
    scoped, _model = D7._scoped(view)
    labels = [s.label for s in scoped.posture.sources]
    assert labels == ["Sources run #1 · Lab appliances", "Sources run #1 · Lab network",
                      "Sources run #1 · Lab network rescan"]


# ----------------------------------------------------------------------------- grade rubric, unit level
def _grade(versions, suites, **kw):
    from backend.utilities.cbom_sources import network_estate as NE

    return NE.grade_tls(_tls(versions, suites, **kw), kw.pop("as_of", None) if "as_of" in kw else NOW.date())


@pytest.mark.parametrize("versions,suites,leaf,expected", [
    (["TLSv1.3"], {"TLSv1.3": ["TLS_AES_256_GCM_SHA384"]}, None, "A"),
    (["SSLv3", "TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]}, None, "C"),
    (["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_NULL_SHA256"]}, None, "F"),
    (["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]},
     None, "C"),
    (["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]},
     {"key_alg": "RSA", "key_size": 1024, "self_signed": False, "not_after": "2030-01-01T00:00:00Z"}, "B"),
    (["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]},
     {"key_alg": "RSA", "key_size": 2048, "self_signed": True, "not_after": "2030-01-01T00:00:00Z"},
     "T (if trusted: A)"),
    (["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]},
     {"key_alg": "RSA", "key_size": 2048, "self_signed": False, "not_after": "2026-01-01T00:00:00Z"},
     "T (if trusted: A)"),
])
def test_grade_caps(versions, suites, leaf, expected):
    assert _grade(versions, suites, leaf=leaf).text == expected


def test_group_names_are_iana_case():
    from backend.utilities.cbom_sources import network_estate as NE

    assert NE.norm_group("X25519") == "x25519" and NE.norm_group("x25519mlkem768") == "X25519MLKEM768"
    assert NE.norm_group("prime256v1") == "secp256r1"


# ----------------------------------------------------------------------------- AWS Private CA collector (B-03)
def _pem() -> tuple[str, str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ZeroShield-AWS-PCA-Test"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ZeroShield")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(0x1234ABCD5678EF01).not_valid_before(dt.datetime(2026, 11, 17))
            .not_valid_after(dt.datetime(2027, 11, 17))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    import hashlib

    der = cert.public_bytes(serialization.Encoding.DER)
    return cert.public_bytes(serialization.Encoding.PEM).decode(), hashlib.sha256(der).hexdigest(), "1234abcd5678ef01"


def test_aws_private_ca_subject_is_a_dn_and_its_certificate_gives_the_thumbprint():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_cbom_aws_collect_wp4 import ACCOUNT, REGION, _Acct  # noqa: E402

    from backend.utilities.cbom_sources import aws_collect

    pem, fp, serial = _pem()
    arn = f"arn:aws:acm-pca:{REGION}:{ACCOUNT}:certificate-authority/"
    cas = [{"Arn": arn + "ok", "Status": "ACTIVE", "Type": "ROOT",
            "CertificateAuthorityConfiguration": {"KeyAlgorithm": "EC_prime256v1", "SigningAlgorithm": "SHA256WITHECDSA",
                                                  "Subject": {"CommonName": "ZeroShield-AWS-PCA-Test",
                                                              "Organization": "ZeroShield", "Country": "IN"}}},
           {"Arn": arn + "denied", "Status": "ACTIVE", "Type": "SUBORDINATE",
            "CertificateAuthorityConfiguration": {"KeyAlgorithm": "RSA_2048", "SigningAlgorithm": "SHA256WITHRSA",
                                                  "Subject": {"CommonName": "Issuing, CA #2"}}},
           {"Arn": arn + "deleted", "Status": "DELETED", "Type": "ROOT",
            "CertificateAuthorityConfiguration": {"KeyAlgorithm": "RSA_2048", "SigningAlgorithm": "SHA256WITHRSA",
                                                  "Subject": {"CommonName": "Old root"}}}]
    acct = _Acct({"acm-pca": [
        ("list_certificate_authorities", {"CertificateAuthorities": cas}, None),
        ("get_certificate_authority_certificate", {"Certificate": pem}, {"CertificateAuthorityArn": arn + "ok"}),
        ("get_certificate_authority_certificate", "AccessDeniedException", {"CertificateAuthorityArn": arn + "denied"}),
    ]})
    found: list[dict] = []
    aws_collect._region_services(acct, REGION, f"aws:{ACCOUNT}", found.append, {})
    for stub in acct.stubs:
        stub.assert_no_pending_responses()  # DELETED CA: no certificate call
    ca = {a["location"].rsplit("/", 1)[-1]: a for a in found if a["type"] == "cloud_ca"}
    ok = ca["ok"]
    # the X.509 subject wins (RFC 4514 string, as every other collector writes it); never the Subject dict as JSON
    assert ok["facts"]["subject"] == ok["name"] == "O=ZeroShield,CN=ZeroShield-AWS-PCA-Test"
    assert ok["facts"]["certificate_read"] == "ok" and ok["facts"]["self_signed"] is True
    assert ok["facts"]["fingerprint_sha256"] == fp and ok["facts"]["serial"] == serial
    assert ca["denied"]["name"] == "CN=Issuing\\, CA #2" and "{" not in ca["denied"]["name"]
    assert ca["denied"]["facts"]["certificate_read"] == "AccessDeniedException"
    assert "issuer" not in ca["denied"]["facts"]  # a subordinate CA's issuer is not its own subject
    assert ca["deleted"]["facts"]["certificate_read"] == "not_issued"
    assert ca["deleted"]["facts"]["issuer"] == "CN=Old root" and ca["deleted"]["facts"]["self_signed"] is True


def test_dn_from_an_aws_subject_dict():
    from backend.utilities.cbom_sources.cert_estate import dn_from_mapping

    assert dn_from_mapping({"CommonName": "Root", "Organization": "Bank", "Country": "IN"}) == "CN=Root,O=Bank,C=IN"
    assert dn_from_mapping({"CommonName": "a,b+c"}) == "CN=a\\,b\\+c"
    assert dn_from_mapping(None) == "" and dn_from_mapping({}) == ""


def test_shared_certificate_predicates():
    from backend.utilities.cbom_sources.cert_estate import is_certificate_record, thumbprint

    assert is_certificate_record(BUNDLE) is False and is_certificate_record(CERT_ROOT) is True
    assert thumbprint({"fingerprint_sha256": ("AB:" * 32)[:-1]}) == "ab" * 32
    assert thumbprint({"fingerprint_sha256": "SHA256:lzKIsD0zuPFhjJOQAe9Qh+Pq1HO1vbFQ+ZQLvVPR7Ik"}) == ""
    assert thumbprint({"certificate_sha256": "cd" * 32}) == "cd" * 32
