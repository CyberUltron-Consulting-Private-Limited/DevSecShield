"""CB-21 PR-1: one cross-source asset key (engine step 3 "Correlate").

The fact shapes below are copied from the collectors that store them:
* network prober / Linux file: ``scan_node/zs_scan_node/certparse.py::cert_facts`` (RFC 4514 DNs, hex serial without
  leading zeros, SHA-256 of the DER, ``...Z`` times);
* Windows store: ``scan_node/zs_scan_node/collectors/windows_winrm.py::parse_certificates`` (.NET DNs with ", ",
  SHA-1 thumbprint, NotAfter in round-trip "o" format, no NotBefore, no serial);
* AWS ACM: ``backend/utilities/cbom_sources/aws_collect.py::_cert_asset`` (Issuer "Amazon", colon serial);
* code scan: ``cbom_json`` certificate components (subject and issuer CN only, no serial, no fingerprint).
"""
from __future__ import annotations

import datetime as dt
import itertools

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, CbomCollectionSource
from backend.utilities.cbom_sources import asset_keys as AK
from backend.utilities.cbom_sources import collections_view as CV
from backend.utilities.cbom_sources import identity as ID

SERIAL = "f3a1c2b4d5e6f708192a3b4c5d6e7f80"  # 128 bits, as Amazon issues them
COLON_SERIAL = ":".join(SERIAL[i:i + 2] for i in range(0, len(SERIAL), 2)).upper()
NODE_ISSUER = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"
NODE = {"source": "tls", "subject": "CN=www.example.com", "issuer": NODE_ISSUER, "serial": SERIAL,
        "not_before": "2026-06-01T00:00:00Z", "not_after": "2027-07-01T23:59:59Z", "key_alg": "RSA", "key_size": 2048,
        "san": ["www.example.com"], "is_ca": False, "self_signed": False, "fingerprint_sha256": "ab" * 32}
LINUX_FILE = {**NODE, "source": "file"}
WINDOWS = {"store": "My", "subject": "CN=www.example.com", "issuer": "CN=Amazon RSA 2048 M02, O=Amazon, C=US",
           "thumbprint": "0F" * 20, "not_after": "2027-07-01T23:59:59.0000000Z", "key_alg": "RSA", "key_size": 2048,
           "has_private_key": True, "source": "windows-store"}
ACM_ARN = "arn:aws:acm:ap-south-1:123456789012:certificate/7f1c2a"
ACM = {"subject": "CN=www.example.com", "issuer": "Amazon", "serial": COLON_SERIAL,
       "not_before": "2026-06-01T00:00:00Z", "not_after": "2027-07-01T23:59:59Z", "san": ["www.example.com"],
       "status": "ISSUED", "aws_type": "AMAZON_ISSUED", "source": "aws", "identity": ACM_ARN}

SAN_SERIAL = "9c0d1e2f30415263748596a7b8c9dae1"
SAN_NODE = {**NODE, "subject": "", "serial": SAN_SERIAL, "fingerprint_sha256": "cd" * 32, "san": ["api.example.com"]}
SAN_ACM = {**ACM, "subject": None, "serial": SAN_SERIAL.upper(), "san": ["api.example.com"]}

LAB_CA = {"source": "tls", "subject": "CN=ZeroShield Lab CA,O=ZeroShield Lab", "issuer": "CN=ZeroShield Lab CA,O=ZeroShield Lab",
          "serial": "3e8", "not_before": "2026-01-01T00:00:00Z", "not_after": "2036-01-01T00:00:00Z", "is_ca": True,
          "self_signed": True, "fingerprint_sha256": "5a" * 32, "key_alg": "RSA", "key_size": 4096}


def node(facts, *, asset_type="certificate", location="10.0.0.5:443#chain[0]", target="10.0.0.5", scope="src-1"):
    """One observation by source ``src-1`` (the scope that makes a private / documentation address unique)."""
    return AK.Observation(kind=asset_type, facts=facts, location=location, target=target, scope=scope)


# ----------------------------------------------------------------------------- the must-pass cases
def test_da_p3_acm_issuer_amazon_and_the_node_dn_are_one_key():
    """DA-P3: ACM says Issuer "Amazon", the node the full DN; the serials match -> one asset (no other help)."""
    acm = node(ACM, location=ACM_ARN, target="123456789012")
    probe = node(NODE)
    assert AK.asset_key(acm) == AK.asset_key(probe)
    assert AK.asset_key(acm).startswith("cert:") and len(AK.asset_key(acm)) <= 64
    assert AK.key_basis(acm) == AK.key_basis(probe) == "serial"


def test_lab_ca_seen_in_four_chains_is_one_key():
    """CB-19 §1.7: the lab CA certificate is chain[1] of four endpoints -> one key, small serial included."""
    seen = [node(LAB_CA, location=f"10.0.0.{n}:443#chain[1]", target=f"10.0.0.{n}") for n in (5, 6, 7, 8)]
    keys = {AK.asset_key(o) for o in seen}
    assert len(keys) == 1 and None not in keys
    assert set(AK.correlate(seen)) == keys


def test_p1_prober_linux_windows_and_acm_views_of_one_certificate_are_one_asset():
    """CB-24 probe P1: today 3 identities (Windows has no NotBefore, ACM's issuer is "Amazon") -> one."""
    views = [node(NODE), node(LINUX_FILE, asset_type="certificate", location="/etc/ssl/www.pem", target="web-1"),
             node(WINDOWS, location="LocalMachine\\My\\" + "0F" * 20, target="win-1"),
             node(ACM, location=ACM_ARN, target="123456789012")]
    keys = AK.correlate(views)
    assert len(set(keys)) == 1 and isinstance(keys[0], str)
    # the three that carry a serial agree without correlation; Windows joins through its DN and notAfter
    assert AK.asset_key(views[0]) == AK.asset_key(views[1]) == AK.asset_key(views[3]) == keys[0]
    assert AK.key_basis(views[2]) == "sha1"  # its thumbprint (no other source reports SHA-1)
    assert _link(WINDOWS, "dn") == _link(NODE, "dn")


def test_p1_san_only_certificate_gets_one_key():
    file_view = node(SAN_NODE, location="/etc/ssl/api.pem", target="web-1")
    probe = node(SAN_NODE)
    acm = node(SAN_ACM, location=ACM_ARN + "-san", target="123456789012")
    keys = AK.correlate([file_view, probe, acm])
    assert len(set(keys)) == 1 and isinstance(keys[0], str)
    assert AK.asset_key(file_view) == keys[0]


def test_p1_through_the_team_view_counts_each_certificate_once(engine):
    """The four collectors plus the SAN-only certificate through ``load_sources_result`` + ``resolve``: 2 assets."""
    with Session(engine) as s:
        run = _run(s)
        _asset(s, run, "network", NODE, location="10.0.0.5:443#chain[0]", days_ago=4)
        _asset(s, run, "linux_servers", LINUX_FILE, location="/etc/ssl/www.pem", days_ago=3)
        _asset(s, run, "windows_servers", WINDOWS, location="LocalMachine\\My\\" + "0F" * 20, days_ago=2)
        _asset(s, run, "aws_account", ACM, location=ACM_ARN, days_ago=1)
        _asset(s, run, "network-2", SAN_NODE, location="10.0.0.9:443#chain[0]", days_ago=4)
        _asset(s, run, "linux-2", SAN_NODE, location="/etc/ssl/api.pem", days_ago=3)
        _asset(s, run, "aws-2", SAN_ACM, location=ACM_ARN + "-san", days_ago=1)
        s.commit()
        result = CV.load_sources_result(s, 1)
    assert len(result.rows) == 7
    kept = CV.resolve([], result.rows).sources_rows
    assert len(kept) == 2  # dev: 6 (P1's three identities + an unidentified SAN-only row per source)
    assert {item.collection.source_kind for item in kept} == {"aws_account", "aws-2"}  # latest observation wins


# ----------------------------------------------------------------------------- negative cases
def test_two_different_certificates_with_the_same_cn_stay_two_assets():
    other = {**NODE, "serial": "0123456789abcdef0123456789abcdef", "fingerprint_sha256": "ef" * 32}
    a, b = node(NODE), node(other, location="10.0.0.6:443#chain[0]")
    assert AK.asset_key(a) != AK.asset_key(b)
    # same CN, issuer and even the same notAfter: a Windows row matching both by DN does not bridge them, and as it
    # cannot tell which one it is, it joins neither (review of #137, minor at L437)
    keys = AK.correlate([a, node(WINDOWS, location="LocalMachine\\My\\x"), b])
    assert keys[0] != keys[2]
    assert keys[1] not in (keys[0], keys[2]) and isinstance(keys[1], str)


def test_a_code_row_matching_two_certificates_by_cn_is_not_merged_with_either(engine):
    other = {**NODE, "serial": "0123456789abcdef0123456789abcdef", "fingerprint_sha256": "ef" * 32}
    with Session(engine) as s:
        run = _run(s)
        _asset(s, run, "net-a", NODE, location="10.0.0.5:443#chain[0]", days_ago=2)
        _asset(s, run, "net-b", other, location="10.0.0.6:443#chain[0]", days_ago=2)
        s.commit()
        result = CV.load_sources_result(s, 1)
    code = AK.code_certificate_key("www.example.com", "Amazon RSA 2048 M02", "2026-06-01T00:00:00Z",
                                   "2027-07-01T23:59:59Z")
    resolution = CV.resolve([(7, dt.datetime(2026, 11, 1), code)], result.rows)
    assert len(resolution.sources_rows) == 2 and resolution.dropped_code == set()
    assert resolution.code_kept(7, code)


def test_reissued_certificate_with_the_same_key_pair_is_a_new_asset_but_the_same_observation():
    """Renewal keeps the key pair (same SPKI) but gets a new serial and dates: a different certificate asset; the
    per-source observation key drift and waves use is unchanged (it reports "renewed")."""
    renewed = {**NODE, "serial": "77" * 16, "not_before": "2027-06-01T00:00:00Z", "not_after": "2028-07-01T23:59:59Z",
               "fingerprint_sha256": "12" * 32}
    old_row = CbomCollectedAsset(team_id=1, run_id=1, job_id=1, attempt=1, asset_key="k1", asset_type="certificate",
                                 cdx_type="certificate", target="10.0.0.5", location="10.0.0.5:443#chain[0]",
                                 facts=NODE)
    new_row = CbomCollectedAsset(team_id=1, run_id=2, job_id=2, attempt=1, asset_key="k2", asset_type="certificate",
                                 cdx_type="certificate", target="10.0.0.5", location="10.0.0.5:443#chain[0]",
                                 facts=renewed)
    assert AK.asset_key(old_row) != AK.asset_key(new_row)
    assert AK.observation_key(old_row, "src-uid") == AK.observation_key(new_row, "src-uid")
    assert AK.correlate([old_row, new_row])[0] != AK.correlate([old_row, new_row])[1]


def test_existing_per_source_keys_are_unchanged():
    """Drift, waves and remediation assignments are keyed by ``identity``: CB-21 must not move them."""
    row = CbomCollectedAsset(team_id=1, run_id=1, job_id=1, attempt=1, asset_key="type|t|l|i",
                             asset_type="certificate", cdx_type="certificate", target="10.0.0.5",
                             location="10.0.0.5:443#chain[0]", facts=NODE)
    assert ID.node_identity(row) == "cert|10.0.0.5|10.0.0.5:443#chain[0]|cn=www.example.com|" + NODE_ISSUER.lower()
    assert ID.stable_key("node", "src-uid", ID.node_identity(row)) == "01108eae896457e39069a5db01217c87c6e74957"  # dev
    assert AK.observation_key(row, "src-uid") == ID.stable_key("node", "src-uid", ID.node_identity(row))
    key = CbomCollectedAsset(team_id=1, run_id=1, job_id=1, attempt=1, asset_key="kms_key|acct|arn|x",
                             asset_type="kms_key", cdx_type="related-crypto-material", target="acct", location="arn")
    assert AK.observation_key(key, "s") == ID.stable_key("node", "s", "key|kms_key|acct|arn|x")
    assert AK.code_observation_key({"asset_type": "certificate", "title": "cert.pem", "location": "a/cert.pem:3",
                                    "bom_ref": "crypto-cert-l3"}, "repo:h/o/r@main") == \
        ID.stable_key("code", "repo:h/o/r@main", ID.code_identity({"asset_type": "certificate", "title": "cert.pem",
                                                                   "location": "a/cert.pem:3",
                                                                   "bom_ref": "crypto-cert-l3"}))


# ----------------------------------------------------------------------------- endpoints and cloud resources
@pytest.mark.parametrize("a,b", [
    ("[2001:DB8:0:0:0:0:0:1]:443", "[2001:db8::1]:443"),
    ("[::ffff:10.0.0.5]:443", "10.0.0.5:443"),
    ("WWW.Example.COM.:443", "www.example.com:443"),
    ("tls://[2001:db8::1]:443/", "[2001:db8::1]:443"),
    ("  10.0.0.5:0443 ", "10.0.0.5:443"),
])
def test_endpoint_keys_normalise_host_and_port(a, b):
    ka, kb = AK.asset_key(node({}, asset_type="tls_endpoint", location=a)), AK.asset_key(
        node({}, asset_type="tls_endpoint", location=b))
    assert ka == kb and ka.startswith("ep:")
    assert AK.endpoint_host_port(b) in ("[2001:db8::1]:443", "10.0.0.5:443", "www.example.com:443")


@pytest.mark.parametrize("a,b", [
    ("[2001:db8::1]:443", "[2001:db8::2]:443"),
    ("[2001:db8::1]:443", "[2001:db8::1]:8443"),
    ("10.0.0.5:443", "[2001:db8::a00:5]:443"),
    ("10.0.0.5:22", "10.0.0.5:443"),
])
def test_different_endpoints_have_different_keys(a, b):
    assert AK.asset_key(node({}, asset_type="tls_endpoint", location=a)) != AK.asset_key(
        node({}, asset_type="tls_endpoint", location=b))


@pytest.mark.parametrize("where", ["2001:db8::1:443", "[2001:db8::1]", "10.0.0.5", "10.0.0.5:70000", "", "[zz]:443"])
def test_an_endpoint_without_a_parseable_host_and_port_has_no_key(where):
    assert AK.endpoint_host_port(where) is None
    assert AK.asset_key(node({}, asset_type="tls_endpoint", location=where, target="")) is None


def test_ssh_and_tls_endpoints_share_the_host_port_space():
    assert AK.asset_key(node({}, asset_type="ssh_endpoint", location="[2001:db8::1]:22")) == \
        AK.asset_key(node({}, asset_type="tls_endpoint", location="[2001:DB8::1]:22"))


def test_cloud_resources_are_keyed_by_their_arn_or_resource_id():
    arn = "arn:aws:kms:ap-south-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    a = node({"identity": arn}, asset_type="kms_key", location=arn, target="123456789012")
    b = node({"identity": arn + " "}, asset_type="kms_key", location="elsewhere", target="other label")
    assert AK.asset_key(a) == AK.asset_key(b) and AK.asset_key(a).startswith("cloud:")
    az = "/subscriptions/S1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/V1"
    assert AK.asset_key(node({"identity": az}, asset_type="key_vault")) == \
        AK.asset_key(node({"identity": az.lower()}, asset_type="key_vault"))
    assert AK.asset_key(node({"identity": "vol-0abc"}, asset_type="disk_encryption")) is None


# ----------------------------------------------------------------------------- normalisation
def test_case_and_whitespace_never_split_a_certificate():
    noisy = {**NODE, "serial": "  00" + SERIAL.upper() + " ", "fingerprint_sha256": ":".join(["AB"] * 32),
             "subject": "  cn = WWW.Example.com ", "issuer": "/C=US/O=Amazon/CN=Amazon  RSA 2048 M02",
             "not_after": "2027-07-01 23:59:59+00:00"}
    assert AK.asset_key(node(noisy)) == AK.asset_key(node(NODE))
    slash = {**WINDOWS, "issuer": "/C=US/O=amazon/CN=AMAZON RSA 2048 M02", "subject": "/CN=www.example.com"}
    assert _link(slash, "dn") == _link(WINDOWS, "dn") and _link(slash, "cn") == _link(WINDOWS, "cn")
    assert _link(slash, "dn") is not None
    assert AK.norm_dn('O="Acme, Inc.", CN=a') == AK.norm_dn("CN=A,O=Acme\\, Inc.") == "cn=a,o=acme, inc."


def test_times_are_compared_in_utc_to_the_second():
    shifted = {**WINDOWS, "not_after": "2027-07-02T05:29:59+05:30"}
    assert AK.link_keys(node(shifted)) == AK.link_keys(node(WINDOWS))
    assert _link(NODE, "dn") == _link(WINDOWS, "dn")  # "...59Z" and "...59.0000000Z"
    later = {**WINDOWS, "not_after": "2027-07-01T23:59:58Z"}
    assert _link(later, "dn") != _link(WINDOWS, "dn")


def test_a_short_serial_needs_the_same_issuer_dn_and_a_long_one_does_not():
    short = {"serial": "1f", "issuer": "CN=Lab CA", "not_after": "2027-01-01T00:00:00Z"}
    other_ca = {**short, "issuer": "CN=Other Lab CA"}
    assert AK.asset_key(node(short)) != AK.asset_key(node(other_ca))
    assert AK.asset_key(node(short)) == AK.asset_key(node({**short, "issuer": "cn=lab  ca"}))
    long_ = {"serial": "0a:1b:2c:3d:4e:5f:60:71:82", "issuer": "CN=X", "not_after": "2027-01-01T00:00:00Z"}
    assert AK.asset_key(node(long_)) == AK.asset_key(node({**long_, "issuer": "Amazon"}))


# ----------------------------------------------------------------------------- the "not correlated" value
def test_correlation_required_but_absent_is_a_distinct_falsy_value():
    bare = node({"key_alg": "RSA"})  # a certificate with no serial, fingerprint, subject or notAfter
    assert AK.asset_key(bare) is AK.NOT_CORRELATED
    assert not AK.NOT_CORRELATED and not isinstance(AK.NOT_CORRELATED, str)
    assert AK.NOT_CORRELATED.reason == "not_correlated"
    assert AK.correlation_missing(bare)
    iac = AK.Observation(kind="key", facts={"cloud_resource": "aws_kms_key"}, location="main.tf", origin="code")
    assert AK.asset_key(iac) is AK.NOT_CORRELATED and AK.correlation_missing(iac)
    algorithm = node({}, asset_type="crypto_library", location="/usr/lib/libssl.so.3")
    assert AK.asset_key(algorithm) is None and not AK.correlation_missing(algorithm)
    assert AK.correlate([bare, algorithm, node(NODE)])[:2] == [AK.NOT_CORRELATED, None]


def test_the_not_correlated_reason_is_the_qgrade_reason():
    from backend.utilities.cbom_sources import qgrade

    assert AK.NOT_CORRELATED.reason in qgrade.REASONS


# ----------------------------------------------------------------------------- purity
def test_keys_are_pure_and_correlation_does_not_depend_on_order():
    views = [node(NODE), node(WINDOWS, location="w"), node(ACM, location=ACM_ARN), node(SAN_NODE),
             node(LAB_CA, location="x"), node({**NODE, "serial": "0123456789abcdef0123456789abcdef",
                                               "fingerprint_sha256": "ef" * 32}, location="y")]
    expected = AK.correlate(views)
    for perm in itertools.permutations(range(len(views))):
        keys = AK.correlate([views[i] for i in perm])
        got = [None] * len(views)
        for pos, i in enumerate(perm):
            got[i] = keys[pos]
        assert got == expected  # including the Windows row that matches two certificates by DN (it joins neither)
    assert [AK.asset_key(v) for v in views] == [AK.asset_key(v) for v in views]


def test_mapping_and_row_shapes_give_the_same_key():
    row = CbomCollectedAsset(team_id=1, run_id=1, job_id=1, attempt=1, asset_key="k", asset_type="certificate",
                             cdx_type="certificate", target="10.0.0.5", location="10.0.0.5:443#chain[0]", facts=NODE)
    as_map = {"asset_type": "certificate", "facts": NODE, "location": "10.0.0.5:443#chain[0]"}
    assert AK.asset_key(row) == AK.asset_key(as_map) == AK.asset_key(node(NODE))


# ----------------------------------------------------------------------------- code scans
def test_a_code_scan_certificate_joins_the_windows_view_of_the_same_certificate(engine):
    """Code rows carry CN-only names and both dates; Windows has no NotBefore. Dev's identity included NotBefore,
    so the two never met; the code row is now superseded by the newer Windows observation."""
    with Session(engine) as s:
        run = _run(s)
        _asset(s, run, "windows_servers", WINDOWS, location="LocalMachine\\My\\" + "0F" * 20, days_ago=1)
        s.commit()
        result = CV.load_sources_result(s, 1)
    code = AK.code_certificate_key("www.example.com", "Amazon RSA 2048 M02", "2026-06-01T00:00:00Z",
                                   "2027-07-01T23:59:59Z")
    resolution = CV.resolve([(7, dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=5), code)], result.rows)
    assert not resolution.code_kept(7, code)
    assert resolution.canonical(code) == result.rows[0].identity


def test_code_scan_certificate_identities_are_asset_keys():
    scan = {"cbom_json": {"components": [{
        "bom-ref": "crypto-cert-1", "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
            "subjectName": "www.example.com", "issuerName": "Amazon RSA 2048 M02",
            "notValidBefore": "2026-06-01T00:00:00Z", "notValidAfter": "2027-07-01T23:59:59Z"}}}]}}
    ids = CV.code_cert_identities(scan)
    assert ids == {"crypto-cert-1": AK.code_certificate_key("www.example.com", "Amazon RSA 2048 M02",
                                                            "2026-06-01T00:00:00Z", "2027-07-01T23:59:59Z")}
    assert ids["crypto-cert-1"].startswith("cert:")


# ----------------------------------------------------------------------------- review of #137: 18 adversarial cases
REAL = {**NODE, "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
        "not_before": "2026-07-01T00:00:00Z"}


def test_r1_a_re_signed_copy_with_the_same_long_serial_is_a_different_certificate():
    """TLS inspection re-signs with the original serial and dates: other issuer, key and DER -> 2 assets."""
    forged = {**REAL, "issuer": "CN=Corp TLS Inspection CA,O=Corp", "fingerprint_sha256": "cd" * 32, "key_size": 1024}
    keys = AK.correlate([node(REAL), node(forged, location="10.9.0.1:443#chain[0]")])
    assert keys[0] != keys[1]
    # ACM (Issuer "Amazon", no DN) matches both by serial: it cannot say which one it is, so it joins neither
    acm = node({**ACM, "not_before": REAL["not_before"]}, location=ACM_ARN)
    keys = AK.correlate([node(REAL), node(forged, location="10.9.0.1:443#chain[0]"), acm])
    assert len(set(keys)) == 3
    # the serial key both certificates share names neither of them
    assert AK.asset_key(node(REAL)) not in keys[:2]


def test_r2_two_same_named_test_cas_counting_from_one_issue_different_certificates():
    one = {"subject": "CN=api.dev", "issuer": "CN=Test CA", "serial": "01", "not_after": "2027-01-01T10:00:00Z",
           "fingerprint_sha256": "11" * 32}
    two = {"subject": "CN=db.prod", "issuer": "CN=Test CA", "serial": "1", "not_after": "2027-01-01T18:30:00Z",
           "fingerprint_sha256": "22" * 32}
    assert AK.asset_key(node(one)) != AK.asset_key(node(two))
    keys = AK.correlate([node(one), node(two, location="x")])
    assert keys[0] != keys[1]
    # the same short-serial certificate with no fingerprint (a file read without DER) still joins its own copy
    assert AK.asset_key(node({**one, "fingerprint_sha256": None})) == AK.asset_key(node({**one, "fingerprint_sha256": None}))


WIN_OLD = {**WINDOWS, "thumbprint": "AA" * 20, "key_size": 1024}
WIN_NEW = {**WINDOWS, "thumbprint": "BB" * 20, "key_size": 3072}


def test_r3_two_windows_rows_with_different_thumbprints_are_two_certificates():
    """A reissue that keeps the expiry (same DN and notAfter second) leaves the old certificate in the store."""
    keys = AK.correlate([node(WIN_OLD, location="a"), node(WIN_NEW, location="b")])
    assert keys[0] != keys[1]


def test_r3b_two_windows_rows_with_different_thumbprints_count_twice_in_the_team_view(engine):
    with Session(engine) as s:
        run = _run(s)
        _asset(s, run, "win-a", WIN_OLD, location="My\\aa", days_ago=2)
        _asset(s, run, "win-b", WIN_NEW, location="My\\bb", days_ago=1)
        s.commit()
        result = CV.load_sources_result(s, 1)
    assert len(CV.resolve([], result.rows).sources_rows) == 2


def test_r4_a_code_row_for_the_old_certificate_is_not_dropped_behind_its_reissue(engine):
    """dev's identity used notBefore; a reissue with the same CN, issuer CN and notAfter but a new notBefore is
    another certificate, and the code finding on the old one stays."""
    with Session(engine) as s:
        run = _run(s)
        _asset(s, run, "net", REAL, location="10.0.0.5:443#chain[0]", days_ago=1)
        s.commit()
        result = CV.load_sources_result(s, 1)
    old = AK.code_certificate_key("www.example.com", "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                                  "2025-07-01T00:00:00Z", REAL["not_after"])
    same = AK.code_certificate_key("www.example.com", "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                                   REAL["not_before"], REAL["not_after"])
    resolution = CV.resolve([(7, dt.datetime(2026, 1, 1), old), (8, dt.datetime(2026, 1, 1), same)], result.rows)
    assert resolution.code_kept(7, old)
    assert not resolution.code_kept(8, same)  # the same certificate (same notBefore) is still matched


def test_r5_a_64_bit_serial_with_a_leading_zero_nibble_is_still_long():
    serial = "0f3a1c2b4d5e6f70"
    probe = node({**NODE, "serial": serial.lstrip("0")})
    acm = node({**ACM, "serial": ":".join(serial[i:i + 2] for i in range(0, 16, 2))}, location=ACM_ARN)
    assert AK.asset_key(probe) == AK.asset_key(acm)


def test_r6_not_after_with_an_offset_is_the_same_instant():
    assert _link({**WINDOWS, "not_after": "2027-07-01T18:59:59-05:00"}, "dn") == _link(WINDOWS, "dn")


def test_r7_a_ct_precertificate_and_the_final_certificate_are_one_asset():
    final = {**REAL}
    precert = {**REAL, "fingerprint_sha256": None, "precert_sha256": "99" * 32}
    keys = AK.correlate([node(final), node(precert, location="ct")])
    assert keys[0] == keys[1]


def test_r8_weak_rows_never_bridge_two_strong_certificates_in_any_order():
    other = {**NODE, "serial": "0123456789abcdef0123456789abcdef", "fingerprint_sha256": "ef" * 32}
    views = [node(NODE), node(other, location="b"), node(WINDOWS, location="w1"),
             node({**WINDOWS, "thumbprint": "1E" * 20}, location="w2"), node(LINUX_FILE, location="f")]
    for perm in itertools.permutations(range(len(views))):
        keys = AK.correlate([views[i] for i in perm])
        got = dict(zip(perm, keys))
        assert got[0] != got[1] and got[0] == got[4]
        assert got[2] not in (got[0], got[1]) and got[3] not in (got[0], got[1])


def test_r9_eighty_mixed_observations_partition_identically_in_300_shuffles():
    import random

    base = [NODE, LINUX_FILE, WINDOWS, ACM, SAN_NODE, SAN_ACM, LAB_CA, REAL, WIN_OLD, WIN_NEW]
    views = [node(base[i % len(base)], location=f"l{i}") for i in range(80)]
    expected = AK.correlate(views)
    rng = random.Random(137)
    for _ in range(300):
        order = list(range(80))
        rng.shuffle(order)
        keys = AK.correlate([views[i] for i in order])
        assert [k for _i, k in sorted(zip(order, keys))] == expected


def test_r10_endpoint_forms():
    assert AK.endpoint_host_port("[::ffff:203.0.113.5]:443") == "203.0.113.5:443"
    assert AK.endpoint_host_port("[2001:DB8::0:1]:443") == "[2001:db8::1]:443"
    assert AK.endpoint_host_port("https://WWW.Example.com.:8443/x") == "www.example.com:8443"


@pytest.mark.parametrize("url,want", [("https://www.example.com/", "www.example.com:443"),
                                      ("http://www.example.com", "www.example.com:80"),
                                      ("ldaps://dc1.corp.example", "dc1.corp.example:636"),
                                      ("ssh://[2001:db8::1]", "[2001:db8::1]:22")])
def test_r10b_a_url_without_a_port_gets_the_scheme_default(url, want):
    assert AK.endpoint_host_port(url) == want


@pytest.mark.parametrize("where", ["10.0.0.5:443", "127.0.0.1:8443", "[fe80::1]:443", "[fd00::5]:443",
                                   "192.168.1.10:22", "172.16.0.1:443"])
def test_r10c_private_and_loopback_endpoints_are_scoped_to_their_source(where):
    a = AK.Observation(kind="tls_endpoint", location=where, scope="source-a")
    b = AK.Observation(kind="tls_endpoint", location=where, scope="source-b")
    assert AK.asset_key(a) != AK.asset_key(b)
    assert AK.asset_key(a) == AK.asset_key(AK.Observation(kind="tls_endpoint", location=where, scope="source-a"))
    assert AK.asset_key(AK.Observation(kind="tls_endpoint", location=where)) is None  # no scope known: no key
    public = "93.184.215.14:443"  # TEST-NET ranges count as private in ipaddress
    assert AK.asset_key(AK.Observation(kind="tls_endpoint", location=public, scope="source-a")) == \
        AK.asset_key(AK.Observation(kind="tls_endpoint", location=public, scope="source-b"))


def test_r11_azure_ids_fold_case_and_arn_partitions_stay_apart():
    az = "/subscriptions/S1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/V1"
    assert AK.cloud_resource_id(az) == AK.cloud_resource_id(az.upper())
    assert AK.cloud_resource_id("arn:aws:kms:us-east-1:1:key/k") != AK.cloud_resource_id("arn:aws-cn:kms:us-east-1:1:key/k")


@pytest.mark.parametrize("a,b", [
    ("//certificatemanager.googleapis.com/projects/p/locations/global/certificates/c",
     "projects/p/locations/global/certificates/c"),
    ("//sqladmin.googleapis.com/projects/p/instances/i", "projects/p/instances/i"),
    ("https://v1.vault.azure.net/certificates/web/0123456789abcdef0123456789abcdef", "https://V1.vault.azure.net/certificates/web"),
    ("https://v1.vault.azure.cn/keys/k1/abc", "https://v1.vault.azure.cn/keys/k1/"),
    ("https://v1.vault.usgovcloudapi.net/secrets/s1/v2", "https://v1.vault.usgovcloudapi.net/secrets/s1"),
])
def test_r11b_cloud_resource_id_forms(a, b):
    assert AK.cloud_resource_id(a) and AK.cloud_resource_id(a) == AK.cloud_resource_id(b)


def test_r12_a_sha256_in_the_thumbprint_field_is_never_read_as_sha1():
    assert not [k for k in AK.link_keys(node({**WINDOWS, "thumbprint": "AB" * 32})) if k.basis == "sha1"]


def test_r13_integer_and_text_serials_agree_and_negative_text_serials_have_none():
    assert AK.norm_serial(int(SERIAL, 16)) == AK.norm_serial(SERIAL.upper()) == SERIAL
    assert AK.norm_serial("-1f") == "" and AK.norm_serial(-31) == ""
    assert AK.norm_serial("1f") == "1f"


def test_r14_correlation_is_linear_on_a_device_fleet_sharing_cn_issuer_and_not_after():
    """IEEE 802.1AR device certificates: same CN, issuer and notAfter 9999-12-31, distinct serials (the review
    measured 8k -> 37 s with the quadratic bucket loop)."""
    import time

    fleet = [node({"subject": f"CN=device,SERIALNUMBER=SN{i:06d}", "issuer": "CN=Device CA,O=Maker",
                   "serial": format(10**20 + i, "x"), "not_after": "9999-12-31T23:59:59Z",
                   "fingerprint_sha256": format(i, "064x")}, location=f"d{i}") for i in range(8000)]
    fleet += [node({"subject": "CN=device", "issuer": "CN=Device CA, O=Maker", "thumbprint": format(i, "040x"),
                    "not_after": "9999-12-31T23:59:59Z"}, location=f"w{i}") for i in range(200)]
    started = time.perf_counter()
    keys = AK.correlate(fleet)
    elapsed = time.perf_counter() - started
    assert len(set(keys)) == 8200  # nothing merged: every certificate differs
    assert elapsed < 10, elapsed


# ----------------------------------------------------------------------------- helpers
def _link(facts, basis):
    return next((k.key for k in AK.link_keys(node(facts)) if k.basis == basis), None)


@pytest.fixture
def engine():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    yield eng
    eng.dispose()


def _run(s: Session) -> CbomCollectionRun:
    run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id=f"r-{dt.datetime.utcnow().timestamp()}",
                            status="success")
    s.add(run)
    s.flush()
    return run


def _asset(s: Session, run: CbomCollectionRun, kind: str, facts: dict, *, location: str, days_ago: int) -> None:
    source = CbomCollectionSource(team_id=1, owner_user_id=1, kind=kind, name=f"{kind}-src", name_lower=f"{kind}-src",
                                  config={}, created_at=dt.datetime.utcnow())
    s.add(source)
    s.flush()
    job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=source.id, kind="collect", status="success",
                            attempts=1, finished_at=dt.datetime.utcnow() - dt.timedelta(days=days_ago), params={})
    s.add(job)
    s.flush()
    s.add(CbomCollectedAsset(team_id=1, run_id=run.id, job_id=job.id, source_id=source.id, attempt=1,
                             asset_key=f"k-{kind}-{location}", asset_type="certificate", cdx_type="certificate",
                             target=location.split(":")[0], location=location, name="cert", algorithm="RSA",
                             key_size=2048, facts=facts, finding_codes=[]))
