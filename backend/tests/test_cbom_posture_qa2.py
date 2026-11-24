"""Staging QA round 2, lane Q3 (24 Nov 2026), D6-D10: one resource counted once, whatever reads it.

Q3-01  D6 and D9 printed each resource once per source when two sources read the same AWS account (team 1: KMS
       70 rows for 48 keys, resources 136 for 70, managed TLS 48 for 24, secrets 162 for 83, D9 stores 132 for 68,
       EKS secrets 2 for 1).  Root cause: every Sources asset was identified within its own source
       (``node|<source uid>|...``), so "latest observation wins" never met the second source's copy.  Fix:
       ``resource_identity`` (ARN / provider resource id / host:port / target + location) and ``also_seen``.
Q3-03  D10 printed a deleted source on current library rows (``mapper.library_component`` had no deleted check).
Q3-11  D10 had no crypto-product rows (HSM, KMIP, key manager, appliance, cloud KMS) and pooled only code scans.

Fixture: ``support/two_aws_roles.py`` (staging run #57's assets API, two IAM roles on one account) and
``support/sources_every_type.py``.  Oracle: literals counted from the fixture JSON (unique ARNs per type), never the
product's aggregation.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import sys
from collections import Counter
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.tests.support import sources_every_type as FX  # noqa: E402
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.tests.test_cbom_sources_posture_d6_d9_d10 import kpi_cards, rows_under, story  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView, merge_collections  # noqa: E402
from backend.utilities.pdf import cbom_assurance_register_pdf as d10  # noqa: E402
from backend.utilities.pdf import cbom_data_at_rest_pdf as d9  # noqa: E402
from backend.utilities.pdf import cbom_infra_posture_pdf as d6  # noqa: E402
from backend.utilities.pdf import cbom_network_tls_pdf as d7  # noqa: E402

NOW = dt.datetime(2026, 11, 24, 6, 0, tzinfo=dt.timezone.utc)
NEWER, OLDER = "aws-pca-test", "stgqa-aws-ap-south-1"  # job 521 finished 30 s after job 520


def _empty() -> TeamCbomView:
    return TeamCbomView(team_id=1, team_name="Staging", generated_at=NOW, as_of=NOW.date(), fingerprint="q3qa0001")


def _view(**kwargs) -> TeamCbomView:
    rows, collections = AWS2.build(**kwargs)
    return merge_collections(_empty(), rows, collections)


@pytest.fixture(scope="module")
def view() -> TeamCbomView:
    return _view()


def _unique(kind: str, job: int = 520, **facts) -> int:
    """Unique resource ids of one type in the fixture JSON (the oracle)."""
    return len({i["location"] for i in AWS2.items() if i["type"] == kind and i["job_id"] == job
                and all(i["facts"].get(k) == v for k, v in facts.items())})


def test_fixture_is_two_sources_reading_one_account():
    by_job = Counter(i["job_id"] for i in AWS2.items())
    assert by_job == {520: 229, 521: 229}
    for kind in ("kms_key", "storage_encryption", "load_balancer_tls", "cdn_tls", "cloud_secret"):
        assert _unique(kind, 520) == _unique(kind, 521)
    assert (_unique("kms_key"), _unique("storage_encryption"), _unique("load_balancer_tls"), _unique("cdn_tls"),
            _unique("cloud_secret"), _unique("cloud_ca")) == (19, 65, 21, 3, 73, 2)
    assert _unique("storage_encryption", encrypted=False) == 10


# ------------------------------------------------------------------------------------------------ Q3-01 D6
def test_d6_kms_register_lists_each_key_once(view):
    rows = rows_under(story(d6, view), "Key")
    assert len(rows) == 19  # staging printed 2 x 19 for this account
    assert len({r["Location"] for r in rows}) == 19
    assert kpi_cards(story(d6, view))["KMS keys"] == "19"


def test_d6_registers_count_each_resource_once(view):
    body = story(d6, view)
    resources = rows_under(body, "Resource")
    at_rest = [r for r in resources if "Native type" in r]
    assert len(at_rest) == 65 + 1  # 65 storage settings + the Glue catalog
    managed = rows_under(body, "Endpoint")
    assert len(managed) == 21 + 3 == 24
    secrets = [r for r in resources if "Service" in r]
    assert len(secrets) == 73 + 2  # secrets + the two private CAs
    cards = kpi_cards(body)
    assert cards["Not encrypted"] == str(10 + 1)  # 10 volumes / buckets + the DISABLED Glue catalog
    assert int(cards["Facts"]) == 19 + 66 + 24 + 75


def test_d6_source_cell_names_the_newest_reader_and_the_other(view):
    rows = rows_under(story(d6, view), "Key")
    assert {r["Source"] for r in rows} == {f"{NEWER} (also: {OLDER})"}


def test_d6_managed_tls_equals_d7_listener_count(view):
    managed = rows_under(story(d6, view), "Endpoint")
    scoped, _model = d7._scoped(view)
    listeners = [f for f in d7._endpoints(scoped) if d7._collected_tls(f)]
    assert len(listeners) == len(managed) == 24


# ------------------------------------------------------------------------------------------------ Q3-01 D9
def test_d9_lists_each_store_once(view):
    body = story(d9, view)
    stores = rows_under(body, "Store")
    assert len(stores) == len({r["Location"] for r in stores})
    cards = kpi_cards(body)
    assert cards["Data stores"] == str(len(stores))
    eks = [r for r in stores if "eks" in r["Location"].casefold()]
    assert cards["Kubernetes secrets"] == "1" and not eks  # EKS secrets: their own KPI, once


def test_d9_store_count_is_unique_resources(view):
    stores = rows_under(story(d9, view), "Store")
    single = merge_collections(_empty(), *AWS2.build(jobs=(521,)))
    assert len(stores) == len(rows_under(story(d9, single), "Store"))


# ------------------------------------------------------------------------------------------------ Q3-01 rules
def test_headline_assets_count_each_resource_once(view):
    one = merge_collections(_empty(), *AWS2.build(jobs=(520,)))
    assert len([a for a in view.assets if a.current]) == len([a for a in one.assets if a.current])


def test_deleted_newer_source_never_hides_the_live_observation():
    folded = _view(deleted=(521,))
    rows = rows_under(story(d6, folded), "Key")
    assert len(rows) == 19
    assert {r["Source"] for r in rows} == {OLDER}  # the live source, and the deleted one is never named


def test_one_collection_reporting_a_location_twice_is_not_folded():
    from backend.utilities.cbom_sources.collections_view import link_resources

    rows, _c = AWS2.build(jobs=(520,))
    twin = next(r for r in rows if r.node_type == "kms_key")
    copy = dataclasses.replace(twin, row=dict(twin.row), identity=twin.identity + "-twin")
    rows.append(copy)
    link_resources(rows)
    assert not twin.identity.startswith("res|") and not copy.identity.startswith("res|")


def test_resource_identity_rules():
    from backend.utilities.cbom_sources.resource_identity import (
        resource_identity as rid,
    )

    arn = "arn:aws:kms:ap-south-1:444455556666:key/1"
    assert rid("kms_key", "aws:444455556666", arn) == rid("kms_key", "aws:other-label", arn) == f"res|kms_key|{arn}"
    assert rid("tls_endpoint", "10.0.0.5", "10.0.0.5:443") == rid("tls_endpoint", "lab", "10.0.0.5:443")
    assert rid("tls_endpoint", "x", "10.0.0.5:443", {"sni": "a.example"}) != rid("tls_endpoint", "x", "10.0.0.5:443")
    assert rid("disk_encryption", "web01", "/dev/mapper/data") == "res|disk_encryption|web01|/dev/mapper/data"
    assert rid("managed_key", "", "transit/keys/a") is None  # no host: not unique across two Vault servers
    assert rid("certificate", "x", arn) is None and rid("crypto_library", "x", "package:libssl3") is None


# ------------------------------------------------------------------------------------------------ Q3-03 / Q3-11 D10
def _every_type(deleted: tuple[str, ...] = ()) -> TeamCbomView:
    rows, collections = FX.build()
    gone = {c.key for c in collections if c.source_name in deleted}
    if gone:
        collections = [dataclasses.replace(c, source_kind="") if c.key in gone else c for c in collections]
        by_key = {c.key: c for c in collections}
        rows = [dataclasses.replace(r, collection=by_key[r.collection.key]) for r in rows]
    empty = TeamCbomView(team_id=1, team_name="Bank One", generated_at=FX.OBSERVED, as_of=FX.OBSERVED.date(),
                         fingerprint="b1f1x000")
    return merge_collections(empty, rows, collections)


def test_d10_leaves_a_deleted_source_out_of_library_rows():
    folded = _every_type(deleted=("Lab registry images",))
    lib = next(lib for lib in folded.libs if lib.name == "libcrypto1.1")
    assert lib.source_labels == ("Lab registry mirror",)
    text = " ".join(" ".join(r.values()) for r in rows_under(story(d10, folded), "Component"))
    assert "Lab registry images" not in text


def test_d10_lists_crypto_products_with_every_source_that_uses_them():
    folded = _every_type()
    products = {lib.name: lib for lib in folded.libs if lib.ecosystem.startswith("crypto product")}
    assert {"SoftHSM v2", "PyKMIP 0.10.0 Software Server", "HashiCorp Vault",
            "AWS Key Management Service (KMS)", "Google Cloud Key Management Service", "Azure Key Vault",
            "OCI Vault (Key Management)"} <= set(products)
    assert products["SoftHSM v2"].version == "2.6"
    assert products["AWS Key Management Service (KMS)"].source_labels == ("AWS production",)
    rows = rows_under(story(d10, folded), "Component")
    assert {"SoftHSM v2", "Azure Key Vault"} <= {r["Component"] for r in rows}
    hsm = next(r for r in rows if r["Component"] == "SoftHSM v2")
    assert hsm["Known-vulnerability / end-of-life status"] == "product: see the vendor assurance columns"
    # the two AWS roles of run #57: the KMS product row names both, not only the newest reader
    both = merge_collections(_empty(), *AWS2.build())
    kms = next(lib for lib in both.libs if lib.name == "AWS Key Management Service (KMS)")
    assert set(kms.source_labels) == {NEWER, OLDER}


def test_d10_ledger_pools_every_live_source_with_crypto():
    folded = _every_type(deleted=("Lab registry images",))
    live_with_crypto = {c.key for c in folded.collections if c.source_kind}
    assert 0 < folded.compliance_sources_pooled <= len(live_with_crypto)
    before = _every_type()
    assert before.compliance_sources_pooled == folded.compliance_sources_pooled + 1


# ------------------------------------------------------------------------------------------------ Q3-02 D8 weak crypto
def _with_estate(**kwargs) -> TeamCbomView:
    from backend.utilities.cbom_sources.cert_estate import EstateInputs

    rows, collections = AWS2.build(**kwargs)
    built = merge_collections(_empty(), rows, collections)
    built.estate = EstateInputs(rows=tuple(rows))  # as load_team_cbom_view sets it
    return built


def test_d8_weak_crypto_counts_the_classifiers_weak_key_or_signature():
    from backend.utilities.cbom_sources.cert_estate import (
        unique_certificates,
        weak_crypto,
    )
    from backend.utilities.pdf import cbom_cert_register_pdf as d8

    folded = _with_estate()
    estate = unique_certificates(folded)
    weak = [c.subject for c in estate.certificates if weak_crypto(c)]
    assert len(weak) == 1 and weak[0].endswith("CN=c1-rsa1024-selfsigned-sha1.cba1.acme.test")  # RSA-1024, SHA-1
    cards = {c[0]: c[1] for c in d8._kpi_cards(d8.register_rows(folded, estate))}
    assert cards["Weak crypto"] == "1"  # staging: always 0 (only WEAK_* codes were counted)


@pytest.mark.parametrize("codes,fields,weak", [
    (("RSA_LT_2048",), {}, True),
    (("SIG_SHA1",), {}, True),
    (("CERT_SELF_SHA1", "CERT_SELF_SIGNED"), {}, True),  # a self-signed SHA-1 certificate: weak signature
    (("WEAK_KEY",), {}, True),  # the code lane's names still count
    ((), {"public_key_algorithm": "RSA", "key_size": "1024"}, True),  # SP 800-131A: disallowed
    ((), {"signature_algorithm": "sha1WithRSAEncryption", "public_key_algorithm": "RSA", "key_size": "2048"}, True),
    (("QUANTUM_VULNERABLE", "CERT_EXPIRED"), {"public_key_algorithm": "RSA", "key_size": "2048",
                                              "signature_algorithm": "sha256WithRSAEncryption"}, False),
])
def test_weak_crypto_rule(codes, fields, weak):
    from backend.utilities.cbom_sources.cert_estate import (
        unique_certificates,
        weak_crypto,
    )
    from backend.utilities.dashboard.cbom_team_rollup import CertAgg

    cert = CertAgg(key="c1", identity_strong=True, name="CN=x", finding_codes=codes, current=True, **fields)
    built = dataclasses.replace(_empty(), certs=(cert,))
    (estate,) = unique_certificates(built).certificates
    assert weak_crypto(estate) is weak


# ------------------------------------------------------------------------------------------------ Q3-04 one list
def test_certificate_hygiene_is_the_d8_list_and_never_names_a_deleted_source():
    import datetime as _dt

    from backend.utilities.cbom_sources import cert_hygiene as HYG
    from backend.utilities.cbom_sources.cert_estate import unique_certificates

    folded = _with_estate(deleted=(521,))
    estate = unique_certificates(folded)
    listed = HYG.from_estate(estate, _dt.datetime(2026, 11, 24, 6, tzinfo=_dt.timezone.utc))
    assert listed.counts()["certificates"] == len(estate) == 13 + 2  # 13 certificates + 2 private CAs (D8's rows)
    assert {c.key for c in listed.certs} == {c.key for c in estate.certificates}
    names = {o["source_name"] for c in listed.certs for o in c.observations}
    assert names == {OLDER} and NEWER not in repr(HYG.page(listed, flagged_only=False))
    acm = next(c for c in listed.certs if "c3-rsa2048-valid" in (c.subject or ""))
    assert "unmanaged" not in acm.flags  # an ACM certificate is managed (its ARN)


# ------------------------------------------------------------------------------------------------ Q3-06 the SSL Labs guide
# github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide (read 24 Nov 2026, changes to 2009r of 16 May 2025)
GCM12 = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
AES13 = "TLS_AES_256_GCM_SHA384"
LEAF = {"subject": "CN=pay.bank.example", "issuer": "CN=Bank Issuing CA", "not_after": "2030-01-01T00:00:00Z",
        "key_alg": "RSA", "key_size": 2048, "sig_alg": "sha256WithRSAEncryption", "self_signed": False,
        "san": ["pay.bank.example", "*.pay.bank.example"]}


def _tls(versions, suites, **extra):
    facts = {"service": "tls", "tls": True, "negotiated_group": "x25519",
             "versions": {v: (v in versions) for v in ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")},
             "cipher_suites": {v: [{"name": n} for n in names] for v, names in suites.items()},
             "cipher_suites_complete": {v: True for v in suites}, "leaf": dict(LEAF)}
    facts.update(extra)
    return facts


def _g(versions, suites, chain=None, **extra):
    from backend.utilities.cbom_sources import network_estate as NE

    day = dt.date(2026, 11, 24)
    return NE.grade_tls(_tls(versions, suites, **extra), day, chain) if chain is not None else \
        NE.grade_tls(_tls(versions, suites, **extra), day)


MODERN = (["TLSv1.2", "TLSv1.3"], {"TLSv1.2": [GCM12], "TLSv1.3": [AES13]})


def test_a_plus_needs_hsts_of_six_months_and_no_warning():
    assert _g(*MODERN, hsts_max_age=31_536_000).text == "A+"
    assert _g(*MODERN, hsts_max_age=86_400).text == "A"  # HSTS too short for A+
    assert _g(*MODERN).text == "A"  # HSTS not read: no A+, and no A- for it (Divergence row)
    assert _g(*MODERN, hsts_max_age=0).text == "A-"  # 2009r: HSTS disabled
    assert _g(*MODERN, hsts_max_age=31_536_000, service="smtp").text == "A"  # HSTS is never judged on SMTP


def test_a_minus_for_no_tls13_or_static_rsa_next_to_forward_secrecy():
    assert _g(["TLSv1.2"], {"TLSv1.2": [GCM12]}).text == "A-"  # 2009r
    mixed = _g(["TLSv1.2", "TLSv1.3"], {"TLSv1.2": [GCM12, "TLS_RSA_WITH_AES_256_GCM_SHA384"], "TLSv1.3": [AES13]})
    assert mixed.text == "A-" and "static RSA key exchange accepted next to forward-secret suites" in mixed.warnings


def test_b_only_when_forward_secrecy_is_not_supported_at_all():
    none = _g(["TLSv1.2"], {"TLSv1.2": ["TLS_RSA_WITH_AES_256_GCM_SHA384"]})
    assert none.letter == "B" and any("no forward secrecy" in c for c in none.caps)


def test_ssl3_caps_at_b_and_ssl3_as_the_best_protocol_fails():
    assert _g(["SSLv3", "TLSv1.2", "TLSv1.3"], {"TLSv1.2": [GCM12], "TLSv1.3": [AES13]}).letter == "B"
    assert _g(["SSLv3"], {"SSLv3": ["TLS_RSA_WITH_AES_128_CBC_SHA"]}).letter == "F"


def test_m_for_a_name_mismatch_and_only_with_a_server_name():
    assert _g(*MODERN, sni="pay.bank.example").text == "A"
    assert _g(*MODERN, sni="api.pay.bank.example").text == "A"  # the wildcard covers one label
    wrong = _g(*MODERN, sni="other.example")
    assert wrong.letter == "M" and wrong.text == "M (if the name matched: A)"
    assert _g(*MODERN).letter == "A"  # probed by address: no host name to compare


def test_t_for_an_untrusted_chain_or_a_sha1_signature():
    root_missing = [{"chain_issuer": "sent", "chain_top": False, "is_ca": False},
                    {"chain_issuer": "missing", "chain_top": True, "is_ca": True}]
    untrusted = _g(*MODERN, chain=root_missing)
    assert untrusted.letter == "T" and "chain ends at a CA the scan node does not trust" in untrusted.caps
    sha1 = _g(*MODERN, chain=[{"chain_issuer": "sent", "chain_top": False, "sig_alg": "sha1WithRSAEncryption"},
                              {"chain_issuer": "trusted", "chain_top": True, "is_ca": True}])
    assert sha1.text == "T (if trusted: A)" and "SHA-1 signature in the served chain" in sha1.caps
    trusted = [{"chain_issuer": "sent", "chain_top": False}, {"chain_issuer": "trusted", "chain_top": True}]
    assert _g(*MODERN, chain=trusted).text == "A"


def test_incomplete_chain_caps_at_b():
    gap = [{"chain_issuer": "missing", "chain_top": False, "is_ca": False},
           {"chain_issuer": "trusted", "chain_top": True, "is_ca": True}]
    graded = _g(*MODERN, chain=gap)
    assert graded.letter == "B" and any("incomplete chain" in c for c in graded.caps)


@pytest.mark.parametrize("versions,suites,letter", [
    (["TLSv1.0"], {"TLSv1.0": ["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"]}, "C"),  # 2009j: no TLS 1.2
    (["TLSv1.0", "TLSv1.2", "TLSv1.3"], {"TLSv1.0": ["TLS_RSA_WITH_RC4_128_SHA"], "TLSv1.2": [GCM12],
                                         "TLSv1.3": [AES13]}, "B"),  # 2009i: RC4 on TLS 1.0 only
    (["TLSv1.2"], {"TLSv1.2": ["TLS_RSA_WITH_RC4_128_SHA"]}, "F"),  # 2009k: only RC4
    (["TLSv1.0", "TLSv1.2", "TLSv1.3"], {"TLSv1.0": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"], "TLSv1.2": [GCM12],
                                         "TLSv1.3": [AES13]}, "B"),  # 2009n: 3DES caps C only with TLS 1.1+
    (["TLSv1.2"], {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", GCM12]}, "C"),
])
def test_protocol_and_cipher_caps(versions, suites, letter):
    assert _g(versions, suites).letter == letter


def test_rubric_documents_every_divergence():
    from backend.utilities.cbom_sources import network_estate as NE

    parts = [part for part, _rule in NE.RUBRIC]
    assert {"A+", "A-", "M", "T", "Cap B", "Divergence"} <= set(parts)
    text = " ".join(rule for _part, rule in NE.RUBRIC)
    for needle in ("Heartbleed", "ROBOT", "HSTS", "trust store", "SNI", "reference browsers"):
        assert needle in text


# ------------------------------------------------------------------------------------------------ Q3-05 grade in the run API
def test_run_assets_carry_the_d7_grade_of_a_probed_endpoint():
    from types import SimpleNamespace

    from backend.utilities.cbom_sources import network_estate as NE
    from backend.utilities.cbom_sources import run_assets as RA

    facts = _tls(["TLSv1.0", "TLSv1.2", "TLSv1.3"], {"TLSv1.2": [GCM12], "TLSv1.3": [AES13]},
                 cipher_suites_complete={"TLSv1.2": False})
    row = SimpleNamespace(id=7, asset_type="tls_endpoint", job_id=None, location="10.232.0.101:443", facts=facts)
    items = [{"id": 7}, {"id": 8}]
    RA.add_tls_grades(None, 1, {7: row, 8: SimpleNamespace(id=8, asset_type="kms_key", job_id=None,
                                                           location="arn:x", facts={})}, items,
                      today=dt.date(2026, 11, 24))
    assert items[1]["tls_grade"] is None
    grade = items[0]["tls_grade"]
    assert grade == NE.grade_tls(facts, dt.date(2026, 11, 24)).record()
    assert (grade["grade"], grade["letter"], grade["provisional"]) == ("B*", "B", True)
    assert "TLS 1.0 / 1.1 offered" in grade["caps"] and isinstance(grade["score"], int)


# ------------------------------------------------------------------------------------------------ Q3-08 ACM thumbprints
def test_acm_certificates_get_their_sha256_from_get_certificate():
    """14 of team 1's D8 rows had no SHA-256: the collector never asked ACM for the (public) certificate body.  Asked
    after every DescribeCertificate, only for an issued certificate; a denial keeps the row and records a gap."""
    import hashlib
    import ssl

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_cbom_aws_cb33 import (
        ACM_PREFIX,
        Plan,
        _body_pem,
        _cert_detail,
        _cert_summary,
        run,
    )

    pem = _body_pem()
    plan = Plan()
    plan.acm = [("list_certificates", {"CertificateSummaryList": [_cert_summary(n) for n in (1, 2, 3)]}, None),
                ("describe_certificate", _cert_detail(1), {"CertificateArn": f"{ACM_PREFIX}c1"}),
                ("describe_certificate", _cert_detail(2), {"CertificateArn": f"{ACM_PREFIX}c2"}),
                ("describe_certificate", _cert_detail(3, Status="PENDING_VALIDATION"),
                 {"CertificateArn": f"{ACM_PREFIX}c3"}),
                ("get_certificate", {"Certificate": pem}, {"CertificateArn": f"{ACM_PREFIX}c1"}),
                ("get_certificate", "AccessDeniedException", {"CertificateArn": f"{ACM_PREFIX}c2"})]
    _services, found, _rows = run(plan)  # every recorded call made, in order; c3 (no body) never asked
    certs = {a["location"].rsplit("/", 1)[-1]: a for a in found if a["type"] == "certificate"}
    assert certs["c1"]["facts"]["fingerprint_sha256"] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
    assert certs["c1"]["facts"]["certificate_read"] == "ok"
    assert "fingerprint_sha256" not in certs["c2"]["facts"]
    assert certs["c2"]["facts"]["certificate_read"] == "AccessDeniedException"
    assert "certificate_read" not in certs["c3"]["facts"]
    gaps = [a for a in found if a["type"] == "coverage" and "#body" in a["location"]]
    assert len(gaps) == 1 and gaps[0]["facts"].get("incomplete") is True  # listed; its thumbprint missing


def test_the_reader_role_may_read_public_certificate_bodies_only():
    from backend.utilities.cbom_sources import templates as T

    text = T.cloudformation_template("zs-ext-AAAA-BBBB-CCCC-DDDD", "account")
    assert "acm:ExportCertificate" in T.DENY_ACTIONS  # the private key stays out of reach
    assert "- acm:GetCertificate" in text and "AllowPublicCertificateBodies" in text


def test_a_deleted_aws_private_ca_is_never_listed_as_valid():
    from backend.utilities.cbom_sources.cert_estate import unique_certificates

    folded = _with_estate()
    pca = next(c for c in unique_certificates(folded).certificates if "AWS-PCA-Test" in c.subject)
    assert pca.lifecycle == "deleted" and pca.status == "deleted" and pca.band.band == "VALID"
