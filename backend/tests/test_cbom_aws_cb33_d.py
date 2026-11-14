"""CB-33 PR-D: botocore >= 1.44 and ACME-issued ACM certificates (EC-3).

Before this change (dev, botocore 1.41.5):
* ``ListCertificates`` returns only certificates whose key pair origin is ``AWS_MANAGED`` or ``CUSTOMER_PROVIDED``
  unless ``CertificateKeyPairOrigins`` asks for ``ACME`` too, and botocore 1.41.5 does not model that parameter:
  ACM certificates issued through ACME were never inventoried;
* so every account carried a ``by_choice`` row saying "ACME-issued ACM certificates are not listed by this SDK
  version".

Now boto3 / botocore are on the 1.44 line, ``acm()`` asks for every key pair origin, and each certificate carries
``key_pair_origin`` (PR-B already keeps ACME certificates out of ``CERT_UNUSED``).  The disclosure row is gone.

The botocore 1.44.3 ACM model says (``ListCertificates.CertificateKeyPairOrigins``): "Default filtering returns only
certificates with key pair origin of AWS_MANAGED and CUSTOMER_PROVIDED."  Recorded responses only (Stubber); no AWS.

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_aws_cb33_d.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import botocore  # noqa: E402

from backend.utilities.cbom_sources import aws_collect  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from test_cbom_aws_cb33 import (ACM_PREFIX, LABEL, Plan, _ACM_MODEL, _Acct, _cert_detail, _cert_summary,  # noqa: E402
                                _enum, run, stored)

LOCK = Path(__file__).resolve().parents[1] / "uv.lock"
ORIGINS = ["AWS_MANAGED", "CUSTOMER_PROVIDED", "ACME"]
EVERY_KEY_TYPE = {"keyTypes": aws_collect.ACM_KEY_TYPES}  # every key type (CB-04 PR-3b: from algid's capture)


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", text)[:3])


def _locked(name: str) -> str:
    match = re.search(rf'\[\[package\]\]\nname = "{re.escape(name)}"\nversion = "([^"]+)"', LOCK.read_text())
    assert match, name
    return match.group(1)


def codes(asset: dict) -> set[str]:
    return set(stored([asset])[0].finding_codes)


# ============================================================================ the dependency
def test_the_lock_pins_boto3_and_botocore_on_the_1_44_line_or_later():
    assert _version(_locked("botocore")) >= (1, 44, 0) and _version(_locked("boto3")) >= (1, 44, 0)
    assert _version(_locked("s3transfer")) >= (0, 19, 0)  # what boto3 1.44 requires


def test_the_installed_botocore_models_acme_listing():
    assert _version(botocore.__version__) >= (1, 44, 0), botocore.__version__
    params = _ACM_MODEL.operation_model("ListCertificates").input_shape.members
    assert "CertificateKeyPairOrigins" in params
    assert set(ORIGINS) == set(_ACM_MODEL.shape_for("CertificateKeyPairOrigin").enum)


# ============================================================================ ACME certificates are listed
def test_acm_asks_for_every_key_pair_origin_and_records_it():
    plan = Plan()
    plan.acm = [("list_certificates", {"CertificateSummaryList": [
        _cert_summary(1, CertificateKeyPairOrigin=_enum(_ACM_MODEL, "CertificateKeyPairOrigin", "ACME")),
        _cert_summary(2, CertificateKeyPairOrigin="AWS_MANAGED"),
        _cert_summary(3)]},  # an origin ACM did not state
        {"Includes": EVERY_KEY_TYPE, "CertificateKeyPairOrigins": ORIGINS, "MaxItems": 1000}),
        ("describe_certificate", _cert_detail(1, CertificateKeyPairOrigin="ACME"), {"CertificateArn": f"{ACM_PREFIX}c1"}),
        ("describe_certificate", _cert_detail(2), {"CertificateArn": f"{ACM_PREFIX}c2"}),
        ("describe_certificate", _cert_detail(3), {"CertificateArn": f"{ACM_PREFIX}c3"})]
    services, found, _rows = run(plan)
    assert services["acm"] == "ok"
    certs = {a["location"].rsplit("/", 1)[-1]: a for a in found if a["type"] == "certificate"}
    assert certs["c1"]["facts"]["key_pair_origin"] == "ACME"
    assert certs["c2"]["facts"]["key_pair_origin"] == "AWS_MANAGED"
    assert certs["c3"]["facts"]["key_pair_origin"] is None  # unknown, never guessed
    # unattached, issued, AMAZON_ISSUED: the ACME one is managed by its ACME client (PR-B rule), the others are unused
    assert "CERT_UNUSED" not in codes(certs["c1"])
    assert "CERT_UNUSED" in codes(certs["c2"]) and "CERT_UNUSED" in codes(certs["c3"])


def test_the_detail_states_the_origin_when_the_summary_does_not():
    plan = Plan()
    plan.acm = [("list_certificates", {"CertificateSummaryList": [_cert_summary(1)]}, None),
                ("describe_certificate", _cert_detail(1, CertificateKeyPairOrigin="ACME"),
                 {"CertificateArn": f"{ACM_PREFIX}c1"})]
    _services, found, _rows = run(plan)
    (cert,) = [a for a in found if a["type"] == "certificate"]
    assert cert["facts"]["key_pair_origin"] == "ACME"


def test_the_acme_disclosure_row_is_gone():
    found: list[dict] = []
    target = aws_collect.read_target(_Acct(Plan()), "global", {"regions": ["ap-south-1"]}, found.append, lambda: None)
    assert target["target"].endswith("/global")
    assert not [a for a in found if a["location"].endswith("#acme")]


# ============================================================================ drift across the upgrade
def test_the_upgrade_resolves_nothing_and_an_acme_certificate_appears_as_new():
    """Run N on dev stored certificates without ``key_pair_origin`` (and no ACME certificate); run N+1 after the
    upgrade lists the same certificates with it, plus an ACME one: no finding is resolved or opened, the ACME
    certificate is ``new_asset`` only."""
    def certs(with_origin: bool, with_acme: bool):
        plan = Plan()
        summaries = [_cert_summary(2, **({"CertificateKeyPairOrigin": "AWS_MANAGED"} if with_origin else {})),
                     _cert_summary(4, InUse=True, **({"CertificateKeyPairOrigin": "CUSTOMER_PROVIDED"}
                                                     if with_origin else {}))]
        details = [("describe_certificate", _cert_detail(2), {"CertificateArn": f"{ACM_PREFIX}c2"}),
                   ("describe_certificate", _cert_detail(4, InUseBy=["arn:aws:elasticloadbalancing:x"]),
                    {"CertificateArn": f"{ACM_PREFIX}c4"})]
        if with_acme:
            summaries.insert(0, _cert_summary(1, CertificateKeyPairOrigin="ACME"))
            details.insert(0, ("describe_certificate", _cert_detail(1, CertificateKeyPairOrigin="ACME"),
                               {"CertificateArn": f"{ACM_PREFIX}c1"}))
        plan.acm = [("list_certificates", {"CertificateSummaryList": summaries}, None), *details]
        _s, found, _r = run(plan)
        out = [a for a in found if a["type"] == "certificate"]
        if not with_origin:  # what dev stored: no key_pair_origin fact at all
            for a in out:
                a["facts"].pop("key_pair_origin", None)
        return out

    before, after = stored(certs(False, False)), stored(certs(True, True))
    d = D.compare(D.node_views(before, "src", reclassify=False), D.node_views(after, "src", reclassify=False),
                  D.job_gaps(after))
    assert d["resolved"] == [] and d["removed"] == [] and d["collector_changes"] == []
    assert [x["location"] for x in d["added"]] == [f"{ACM_PREFIX}c1"]
    # the ACME certificate's own findings come with it (new_asset); no finding of a known certificate opens
    assert {(x["location"], x.get("new_asset")) for x in d["opened"]} <= {(f"{ACM_PREFIX}c1", True)}
    assert "CERT_UNUSED" not in {x["code"] for x in d["opened"]}
    assert all(a.target == LABEL for a in after)
