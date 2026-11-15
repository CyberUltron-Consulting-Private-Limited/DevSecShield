"""CB-33 PR-A2: AWS scope edges (HF-1, HF-2, HF-10, B10, B11).

Before this change (dev 13588d9):
* HF-1: a service that failed in one region wrote a coverage row with no scope on the account-wide target
  ``aws:<acct>``, so drift hid every asset of the account behind it; and a region whose services were all
  ``not_enabled`` (an opt-in region the account never enabled) was counted failed, so the whole job was never compared
  again: one typo or opt-in region stopped drift for the account;
* HF-2: CloudFront serves certificates from ACM in us-east-1, which were never read unless us-east-1 was configured;
* HF-10: a private API Gateway domain and a public one with the same name had the same location, so one of the two
  was dropped, depending on list order;
* B10: API Gateway policies that AWS's table does not list (newer SDK names) got a guessed ``min_version``, an unknown
  name got ``TLSv1.2``, and nothing said where the value came from;
* B11: CloudFront distributions had no post-quantum fact, so they were never judged (qv None) although AWS documents
  hybrid post-quantum key exchange on every CloudFront security policy, viewer to edge.

Recorded responses only (botocore's Stubber over the 1.41.5 models; every enum value goes through ``_enum``).  No AWS.

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_aws_cb33_a2.py
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import botocore.session  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402
from botocore.stub import Stubber  # noqa: E402

from backend.utilities.cbom_sources import aws_collect  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

ACCOUNT = "123456789012"
LABEL = f"aws:{ACCOUNT}"
REGION = "ap-south-1"
_BS = botocore.session.get_session()
_APIGW = _BS.get_service_model("apigateway")
_CF = _BS.get_service_model("cloudfront")
_ACM = _BS.get_service_model("acm")
NOW = dt.datetime(2026, 11, 14, 6, 0, 0)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "cb33_a2_dev_rows.json"
# SecurityPolicy values the botocore 1.44.3 model adds to 1.41.5's (read from the 1.44.3 wheel's apigateway model,
# 2026-11-14); none is on AWS's "Supported security policies" page yet
NEWER_APIGW_POLICIES = ("SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_Ext2_PQ_2025_09",
                        "SecurityPolicy_TLS13_1_2_Ext2_FIPS_PQ_2025_09")
# The order T19b's estate was recorded in (fixtures/cb33_a2_dev_rows.json: domain d<i> is policy i, None at d14): the
# 1.41.5 model's SecurityPolicy enum, then the newer three. botocore 1.44.3 lists those three INSIDE its enum, so taking
# the order from the installed model moved every domain after d6 to another policy and T19b compared different rows.
# Values a later botocore adds go after d14 (not in the fixture, so not compared).
RECORDED_APIGW_ORDER = ("TLS_1_0", "TLS_1_2", "SecurityPolicy_TLS13_1_3_2025_09", "SecurityPolicy_TLS13_1_3_FIPS_2025_09",
                        "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09",
                        "SecurityPolicy_TLS13_1_2_PQ_2025_09", "SecurityPolicy_TLS13_1_2_2021_06",
                        "SecurityPolicy_TLS13_2025_EDGE", "SecurityPolicy_TLS12_PFS_2025_EDGE",
                        "SecurityPolicy_TLS12_2018_EDGE") + NEWER_APIGW_POLICIES


def _every_apigw_policy() -> list[str]:
    """Every SecurityPolicy this test knows, once: the recorded order, then any value the installed model adds."""
    return list(RECORDED_APIGW_ORDER) + [p for p in _APIGW.shape_for("SecurityPolicy").enum if p not in RECORDED_APIGW_ORDER]


def _enum(model, shape: str, value: str, *, newer: tuple[str, ...] = ()) -> str:
    assert value in model.shape_for(shape).enum or value in newer, f"{value!r} is not a {shape}"
    return value


def _err(code: str, op: str = "Op") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "recorded"}}, op)


class _Raises:
    """A client whose every call raises one error code (a denied, failing or not-enabled service)."""

    def __init__(self, code: str):
        self.code = code

    def __getattr__(self, method):
        def fail(*_a, **_k):
            raise _err(self.code, method)
        if method == "get_paginator":
            return lambda *_a, **_k: type("P", (), {"paginate": fail})()
        return fail


class _Acct:
    """Stubbed clients by (service, region); a region of None answers for any region.  Anything else raises
    ``default`` (AccessDenied: the test drops those service rows)."""
    account = ACCOUNT

    def __init__(self, calls: dict[tuple[str, str | None], list[tuple[str, Any, dict | None]]], default="AccessDenied",
                 raising: dict[str, str] | None = None):
        self.clients: dict[tuple[str, str | None], Any] = {}
        self.stubs: list[Stubber] = []
        self.asked: list[tuple[str, str]] = []
        self.default, self.raising = default, raising or {}
        for (service, region), plan in calls.items():
            client = _BS.create_client(service, region_name=region or REGION, aws_access_key_id="x",
                                       aws_secret_access_key="y")
            stub = Stubber(client)
            for method, answer, params in plan:
                if isinstance(answer, str):
                    stub.add_client_error(method, service_error_code=answer, http_status_code=400,
                                          expected_params=params)
                else:
                    stub.add_response(method, answer, params)
            stub.activate()
            self.clients[(service, region)] = client
            self.stubs.append(stub)

    def client(self, service, region):
        self.asked.append((service, region))
        if service in self.raising:
            return _Raises(self.raising[service])
        return self.clients.get((service, region)) or self.clients.get((service, None)) or _Raises(self.default)

    def done(self):
        for stub in self.stubs:
            stub.assert_no_pending_responses()


def regional(acct, region=REGION, keep_denied=False):
    found: list[dict] = []
    rows = aws_collect._region_services(acct, region, LABEL, found.append, {})
    acct.done()
    if not keep_denied:
        denied = {f"{svc} in {region}" for svc, status, _d in rows if status == "denied"}
        found = [a for a in found if not (a["type"] == "coverage" and a["facts"]["check"] in denied)]
    return rows, found


def global_pass(acct, regions=(REGION,), keep_denied=False):
    found: list[dict] = []
    rows = aws_collect._global_services(acct, LABEL, found.append, regions=list(regions))
    acct.done()
    if not keep_denied:
        denied = {f"{svc} (global)" for svc, status, _d in rows if status == "denied"}
        found = [a for a in found if not (a["type"] == "coverage" and a["facts"]["check"] in denied)]
    return rows, found


def stored(found: list[dict], at: dt.datetime = NOW) -> list[SimpleNamespace]:
    out = []
    for i, a in enumerate(found):
        facts = a.get("facts") or {}
        verdict = classify(a["type"], a.get("algorithm"), a.get("key_size"), a.get("protocol"), facts, at)
        out.append(SimpleNamespace(
            id=i, asset_type=a["type"], finding_codes=verdict["finding_codes"], impact=verdict["impact"],
            quantum_vulnerable=verdict["quantum_vulnerable"], facts=facts, created_at=at, target=a["target"],
            location=a["location"], name=a.get("name"), algorithm=a.get("algorithm"), key_size=a.get("key_size"),
            protocol=a.get("protocol"), cdx_type=verdict["cdx_type"],
            asset_key=J._asset_key(a["type"], a["target"], a["location"], facts, a.get("name"))))
    return out


def codes(a: dict) -> set[str]:
    facts = a.get("facts") or {}
    return set(classify(a["type"], a.get("algorithm"), a.get("key_size"), a.get("protocol"), facts, NOW)["finding_codes"])


# ----------------------------------------------------------------------------- recorded answers
def domain(name: str, policy: str | None = "TLS_1_2", *, private_id: str | None = None, types=("REGIONAL",),
           status="AVAILABLE", access=None) -> dict[str, Any]:
    out: dict[str, Any] = {"domainName": name, "endpointConfiguration": {"types": list(types)},
                           "domainNameStatus": _enum(_APIGW, "DomainNameStatus", status)}
    if policy is not None:
        out["securityPolicy"] = _enum(_APIGW, "SecurityPolicy", policy, newer=NEWER_APIGW_POLICIES)
    if private_id:
        out["domainNameId"] = private_id
        out["domainNameArn"] = f"arn:aws:apigateway:{REGION}:{ACCOUNT}:/domainnames/{name}+{private_id}"
    if access:
        out["endpointAccessMode"] = access
    return out


def distribution(n: int, minimum: str = "TLSv1.2_2021", cert: str | None = None) -> dict[str, Any]:
    viewer: dict[str, Any] = {"MinimumProtocolVersion": _enum(_CF, "MinimumProtocolVersion", minimum)}
    if cert:
        viewer.update(ACMCertificateArn=cert, SSLSupportMethod="sni-only", CertificateSource="acm")
    else:
        viewer["CloudFrontDefaultCertificate"] = True
    return {"Id": f"E{n:05d}", "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E{n:05d}", "Status": "Deployed",
            "LastModifiedTime": dt.datetime(2026, 1, 1), "DomainName": f"d{n}.cloudfront.net",
            "Aliases": {"Quantity": 0},
            "Origins": {"Quantity": 1, "Items": [{"Id": "o", "DomainName": "origin.bank.example"}]},
            "DefaultCacheBehavior": {"TargetOriginId": "o", "ViewerProtocolPolicy": "https-only"},
            "CacheBehaviors": {"Quantity": 0}, "CustomErrorResponses": {"Quantity": 0}, "Comment": "",
            "PriceClass": "PriceClass_All", "Enabled": True, "ViewerCertificate": viewer,
            "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
            "WebACLId": "", "HttpVersion": "http2", "IsIPV6Enabled": True, "Staging": False}


def dist_page(*dists) -> dict[str, Any]:
    return {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": len(dists),
                                 "Items": list(dists)}}


def us_east_cert(n: int) -> str:
    return f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/0000cafe-0000-0000-0000-{n:012d}"


def cert_detail(n: int, days: int = 200, cert_type: str = "IMPORTED") -> dict[str, Any]:
    return {"Certificate": {"CertificateArn": us_east_cert(n), "DomainName": f"www{n}.bank.example",
                            "Subject": f"CN=www{n}.bank.example", "Issuer": "CN=Bank CA", "Serial": "01",
                            "NotBefore": NOW - dt.timedelta(days=300), "NotAfter": NOW + dt.timedelta(days=days),
                            "KeyAlgorithm": _enum(_ACM, "KeyAlgorithm", "RSA_2048"),
                            "SignatureAlgorithm": "SHA256WITHRSA", "Status": _enum(_ACM, "CertificateStatus", "ISSUED"),
                            "Type": _enum(_ACM, "CertificateType", cert_type), "InUseBy": [f"E{n:05d}"],
                            "RenewalEligibility": "INELIGIBLE"}}


# ============================================================================ HF-1 service rows are region-scoped
EMITTED_BY = {  # one location each service's assets use (from the emit calls in aws_collect)
    "kms": [f"arn:aws:kms:{REGION}:{ACCOUNT}:key/k1", f"arn:aws:kms:{REGION}:{ACCOUNT}:custom-key-store/cks-1"],
    "acm": [f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/c1"],
    "acm-pca": [f"arn:aws:acm-pca:{REGION}:{ACCOUNT}:certificate-authority/ca1"],
    "secretsmanager": [f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:db-AbCd"],
    "ec2": [f"arn:aws:ec2:{REGION}:{ACCOUNT}:ebs-encryption-by-default", f"arn:aws:ec2:{REGION}:{ACCOUNT}:volume/vol-1"],
    "ec2-keypairs": [f"arn:aws:ec2:{REGION}:{ACCOUNT}:key-pair/deploy"],
    "ssm": [f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/app/key"],
    "lambda": [f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:f1:$LATEST#environment/API_KEY"],
    "ecs": [f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/web:3#containerDefinitions/app/environment/KEY"],
    "ec2-userdata": [f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-1#userData"],
    "rds": [f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders", f"arn:aws:rds:{REGION}:{ACCOUNT}:db:orders#parameters",
            f"arn:aws:rds:{REGION}:{ACCOUNT}:cluster:c1"],
    "elasticloadbalancing": [f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:listener/app/lb/1/2"],
    "elb-classic": [f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/old#listener/443"],
    "apigateway": [f"arn:aws:apigateway:{REGION}::/domainnames/api.bank.example",
                   f"arn:aws:apigateway:{REGION}:{ACCOUNT}:/domainnames/api.bank.example+abc123"],
    "eks": [f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/prod"],
    "glue": [f"arn:aws:glue:{REGION}:{ACCOUNT}:catalog",
             f"arn:aws:glue:{REGION}:{ACCOUNT}:securityConfiguration/sc1",
             f"arn:aws:glue:{REGION}:{ACCOUNT}:connection/jdbc1"],
}


def _view(location: str, asset_type: str = "kms_key") -> D.View:
    return SimpleNamespace(extra={"target": LABEL, "location": location}, asset_type=asset_type)  # type: ignore[return-value]


@pytest.mark.parametrize("code", ["AccessDenied", "InternalError", "OptInRequired"])
def test_hf1_a_failed_service_hides_only_its_own_assets_in_its_own_region(code):
    rows, found = regional(_Acct({}, default=code), keep_denied=True)
    services = {svc for svc, _s, _d in rows}
    assert services == set(EMITTED_BY), services ^ set(EMITTED_BY)
    by_check = {a["facts"]["check"]: a for a in found if a["type"] == "coverage"}
    elsewhere = [loc.replace(f":{REGION}:", ":eu-west-1:") for locs in EMITTED_BY.values() for loc in locs]
    for svc, locations in EMITTED_BY.items():
        row = by_check[f"{svc} in {REGION}"]
        assert row["facts"].get("scope"), (svc, row)
        (gap,) = D.job_gaps(stored([row]))
        for loc in locations:
            assert gap.covers(_view(loc), listed=False), (svc, loc)  # never a removal of what it did not read
        others = [loc for other, locs in EMITTED_BY.items() if other != svc for loc in locs
                  if not any(loc.startswith(p) for p in row["facts"]["scope"])]
        assert others, svc  # it leaves other services alone ...
        assert not any(gap.covers(_view(loc), listed=False) for loc in elsewhere), svc  # ... and other regions


def test_hf1_global_service_rows_are_scoped_to_their_service():
    acct = _Acct({}, default="AccessDenied")
    rows, found = global_pass(acct, regions=[REGION], keep_denied=True)
    scopes = {a["facts"]["check"]: a["facts"].get("scope") for a in found if a["type"] == "coverage"}
    assert scopes["iam (global)"] == [f"arn:aws:iam::{ACCOUNT}:"]
    assert scopes["s3 (global)"] == ["arn:aws:s3:::"]
    # CloudFront's certificates live in ACM in us-east-1; when us-east-1 is not read on its own, they are this pass's
    assert scopes["cloudfront (global)"] == [f"arn:aws:cloudfront::{ACCOUNT}:", f"arn:aws:acm:us-east-1:{ACCOUNT}:certificate/"]
    _rows, found = global_pass(_Acct({}, default="AccessDenied"), regions=["us-east-1", REGION], keep_denied=True)
    scopes = {a["facts"]["check"]: a["facts"].get("scope") for a in found if a["type"] == "coverage"}
    assert scopes["cloudfront (global)"] == [f"arn:aws:cloudfront::{ACCOUNT}:"]


def test_hf1_a_region_that_is_not_enabled_keeps_the_job_comparable_and_drift_resolves_a_real_fix():
    """me-south-1 is an opt-in region the account never enabled; ap-south-1 holds a key whose rotation is turned on
    between the two runs.  The fix must be ``resolved``; nothing of ap-south-1 may hide behind me-south-1's rows."""
    from test_cbom_aws_cb33 import Plan, meta, rotation, run as kms_run  # the PR-A harness (KMS only)

    def job(rotation_on: bool):
        services, found, rows = kms_run(Plan().keys(1).describe(1, meta(1)).rotation(1, rotation(rotation_on)))
        rows = [r for r in rows if r[1] != "denied"]  # services the harness did not record (as kms_run drops their rows)
        off_rows, off_found = regional(_Acct({}, default="OptInRequired"), "me-south-1", keep_denied=True)
        targets = [aws_collect._region_target(LABEL, REGION, rows, sum(1 for a in found if a["type"] == "coverage"
                                                                         and not a["facts"].get("by_choice")), 5),
                   aws_collect._region_target(LABEL, "me-south-1", off_rows, len(off_rows), 5)]
        return targets, found + off_found

    targets1, found1 = job(False)
    targets2, found2 = job(True)
    assert [t["status"] for t in targets2] == ["ok", "not_supported"]
    summary = aws_collect.summary(targets2, 1, 0.0)
    assert summary["counts"]["failed"] == 0 and summary["counts"]["partial"] == 1 and summary["counts"]["not_enabled"] == 1
    result = {**summary, "asset_count": len(found2)}
    outcome, extra = J._outcome(SimpleNamespace(kind="collect"), "success", result, len(found2))
    ok, why = D.job_comparable(SimpleNamespace(kind="collect", status="success", result={**result, **extra},
                                               outcome=outcome))
    assert ok, why
    before, after = stored(found1), stored(found2)
    d = D.compare(D.node_views(before, "src", reclassify=False), D.node_views(after, "src", reclassify=False),
                  D.job_gaps(after))
    resolved = [(x["location"], x["code"]) for x in d["resolved"]]
    assert resolved == [(f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1234abcd-0000-0000-0000-000000000001", "KMS_NO_ROTATION")]
    assert d["removed"] == [] and d["added"] == []


def test_hf1_a_region_with_a_real_failure_still_fails_its_target():
    rows, _found = regional(_Acct({}, default="InternalError"))
    target = aws_collect._region_target(LABEL, REGION, rows, 0, 1)
    assert target["status"] == "error"
    summary = aws_collect.summary([target], 1, 0.0)
    assert summary["counts"]["failed"] == 1 and "not_enabled" not in summary["counts"]


def test_hf1_on_the_worker_pool_a_not_enabled_region_slice_keeps_the_parent_comparable(monkeypatch, tmp_path):
    """The production path: the source fans out into account x region slices (``slices.finalize`` counts them)."""
    import test_cbom_cloud_pool_f1 as P
    from sqlmodel import Session

    engine = P._make_engine("sqlite", tmp_path)
    monkeypatch.setenv("CBOM_CLOUD_TEAM_MAX_CONCURRENCY", "8")
    monkeypatch.setattr(P.W, "IDLE_SLEEP_S", 0.05)

    def collect(team_id, cfg, external_id, role_arn, region, emit, should_stop, **_kw):
        acct = role_arn.split(":")[4]
        if region == "me-south-1":  # every service: OptInRequired
            rows = [(svc, "not_enabled", "OptInRequired") for svc in EMITTED_BY]
            target = aws_collect._region_target(f"aws:{acct}", region, rows, len(rows), 1)
        else:
            emit(P._asset(acct, region))
            target = {"target": f"aws:{acct}/{region}", "status": "ok", "assets": 1}
        return aws_collect.summary([target], team_id, 0.0, quiet=True)

    monkeypatch.setattr(P.aws_org, "plan_slices", P._plan(1))
    monkeypatch.setattr(P.aws_org, "collect_slice", collect)
    user = P._team(engine, 1)
    P._source(engine, 1, regions=("ap-south-1", "me-south-1"))
    P._queue(engine, 1, user, "not-enabled-0001")
    P._drain(engine)
    (parent,) = P._jobs(engine, kind="collect")
    assert parent.result["counts"] == {"total": 3, "ok": 2, "partial": 1, "failed": 0, "skipped": 0, "not_enabled": 1}
    assert parent.outcome == "partial"
    with Session(engine) as s:
        assert D.job_comparable(s.get(type(parent), parent.id)) == (True, None)


# ============================================================================ HF-2 CloudFront's us-east-1 certificates
def test_hf2_cloudfront_certificates_in_us_east_1_are_read_once_each_and_judged():
    acct = _Acct({
        ("cloudfront", None): [("list_distributions", dist_page(distribution(1, cert=us_east_cert(1)),
                                                                distribution(2, cert=us_east_cert(1)),
                                                                distribution(3, cert=us_east_cert(2)),
                                                                distribution(4)), None)],
        ("acm", "us-east-1"): [("describe_certificate", cert_detail(1, days=10), {"CertificateArn": us_east_cert(1)}),
                               ("describe_certificate", cert_detail(2, days=400), {"CertificateArn": us_east_cert(2)})],
    })
    rows, found = global_pass(acct, regions=[REGION])
    assert dict((s, st) for s, st, _d in rows)["cloudfront"] == "ok"
    certs = {a["location"]: a for a in found if a["type"] == "certificate"}
    assert set(certs) == {us_east_cert(1), us_east_cert(2)}
    one = certs[us_east_cert(1)]
    assert one["target"] == LABEL and one["facts"]["identity"] == us_east_cert(1)
    assert "CERT_EXPIRES_30D" in codes(one) and "CERT_EXPIRES_30D" not in codes(certs[us_east_cert(2)])
    # the same identity the us-east-1 regional pass gives, so adding us-east-1 later changes no asset key
    regional_twin = aws_collect._cert_asset(us_east_cert(1), LABEL, cert_detail(1, days=10)["Certificate"],
                                            summary={"CertificateArn": us_east_cert(1)})
    assert (J._asset_key(one["type"], one["target"], one["location"], one["facts"], one["name"])
            == J._asset_key(regional_twin["type"], regional_twin["target"], regional_twin["location"],
                            regional_twin["facts"], regional_twin["name"]))


def test_hf2_a_certificate_that_cannot_be_read_is_one_exact_arn_row():
    acct = _Acct({
        ("cloudfront", None): [("list_distributions", dist_page(distribution(1, cert=us_east_cert(1)),
                                                                distribution(2, cert=us_east_cert(2))), None)],
        ("acm", "us-east-1"): [("describe_certificate", "AccessDeniedException", {"CertificateArn": us_east_cert(1)}),
                               ("describe_certificate", cert_detail(2), {"CertificateArn": us_east_cert(2)})],
    })
    rows, found = global_pass(acct, regions=[REGION])
    assert dict((s, st) for s, st, _d in rows)["cloudfront"] == "partial"
    gaps = [a for a in found if a["type"] == "coverage"]
    assert len(gaps) == 1 and gaps[0]["facts"]["scope"] == [us_east_cert(1)] and gaps[0]["facts"]["status"] == "denied"
    assert [a["location"] for a in found if a["type"] == "certificate"] == [us_east_cert(2)]
    assert len([a for a in found if a["type"] == "cdn_tls"]) == 2


def test_hf2_with_us_east_1_configured_the_regional_pass_reads_them_and_cloudfront_does_not():
    acct = _Acct({("cloudfront", None): [("list_distributions", dist_page(distribution(1, cert=us_east_cert(1))), None)]})
    _rows, found = global_pass(acct, regions=["us-east-1", REGION])
    assert ("acm", "us-east-1") not in acct.asked
    assert [a["type"] for a in found] == ["cdn_tls"]


# ============================================================================ HF-10 private API Gateway domains
@pytest.mark.parametrize("private_first", [False, True])
def test_hf10_a_private_and_a_public_domain_with_one_name_are_two_rows(private_first):
    public = domain("api.bank.example", "TLS_1_0")
    private = domain("api.bank.example", "TLS_1_2", private_id="abc123", types=("PRIVATE",), access="BASIC")
    items = [private, public] if private_first else [public, private]
    acct = _Acct({("apigateway", None): [("get_domain_names", {"items": items}, None)]})
    _rows, found = regional(acct)
    domains = {a["location"]: a for a in found if a["type"] == "api_tls"}
    pub_loc = f"arn:aws:apigateway:{REGION}::/domainnames/api.bank.example"
    priv_loc = f"arn:aws:apigateway:{REGION}:{ACCOUNT}:/domainnames/api.bank.example+abc123"
    assert set(domains) == {pub_loc, priv_loc}  # the public location (its stored identity) is unchanged
    assert "MIN_TLS10" in codes(domains[pub_loc]) and "MIN_TLS10" not in codes(domains[priv_loc])
    keys = {J._asset_key(a["type"], a["target"], a["location"], a["facts"], a.get("name")) for a in domains.values()}
    assert len(keys) == 2
    assert domains[priv_loc]["facts"]["endpoint_access_mode"] == "BASIC"
    assert domains[pub_loc]["facts"]["domain_name_status"] == "AVAILABLE"


# ============================================================================ B10 API Gateway min_version
@pytest.mark.parametrize("policy", _every_apigw_policy())
def test_b10_every_known_security_policy_has_a_min_version_and_says_where_it_came_from(policy):
    facts = aws_collect._apigw_tls_facts(policy)
    assert facts["min_version"] in ("TLSv1.0", "TLSv1.2", "TLSv1.3"), (policy, facts)
    assert facts["min_version_source"], facts
    if "TLS13_1_3" in policy or policy == "SecurityPolicy_TLS13_2025_EDGE":
        assert facts["min_version"] == "TLSv1.3"  # TLS-1.3-only policies read as TLS 1.3 (B10)


def test_b10_unknown_and_absent_policies():
    unknown = aws_collect._apigw_tls_facts("SecurityPolicy_FUTURE_2031_01")
    assert unknown["min_version"] is None and unknown["min_version_source"] == "unknown policy"
    assert "protocols" not in unknown
    acct = _Acct({("apigateway", None): [("get_domain_names", {"items": [domain("old.bank.example", None)]}, None)]})
    _rows, found = regional(acct)
    (row,) = [a for a in found if a["type"] == "api_tls"]
    assert row["facts"]["security_policy"] == "TLS_1_0" and row["facts"]["min_version"] == "TLSv1.0"
    assert row["facts"]["min_version_source"] == "securityPolicy absent (assumed TLS_1_0)"
    assert "MIN_TLS10" in codes(row)  # the default is kept, so the finding does not vanish (EC-5)


# ============================================================================ B11 CloudFront post-quantum facts
@pytest.mark.parametrize("minimum", list(_CF.shape_for("MinimumProtocolVersion").enum))
def test_b11_every_cloudfront_policy_is_hybrid_post_quantum_viewer_to_edge(minimum):
    acct = _Acct({("cloudfront", None): [("list_distributions", dist_page(distribution(1, minimum)), None)]})
    _rows, found = global_pass(acct, regions=["us-east-1"])
    (row,) = [a for a in found if a["type"] == "cdn_tls"]
    facts = row["facts"]
    assert facts["pq_group_supported"] is True and facts["pq_policy_source"]
    assert isinstance(facts["pq_groups"], list)
    verdict = classify("cdn_tls", None, None, "TLS", facts, NOW)
    assert verdict["quantum_vulnerable"] is False and "NO_PQ_KEX" not in verdict["finding_codes"]
    if minimum in ("SSLv3", "TLSv1", "TLSv1_2016"):
        assert {"MIN_TLS10", "MIN_SSLv3"} & set(verdict["finding_codes"]), verdict  # old minimums keep their finding


# ============================================================================ T19b no code vanishes
def t19b_estate() -> tuple[_Acct, _Acct]:
    """API Gateway domains on every policy (and none), CloudFront on every minimum: the estate T19b compares."""
    extra = _every_apigw_policy()[len(RECORDED_APIGW_ORDER):]
    names = list(RECORDED_APIGW_ORDER) + [None] + extra  # d<i> as recorded (None at d14) under any botocore
    domains = [domain(f"d{i}.bank.example", p) for i, p in enumerate(names)]
    regional_acct = _Acct({("apigateway", None): [("get_domain_names", {"items": domains}, None)]})
    minimums = list(_CF.shape_for("MinimumProtocolVersion").enum)
    global_acct = _Acct({("cloudfront", None): [
        ("list_distributions", dist_page(*[distribution(i, m) for i, m in enumerate(minimums)]), None)]})
    return regional_acct, global_acct


def _estate_rows(global_kwargs: dict[str, Any]) -> list[dict]:
    regional_acct, global_acct = t19b_estate()
    found: list[dict] = []
    aws_collect._region_services(regional_acct, REGION, LABEL, found.append, {})
    aws_collect._global_services(global_acct, LABEL, found.append, **global_kwargs)
    return [a for a in found if a["type"] in ("api_tls", "cdn_tls")]


def test_t19b_no_finding_vanishes_against_the_rows_dev_stored():
    """``fixtures/cb33_a2_dev_rows.json`` holds what dev 13588d9 emitted for ``t19b_estate`` (regenerate it on dev with
    ``python tests/test_cbom_aws_cb33_a2.py``); under the classifier of this branch, every code a dev row carried is
    still carried by the same location, so the release resolves nothing."""
    dev_rows = json.loads(FIXTURE.read_text())
    new = {a["location"]: a for a in _estate_rows({"regions": [REGION]})}
    assert {r["location"] for r in dev_rows} <= set(new)
    vanished = {r["location"]: sorted(codes(r) - codes(new[r["location"]])) for r in dev_rows}
    assert {loc: c for loc, c in vanished.items() if c} == {}
    # and the intended changes: CloudFront rows are judged now (qv None -> False), nothing else moves
    for r in dev_rows:
        before = classify(r["type"], None, None, r.get("protocol"), r["facts"], NOW)["quantum_vulnerable"]
        after = classify(r["type"], None, None, new[r["location"]].get("protocol"), new[r["location"]]["facts"],
                         NOW)["quantum_vulnerable"]
        if r["type"] == "cdn_tls":
            assert (before, after) == (None, False)
        else:
            assert before == after, (r["location"], before, after)


if __name__ == "__main__":  # regenerate the fixture: run this file with python on dev's code (before PR-A2)
    found = _estate_rows({})
    FIXTURE.write_text(json.dumps([{"type": a["type"], "location": a["location"], "protocol": a.get("protocol"),
                                    "facts": a["facts"]} for a in found], indent=1, sort_keys=True) + "\n")
    print(f"wrote {len(found)} rows to {FIXTURE}")
