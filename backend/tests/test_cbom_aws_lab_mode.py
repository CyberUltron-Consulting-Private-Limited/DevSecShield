"""Lab mode for test deployments (CB-A1 PLAN §2; lab_mode.py): CBOM_AWS_LAB_SAME_ACCOUNT=1 lets a test deployment
validate and collect an AWS role in its own account, still requiring the external ID and the data-plane deny.
Off, or on a deployment that says it is production (or does not say it is a test deployment), the refusal is the same
as before. Every use is logged and audited; the settings, the validation and every run say so (the UI banners).

No network: the STS / IAM / KMS / Secrets Manager calls are fakes that behave like AWS for one role."""
from __future__ import annotations

import os
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.tests.test_cbom_sources_api import api, world  # noqa: E402,F401
from backend.utilities.cbom_sources import aws_collect, aws_validate, lab_mode  # noqa: E402
from backend.utilities.cbom_sources.templates import DENY_ACTIONS  # noqa: E402

OWN = "935951870001"
PRINCIPAL = f"arn:aws:iam::{OWN}:user/devsecshield/devsecshield-developer"
OWN_ROLE = f"arn:aws:iam::{OWN}:role/ZeroShieldCBOMReader"
OTHER_ROLE = "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader"
EXT = "zs-ext-AAAA-BBBB-CCCC-DDDD"
REFUSED = "This role is in ZeroShield's own AWS account; use a role in your account"
BANNER = "Lab mode: same-account collection — not for production"
DENY_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": DENY_ACTIONS, "Resource": "*"}]}


class _Denied(Exception):
    def __init__(self, code="AccessDenied"):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _Client:
    def __init__(self, role):
        self.role = role

    # sts
    def assume_role(self, **kw):
        if self.role["calls"] is not None:
            self.role["calls"].append(kw)
        if "ExternalId" not in kw and self.role["needs_external_id"]:
            raise _Denied()
        if "ExternalId" in kw and kw["ExternalId"] != EXT:
            raise _Denied()
        return {"Credentials": {"AccessKeyId": "ASIAFAKE", "SecretAccessKey": "fake", "SessionToken": "fake"}}

    # iam
    def list_attached_role_policies(self, **_kw):
        return {"AttachedPolicies": [{"PolicyName": "SecurityAudit"}]}

    def list_role_policies(self, **_kw):
        return {"PolicyNames": ["ZeroShieldCBOMReaderDeny"] if self.role["deny"] else []}

    def get_role_policy(self, **_kw):
        return {"PolicyDocument": DENY_DOC}

    # kms / secretsmanager
    def list_keys(self, **_kw):
        return {"Keys": [{"KeyId": "k1"}]}

    def get_secret_value(self, **_kw):
        raise _Denied("AccessDeniedException")


class _Session:
    def __init__(self, role):
        self.role = role

    def client(self, _service, **_kw):
        return _Client(self.role)


@pytest.fixture()
def role(monkeypatch):
    """A correctly set-up reader role (external ID required, deny attached); tests break one thing at a time."""
    import boto3

    state = {"needs_external_id": True, "deny": True, "calls": []}
    monkeypatch.setattr(aws_validate, "_boto", lambda **_kw: (_Session(state), None))
    monkeypatch.setattr(aws_collect, "_boto", lambda **_kw: (_Session(state), None))
    monkeypatch.setattr(boto3.session, "Session", lambda **_kw: _Session(state))
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", PRINCIPAL)
    monkeypatch.delenv("CBOM_AWS_LAB_SAME_ACCOUNT", raising=False)
    monkeypatch.delenv("DSS_ENV", raising=False)
    return state


def _validate(role_arn=OWN_ROLE, scope="account"):
    return aws_validate.validate_aws_role(7, role_arn, EXT, ["ap-south-1"], scope)


def _lab(monkeypatch, env="staging"):
    monkeypatch.setenv("CBOM_AWS_LAB_SAME_ACCOUNT", "1")
    if env is None:
        monkeypatch.delenv("DSS_ENV", raising=False)
    else:
        monkeypatch.setenv("DSS_ENV", env)


# ----------------------------------------------------------------------------- the switch itself
def test_switch_off_refuses_exactly_as_before_and_calls_nothing(role):
    out = _validate()
    assert out["status"] == "failed" and "lab_mode" not in out
    assert out["checks"][0] == {"check": "Role assumed with external ID", "status": "fail", "detail": REFUSED}
    assert all(c["status"] == "skipped" for c in out["checks"][1:]) and len(out["checks"]) == 6
    assert role["calls"] == []  # AWS was never called
    assert lab_mode.lab_same_account() is False


@pytest.mark.parametrize("env", ["production", "PROD", None, "", "qa-prod", "staging-ish"])
def test_production_or_unknown_deployment_refuses_the_switch(role, monkeypatch, capsys, env):
    _lab(monkeypatch, env)
    assert lab_mode.lab_same_account() is False
    out = _validate()
    assert out["checks"][0]["detail"] == REFUSED and out["status"] == "failed" and "lab_mode" not in out
    assert role["calls"] == []
    assert "lab_mode same_account REFUSED" in capsys.readouterr().out  # the refused attempt is logged


@pytest.mark.parametrize("value", ["0", "", "no", "false"])
def test_switch_values_that_are_off(role, monkeypatch, value):
    monkeypatch.setenv("CBOM_AWS_LAB_SAME_ACCOUNT", value)
    monkeypatch.setenv("DSS_ENV", "staging")
    assert lab_mode.lab_same_account() is False
    assert _validate()["checks"][0]["detail"] == REFUSED


# ----------------------------------------------------------------------------- on: only the own-account check is passed
def test_lab_mode_passes_the_own_account_check_and_every_other_check_runs(role, monkeypatch, capsys):
    _lab(monkeypatch)
    out = _validate()
    assert out["status"] == "passed", out
    assert out["lab_mode"] == "same_account" and len(out["checks"]) == 6
    assert out["checks"][0]["detail"] == "AssumeRole succeeded with your external ID (lab mode: role in this deployment's own account)"
    assert [c["check"] for c in out["checks"]] == ["Role assumed with external ID", "Role refused without external ID",
                                                    "SecurityAudit attached", "Data-plane deny present",
                                                    "Test read: list KMS keys", "Test secret read was denied"]
    assert any("ExternalId" not in c for c in role["calls"])  # the no-external-ID probe still ran
    logged = capsys.readouterr().out
    assert "lab_mode same_account USED account=935951870001" in logged and "where=validate" in logged


def test_lab_mode_still_fails_without_the_external_id_condition(role, monkeypatch):
    _lab(monkeypatch)
    role["needs_external_id"] = False
    out = _validate()
    row = next(c for c in out["checks"] if c["check"] == "Role refused without external ID")
    assert out["status"] == "failed" and row["status"] == "fail" and "without the external ID" in row["detail"]


def test_lab_mode_still_fails_without_the_data_plane_deny(role, monkeypatch):
    _lab(monkeypatch)
    role["deny"] = False
    out = _validate()
    row = next(c for c in out["checks"] if c["check"] == "Data-plane deny present")
    assert out["status"] == "failed" and row["status"] == "fail" and "missing" in row["detail"]


def test_lab_mode_refuses_an_organization_source_in_the_own_account(role, monkeypatch):
    _lab(monkeypatch)
    out = _validate(scope="organization")
    assert out["status"] == "failed" and "single-account" in out["checks"][0]["detail"] and role["calls"] == []


def test_a_role_in_another_account_is_unaffected_by_lab_mode(role, monkeypatch):
    _lab(monkeypatch)
    out = _validate(OTHER_ROLE)
    assert out["status"] == "passed" and "lab_mode" not in out
    assert out["checks"][0]["detail"] == "AssumeRole succeeded with your external ID"


# ----------------------------------------------------------------------------- collection repeats the guard
def test_collection_refuses_the_own_account_without_lab_mode(role):
    with pytest.raises(aws_collect.AwsCollectError, match="ZeroShield's own AWS account"):
        aws_collect.collect_aws(7, {"role_arn": OWN_ROLE, "regions": ["ap-south-1"], "scope": "account"}, EXT,
                                lambda _a: None, lambda: None)
    assert role["calls"] == []


def test_collection_on_production_refuses_the_switch(role, monkeypatch):
    _lab(monkeypatch, "production")
    with pytest.raises(aws_collect.AwsCollectError, match="ZeroShield's own AWS account"):
        aws_collect.collect_aws(7, {"role_arn": OWN_ROLE, "regions": ["ap-south-1"], "scope": "account"}, EXT,
                                lambda _a: None, lambda: None)


def test_collection_in_lab_mode_still_refuses_a_role_without_the_external_id(role, monkeypatch, capsys):
    _lab(monkeypatch)
    role["needs_external_id"] = False
    with pytest.raises(aws_collect.AwsCollectError, match="without the external ID"):
        aws_collect.collect_aws(7, {"role_arn": OWN_ROLE, "regions": ["ap-south-1"], "scope": "account"}, EXT,
                                lambda _a: None, lambda: None)
    assert "where=collect" in capsys.readouterr().out


def test_cloud_worker_labels_every_run_of_a_lab_source(role, monkeypatch):
    from backend.workers.cbom_cloud_worker import _aws_lab_mode

    cfg = {"role_arn": OWN_ROLE, "scope": "account"}
    assert _aws_lab_mode(cfg) is None  # off
    _lab(monkeypatch)
    assert _aws_lab_mode(cfg) == "same_account"
    assert _aws_lab_mode({"role_arn": OTHER_ROLE, "scope": "account"}) is None
    assert _aws_lab_mode({**cfg, "scope": "organization"}) is None
    _lab(monkeypatch, "production")
    assert _aws_lab_mode(cfg) is None


# ----------------------------------------------------------------------------- API: settings, validate, audit
def test_settings_and_validate_api_say_lab_mode_and_audit_it(api, world, role, monkeypatch):  # noqa: F811
    from sqlmodel import Session, select

    from backend.new_models import CbomCollectionAuditEvent
    from backend.routers import cbom_sources

    assert api("GET", "/1/cbom/sources/settings").json()["settings"]["aws_lab_same_account"] is False
    _lab(monkeypatch)
    assert api("GET", "/1/cbom/sources/settings").json()["settings"]["aws_lab_same_account"] is True
    ext = api("GET", "/1/cbom/sources/settings").json()["settings"]["aws_external_id"]
    real = aws_validate.validate_aws_role
    monkeypatch.setattr(cbom_sources, "validate_aws_role",
                        lambda team, arn, _ext, regions, scope, **kw: real(team, arn, EXT, regions, scope, **kw))
    assert ext  # the team's own id is replaced by the fake role's
    src = api("POST", "/1/cbom/sources/items", json={"kind": "aws_account", "name": "sandbox", "config": {
        "role_arn": OWN_ROLE, "regions": ["ap-south-1"]}}).json()["source"]
    r = api("POST", f"/1/cbom/sources/items/{src['id']}/test").json()
    assert r["status"] == "passed" and r["lab_mode"] == "same_account"
    engine, _ids = world
    with Session(engine) as session:
        actions = [e.action for e in session.exec(select(CbomCollectionAuditEvent)).all()]
    assert "source.validate.lab_same_account" in actions


def test_banner_sentence_matches_the_ui():
    assert lab_mode.LAB_BANNER == BANNER


def test_the_runbook_policies_pass_the_checks_they_are_written_for():
    """deploy/staging/README.md gives the owner JSON to paste: the deny must satisfy "Data-plane deny present" and list
    exactly the template's actions; the trust policy must carry the external ID condition."""
    import json
    import re
    from pathlib import Path

    readme = (Path(_REPO_ROOT) / "deploy/staging/README.md").read_text()
    section = readme.split("## AWS collection on staging (lab mode)", 1)[1].split("\n## ", 1)[0]
    docs = [json.loads(block) for block in re.findall(r"```json\n(.*?)\n```", section, re.S)]
    assert len(docs) == 3
    deny = next(d for d in docs if d["Statement"][0]["Effect"] == "Deny")
    assert deny["Statement"][0]["Action"] == DENY_ACTIONS
    assert aws_validate.check_role_policies([deny], lambda_cmk=False)[0][0] == "pass"
    trust = next(d for d in docs if "Principal" in d["Statement"][0])
    assert trust["Statement"][0]["Principal"]["AWS"] == PRINCIPAL
    assert trust["Statement"][0]["Condition"] == {"StringEquals": {"sts:ExternalId": "<EXTERNAL_ID>"}}
    assert "CBOM_AWS_PRINCIPAL_ARN` | `" + PRINCIPAL in section and "`CBOM_AWS_LAB_SAME_ACCOUNT` | `1`" in section
    assert not re.search(r"AKIA[0-9A-Z]{16}", readme)  # placeholders only, never a key
