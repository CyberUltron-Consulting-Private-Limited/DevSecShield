"""Reader role template (Lambda / Glue opt-ins) and the validator that checks a deployed role matches it.

The template is resolved the way CloudFormation would (Conditions, Fn::If, AWS::NoValue) for every parameter
combination, and the resulting inline policies are fed to the validator: the template and the validator must agree,
and anything that is not exactly the template's deny must fail.  No network.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cbom_aws_reader_template.py -q
"""
from __future__ import annotations

import itertools
import json
import sys
import urllib.parse
from pathlib import Path

import pytest
import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from botocore.exceptions import ClientError  # noqa: E402

from backend.utilities.cbom_sources import aws_validate  # noqa: E402
from backend.utilities.cbom_sources.aws_validate import GLUE_CHECK, LAMBDA_CHECK, check_role_policies  # noqa: E402
from backend.utilities.cbom_sources.templates import DENY_ACTIONS, REQUIRED_DENY, cloudformation_template  # noqa: E402

EXT = "zs-ext-AAAA-BBBB-CCCC-DDDD"
ROLE = "arn:aws:iam::111122223333:role/ZeroShieldCBOMReader"
NOVALUE = object()


class _CfnLoader(yaml.SafeLoader):
    pass


def _tag(name):
    def construct(loader, node):
        if isinstance(node, yaml.ScalarNode):
            return {name: loader.construct_scalar(node)}
        if isinstance(node, yaml.SequenceNode):
            return {name: loader.construct_sequence(node, deep=True)}
        return {name: loader.construct_mapping(node, deep=True)}
    return construct


for _t, _n in (("!If", "Fn::If"), ("!Ref", "Ref"), ("!Sub", "Fn::Sub"), ("!Equals", "Fn::Equals"), ("!Or", "Fn::Or"),
               ("!Condition", "Condition"), ("!GetAtt", "Fn::GetAtt")):
    _CfnLoader.add_constructor(_t, _tag(_n))


@pytest.fixture(autouse=True)
def _configured_deployment(monkeypatch):
    """These tests exercise a deployment set up for AWS collection (Validate refuses otherwise: G3 item 6)."""
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", "arn:aws:iam::123456789012:role/zeroshield-cbom")


def _resolve_template(text: str, overrides: dict[str, str] | None = None) -> tuple[dict, list[dict]]:
    """(parameters used, inline policies) of the role, as CloudFormation would create them."""
    doc = yaml.load(text, Loader=_CfnLoader)  # noqa: S506 - SafeLoader subclass with CloudFormation tags only
    params = {name: str(p.get("Default")) for name, p in doc["Parameters"].items()}
    params.update(overrides or {})

    def value(node):
        return params[node["Ref"]] if isinstance(node, dict) and "Ref" in node else node

    def cond(expr):
        if "Fn::Equals" in expr:
            a, b = expr["Fn::Equals"]
            return value(a) == value(b)
        if "Fn::Or" in expr:
            return any(cond(e) for e in expr["Fn::Or"])
        if "Condition" in expr:
            return cond(doc["Conditions"][expr["Condition"]])
        raise AssertionError(expr)

    conditions = {name: cond(expr) for name, expr in doc["Conditions"].items()}

    def resolve(node):
        if isinstance(node, dict):
            if set(node) == {"Fn::If"}:
                name, yes, no = node["Fn::If"]
                return resolve(yes if conditions[name] else no)
            if node == {"Ref": "AWS::NoValue"}:
                return NOVALUE
            return {k: r for k, r in ((k, resolve(v)) for k, v in node.items()) if r is not NOVALUE}
        if isinstance(node, list):
            return [r for r in (resolve(x) for x in node) if r is not NOVALUE]
        return node

    role = doc["Resources"]["ZeroShieldCBOMReaderRole"]["Properties"]
    return params, resolve(role["Policies"])


def _docs(policies):
    return [p["PolicyDocument"] for p in policies]


# ----------------------------------------------------------------------------- template
@pytest.mark.parametrize("scope,lambda_cmk,glue", list(itertools.product(["account", "organization"], [False, True], [False, True])))
def test_every_variant_resolves_to_policies_the_validator_accepts(scope, lambda_cmk, glue):
    text = cloudformation_template(EXT, scope, read_lambda_cmk=lambda_cmk, read_glue=glue)
    params, policies = _resolve_template(text)
    assert params["DecryptCustomerKeyLambdaEnvironments"] == str(lambda_cmk).lower()
    assert params["ReadGlueConnections"] == str(glue).lower()
    statements = [s for p in policies for s in p["PolicyDocument"]["Statement"]]
    deny = next(s for s in statements if s["Sid"] == "DenyKeyUseAndDataPlaneReads")
    assert set(deny["Action"]) == set(DENY_ACTIONS) - {"kms:Decrypt"} and "Condition" not in deny
    decrypt = [s for s in statements if s["Effect"] == "Deny" and s["Action"] == "kms:Decrypt"]
    assert len(decrypt) == 1
    if lambda_cmk:
        assert decrypt[0]["Condition"] == {"StringNotLike": {"kms:ViaService": "lambda.*.amazonaws.com"}}
        allow = next(s for s in statements if s.get("Sid") == "AllowDecryptOnlyThroughLambda")
        assert allow["Condition"] == {"StringLike": {"kms:ViaService": "lambda.*.amazonaws.com"}}
    else:
        assert "Condition" not in decrypt[0]
    glue_allow = [s for s in statements if s.get("Sid") == "AllowGlueConnectionMetadata"]
    assert (glue_allow[0]["Action"] if glue_allow else None) == (["glue:GetConnection", "glue:GetConnections"] if glue else None)
    if not lambda_cmk and not glue:
        assert [p["PolicyName"] for p in policies] == ["ZeroShieldCBOMReaderDeny"]  # no Allow at all by default
    deny_row, lambda_row = check_role_policies(_docs(policies), lambda_cmk=lambda_cmk)
    assert deny_row[0] == "pass", deny_row
    assert (lambda_row[0] if lambda_row else None) == ("pass" if lambda_cmk else None)


def test_parameters_flipped_on_the_stack_resolve_the_same_way():
    """A customer may flip the parameters in the CloudFormation console instead of downloading a new file."""
    text = cloudformation_template(EXT, "account")
    _p, policies = _resolve_template(text, {"DecryptCustomerKeyLambdaEnvironments": "true", "ReadGlueConnections": "true"})
    assert check_role_policies(_docs(policies), lambda_cmk=True)[1][0] == "pass"
    assert any(s.get("Sid") == "AllowGlueConnectionMetadata" for p in policies for s in p["PolicyDocument"]["Statement"])


def test_template_text_keeps_its_claims_true():
    default = cloudformation_template(EXT, "account")
    assert "without reading stored secrets" in default and "can never read secrets" not in default
    assert "only its shape is kept" in default  # Lambda env under the default key is returned to SecurityAudit
    both = cloudformation_template(EXT, "account", read_lambda_cmk=True, read_glue=True)
    assert "HidePassword=true" in both and "plain text" in both
    assert "key policy must also allow this role" in both.replace("\n", " ").replace("      ", " ")
    assert "DecryptCustomerKeyLambdaEnvironments=true, ReadGlueConnections=true" in both
    with pytest.raises(ValueError):
        cloudformation_template("not-an-external-id", "account")


# ----------------------------------------------------------------------------- validator: what must fail
def _base(extra: list[dict] | None = None, decrypt: dict | None = None) -> list[dict]:
    statements = [{"Sid": "DenyKeyUseAndDataPlaneReads", "Effect": "Deny", "Resource": "*",
                   "Action": [a for a in DENY_ACTIONS if a != "kms:Decrypt"]}]
    if decrypt is not None:
        statements.append(decrypt)
    return [{"Version": "2012-10-17", "Statement": statements + (extra or [])}]


LAMBDA_ALLOW = {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*",
                "Condition": {"StringLike": {"kms:ViaService": "lambda.*.amazonaws.com"}}}


@pytest.mark.parametrize("condition", [
    {"StringNotLikeIfExists": {"kms:ViaService": "lambda.*.amazonaws.com"}},  # would pass a direct call with no key
    {"ForAnyValue:StringNotLike": {"kms:ViaService": "lambda.*.amazonaws.com"}},
    {"StringNotLike": {"kms:ViaService": ["lambda.*.amazonaws.com", "s3.*.amazonaws.com"]}},  # a second service
    {"StringNotLike": {"kms:ViaService": "*.amazonaws.com"}},
    {"StringNotLike": {"kms:ViaService": "lambda.*.amazonaws.com"}, "Bool": {"aws:SecureTransport": "true"}},
    {"StringNotEquals": {"kms:CallerAccount": "111122223333"}},
])
def test_lambda_on_refuses_any_other_decrypt_condition(condition):
    docs = _base([LAMBDA_ALLOW], {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*", "Condition": condition})
    deny_row, lambda_row = check_role_policies(docs, lambda_cmk=True)
    assert lambda_row[0] == "fail" and "exactly" in lambda_row[1]


def test_lambda_on_needs_a_deny_on_every_resource_and_an_allow():
    narrow = _base([LAMBDA_ALLOW], {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "arn:aws:kms:*:*:key/one",
                                    "Condition": {"StringNotLike": {"kms:ViaService": "lambda.*.amazonaws.com"}}})
    assert check_role_policies(narrow, lambda_cmk=True)[1][0] == "fail"
    no_allow = _base(None, {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*",
                            "Condition": {"StringNotLike": {"kms:ViaService": "lambda.*.amazonaws.com"}}})
    row = check_role_policies(no_allow, lambda_cmk=True)[1]
    assert row[0] == "fail" and "nothing allows it" in row[1]


def test_switch_and_role_must_agree_both_ways():
    carved = _base([LAMBDA_ALLOW], {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*",
                                    "Condition": {"StringNotLike": {"kms:ViaService": "lambda.*.amazonaws.com"}}})
    deny_row, lambda_row = check_role_policies(carved, lambda_cmk=False)
    assert deny_row[0] == "fail" and "option off" in deny_row[1] and lambda_row is None
    plain = _base(None, {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*"})
    deny_row, lambda_row = check_role_policies(plain, lambda_cmk=True)
    assert deny_row[0] == "pass" and lambda_row[0] == "fail" and "still denies kms:Decrypt everywhere" in lambda_row[1]


def test_a_conditional_deny_no_longer_passes_for_required_actions():
    """Before: any Deny listing the action passed, whatever its Condition.  A deny that applies only sometimes is not
    the guarantee the role promises."""
    docs = _base(None, {"Effect": "Deny", "Action": "kms:Decrypt", "Resource": "*"})
    statements = docs[0]["Statement"]
    statements[0]["Action"] = [a for a in statements[0]["Action"] if a != "s3:GetObject"]
    statements.append({"Effect": "Deny", "Action": "s3:GetObject", "Resource": "*",
                       "Condition": {"Bool": {"aws:SecureTransport": "false"}}})
    row, _l = check_role_policies(docs, lambda_cmk=False)
    assert row[0] == "fail" and "Denied only under a condition" in row[1] and "s3:GetObject" in row[1]


def test_missing_and_wildcards():
    row, _l = check_role_policies([{"Statement": [{"Effect": "Deny", "Action": ["kms:*", "secretsmanager:*", "ssm:*", "s3:*"],
                                                   "Resource": "*"}]}], lambda_cmk=False)
    assert row[0] == "pass"
    row, _l = check_role_policies([{"Statement": [{"Effect": "Deny", "Action": "kms:Decrypt", "Resource": ["*"]}]}], lambda_cmk=False)
    assert row[0] == "fail" and all(a in row[1] for a in REQUIRED_DENY if a != "kms:Decrypt")
    row, _l = check_role_policies([{"Statement": [{"Effect": "Deny", "NotAction": "iam:*", "Resource": "*"}]}], lambda_cmk=False)
    assert row[0] == "fail"  # NotAction is never read as a deny of a named action


# ----------------------------------------------------------------------------- validator end to end (stub AWS)
def _err(code):
    return ClientError({"Error": {"Code": code, "Message": "stub"}}, "Op")


class _FakeAws:
    def __init__(self, policies: list[dict], glue_denied: bool = False):
        self.policies, self.glue_denied, self.glue_calls = policies, glue_denied, []

    def session(self, **_kw):
        return self

    def client(self, service, **_kw):
        fake = self

        class C:
            def assume_role(self, **kw):
                if "ExternalId" not in kw:
                    raise _err("AccessDenied")
                return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}

            def list_attached_role_policies(self, **_kw):
                return {"AttachedPolicies": [{"PolicyName": "SecurityAudit"}]}

            def list_role_policies(self, **_kw):
                return {"PolicyNames": [p["PolicyName"] for p in fake.policies]}

            def get_role_policy(self, RoleName, PolicyName):  # noqa: N803 - boto3 names
                doc = next(p["PolicyDocument"] for p in fake.policies if p["PolicyName"] == PolicyName)
                return {"PolicyDocument": urllib.parse.quote(json.dumps(doc))}  # IAM returns URL-encoded JSON

            def list_keys(self, **_kw):
                return {"Keys": []}

            def get_secret_value(self, **_kw):
                raise _err("AccessDeniedException")

            def get_connections(self, **kw):
                fake.glue_calls.append(kw)
                if fake.glue_denied:
                    raise _err("AccessDeniedException")
                return {"ConnectionList": []}

        return C()


@pytest.mark.parametrize("lambda_cmk,glue", list(itertools.product([False, True], [False, True])))
def test_validate_role_end_to_end(monkeypatch, lambda_cmk, glue):
    _p, policies = _resolve_template(cloudformation_template(EXT, "account", read_lambda_cmk=lambda_cmk, read_glue=glue))
    fake = _FakeAws(policies)
    monkeypatch.setattr(aws_validate, "_boto", lambda **_kw: (fake, None))
    import boto3

    monkeypatch.setattr(boto3.session, "Session", fake.session)
    out = aws_validate.validate_aws_role(1, ROLE, EXT, ["ap-south-1"], "account", lambda_cmk=lambda_cmk, read_glue=glue)
    assert out["status"] == "passed", out
    checks = {c["check"]: c["status"] for c in out["checks"]}
    assert (LAMBDA_CHECK in checks) == lambda_cmk and (GLUE_CHECK in checks) == glue
    assert fake.glue_calls == ([{"HidePassword": True, "MaxResults": 1}] if glue else [])


def test_validate_role_fails_when_glue_is_on_but_the_stack_is_not(monkeypatch):
    _p, policies = _resolve_template(cloudformation_template(EXT, "account"))
    fake = _FakeAws(policies, glue_denied=True)
    monkeypatch.setattr(aws_validate, "_boto", lambda **_kw: (fake, None))
    import boto3

    monkeypatch.setattr(boto3.session, "Session", fake.session)
    out = aws_validate.validate_aws_role(1, ROLE, EXT, ["ap-south-1"], "account", read_glue=True)
    glue = next(c for c in out["checks"] if c["check"] == GLUE_CHECK)
    assert out["status"] == "failed" and glue["status"] == "fail" and "ReadGlueConnections=true" in glue["detail"]
