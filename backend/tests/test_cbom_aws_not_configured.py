"""A deployment without CBOM_AWS_PRINCIPAL_ARN cannot collect AWS: its CloudFormation template could only trust the
placeholder account 000000000000 (only a YAML comment said so). The backend now says whether AWS collection is
configured; the template download and Validate refuse with one sentence the form also shows (round 5, G3 item 6)."""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.tests.test_cbom_sources_api import api, world  # noqa: E402,F401
from backend.utilities.cbom_sources import aws_validate  # noqa: E402
from backend.utilities.cbom_sources.templates import AWS_NOT_CONFIGURED, aws_collection_configured  # noqa: E402

MSG = "This ZeroShield deployment is not set up for AWS collection; contact your administrator"
ARN = "arn:aws:iam::123456789012:role/zeroshield-cbom"


def test_unconfigured_deployment_says_so_everywhere(api, world, monkeypatch):
    monkeypatch.delenv("CBOM_AWS_PRINCIPAL_ARN", raising=False)
    assert AWS_NOT_CONFIGURED == MSG and aws_collection_configured() is False
    settings = api("GET", "/1/cbom/sources/settings").json()["settings"]
    assert settings["aws_collection_configured"] is False
    assert api("GET", "/1/cbom/sources/overview").json()["settings"]["aws_collection_configured"] is False
    tpl = api("GET", "/1/cbom/sources/aws/template?scope=account")
    assert tpl.status_code == 409 and MSG in tpl.text and "000000000000" not in tpl.text

    def no_boto():
        raise AssertionError("Validate must not call AWS when the deployment is not configured")

    monkeypatch.setattr(aws_validate, "_boto", no_boto)
    out = aws_validate.validate_aws_role(1, "arn:aws:iam::111122223333:role/R", "zs-ext-AAAA-BBBB-CCCC-DDDD",
                                         ["us-east-1"], "account")
    assert out["status"] == "failed"
    assert out["checks"][0] == {"check": "Role assumed with external ID", "status": "fail", "detail": MSG}
    assert all(c["status"] == "skipped" for c in out["checks"][1:])


def test_configured_deployment_serves_a_template_trusting_its_account(api, world, monkeypatch):
    monkeypatch.setenv("CBOM_AWS_PRINCIPAL_ARN", ARN)
    assert api("GET", "/1/cbom/sources/settings").json()["settings"]["aws_collection_configured"] is True
    tpl = api("GET", "/1/cbom/sources/aws/template?scope=account")
    assert tpl.status_code == 200 and "123456789012" in tpl.text and "000000000000" not in tpl.text
