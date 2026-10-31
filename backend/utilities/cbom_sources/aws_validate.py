"""Validate a customer's read-only AWS role with real STS calls.

Runs in a worker thread with a hard deadline checked between calls; every botocore call has short
timeouts and at most two attempts.  No database session is held while AWS is called.  The temporary
credentials from AssumeRole are used for read-only checks and then dropped.

Check rows are ``pass`` / ``fail`` / ``skipped`` / ``error``: ``fail`` means the customer's setup is
wrong, ``error`` means ZeroShield could not run the check (it carries a ref for the logs).
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
from typing import Any

from backend.utilities.cbom_sources.common import log, new_ref
from backend.utilities.cbom_sources.kinds import aws_account_id
from backend.utilities.cbom_sources.templates import REQUIRED_DENY, zeroshield_account_id

DEADLINE_SECONDS = 20.0


def _boto():
    import boto3  # imported lazily: only this path needs it
    from botocore.config import Config

    cfg = Config(connect_timeout=5, read_timeout=8, retries={"max_attempts": 2, "mode": "standard"})
    key = os.environ.get("CBOM_AWS_ACCESS_KEY_ID")
    secret = os.environ.get("CBOM_AWS_SECRET_ACCESS_KEY")
    if key and secret:
        session = boto3.session.Session(aws_access_key_id=key, aws_secret_access_key=secret)
    else:
        session = boto3.session.Session()
    return session, cfg


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None) or {}
    return str((response.get("Error") or {}).get("Code") or type(exc).__name__)


def _row(check: str, status: str, detail: str) -> dict[str, str]:
    return {"check": check, "status": status, "detail": detail}


def validate_aws_role(team_id: int, role_arn: str, external_id: str, regions: list[str], scope: str) -> dict[str, Any]:
    started = time.monotonic()
    rows: list[dict[str, str]] = []
    member_accounts: int | None = None

    def remaining() -> float:
        return DEADLINE_SECONDS - (time.monotonic() - started)

    names = [
        "Role assumed with external ID", "Role refused without external ID", "SecurityAudit attached",
        "Data-plane deny present", "Test read: list KMS keys", "Test secret read was denied",
    ]
    if scope == "organization":
        names.append("Organization member accounts listed")

    own_account = zeroshield_account_id()
    customer_account = aws_account_id(role_arn)
    if own_account and customer_account == own_account:
        rows.append(_row(names[0], "fail", "This role is in ZeroShield's own AWS account; use a role in your account"))
        return {"status": "failed", "checks": rows + [_row(n, "skipped", "Not run") for n in names[1:]]}

    try:
        session, cfg = _boto()
        sts = session.client("sts", region_name=regions[0] if regions else "us-east-1", config=cfg)
    except Exception as exc:
        ref = new_ref()
        log("aws validate FAILED", ref=ref, team=team_id, error=type(exc).__name__)
        return {"status": "error", "checks": [_row(n, "error", f"ZeroShield could not start AWS checks (ref {ref})") for n in names]}

    session_name = f"zs-cbom-validate-{team_id}"[:64]
    creds = None
    try:
        assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name, ExternalId=external_id,
                                  DurationSeconds=900)
        creds = assumed["Credentials"]
        rows.append(_row(names[0], "pass", "AssumeRole succeeded with your external ID"))
    except Exception as exc:
        code = _code(exc)
        if code in ("AccessDenied", "AccessDeniedException"):
            detail = "AWS refused AssumeRole: the role does not exist, or its trust policy does not allow ZeroShield with this external ID"
            rows.append(_row(names[0], "fail", detail))
        elif code in ("NoCredentialsError", "InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken",
                      "EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError"):
            ref = new_ref()
            log("aws validate FAILED", ref=ref, team=team_id, error=code)
            rows.append(_row(names[0], "error", f"ZeroShield could not call AWS STS (ref {ref})"))
        else:
            rows.append(_row(names[0], "fail", f"AssumeRole failed: {code}"))
        rows.extend(_row(n, "skipped", "Skipped because the role could not be assumed") for n in names[1:])
        status = "error" if rows[0]["status"] == "error" else "failed"
        return {"status": status, "checks": rows}

    # Without the external ID the trust policy must refuse us.
    if remaining() > 2:
        try:
            sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name + "-noext", DurationSeconds=900)
            rows.append(_row(names[1], "fail", "The role can be assumed without the external ID; add the sts:ExternalId condition"))
        except Exception as exc:
            code = _code(exc)
            if code in ("AccessDenied", "AccessDeniedException"):
                rows.append(_row(names[1], "pass", "AssumeRole without the external ID was refused"))
            else:
                rows.append(_row(names[1], "error", f"Could not run this check: {code}"))
    else:
        rows.append(_row(names[1], "skipped", "Out of time"))

    import boto3

    assumed_session = boto3.session.Session(
        aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    role_name = role_arn.rsplit("/", 1)[-1]
    try:
        iam = assumed_session.client("iam", config=cfg)
        if remaining() > 2:
            attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
            if any(p.get("PolicyName") == "SecurityAudit" for p in attached):
                rows.append(_row(names[2], "pass", "AWS managed SecurityAudit is attached"))
            else:
                rows.append(_row(names[2], "fail", "SecurityAudit is not attached to the role"))
        else:
            rows.append(_row(names[2], "skipped", "Out of time"))
        if remaining() > 2:
            denied: set[str] = set()
            for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])[:20]:
                document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument")
                if isinstance(document, str):
                    document = json.loads(urllib.parse.unquote(document))
                for statement in (document or {}).get("Statement", []):
                    if statement.get("Effect") != "Deny":
                        continue
                    actions = statement.get("Action", [])
                    denied.update([actions] if isinstance(actions, str) else actions)
            missing = [a for a in REQUIRED_DENY if a not in denied and a.split(":")[0] + ":*" not in denied]
            if missing:
                rows.append(_row(names[3], "fail", "The deny statement is missing: " + ", ".join(missing)))
            else:
                rows.append(_row(names[3], "pass", "Explicit deny covers key use and secret, parameter and object reads"))
        else:
            rows.append(_row(names[3], "skipped", "Out of time"))
    except Exception as exc:
        code = _code(exc)
        for name in names[2:4]:
            if not any(r["check"] == name for r in rows):
                rows.append(_row(name, "fail" if code.startswith("AccessDenied") else "error",
                                 f"Could not read the role's policies: {code}"))

    region = regions[0] if regions else "us-east-1"
    if remaining() > 2:
        try:
            kms = assumed_session.client("kms", region_name=region, config=cfg)
            keys = kms.list_keys(Limit=50).get("Keys", [])
            rows.append(_row(names[4], "pass", f"Listed {len(keys)} KMS key(s) in {region}"))
        except Exception as exc:
            rows.append(_row(names[4], "fail", f"kms:ListKeys failed in {region}: {_code(exc)}"))
    else:
        rows.append(_row(names[4], "skipped", "Out of time"))

    if remaining() > 2:
        probe = f"arn:aws:secretsmanager:{region}:{customer_account}:secret:zeroshield-cbom-probe-doesnotexist"
        try:
            assumed_session.client("secretsmanager", region_name=region, config=cfg).get_secret_value(SecretId=probe)
            rows.append(_row(names[5], "fail", "A secret read was allowed; the deny statement is not effective"))
        except Exception as exc:
            code = _code(exc)
            if code in ("AccessDeniedException", "AccessDenied"):
                rows.append(_row(names[5], "pass", "secretsmanager:GetSecretValue was denied"))
            elif code == "ResourceNotFoundException":
                rows.append(_row(names[5], "fail", "The role is allowed to read secrets (the probe got 'not found', not 'denied')"))
            else:
                rows.append(_row(names[5], "error", f"Could not run this check: {code}"))
    else:
        rows.append(_row(names[5], "skipped", "Out of time"))

    if scope == "organization":
        if remaining() > 2:
            try:
                org = assumed_session.client("organizations", config=cfg)
                count = 0
                token = None
                for _ in range(10):
                    page = org.list_accounts(**({"NextToken": token} if token else {}))
                    count += len(page.get("Accounts", []))
                    token = page.get("NextToken")
                    if not token or remaining() < 2:
                        break
                member_accounts = count
                rows.append(_row(names[6], "pass", f"Found {count} member accounts"))
            except Exception as exc:
                rows.append(_row(names[6], "fail", f"organizations:ListAccounts failed: {_code(exc)}; use the management account role"))
        else:
            rows.append(_row(names[6], "skipped", "Out of time"))

    creds = None  # drop the temporary credentials
    statuses = {r["status"] for r in rows}
    status = "passed" if statuses <= {"pass"} else ("failed" if "fail" in statuses else "error")
    out: dict[str, Any] = {"status": status, "checks": rows}
    if member_accounts is not None:
        out["member_accounts"] = member_accounts
    return out
