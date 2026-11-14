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
from backend.utilities.cbom_sources.lab_mode import LAB_MODE, own_account_decision
from backend.utilities.cbom_sources.templates import (
    AWS_NOT_CONFIGURED, LAMBDA_DECRYPT_CONDITION, REQUIRED_DENY, zeroshield_account_id)

DEADLINE_SECONDS = 20.0
LAMBDA_CHECK = "Lambda customer-key decryption only through Lambda"
GLUE_CHECK = "Glue connections readable (passwords hidden)"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _covers(actions: list[str], action: str) -> bool:
    service = action.split(":", 1)[0]
    return any(a == action or a == f"{service}:*" or a == "*" for a in actions)


def _normalised_condition(condition: Any) -> Any:
    """Condition values may be a string or a list of strings; compare them as sorted lists."""
    if not isinstance(condition, dict):
        return condition
    return {op: ({k: sorted(_as_list(v)) for k, v in keys.items()} if isinstance(keys, dict) else keys)
            for op, keys in condition.items()}


def check_role_policies(documents: list[dict[str, Any]], *, lambda_cmk: bool) -> tuple[tuple[str, str], tuple[str, str] | None]:
    """Judge the role's inline policy documents.  Returns ((status, detail) for "Data-plane deny present",
    (status, detail) for the Lambda opt-in or None when the opt-in is off).

    Every REQUIRED_DENY action must be denied by a statement with no Condition on Resource "*".  The one exception is
    kms:Decrypt when the source's Lambda opt-in is on: its deny must then carry exactly the Lambda carve-out
    (StringNotLike kms:ViaService lambda.*.amazonaws.com) -- anything else is refused, because a different condition
    (another service, IfExists, a set operator) could let ZeroShield decrypt directly or through another service."""
    unconditional: list[str] = []
    conditional: list[tuple[list[str], Any]] = []
    allows: list[tuple[list[str], Any]] = []
    for document in documents:
        for statement in _as_list((document or {}).get("Statement")):
            if not isinstance(statement, dict) or "Action" not in statement:
                continue  # NotAction statements are never counted as a deny of a named action
            actions = [str(a) for a in _as_list(statement.get("Action"))]
            if statement.get("Effect") == "Allow":
                allows.append((actions, statement.get("Condition")))
                continue
            if statement.get("Effect") != "Deny" or "*" not in _as_list(statement.get("Resource")):
                continue
            if statement.get("Condition"):
                conditional.append((actions, statement.get("Condition")))
            else:
                unconditional.extend(actions)

    carve_out = _normalised_condition(LAMBDA_DECRYPT_CONDITION)
    missing: list[str] = []
    only_conditional: list[str] = []
    for action in REQUIRED_DENY:
        if _covers(unconditional, action):
            continue
        if action == "kms:Decrypt" and lambda_cmk:
            continue  # judged below
        if any(_covers(actions, action) for actions, _c in conditional):
            only_conditional.append(action)
        else:
            missing.append(action)

    lambda_row: tuple[str, str] | None = None
    decrypt_carved = any(_covers(actions, "kms:Decrypt") and _normalised_condition(cond) == carve_out
                         for actions, cond in conditional)
    if lambda_cmk:
        other_decrypt_conditions = [cond for actions, cond in conditional
                                    if _covers(actions, "kms:Decrypt") and _normalised_condition(cond) != carve_out]
        allowed_through_lambda = any(_covers(actions, "kms:Decrypt") for actions, _c in allows)
        if _covers(unconditional, "kms:Decrypt"):
            lambda_row = ("fail", "Decrypting Lambda environments is on for this source, but the role still denies "
                                  "kms:Decrypt everywhere: update the stack with DecryptCustomerKeyLambdaEnvironments=true, "
                                  "or turn the option off in ZeroShield")
        elif other_decrypt_conditions or not decrypt_carved:
            lambda_row = ("fail", "kms:Decrypt must be denied unless the request comes through Lambda, with exactly "
                                  "Condition StringNotLike kms:ViaService \"lambda.*.amazonaws.com\"; the role has "
                                  + ("a different condition" if other_decrypt_conditions else "no such deny")
                                  + ". Redeploy the ZeroShield template")
        elif not allowed_through_lambda:
            lambda_row = ("fail", "kms:Decrypt is carved out for Lambda but nothing allows it: redeploy the template "
                                  "with DecryptCustomerKeyLambdaEnvironments=true (statement AllowDecryptOnlyThroughLambda)")
        else:
            lambda_row = ("pass", "kms:Decrypt is denied unless the request comes through Lambda. Each customer-managed "
                                  "key's key policy must also allow this role")
    elif decrypt_carved and not _covers(unconditional, "kms:Decrypt"):
        only_conditional = [a for a in only_conditional if a != "kms:Decrypt"]
        return (("fail", "The role lets Lambda decrypt environments with customer-managed keys, but this source has "
                         "that option off: turn it on in ZeroShield, or update the stack with "
                         "DecryptCustomerKeyLambdaEnvironments=false"
                 + (f"; also missing: {', '.join(missing + only_conditional)}" if missing or only_conditional else "")),
                None)

    if missing or only_conditional:
        parts = []
        if missing:
            parts.append("The deny statement is missing: " + ", ".join(missing))
        if only_conditional:
            parts.append("Denied only under a condition (the deny must be unconditional): " + ", ".join(only_conditional))
        return ("fail", "; ".join(parts)), lambda_row
    return ("pass", "Explicit deny covers key use and secret, parameter and object reads"), lambda_row


class NoZeroShieldCredentials(RuntimeError):
    pass


def _boto(*, retries: int = 2, mode: str = "standard"):
    """ZeroShield's own AWS principal (the one customers trust), from CBOM_AWS_* only.

    Ambient credentials (instance role, ~/.aws, AWS_*) are never used: they could belong to
    ZeroShield's own infrastructure, whose inventory must never land in a customer's CBOM.
    Ambient endpoints are ignored the same way: AWS_ENDPOINT_URL, AWS_ENDPOINT_URL_<SERVICE> and endpoint_url in
    ~/.aws/config point at ZeroShield's own services (e.g. AWS_ENDPOINT_URL_S3=http://minio:9000 for uploads in
    deploy/local and the staging MinIO profile); a customer's account is always called at AWS."""
    import boto3  # imported lazily: only this path needs it
    from botocore.config import Config

    cfg = Config(connect_timeout=5, read_timeout=8, retries={"max_attempts": retries, "mode": mode},
                 ignore_configured_endpoint_urls=True)
    key = os.environ.get("CBOM_AWS_ACCESS_KEY_ID")
    secret = os.environ.get("CBOM_AWS_SECRET_ACCESS_KEY")
    token = os.environ.get("CBOM_AWS_SESSION_TOKEN") or None
    if not (key and secret):
        raise NoZeroShieldCredentials("CBOM_AWS_ACCESS_KEY_ID / CBOM_AWS_SECRET_ACCESS_KEY are not configured")
    session = boto3.session.Session(aws_access_key_id=key, aws_secret_access_key=secret, aws_session_token=token)
    return session, cfg


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None) or {}
    return str((response.get("Error") or {}).get("Code") or type(exc).__name__)


def _row(check: str, status: str, detail: str) -> dict[str, str]:
    return {"check": check, "status": status, "detail": detail}


def validate_aws_role(team_id: int, role_arn: str, external_id: str, regions: list[str], scope: str,
                      lambda_cmk: bool = False, read_glue: bool = False) -> dict[str, Any]:
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
    if lambda_cmk:
        names.append(LAMBDA_CHECK)
    if read_glue:
        names.append(GLUE_CHECK)

    own_account = zeroshield_account_id()
    if own_account is None:  # the role could only trust the placeholder account: nothing to validate
        return {"status": "failed", "checks": [_row(names[0], "fail", AWS_NOT_CONFIGURED)]
                + [_row(n, "skipped", "Not run") for n in names[1:]]}
    customer_account = aws_account_id(role_arn)
    # The role may not be in ZeroShield's own account, except in lab mode on a test deployment (lab_mode.py), where
    # every other check below still runs and must pass.
    refusal, lab = own_account_decision(customer_account, own_account, scope, team_id=team_id, where="validate")
    if refusal:
        rows.append(_row(names[0], "fail", refusal))
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
        rows.append(_row(names[0], "pass", "AssumeRole succeeded with your external ID"
                         + (" (lab mode: role in this deployment's own account)" if lab else "")))
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
        return {"status": status, "checks": rows, **({"lab_mode": LAB_MODE} if lab else {})}

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
            documents: list[dict[str, Any]] = []
            for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])[:20]:
                document = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument")
                if isinstance(document, str):
                    document = json.loads(urllib.parse.unquote(document))
                documents.append(document or {})
            deny_row, lambda_row = check_role_policies(documents, lambda_cmk=lambda_cmk)
            rows.append(_row(names[3], *deny_row))
            if lambda_row is not None:
                rows.append(_row(LAMBDA_CHECK, *lambda_row))
        else:
            rows.append(_row(names[3], "skipped", "Out of time"))
    except Exception as exc:
        code = _code(exc)
        for name in names[2:4] + ([LAMBDA_CHECK] if lambda_cmk else []):
            if not any(r["check"] == name for r in rows):
                rows.append(_row(name, "fail" if code.startswith("AccessDenied") else "error",
                                 f"Could not read the role's policies: {code}"))
    if lambda_cmk and not any(r["check"] == LAMBDA_CHECK for r in rows):
        rows.append(_row(LAMBDA_CHECK, "skipped", "Out of time"))

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

    if read_glue:
        if remaining() > 2:
            try:  # one connection at most, password hidden; the answer is dropped unread
                assumed_session.client("glue", region_name=region, config=cfg).get_connections(HidePassword=True, MaxResults=1)
                rows.append(_row(GLUE_CHECK, "pass", f"glue:GetConnections answered in {region} (asked with HidePassword=true)"))
            except Exception as exc:
                code = _code(exc)
                if code in ("AccessDeniedException", "AccessDenied"):
                    rows.append(_row(GLUE_CHECK, "fail", "glue:GetConnections was denied: update the stack with "
                                                         "ReadGlueConnections=true, or turn the option off in ZeroShield"))
                else:
                    rows.append(_row(GLUE_CHECK, "error", f"Could not run this check: {code}"))
        else:
            rows.append(_row(GLUE_CHECK, "skipped", "Out of time"))

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
    if lab:
        out["lab_mode"] = LAB_MODE
    if member_accounts is not None:
        out["member_accounts"] = member_accounts
    return out
