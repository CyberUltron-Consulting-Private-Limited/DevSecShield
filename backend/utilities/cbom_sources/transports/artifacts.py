"""What a customer installs on their side for a transport (``GET .../fleet/transports/artifacts/{name}``).

Every wrapper is rendered for the deployment's active, verified zs-collect release (sha256 per architecture baked in,
the manifest signature and the release public key embedded), by the same ``wrappers.py`` the scan node carries.  The
backend never serves a binary: the customer mirrors the signed release themselves (contract open question 10).

* ``ssm-document``       the ``devsecshield-*`` Command document (JSON)
* ``ssm-role-cfn``       the separate run-command role (CloudFormation): SendCommand only for ``document/devsecshield-*``
                         and only on instances tagged as the customer chooses, read its invocations, read the output
                         prefix; it trusts ZeroShield's account with the team's external id.  The read-only reader role
                         stays read-only.
* ``salt-state``         ``zeroshield/zs_collect.sls`` + ``zeroshield/zs-collect-run.sh`` for the master's file roots
* ``ansible-collection`` the playbook + ``files/zs-collect-run.sh`` for an AWX/AAP project
* ``zs-collect-manifest`` the signed manifest and its signature
* ``zs-collect-pubkey``  the release public key and its fingerprint
"""
from __future__ import annotations

import re
from typing import Any

from backend.utilities.cbom_sources.templates import zeroshield_account_id
from backend.utilities.cbom_sources.transports import wrappers
from backend.utilities.cbom_sources.transports.models import CbomZsCollectRelease
from backend.utilities.cbom_sources.transports.registry import key_fingerprint, public_key_pem

NAMES = ("ssm-document", "ssm-role-cfn", "salt-state", "ansible-collection", "zs-collect-manifest", "zs-collect-pubkey")
NEEDS_RELEASE = {"ssm-document", "salt-state", "ansible-collection", "zs-collect-manifest"}


def launcher(release: CbomZsCollectRelease) -> str:
    return wrappers.render_wrapper(release.manifest or {}, public_key_pem(), release.manifest_sig)


def document_name(release: CbomZsCollectRelease) -> str:
    return "devsecshield-zs-collect-" + re.sub(r"[^A-Za-z0-9_.-]", "-", release.version)


def ssm_role_cfn(external_id: str, tag_key: str = "zs-collect", tag_value: str = "enabled") -> str:
    if not re.fullmatch(r"zs-ext-[A-Z0-9]{4}(-[A-Z0-9]{4}){3}", external_id or ""):
        raise ValueError("unexpected external id format")
    account = zeroshield_account_id() or "000000000000"
    note = "# NOTE: ZeroShieldAccountId is a placeholder (CBOM_AWS_PRINCIPAL_ARN is not configured on the server).\n" \
        if account == "000000000000" else ""
    return f"""# ZeroShield CBOM run-command role for the AWS SSM transport (separate from the read-only reader role).
# It may run only devsecshield-* Command documents, only on instances that carry the tag you choose below, and read
# only those commands' results and the output prefix. Deploy it in each account whose instances ZeroShield collects.
{note}AWSTemplateFormatVersion: "2010-09-09"
Description: ZeroShield CBOM run-command role (SSM SendCommand of devsecshield-* documents on tagged instances only)
Parameters:
  ZeroShieldAccountId:
    Type: String
    Default: "{account}"
    AllowedPattern: "^[0-9]{{12}}$"
  ExternalId:
    Type: String
    Default: "{external_id}"
    NoEcho: true
    AllowedPattern: "^[A-Za-z0-9+=,.@:/_-]+$"
  RoleName:
    Type: String
    Default: ZeroShieldCBOMRunCommand
  InstanceTagKey:
    Type: String
    Default: "{tag_key}"
  InstanceTagValue:
    Type: String
    Default: "{tag_value}"
  OutputBucket:
    Type: String
    Default: ""
    Description: Optional S3 bucket for command output (needed for outputs over 24,000 characters)
  OutputPrefix:
    Type: String
    Default: "zeroshield-cbom"
Conditions:
  HasBucket: !Not [!Equals [!Ref OutputBucket, ""]]
Resources:
  ZeroShieldCBOMRunCommandRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:${{AWS::Partition}}:iam::${{ZeroShieldAccountId}}:root"
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref ExternalId
      Policies:
        - PolicyName: ZeroShieldCBOMRunCommand
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: RunOnlyZeroShieldDocuments
                Effect: Allow
                Action: ssm:SendCommand
                Resource: !Sub "arn:${{AWS::Partition}}:ssm:*:${{AWS::AccountId}}:document/devsecshield-*"
              - Sid: OnlyOnTaggedInstances
                Effect: Allow
                Action: ssm:SendCommand
                Resource: !Sub "arn:${{AWS::Partition}}:ec2:*:${{AWS::AccountId}}:instance/*"
                Condition:
                  StringEquals:
                    "ssm:resourceTag/${{InstanceTagKey}}": !Ref InstanceTagValue
              - Sid: ReadCommandsAndInstances
                Effect: Allow
                Action:
                  - ssm:ListCommandInvocations
                  - ssm:GetCommandInvocation
                  - ssm:CancelCommand
                  - ssm:DescribeInstanceInformation
                  - ssm:DescribeDocument
                Resource: "*"
              - !If
                - HasBucket
                - Sid: ReadCommandOutput
                  Effect: Allow
                  Action: s3:GetObject
                  Resource: !Sub "arn:${{AWS::Partition}}:s3:::${{OutputBucket}}/${{OutputPrefix}}/*"
                - !Ref AWS::NoValue
Outputs:
  RoleArn:
    Value: !GetAtt ZeroShieldCBOMRunCommandRole.Arn
"""


def render(name: str, release: CbomZsCollectRelease | None, external_id: str) -> tuple[str, Any]:
    """(media type, body) of one artifact.  Raises LookupError when it needs a release and none is active."""
    if name not in NAMES:
        raise KeyError(name)
    if name in NEEDS_RELEASE and release is None:
        raise LookupError("No verified zs-collect release is active in this deployment")
    if name == "zs-collect-pubkey":
        return "application/json", {"public_key": public_key_pem(), "fingerprint": key_fingerprint()}
    if name == "ssm-role-cfn":
        return "text/yaml", ssm_role_cfn(external_id)
    assert release is not None
    if name == "zs-collect-manifest":
        return "application/json", {"version": release.version, "manifest": release.manifest_raw,
                                    "signature": release.manifest_sig, "fingerprint": release.key_fingerprint}
    run = launcher(release)
    if name == "ssm-document":
        return "application/json", {"name": document_name(release),
                                    "content": wrappers.render_ssm_document(release.version, run)}
    if name == "salt-state":
        return "application/json", {"version": release.version, "files": wrappers.render_salt(release.version, run)}
    return "application/json", {"version": release.version, "files": wrappers.render_ansible(release.version, run)}
