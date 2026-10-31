"""CloudFormation posture extraction. Same verdicts as the Terraform twin."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.extract_cloudformation import extract_cloudformation
from aibom.cbom.posture.extract_terraform import extract_terraform

_DECLARED = "ENCRYPTED_DECLARED"
_PLAIN = "NOT_ENCRYPTED"
_DEFAULT = "ENCRYPTED_PROVIDER_DEFAULT"
_RDS_ROW = "aws.rds.instance.storage_encrypted"


def _tf(body: str) -> str:
    return f'resource "aws_db_instance" "db" {{\n{body}}}\n'


def _yaml(properties: str) -> str:
    return (
        "Resources:\n"
        "  DB:\n"
        "    Type: AWS::RDS::DBInstance\n"
        f"{properties}"
    )


@pytest.mark.parametrize(
    ("body", "properties", "verdict", "default_row"),
    [
        (
            "  storage_encrypted = true\n",
            "    Properties:\n      StorageEncrypted: true\n",
            _DECLARED,
            None,
        ),
        (
            "  storage_encrypted = false\n",
            "    Properties:\n      StorageEncrypted: false\n",
            _PLAIN,
            None,
        ),
        ("", "", _PLAIN, _RDS_ROW),
    ],
)
def test_rds_twin_matches_terraform(
    body: str, properties: str, verdict: str, default_row: str | None
) -> None:
    terraform = extract_terraform(_tf(body), "main.tf")
    cloud = extract_cloudformation(_yaml(properties), "stack.yaml")
    assert len(terraform) == len(cloud) == 1
    assert terraform[0].verdict == cloud[0].verdict == verdict
    assert terraform[0].default_row == cloud[0].default_row == default_row
    assert terraform[0].unknown_reason == cloud[0].unknown_reason
    assert cloud[0].format == "cloudformation"
    assert cloud[0].native_type == "AWS::RDS::DBInstance"
    assert cloud[0].address == "DB"
    assert cloud[0].layers["service"] == verdict


def test_json_false_matches_the_terraform_twin() -> None:
    raw = (
        '{"Resources":{"DB":{"Type":"AWS::RDS::DBInstance",'
        '"Properties":{"StorageEncrypted":false}}}}'
    )
    cloud = extract_cloudformation(raw, "stack.json")
    terraform = extract_terraform(_tf("  storage_encrypted = false\n"), "main.tf")
    assert cloud[0].verdict == terraform[0].verdict == _PLAIN
    assert cloud[0].default_row is None
    assert cloud[0].line >= 1


def test_json_ref_is_not_treated_as_unencrypted() -> None:
    raw = (
        '{"Resources":{"DB":{"Type":"AWS::RDS::DBInstance",'
        '"Properties":{"StorageEncrypted":{"Ref":"Enc"}}}}}'
    )
    fact = extract_cloudformation(raw, "stack.json")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "unresolved_expression"


def test_s3_absence_matches_the_provider_default() -> None:
    terraform = extract_terraform('resource "aws_s3_bucket" "b" {}\n', "main.tf")
    cloud = extract_cloudformation(
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n",
        "stack.yaml",
    )
    assert terraform[0].verdict == cloud[0].verdict == _DEFAULT
    assert terraform[0].default_row == cloud[0].default_row == "aws.s3.sse_default"


def test_serverless_cluster_twin_is_provider_encrypted() -> None:
    terraform = extract_terraform(
        'resource "aws_rds_cluster" "c" {\n  engine_mode = "serverless"\n}\n',
        "main.tf",
    )
    cloud = extract_cloudformation(
        "Resources:\n"
        "  C:\n"
        "    Type: AWS::RDS::DBCluster\n"
        "    Properties:\n"
        "      EngineMode: serverless\n",
        "stack.yaml",
    )
    row = "aws.rds.cluster.storage_encrypted.serverless"
    assert terraform[0].verdict == cloud[0].verdict == _DEFAULT
    assert terraform[0].default_row == cloud[0].default_row == row


def test_replica_twin_does_not_fail_closed() -> None:
    terraform = extract_terraform(
        'resource "aws_db_instance" "db" {\n  replicate_source_db = "src"\n}\n',
        "main.tf",
    )
    cloud = extract_cloudformation(
        "Resources:\n"
        "  DB:\n"
        "    Type: AWS::RDS::DBInstance\n"
        "    Properties:\n"
        "      SourceDBInstanceIdentifier: src\n",
        "stack.yaml",
    )
    assert terraform[0].verdict == cloud[0].verdict == "UNKNOWN"
    assert terraform[0].unknown_reason == cloud[0].unknown_reason == "default_unknown"


def test_cloudformation_key_rotation_matches_the_reviewed_row() -> None:
    omitted = extract_cloudformation(
        "Resources:\n  Key:\n    Type: AWS::KMS::Key\n",
        "stack.yaml",
    )[0]
    assert omitted.verdict == "UNKNOWN"
    assert ("rotation_default_row", "aws.kms.enable_key_rotation") in [
        (item.name, item.value) for item in omitted.basis
    ]
    enabled = extract_cloudformation(
        "Resources:\n"
        "  Key:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      EnableKeyRotation: true\n",
        "stack.yaml",
    )[0]
    assert ("rotation", "enabled") in [
        (item.name, item.value) for item in enabled.basis
    ]
    disabled = extract_cloudformation(
        "Resources:\n"
        "  Key:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      EnableKeyRotation: false\n",
        "stack.yaml",
    )[0]
    assert ("signal", "KMS_KEY_ROTATION_DISABLED") in [
        (item.name, item.value) for item in disabled.basis
    ]


def test_unresolved_cloudformation_rotation_raises_nothing() -> None:
    fact = extract_cloudformation(
        "Resources:\n"
        "  Key:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      EnableKeyRotation: !Ref Flag\n",
        "stack.yaml",
    )[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "unresolved_expression"
    assert ("signal", "KMS_KEY_ROTATION_DISABLED") not in [
        (item.name, item.value) for item in fact.basis
    ]


def test_cloudformation_rsa_key_spec_is_an_algorithm(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "stack.yaml").write_text(
        "Resources:\n"
        "  Key:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      KeySpec: RSA_2048\n"
        "      EnableKeyRotation: true\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    names = {comp.name for comp in result.components}
    assert "RSA-2048" in names
    assert "key (Key)" in names
    codes = {flag.code for flag in result.flags}
    assert "QUANTUM_VULNERABLE" in codes
    assert "KMS_KEY_ROTATION_DISABLED" not in codes


def test_cloudformation_key_rotation_is_a_scan_flag(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "stack.yaml").write_text(
        "Resources:\n  Key:\n    Type: AWS::KMS::Key\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "KMS_KEY_ROTATION_DISABLED" in {flag.code for flag in result.flags}


def test_cloudformation_json_key_rotation_is_a_scan_flag(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "stack.json").write_text(
        '{"Resources":{"Key":{"Type":"AWS::KMS::Key"}}}',
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "KMS_KEY_ROTATION_DISABLED" in {flag.code for flag in result.flags}


def test_cloudformation_ref_policy_is_not_the_2016_default(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "stack.yaml").write_text(
        "Resources:\n"
        "  Https:\n"
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n"
        "    Properties:\n"
        "      Protocol: HTTPS\n"
        "      SslPolicy: !Ref PolicyName\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" not in {flag.code for flag in result.flags}
    listener = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factAddress") == "Https"
    )
    basis = str((listener.properties or {}).get("crypto:factBasis"))
    assert "unresolved_expression" in basis


def test_cloudformation_https_listener_without_a_policy_is_weak(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "stack.yaml").write_text(
        "Resources:\n"
        "  Https:\n"
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n"
        "    Properties:\n"
        "      Protocol: HTTPS\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_cloudformation_viewer_and_listener_policies(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "stack.yaml").write_text(
        "Resources:\n"
        "  Web:\n"
        "    Type: AWS::CloudFront::Distribution\n"
        "    Properties:\n"
        "      DistributionConfig:\n"
        "        ViewerCertificate:\n"
        "          MinimumProtocolVersion: TLSv1\n"
        "  Https:\n"
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n"
        "    Properties:\n"
        "      Protocol: HTTPS\n"
        "      SslPolicy: ELBSecurityPolicy-TLS13-1-3-2021-06\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    versions = {
        (comp.properties or {}).get("crypto:protocolVersion")
        for comp in result.components
        if comp.name == "TLS"
    }
    assert versions == {"TLSv1.0", "TLSv1.3"}
    codes = {flag.code for flag in result.flags}
    assert "WEAK_PROTOCOL" in codes
    assert "WEAK_CIPHER_SUITE" in codes


def test_unknown_type_and_bad_template_emit_nothing() -> None:
    text = "Resources:\n  Role:\n    Type: AWS::IAM::Role\n"
    assert extract_cloudformation(text, "stack.yaml") == ()
    assert extract_cloudformation("not: [", "stack.yaml") == ()
