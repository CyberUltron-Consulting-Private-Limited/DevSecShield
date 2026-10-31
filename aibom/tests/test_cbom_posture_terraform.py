"""Terraform posture extraction. Inline sources, no fixture trees."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.defaults import load_registry
from aibom.cbom.posture.extract_terraform import assess_sources, extract_terraform
from aibom.cbom.posture.resolve import Absent

_DECLARED = "ENCRYPTED_DECLARED"
_PLAIN = "NOT_ENCRYPTED"
_DEFAULT = "ENCRYPTED_PROVIDER_DEFAULT"
_RDS_ROW = "aws.rds.instance.storage_encrypted"
_S3_ROW = "aws.s3.sse_default"


def _db(body: str) -> str:
    return f'resource "aws_db_instance" "db" {{\n{body}}}\n'


@pytest.mark.parametrize(
    ("body", "verdict", "default_row"),
    [
        ("  storage_encrypted = true\n", _DECLARED, None),
        ("  storage_encrypted = false\n", _PLAIN, None),
        ("", _PLAIN, _RDS_ROW),
    ],
)
def test_storage_encrypted_literal_and_default(
    body: str, verdict: str, default_row: str | None
) -> None:
    fact = extract_terraform(_db(body), "main.tf")[0]
    assert fact.verdict == verdict
    assert fact.default_row == default_row
    assert fact.unknown_reason is None
    assert fact.layers["service"] == verdict
    assert fact.native_type == "aws_db_instance"
    assert fact.format == "terraform"


def test_s3_absence_is_the_encrypted_provider_default() -> None:
    text = 'resource "aws_s3_bucket" "b" {}\n'
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == _DEFAULT
    assert fact.default_row == _S3_ROW
    assert fact.unknown_reason is None


def test_s3_literal_false_is_not_the_provider_default() -> None:
    text = (
        'resource "aws_s3_bucket" "b" {\n'
        "  server_side_encryption_configuration = false\n"
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == _PLAIN
    assert fact.default_row is None


def test_unassessable_not_encrypted_default_is_unknown() -> None:
    row = load_registry().by_id["aws.elasticache.at_rest.redis"]
    assert row.effect == "NOT_ENCRYPTED"
    assert row.assessable_as_unencrypted is False
    got = assess_sources((Absent(),), row)
    assert got.verdict == "UNKNOWN"
    assert got.reason == "default_unknown"


def test_ebs_without_a_default_row_is_unknown() -> None:
    text = 'resource "aws_ebs_volume" "v" {}\n'
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "default_unknown"
    assert fact.default_row is None


def test_count_zero_emits_no_fact() -> None:
    text = (
        'resource "aws_db_instance" "off" {\n'
        "  count = 0\n"
        "  storage_encrypted = false\n"
        "}\n"
        'resource "aws_db_instance" "on" {\n'
        "  storage_encrypted = true\n"
        "}\n"
    )
    facts = extract_terraform(text, "main.tf")
    assert [fact.address for fact in facts] == ["aws_db_instance.on"]
    assert facts[0].verdict == _DECLARED


def test_variable_reference_is_not_treated_as_unencrypted() -> None:
    text = (
        'variable "encrypt" {\n'
        "  default = false\n"
        "}\n"
        'resource "aws_db_instance" "db" {\n'
        "  storage_encrypted = var.encrypt\n"
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "variable_no_default"
    assert fact.default_row is None


def test_local_reference_stays_an_unresolved_expression() -> None:
    text = _db("  storage_encrypted = local.encrypt\n")
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "unresolved_expression"


def test_replica_does_not_take_the_unencrypted_default() -> None:
    text = _db('  replicate_source_db = "src"\n')
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "default_unknown"


def test_serverless_cluster_uses_the_encrypted_sibling_row() -> None:
    text = (
        'resource "aws_rds_cluster" "c" {\n'
        '  engine_mode = "serverless"\n'
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    assert fact.verdict == _DEFAULT
    row = "aws.rds.cluster.storage_encrypted.serverless"
    assert fact.default_row == row


def test_type_outside_the_table_is_skipped() -> None:
    assert extract_terraform('resource "aws_iam_role" "r" {}\n', "main.tf") == ()


def test_parse_error_emits_nothing() -> None:
    assert extract_terraform("resource {", "main.tf") == ()


def test_fact_id_matches_the_codec() -> None:
    fact = extract_terraform(_db("  storage_encrypted = true\n"), "main.tf")[0]
    assert fact.id == make_fact_id(
        "relational_db",
        "aws",
        "aws_db_instance",
        "aws_db_instance.db",
        "main.tf",
    )
    assert fact.line >= 1


def _kms(policy: str) -> str:
    escaped = policy.replace("\\", "\\\\").replace('"', '\\"')
    return (
        'resource "aws_kms_key" "open" {\n'
        f'  policy = "{escaped}"\n'
        "}\n"
    )


def test_public_key_policy_sets_the_signal_and_restricted_does_not() -> None:
    public = '{"Statement":[{"Effect":"Allow","Principal":"*"}]}'
    fact = extract_terraform(_kms(public), "main.tf")[0]
    assert ("signal", "KMS_KEY_POLICY_PUBLIC") in [
        (item.name, item.value) for item in fact.basis
    ]
    restricted = (
        '{"Statement":[{"Effect":"Allow","Principal":"*",'
        '"Condition":{"StringEquals":{"aws:SourceVpc":"vpc-1"}}}]}'
    )
    quiet = extract_terraform(_kms(restricted), "main.tf")[0]
    assert ("signal", "KMS_KEY_POLICY_PUBLIC") not in [
        (item.name, item.value) for item in quiet.basis
    ]


def test_public_gcp_binding_keeps_the_signal_when_conditioned(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto
    text = (
        'resource "google_kms_crypto_key_iam_binding" "open" {\n'
        '  members = ["allUsers"]\n'
        "  condition {\n"
        '    title = "temp"\n'
        "  }\n"
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    pairs = [(item.name, item.value) for item in fact.basis]
    assert ("signal", "KMS_KEY_POLICY_PUBLIC") in pairs
    assert ("exposure_conditional", "true") in pairs
    private = (
        'resource "google_kms_crypto_key_iam_member" "named" {\n'
        '  member = "user:alice@example.com"\n'
        "}\n"
    )
    quiet = extract_terraform(private, "main.tf")[0]
    assert ("signal", "KMS_KEY_POLICY_PUBLIC") not in [
        (item.name, item.value) for item in quiet.basis
    ]
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    scanned = scan_crypto(tmp_path)
    messages = [
        flag.message
        for flag in scanned.flags
        if flag.code == "KMS_KEY_POLICY_PUBLIC"
    ]
    assert messages
    assert "conditional binding: review the condition" in messages[0]
    unresolved = (
        'resource "google_kms_crypto_key_iam_binding" "later" {\n'
        "  members = var.members\n"
        "}\n"
    )
    unknown = extract_terraform(unresolved, "main.tf")[0]
    assert unknown.verdict == "UNKNOWN"
    assert ("signal", "KMS_KEY_POLICY_PUBLIC") not in [
        (item.name, item.value) for item in unknown.basis
    ]


def test_public_key_policy_is_a_scan_flag(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    public = '{"Statement":[{"Effect":"Allow","Principal":"*"}]}'
    (tmp_path / "main.tf").write_text(_kms(public), encoding="utf-8")
    result = scan_crypto(tmp_path)
    assert "KMS_KEY_POLICY_PUBLIC" in {flag.code for flag in result.flags}


def test_rsa_key_spec_is_an_algorithm_and_rotation_does_not_apply(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    text = (
        'resource "aws_kms_key" "rsa" {\n'
        '  customer_master_key_spec = "RSA_2048"\n'
        "}\n"
    )
    fact = extract_terraform(text, "main.tf")[0]
    assert ("key_spec", "RSA_2048") in [
        (item.name, item.value) for item in fact.basis
    ]
    assert ("rotation", "not_applicable") in [
        (item.name, item.value) for item in fact.basis
    ]
    assert ("signal", "KMS_KEY_ROTATION_DISABLED") not in [
        (item.name, item.value) for item in fact.basis
    ]
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    result = scan_crypto(tmp_path)
    asset = next(comp for comp in result.components if comp.name == "RSA-2048")
    props = asset.properties or {}
    assert props["crypto:assetType"] == "algorithm"
    assert props["crypto:keySize"] == "2048"
    assert props["crypto:primitive"] == "pke"
    assert props["crypto:nistQuantumSecurityLevel"] == "0"
    assert props["crypto:securityStrengthBits"] == "112"
    material = next(
        comp for comp in result.components if comp.name == "key (aws_kms_key.rsa)"
    )
    body = material.properties or {}
    assert body["crypto:assetType"] == "related-crypto-material"
    assert body["crypto:materialKind"] == "key"
    assert body["crypto:rotation"] == "not_applicable"
    assert body["crypto:factId"] == fact.id
    codes = {flag.code for flag in result.flags}
    assert "QUANTUM_VULNERABLE" in codes
    assert "WEAK_KEY_SIZE" not in codes
    assert "KMS_KEY_ROTATION_DISABLED" not in codes
    from aibom.emit.cyclonedx import emit_and_validate

    bom = emit_and_validate(result)
    material_bom = next(
        comp for comp in bom["components"] if comp["name"] == "key (aws_kms_key.rsa)"
    )
    algorithm_bom = next(
        comp for comp in bom["components"] if comp["name"] == "RSA-2048"
    )
    linked = material_bom["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert linked["algorithmRef"] == algorithm_bom["bom-ref"]
    from aibom.cbom.normalize import normalize_crypto

    graph = normalize_crypto(result, duration_of_scan=0.0)["cbom_graph"]
    assert {
        "source": material_bom["bom-ref"],
        "rel": "algorithm",
        "target": algorithm_bom["bom-ref"],
    } in graph["edges"]


def test_symmetric_default_key_is_aes_256(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    text = (
        'resource "aws_kms_key" "sym" {\n'
        '  customer_master_key_spec = "SYMMETRIC_DEFAULT"\n'
        "  enable_key_rotation = true\n"
        "}\n"
    )
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    result = scan_crypto(tmp_path)
    asset = next(comp for comp in result.components if comp.name == "AES-256")
    props = asset.properties or {}
    assert props["crypto:keySize"] == "256"
    assert props["crypto:primitive"] == "block-cipher"
    assert props["crypto:quantumVulnerable"] == "false"
    assert props["crypto:nistQuantumSecurityLevel"] == "5"
    assert props["crypto:securityStrengthBits"] == "256"
    material = next(
        comp for comp in result.components if comp.name == "key (aws_kms_key.sym)"
    )
    assert (material.properties or {})["crypto:rotation"] == "enabled"
    assert result.flags == []


def test_azure_and_google_key_specs_become_algorithms(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    text = (
        'resource "azurerm_key_vault_key" "rsa" {\n'
        '  key_type = "RSA"\n'
        "  key_size = 2048\n"
        "}\n"
        'resource "azurerm_key_vault_key" "ec" {\n'
        '  key_type = "EC"\n'
        "  key_size = 256\n"
        "}\n"
        'resource "google_kms_crypto_key" "sym" {\n'
        "  version_template {\n"
        '    algorithm = "GOOGLE_SYMMETRIC_ENCRYPTION"\n'
        "  }\n"
        "}\n"
    )
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    result = scan_crypto(tmp_path)
    by_name = {comp.name: comp.properties or {} for comp in result.components}
    assert by_name["RSA-2048"]["crypto:keySize"] == "2048"
    assert by_name["ECDSA"]["crypto:curve"] == "P-256"
    assert "crypto:keySize" not in by_name["ECDSA"]
    assert by_name["AES-256"]["crypto:nistQuantumSecurityLevel"] == "5"
    codes = {flag.code for flag in result.flags}
    assert "WEAK_KEY_SIZE" not in codes
    assert "KMS_KEY_ROTATION_DISABLED" not in codes
    assert "QUANTUM_VULNERABLE" in codes


def test_azure_rsa_4096_is_not_labeled_2048(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "main.tf").write_text(
        'resource "azurerm_key_vault_key" "wide" {\n'
        '  key_type = "RSA"\n'
        "  key_size = 4096\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "RSA-2048" not in {comp.name for comp in result.components}


def test_omitted_google_rotation_and_azure_key_rotation(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    text = (
        'resource "google_kms_crypto_key" "open" {\n'
        '  name = "open"\n'
        "}\n"
        'resource "azurerm_key_vault_key" "vault" {\n'
        '  name = "vault"\n'
        "}\n"
    )
    facts = {fact.native_type: fact for fact in extract_terraform(text, "main.tf")}
    google = facts["google_kms_crypto_key"]
    assert google.verdict == "UNKNOWN"
    assert google.unknown_reason == "default_unknown"
    azure = facts["azurerm_key_vault_key"]
    assert ("rotation", "not_applicable") in [
        (item.name, item.value) for item in azure.basis
    ]
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    codes = {flag.code for flag in scan_crypto(tmp_path).flags}
    assert "KMS_KEY_ROTATION_DISABLED" not in codes


def test_aws_key_rotation_follows_the_reviewed_row(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def one(body: str) -> str:
        return f'resource "aws_kms_key" "key" {{\n{body}}}\n'

    omitted = extract_terraform(one(""), "main.tf")[0]
    assert omitted.verdict == "UNKNOWN"
    assert omitted.unknown_reason == "default_unknown"
    assert ("rotation_default_row", "aws.kms.enable_key_rotation") in [
        (item.name, item.value) for item in omitted.basis
    ]
    enabled = extract_terraform(one("  enable_key_rotation = true\n"), "main.tf")[0]
    assert ("rotation", "enabled") in [
        (item.name, item.value) for item in enabled.basis
    ]
    assert ("signal", "KMS_KEY_ROTATION_DISABLED") not in [
        (item.name, item.value) for item in enabled.basis
    ]
    pending = extract_terraform(
        one("  enable_key_rotation = var.rotate\n"), "main.tf"
    )[0]
    assert pending.verdict == "UNKNOWN"
    assert ("signal", "KMS_KEY_ROTATION_DISABLED") not in [
        (item.name, item.value) for item in pending.basis
    ]
    (tmp_path / "main.tf").write_text(
        one("  enable_key_rotation = false\n"), encoding="utf-8"
    )
    assert "KMS_KEY_ROTATION_DISABLED" in {
        flag.code for flag in scan_crypto(tmp_path).flags
    }


def test_omitted_azure_purge_protection_raises_the_reviewed_finding(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    text = (
        'resource "azurerm_key_vault" "vault" {\n'
        '  name = "vault"\n'
        "}\n"
        'resource "azurerm_key_vault_managed_hardware_security_module" "hsm" {\n'
        '  name = "hsm"\n'
        "}\n"
    )
    facts = {fact.address: fact for fact in extract_terraform(text, "main.tf")}
    vault = facts["azurerm_key_vault.vault"]
    assert vault.unknown_reason == "default_unknown"
    assert ("purge_protection_default_row", "azure.keyvault.purge_protection") in [
        (item.name, item.value) for item in vault.basis
    ]
    hsm = facts["azurerm_key_vault_managed_hardware_security_module.hsm"]
    assert ("purge_protection_default_row", "azure.keyvault_hsm.purge_protection") in [
        (item.name, item.value) for item in hsm.basis
    ]
    enabled = extract_terraform(
        'resource "azurerm_key_vault" "vault" {\n'
        "  purge_protection_enabled = true\n"
        "}\n",
        "main.tf",
    )[0]
    assert ("purge_protection", "enabled") in [
        (item.name, item.value) for item in enabled.basis
    ]
    (tmp_path / "main.tf").write_text(
        'resource "azurerm_key_vault" "vault" {\n'
        "  purge_protection_enabled = false\n"
        "}\n",
        encoding="utf-8",
    )
    assert "KMS_KEY_DELETION_UNPROTECTED" in {
        flag.code for flag in scan_crypto(tmp_path).flags
    }


def test_tls_listener_and_a_variable_policy_are_not_the_2016_default(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "main.tf").write_text(
        'resource "aws_lb_listener" "nlb" {\n'
        '  protocol = "TLS"\n'
        "}\n"
        'resource "aws_lb_listener" "https" {\n'
        '  protocol   = "HTTPS"\n'
        "  ssl_policy = var.policy\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" not in {flag.code for flag in result.flags}
    https = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factAddress") == "aws_lb_listener.https"
    )
    basis = str((https.properties or {}).get("crypto:factBasis"))
    assert "unresolved_expression" in basis


def test_https_listener_without_a_policy_uses_the_2016_default(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "main.tf").write_text(
        'resource "aws_lb_listener" "https" {\n'
        '  protocol = "HTTPS"\n'
        "}\n"
        'resource "aws_lb_listener" "http" {\n'
        '  protocol = "HTTP"\n'
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    versions = [
        (comp.properties or {}).get("crypto:protocolVersion")
        for comp in result.components
        if comp.name == "TLS"
    ]
    assert versions == ["TLSv1.0"]
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_azure_web_app_minimum_tls_version(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "main.tf").write_text(
        'resource "azurerm_linux_web_app" "old" {\n'
        "  https_only = true\n"
        "  site_config {\n"
        '    minimum_tls_version = "1.0"\n'
        "  }\n"
        "}\n"
        'resource "azurerm_windows_web_app" "current" {\n'
        "  https_only = true\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    versions = {
        (comp.properties or {}).get("crypto:protocolVersion")
        for comp in result.components
        if comp.name == "TLS"
    }
    assert versions == {"TLSv1.0", "TLSv1.2"}
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_gcp_ssl_policy_profile_raises_the_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "main.tf").write_text(
        'resource "google_compute_ssl_policy" "old" {\n'
        '  profile         = "COMPATIBLE"\n'
        '  min_tls_version = "TLS_1_0"\n'
        "}\n"
        'resource "google_compute_ssl_policy" "locked" {\n'
        '  profile         = "RESTRICTED"\n'
        '  min_tls_version = "TLS_1_0"\n'
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    versions = {
        (comp.properties or {}).get("crypto:protocolVersion")
        for comp in result.components
        if comp.name == "TLS"
    }
    assert versions == {"TLSv1.0", "TLSv1.2"}
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_cloudfront_tlsv1_is_a_weak_protocol_and_suite(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "main.tf").write_text(
        'resource "aws_cloudfront_distribution" "web" {\n'
        "  viewer_certificate {\n"
        '    minimum_protocol_version = "TLSv1"\n'
        "  }\n"
        "}\n"
        'resource "aws_lb_listener" "https" {\n'
        '  ssl_policy = "ELBSecurityPolicy-TLS13-1-3-2021-06"\n'
        '  protocol   = "HTTPS"\n'
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assets = {
        (comp.properties or {}).get("crypto:factId"): comp
        for comp in result.components
        if comp.name == "TLS"
    }
    assert len(assets) == 2
    versions = {
        (comp.properties or {}).get("crypto:protocolVersion")
        for comp in assets.values()
    }
    assert versions == {"TLSv1.0", "TLSv1.3"}
    codes = {flag.code for flag in result.flags}
    assert "WEAK_PROTOCOL" in codes
    assert "WEAK_CIPHER_SUITE" in codes
