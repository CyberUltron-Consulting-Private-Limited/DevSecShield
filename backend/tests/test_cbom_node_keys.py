"""WP6: classification of keys, key stores, database encryption and CAs; the source kinds (SQL Server, Oracle, HSM and
KMIP key managers, Vault / EJBCA / AD CS certificate authorities); grant and policy templates; the knowledge-base
entries and exploit demos of the new codes; and the API path from a saved source to a node job."""
from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import crypto_kb, exploit_demo, kinds, templates  # noqa: E402
from backend.utilities.cbom_sources.classify import CDX_TYPE, classify  # noqa: E402
from test_cbom_sources_api import api, enroll_node, world  # noqa: E402,F401  (the API test fixtures)

WP6_CODES = ["KEY_WEAK_SYMMETRIC", "KEY_PLAINTEXT_EXPORT", "KEY_EXTRACTABLE", "KEY_COMPROMISED", "KEY_NO_ROTATION",
             "DB_TDE_OFF", "DB_LEGACY_PW_HASH", "DB_10G_VERIFIER", "DB_LOGIN_NO_POLICY", "DB_LEGACY_NNE",
             "DB_EOL_VERSION", "CA_WEAK_SIGNING", "CA_ALLOWS_WEAK_KEY", "CA_ALLOWS_ANY_NAME", "CA_LONG_VALIDITY"]


def _codes(asset_type, facts, algorithm=None, key_size=None):
    return set(classify(asset_type, algorithm, key_size, None, facts)["finding_codes"])


# ----------------------------------------------------------------------------- managed keys
@pytest.mark.parametrize("store, algorithm, size, facts, expected", [
    ("pkcs11", "DES3", 168, {"key_class": "secret", "sensitive": True, "extractable": False}, {"KEY_WEAK_SYMMETRIC"}),
    ("pkcs11", "AES", 128, {"key_class": "secret", "sensitive": True, "extractable": True}, {"KEY_EXTRACTABLE"}),
    ("pkcs11", "AES", 256, {"key_class": "secret", "sensitive": False, "extractable": True}, {"KEY_PLAINTEXT_EXPORT"}),
    ("pkcs11", "RSA", 1024, {"key_class": "private", "sensitive": True, "extractable": False},
     {"RSA_LT_2048", "QUANTUM_VULNERABLE"}),
    ("pkcs11", "EC", 256, {"key_class": "private", "sensitive": True, "extractable": False, "curve": "P-256"},
     {"QUANTUM_VULNERABLE"}),
    ("pkcs11", "EC", 192, {"key_class": "public", "curve": "P-192"}, {"EC_LT_224", "QUANTUM_VULNERABLE"}),
    # KMIP hands keys to its clients: Sensitive false / Extractable true are normal there
    ("kmip", "AES", 256, {"key_class": "secret", "sensitive": False, "extractable": True, "state": "Active"}, set()),
    ("kmip", "AES", 256, {"key_class": "secret", "state": "Compromised"}, {"KEY_COMPROMISED"}),
    ("kmip", "3DES", 168, {"key_class": "secret", "state": "Active"}, {"KEY_WEAK_SYMMETRIC"}),
    ("kmip", "RC4", 128, {"key_class": "secret"}, {"KEY_WEAK_SYMMETRIC"}),
    ("vault_transit", "AES", 256, {"key_class": "secret", "auto_rotate_period_s": 0}, {"KEY_NO_ROTATION"}),
    ("vault_transit", "RSA", 2048, {"key_class": "private", "exportable": True, "auto_rotate_period_s": 2592000},
     {"KEY_PLAINTEXT_EXPORT", "QUANTUM_VULNERABLE"}),
    ("vault_transit", "ChaCha20", 256, {"key_class": "secret", "allow_plaintext_backup": True,
                                         "auto_rotate_period_s": 86400}, {"KEY_PLAINTEXT_EXPORT"}),
    ("mssql", "3DES", 128, {"key_class": "secret", "algorithm_desc": "TRIPLE_DES", "role": "database master key"},
     {"KEY_WEAK_SYMMETRIC"}),
    ("mssql", "RSA", 1024, {"key_class": "private", "algorithm_desc": "RSA_1024"}, {"RSA_LT_2048", "QUANTUM_VULNERABLE"}),
    ("mssql", "RSA", None, {"key_class": "private", "role": "Always Encrypted column master key"}, {"QUANTUM_VULNERABLE"}),
])
def test_managed_key_rules(store, algorithm, size, facts, expected):
    assert _codes("managed_key", {"store": store, **facts}, algorithm, size) == expected


def test_quantum_verdicts_and_cyclonedx_types():
    assert classify("managed_key", "AES", 256, None, {"store": "kmip", "key_class": "secret"})["quantum_vulnerable"] is False
    assert classify("managed_key", "RSA", 3072, None, {"store": "kmip", "key_class": "private"})["quantum_vulnerable"] is True
    assert classify("key_store", None, None, None, {"store": "pkcs11"})["finding_codes"] == []
    assert CDX_TYPE["managed_key"] == "related-crypto-material" and CDX_TYPE["db_crypto_policy"] == "protocol"


# ----------------------------------------------------------------------------- databases
def test_database_encryption_logins_and_transport():
    assert _codes("db_encryption", {"engine": "mssql", "scope": "database", "database": "hr", "encrypted": False}) == {"DB_TDE_OFF"}
    assert _codes("db_encryption", {"engine": "oracle", "scope": "tablespace", "encrypted": True,
                                    "algorithm_desc": "3DES168"}, "3DES168") == {"KEY_WEAK_SYMMETRIC"}
    assert _codes("db_encryption", {"engine": "mssql", "encrypted": True}, "AES", 256) == set()
    oracle_users = {"engine": "oracle", "users": [{"name": "APP", "password_versions": "10G 11G 12C"},
                                                  {"name": "BATCH", "password_versions": "11G 12C"},
                                                  {"name": "NEW", "password_versions": "12C"}]}
    out = classify("db_login_policy", None, None, None, oracle_users)
    assert set(out["finding_codes"]) == {"DB_10G_VERIFIER", "DB_LEGACY_PW_HASH"} and out["impact"] == "High"
    assert "APP" in out["texts"]["DB_10G_VERIFIER"] and "APP" not in out["texts"]["DB_LEGACY_PW_HASH"]
    assert "NEW" not in out["finding"]
    mssql = {"engine": "mssql", "logins": [{"name": "sa", "hash_version": 2, "policy_checked": True},
                                           {"name": "legacy", "hash_version": 1, "policy_checked": False},
                                           {"name": "off", "hash_version": None, "policy_checked": False, "disabled": True}]}
    out = classify("db_login_policy", None, None, None, mssql)
    assert set(out["finding_codes"]) == {"DB_LEGACY_PW_HASH", "DB_LOGIN_NO_POLICY"}
    assert "off" not in out["texts"]["DB_LOGIN_NO_POLICY"]
    assert _codes("db_crypto_policy", {"engine": "mssql", "tls": True, "force_encryption": False}) == {"DB_TLS_OPTIONAL"}
    assert _codes("db_crypto_policy", {"engine": "mssql", "tls": True, "force_encryption": True}) == set()
    assert _codes("db_crypto_policy", {"engine": "oracle", "native_encryption_required": True}) == {"DB_LEGACY_NNE"}
    assert _codes("db_crypto_policy", {"engine": "oracle", "version_unsupported": True}) == {"DB_EOL_VERSION"}
    assert _codes("db_crypto_policy", {"engine": "oracle", "sessions_nne_algorithms": ["AES256", "3DES168"]}) == {"WEAK_CIPHER"}


# ----------------------------------------------------------------------------- certificate authorities
def test_ca_rules():
    assert _codes("ca_authority", {"provider": "adcs", "hash_algorithm": "SHA1", "key_type": "RSA"}, "RSA", 4096) == \
        {"CA_WEAK_SIGNING", "QUANTUM_VULNERABLE"}
    assert _codes("ca_authority", {"provider": "adcs", "hash_algorithm": "SHA256", "san_from_request_attributes": True},
                  "RSA", 2048) == {"CA_ALLOWS_ANY_NAME", "QUANTUM_VULNERABLE"}
    assert classify("ca_authority", None, None, None, {"hash_algorithm": "MD5"})["impact"] == "Critical"
    role = {"provider": "vault", "name": "pki/any", "key_type": "RSA", "key_bits": 2048, "allow_any_name": True,
            "max_ttl_s": 2 * 365 * 86400}
    assert _codes("ca_template", role, "RSA", 2048) == {"CA_ALLOWS_ANY_NAME", "CA_LONG_VALIDITY", "QUANTUM_VULNERABLE"}
    esc1 = {"provider": "adcs", "name": "VulnUser", "key_type": "RSA", "key_bits": 1024, "enrollee_supplies_subject": True,
            "client_auth": True, "server_auth": False, "max_ttl_s": 10 * 365 * 86400}
    out = classify("ca_template", "RSA", 1024, None, esc1)
    assert set(out["finding_codes"]) == {"CA_ALLOWS_WEAK_KEY", "CA_ALLOWS_ANY_NAME", "QUANTUM_VULNERABLE"}
    assert out["impacts"]["CA_ALLOWS_ANY_NAME"] == "High"  # client authentication: AD CS ESC1
    assert _codes("ca_template", {"name": "EC", "key_type": "EC", "key_bits": 192}) >= {"CA_ALLOWS_WEAK_KEY"}
    assert _codes("ca_template", {"name": "any", "key_type": "ANY"}) == set()


# ----------------------------------------------------------------------------- knowledge base and demos
@pytest.fixture(scope="module")
def kb(tmp_path_factory):
    out = tmp_path_factory.mktemp("kb") / "kb.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/crypto_kb/build_kb.py"), "2099.01.01.1", str(out)], check=True,
                   capture_output=True, cwd=ROOT, timeout=300)
    return json.loads(out.read_text())


def test_every_wp6_code_has_a_kb_entry_and_a_demo(kb, monkeypatch):
    node = kb["findings"]["node"]
    for code in WP6_CODES:
        assert code in node, code
        assert node[code]["remediation"]["summary"] and node[code]["verify"], code
    monkeypatch.setattr(crypto_kb, "load", lambda: kb)
    for code in WP6_CODES:
        entries = crypto_kb.render("node", [code], context={}, evidence="", title=code)
        demo = exploit_demo.build({"title": code, "finding_codes": [code], "algorithm": "3DES"}, entries)
        assert demo is not None and demo["description"], code


def test_every_code_the_rules_can_emit_is_in_the_kb(kb):
    text = (ROOT / "backend/utilities/cbom_sources/classify_ext/node_keys.py").read_text()
    emitted = set(re.findall(r'out\.add\("([A-Z0-9_]+)"', text))
    assert emitted - set(kb["findings"]["node"]) == set()


# ----------------------------------------------------------------------------- source kinds
def test_database_engines_and_sql_server_password_rule():
    assert {"mssql", "oracle"} <= kinds.COLLECTABLE_DB_ENGINES
    spec = kinds.KINDS["database"]
    cfg = spec.model.model_validate({"engine": "mssql", "host": "sql01.corp", "login": "svc_zscbom"})
    assert cfg.port == 1433 and spec.collectable(cfg)
    assert "SQL Server" in kinds.credential_target_problem("database", cfg, {"password": "x"})
    cert = _ca_cert()
    cfg = spec.model.model_validate({"engine": "mssql", "host": "sql01.corp", "login": "svc_zscbom", "ca_pem": cert})
    assert kinds.credential_target_problem("database", cfg, {"password": "x"}) is None
    with pytest.raises(ValueError, match="service name"):
        spec.model.model_validate({"engine": "oracle", "host": "ora.corp", "login": "zs_cbom"})
    ora = spec.model.model_validate({"engine": "oracle", "host": "ora.corp", "login": "zs_cbom", "database_name": "ORCLPDB1"})
    assert ora.port == 1521 and kinds.credential_target_problem("database", ora, {"password": "x"}) is None


def _ca_cert() -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ca")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_key_manager_kind():
    spec = kinds.KINDS["key_manager"]
    assert spec.group == "databases"
    hsm = spec.model.model_validate({"provider": "pkcs11", "module": "luna", "token_label": " partition1 ",
                                     "host": "ignored", "ca_pem": None})
    assert hsm.token_label == "partition1" and hsm.host is None and spec.secret_fields(hsm) == set()
    assert "pin" in spec.optional_secrets
    for bad in ("/usr/lib/libCryptoki2.so", "../x", ""):
        with pytest.raises(ValueError, match="module"):
            spec.model.model_validate({"provider": "pkcs11", "module": bad})
    kmip = spec.model.model_validate({"provider": "kmip", "host": "kms.corp", "module": "x"})
    assert kmip.port == 5696 and kmip.module is None and spec.secret_fields(kmip) == {"client_cert", "client_key"}
    with pytest.raises(ValueError, match="host"):
        spec.model.model_validate({"provider": "kmip"})
    assert {"module", "host", "port", "ca_pem", "vault"} <= set(spec.where_fields)
    with pytest.raises(ValueError, match="unencrypted PEM private key"):
        kinds.validate_secret_value("client_key", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n")
    with pytest.raises(ValueError, match="PEM client certificate"):
        kinds.validate_secret_value("client_cert", "not a cert")


def test_ca_connector_providers():
    spec = kinds.KINDS["ca_connector"]
    vault = spec.model.model_validate({"provider": "vault", "api_url": "https://vault.corp:8200", "host": "x"})
    assert spec.needs_node(vault) and spec.collectable(vault) and spec.secret_fields(vault) == {"token"}
    assert vault.host is None
    ejbca = spec.model.model_validate({"provider": "ejbca", "api_url": "https://ejbca.corp"})
    assert spec.collectable(ejbca) and spec.secret_fields(ejbca) == {"client_cert", "client_key"}
    adcs = spec.model.model_validate({"provider": "adcs", "login": "CORP\\svc-zscbom", "host": "ca01.corp"})
    assert adcs.port == 5986 and spec.collectable(adcs) and spec.secret_fields(adcs) == {"password"}
    with pytest.raises(ValueError, match="host"):
        spec.model.model_validate({"provider": "adcs", "login": "svc"})
    with pytest.raises(ValueError, match="5986"):
        spec.model.model_validate({"provider": "adcs", "login": "svc", "host": "ca01", "port": 5985})
    for provider in ("venafi", "keyfactor", "digicert", "sectigo", "other"):
        cfg = spec.model.model_validate({"provider": provider, "api_url": "https://clm.example.com"})
        assert not spec.collectable(cfg) and not spec.needs_node(cfg)  # honest: not collected yet


# ----------------------------------------------------------------------------- templates
def test_grants_cover_exactly_what_the_node_reads():
    node = (ROOT / "scan_node/zs_scan_node/collectors/oracle.py").read_text()
    views = {v.lower().replace("v$", "v_$") for v in re.findall(r"\b((?:v\$|dba_)[a-z_]+)\b", node, re.I)}
    grant = templates.DB_GRANTS["oracle"].lower()
    assert views and all(f"sys.{v} to zs_cbom" in grant for v in views), views
    assert "select_catalog_role" not in grant and "select any" not in grant
    mssql = templates.DB_GRANTS["mssql"]
    for perm in ("VIEW SERVER STATE", "VIEW ANY DEFINITION", "CONNECT ANY DATABASE"):
        assert f"GRANT {perm} TO svc_zscbom" in mssql
    assert "CONTROL SERVER TO" not in mssql
    policy = templates.template_text("vault-policy")
    assert 'path "sys/mounts" { capabilities = ["read"] }' in policy
    assert "export" not in re.sub(r"#.*", "", policy) and "backup" not in re.sub(r"#.*", "", policy)
    assert templates.TEMPLATE_NAMES["vault-policy"][1] == "zs-cbom-vault-policy.hcl"


# ----------------------------------------------------------------------------- API: saved source -> node job
def test_key_manager_and_vault_sources_reach_the_node(api, world):
    node_id, token, _ = enroll_node(api)
    cert = _ca_cert()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1()).private_bytes(  # made here; no key material in the repository
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    kmip = {"kind": "key_manager", "name": "kms-1", "node_id": node_id, "test_after_save": True,
            "config": {"provider": "kmip", "host": "kms.corp", "ca_pem": cert},
            "secrets": {"client_cert": cert, "client_key": key}}
    r = api("POST", "/1/cbom/sources/items", json=kmip)
    assert r.status_code == 201, r.text
    assert r.json()["source"]["group"] == "databases" and r.json()["test"]["job_id"]
    hsm = {"kind": "key_manager", "name": "hsm-1", "node_id": node_id,
           "config": {"provider": "pkcs11", "module": "luna"}, "secrets": {"pin": "12345678"}}
    assert api("POST", "/1/cbom/sources/items", json=hsm).status_code == 201
    bad = {**hsm, "name": "hsm-2", "config": {"provider": "pkcs11", "module": "/opt/evil.so"}}
    assert api("POST", "/1/cbom/sources/items", json=bad).status_code in (400, 422)
    vault = {"kind": "ca_connector", "name": "vault-pki", "node_id": node_id,
             "config": {"provider": "vault", "api_url": "https://vault.corp:8200"}, "secrets": {"token": "hvs.reader-token-123"}}
    r = api("POST", "/1/cbom/sources/items", json=vault)
    assert r.status_code == 201, r.text
    no_node = {**vault, "name": "vault-2", "node_id": None}
    assert api("POST", "/1/cbom/sources/items", json=no_node).status_code == 400
    claim = api("POST", "/cbom/node/jobs/claim", None, headers={"X-ZS-Node-Token": token})
    assert claim.status_code == 200, claim.text
    payload = claim.json()
    assert payload["source"]["kind"] == "key_manager" and payload["source"]["config"]["provider"] == "kmip"
    assert payload["source"]["secrets"]["client_key"].strip() == key.strip()
    # secrets are write-only through the user API
    listed = api("GET", "/1/cbom/sources/items?group=databases").text
    assert "BEGIN PRIVATE KEY" not in listed and "12345678" not in listed


def test_run_export_with_wp6_assets_is_valid_cyclonedx(api, world):
    from test_cbom_sources_api import _collect_job
    from test_cbom_wp9_sources import _post_assets

    from backend.utilities.cbom_sources.cdx_xml import validate_xml

    engine, _ = world
    _src, run, claim, hdr = _collect_job(api, engine)
    assets = [
        {"type": "managed_key", "target": "kms.corp", "location": "kmip://kms.corp:5696/7", "name": "legacy-3des",
         "algorithm": "3DES", "key_size": 168, "facts": {"store": "kmip", "key_class": "secret", "state": "Compromised",
                                                         "key_state": "Compromised"}},
        {"type": "key_store", "target": "hsm", "location": "pkcs11:luna/p1", "name": "p1",
         "facts": {"store": "pkcs11", "token_model": "K7"}},
        {"type": "db_encryption", "target": "sql01", "location": "sql01:1433/hr#tde", "name": "hr",
         "facts": {"engine": "mssql", "scope": "database", "encrypted": False}},
        {"type": "db_login_policy", "target": "ora", "location": "ora:1521#logins", "name": "Oracle password verifiers",
         "facts": {"engine": "oracle", "users": [{"name": "APP", "password_versions": "10G 12C"}]}},
        {"type": "db_crypto_policy", "target": "sql01", "location": "sql01:1433#transport", "name": "transport",
         "facts": {"engine": "mssql", "tls": True, "force_encryption": False}},
        {"type": "ca_authority", "target": "ca01", "location": "adcs://ca01/Corp#config", "name": "Corp", "algorithm": "RSA",
         "key_size": 4096, "facts": {"provider": "adcs", "hash_algorithm": "SHA1"}},
        {"type": "ca_template", "target": "ca01", "location": "adcs://ca01/Corp/template/Web", "name": "Web",
         "algorithm": "RSA", "key_size": 1024, "facts": {"provider": "adcs", "name": "Web", "key_type": "RSA", "key_bits": 1024}},
    ]
    assert _post_assets(api, claim["job"], hdr, assets).status_code == 200
    as_json = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").json()
    keys = [c for c in as_json["components"] if c.get("name") == "legacy-3des"]
    rel = keys[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert rel["type"] == "key" and rel["state"] == "compromised" and rel["size"] == 168
    codes = {p["value"] for c in as_json["components"] for p in c.get("properties", []) if p["name"] == "zs:finding_code"}
    assert {"KEY_WEAK_SYMMETRIC", "KEY_COMPROMISED", "DB_TDE_OFF", "DB_10G_VERIFIER", "DB_TLS_OPTIONAL",
            "CA_WEAK_SIGNING", "CA_ALLOWS_WEAK_KEY"} <= codes
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom?format=xml")
    assert r.status_code == 200 and validate_xml(r.content) == []
