"""CBOM Sources assets as posture facts and third-party components: the ONE mapper the team deliverables read.

A Sources run stores what a cloud API, a key manager, a database or a host reported (``CbomCollectedAsset``).  The
team deliverables read a different vocabulary: the code lane's posture facts (``aibom.cbom.posture``: ``kind`` /
``provider`` / ``native_type`` / ``layers`` / ``verdict`` / ``key_management`` ...) and its library components.  Before
this module only probed TLS endpoints were converted (``cbom_team_rollup._probed_tls_fact``), so D6 (Infrastructure and
Cloud Encryption Posture) and D9 (Data-at-Rest Encryption Assessment) listed nothing a cloud account, an HSM or a
database reported, and D10 (Third-Party Cryptographic Assurance) listed code-scan libraries only.

Entry points
* ``posture_fact(...)``   one stored asset -> one posture fact dict, or ``None`` for an asset type no posture register
                          reads (certificates, host keys, probed TLS endpoints: those have their own converters).  PURE.
* ``library_component(...)`` one ``crypto_library`` / ``process_library`` asset -> a third-party component.  PURE.

Callers: ``cbom_team_rollup.merge_collections`` (every team deliverable reads the facts on ``view.posture.facts``, so a
lane that needs Sources posture reads the view; a new asset type is one branch here plus a ``_LANES`` entry).

Verdicts use the code lane's words (``ENCRYPTED_DECLARED`` / ``ENCRYPTED_PROVIDER_DEFAULT`` / ``NOT_ENCRYPTED`` /
``UNKNOWN``).  What a Sources row says is a declared setting read from the system's own configuration (a cloud API, a
database catalog, ``dmsetup``), never a reading of stored data (SOW 7.2).  Every fact keeps the asset's own impact,
and finding codes, so a register row and the run page agree on the finding.

Standard library only at import time (the team roll-up keeps its import closure small).
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

__all__ = [
    "EVIDENCE",
    "MAPPED_TYPES",
    "LIBRARY_TYPES",
    "library_component",
    "posture_fact",
    "purl_identity",
]

EVIDENCE = "collected:CBOM Sources"  # posture ``evidence`` of a fact read from a system's own configuration
ENCRYPTED, PROVIDER_DEFAULT, NOT_ENCRYPTED, UNKNOWN = (
    "ENCRYPTED_DECLARED", "ENCRYPTED_PROVIDER_DEFAULT", "NOT_ENCRYPTED", "UNKNOWN")
LIBRARY_TYPES = frozenset({"crypto_library", "process_library"})
_CLOUDS = ("aws", "azure", "gcp", "oci")
_MAX_TEXT = 300

# where a key_store / managed_key lives (facts.store) -> the provider word the registers print
_STORES = {
    "pkcs11": "HSM (PKCS#11)", "kmip": "KMIP", "vault_transit": "HashiCorp Vault", "vault": "HashiCorp Vault",
    "mssql": "SQL Server", "oracle_wallet": "Oracle", "aws_kms_custom": "aws",
}
# a key id that says the provider holds the key (the data is encrypted, the key is not the customer's)
_PROVIDER_KEYS = re.compile(r"^(aws/|alias/aws/|google-managed|microsoft-managed|oracle-managed|provider-managed)",
                            re.IGNORECASE)
# storage_encryption ``resource`` text -> (posture kind, native type); first match wins
_STORAGE_KINDS: tuple[tuple[re.Pattern[str], str, str], ...] = tuple(
    (re.compile(pattern, re.IGNORECASE), kind, native) for pattern, kind, native in (
        (r"^EBS default", "disk_encryption", "EBS encryption by default"),
        (r"^EBS volume", "block_volume", "EBS volume"),
        (r"^RDS ", "relational_db", "RDS instance"),
        (r"^EKS cluster", "k8s_secrets_etcd", "EKS Kubernetes secrets"),
        (r"^S3 bucket", "object_store", "S3 bucket"),
        (r"^Glue security configuration", "data_warehouse", "Glue security configuration"),
        (r"^Storage account", "object_store", "Azure Storage account"),
        (r"^Cloud Storage bucket", "object_store", "Cloud Storage bucket"),
        (r"^Object Storage bucket", "object_store", "OCI Object Storage bucket"),
        (r"snapshot|backup", "backup", "Backup or snapshot"),
        (r"disk", "block_volume", "Managed disk"),
        (r"database|sql", "relational_db", "Managed database"),
    ))
_DB_KIND = {"mysql": "relational_db", "postgres": "relational_db", "postgresql": "relational_db",
            "mssql": "relational_db", "oracle": "relational_db", "mariadb": "relational_db",
            "mongodb": "nosql_db", "redis": "cache"}
_DB_LABEL = {"mysql": "MySQL", "postgres": "PostgreSQL", "postgresql": "PostgreSQL", "mssql": "SQL Server",
             "oracle": "Oracle", "mongodb": "MongoDB", "redis": "Redis", "mariadb": "MariaDB"}
_SECRET_SERVICE = {"aws": "AWS Secrets Manager", "gcp": "Google Secret Manager", "azure": "Azure Key Vault secret",
                   "oci": "OCI Vault secret"}
_TLS_ORDER = ("SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
_TLS_KEYS = {"SSLv3": "SSLv3", "TLSv1.0": "1.0", "TLSv1.1": "1.1", "TLSv1.2": "1.2", "TLSv1.3": "1.3"}
_OBSOLETE_SUITE = re.compile(r"RC4|3DES|DES-CBC3|_DES_|DES_CBC|NULL|EXPORT|anon|MD5", re.IGNORECASE)


# ----------------------------------------------------------------------------------------------- small helpers
def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return ""
    if type(value) is str and len(value) <= limit and "  " not in value and value.isprintable():
        return value.strip()  # the common case: already one clean line (no copy)
    return " ".join(str(value).split())[:limit]


def _facts(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _tri(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def provider_of(node_type: str, facts: Mapping[str, Any], location: str, source_kind: str = "") -> str:
    """``aws`` / ``azure`` / ``gcp`` / ``oci`` for a cloud resource, the key manager for a key, else ``self_hosted``."""
    stated = str(facts.get("provider") or "").casefold()
    if stated in _CLOUDS:
        return stated
    where = str(location or "")
    if where.startswith("arn:aws"):
        return "aws"
    if where.startswith(("projects/", "//storage.googleapis.com", "https://www.googleapis.com", "//")):
        return "gcp"
    if "/subscriptions/" in where or ".vault.azure.net" in where:
        return "azure"
    if where.startswith("oci://") or "ocid1." in where:
        return "oci"
    kind = str(source_kind or "")
    for cloud, kinds in (("aws", ("aws_account",)), ("azure", ("azure_subscription",)), ("gcp", ("gcp_project",)),
                         ("oci", ("oci_tenancy",))):
        if kind in kinds:
            return cloud
    store = str(facts.get("store") or "")
    if store in _STORES and node_type in ("managed_key", "key_store"):
        return _STORES[store]
    return "self_hosted"


def _exposure(facts: Mapping[str, Any]) -> str:
    public = _tri(facts.get("internet_facing"))
    return "" if public is None else ("public" if public else "internal")


def _key_management(kms_key: Any, *, sse: Any = None) -> tuple[str, bool | None]:
    """(printed key management, customer-managed?) of a storage resource's key id; None: not stated."""
    key = _text(kms_key, 200)
    if key and _PROVIDER_KEYS.match(key):
        return f"provider-managed ({key})", False
    if key:
        return f"customer-managed KMS key {key}", True
    algorithm = _text(sse, 40)
    if algorithm.upper() == "AES256":
        return "provider-managed (SSE-S3)", False
    if algorithm:
        return f"provider-managed ({algorithm})", False
    return "", None


def _at_rest(encrypted: bool | None, customer: bool | None) -> str:
    if encrypted is False:
        return NOT_ENCRYPTED
    if encrypted is True:
        return PROVIDER_DEFAULT if customer is False else ENCRYPTED
    return UNKNOWN


def _rotation(facts: Mapping[str, Any]) -> tuple[str, str]:
    """(normalised rotation: enabled | disabled | not_applicable | unknown, the detail printed next to it)."""
    status = str(facts.get("rotation_status") or "").casefold()
    period = _text(facts.get("rotation_period") or facts.get("rotation_interval")
                   or (f"{facts['rotation_period_days']} days" if facts.get("rotation_period_days") else ""), 40)
    if "auto_rotate_period_s" in facts or "auto_rotate_period" in facts:  # Vault transit
        seconds = facts.get("auto_rotate_period_s", facts.get("auto_rotate_period"))
        if isinstance(seconds, (int, float)) and seconds > 0:
            return "enabled", f"every {int(seconds) // 86400 or 1} days"
        return "disabled", "auto_rotate_period 0"
    purpose = str(facts.get("purpose") or "")
    if str(facts.get("provider") or "") == "gcp" and purpose and purpose != "ENCRYPT_DECRYPT":
        # Cloud KMS rotates symmetric ENCRYPT_DECRYPT keys only; gcp_collect stores None for the others
        return "not_applicable", "automatic rotation exists for symmetric keys only"
    enabled = _tri(facts.get("rotation_enabled"))
    if status in ("on",) or enabled is True:
        return "enabled", period
    if status in ("off",) or enabled is False:
        return "disabled", period
    if status.startswith(("not applicable", "not supported")) or facts.get("auto_rotation_supported") is False:
        return "not_applicable", status or "not supported for this key"
    return "unknown", status


_KEY_SPEC = re.compile(r"^(RSA|HMAC)_(\d+)$|^ECC_(NIST|SECG)_P(\d+)K?\d*$", re.IGNORECASE)


def _algorithm_size(algorithm: Any, key_size: Any) -> str:
    """``AES-256`` / ``RSA-2048`` / ``ECDSA P-256``: a provider key spec (``SYMMETRIC_DEFAULT``, ``RSA_2048``,
    ``ECC_NIST_P256``) is printed as the algorithm it names; any other spec is printed as stored."""
    name = _text(algorithm, 60)
    size = _text(key_size, 10)
    if name.upper() == "SYMMETRIC_DEFAULT":  # AWS / GCP / OCI symmetric keys are AES-256 (GCM)
        return "AES-256"
    spec = _KEY_SPEC.match(name)
    if spec:
        if spec.group(1):
            return f"{spec.group(1).upper()}-{spec.group(2)}"
        return f"ECDSA P-{spec.group(4)}"
    if name and size and size not in name:
        return f"{name}-{size}"
    return name or (f"{size}-bit" if size else "")


def _base(node_type: str, *, fact_id: str, kind: str, provider: str, native: str, name: str, location: str,
          source_label: str, impact: Any, codes: Sequence[str], facts: Mapping[str, Any],
          lane: str) -> dict[str, Any]:
    # a fact carries codes, not the asset's sentence (the asset row keeps it; memory at 50k assets)
    return {
        "id": fact_id,
        "kind": kind,
        "provider": provider,
        "native_type": native,
        "address": name or location,
        "name": name,
        "evidence": EVIDENCE,
        "location": location,  # the resource's own id (ARN, key URI, host:port/database ...)
        "source": source_label,  # "Sources run #52 · AWS production": the collection that read it
        "impact": impact if impact in ("Critical", "High", "Medium", "Low") else None,
        "finding_codes": [str(c) for c in codes if isinstance(c, str) and c],
        "exposure": _exposure(facts),
        "source_asset_type": node_type,
        "lane": lane,
    }


# ----------------------------------------------------------------------------------------------- per asset type
def _key(node_type: str, base: dict[str, Any], facts: dict[str, Any], algorithm: Any, key_size: Any) -> dict[str, Any]:
    """KMS / Key Vault / Vault transit / PKCS#11 / KMIP / database keys: the D6 KMS key register."""
    rotation, detail = _rotation(facts)
    protection = ""
    if facts.get("hsm_backed") is True or facts.get("cloud_hsm_cluster_id"):
        protection = "HSM"
    elif facts.get("store") == "pkcs11":
        protection = "HSM (PKCS#11 token)"
    elif facts.get("store") == "kmip":
        protection = "KMIP key server"
    elif facts.get("origin") == "EXTERNAL":
        protection = "external key material"
    elif facts.get("protection_level"):
        protection = _text(facts.get("protection_level"), 40).lower()
    elif facts.get("store") == "vault_transit":
        protection = "software (Vault transit)"
    elif facts.get("custom_key_store_id"):
        protection = "custom key store"
    if facts.get("exportable") is True or facts.get("extractable") is True or facts.get("sensitive") is False:
        protection = (protection + "; exportable").lstrip("; ")
    usage = facts.get("key_usage") or facts.get("purpose") or facts.get("usage") or facts.get("key_ops")
    if isinstance(usage, (list, tuple)):
        usage = ", ".join(str(u) for u in usage[:6])
    if not usage and facts.get("store") == "pkcs11":
        usage = ", ".join(op for op in ("encrypt", "decrypt", "sign", "verify", "wrap", "unwrap", "derive")
                          if facts.get(op) is True)
    deletion = ""
    if facts.get("deletion_allowed") is False:
        deletion = "deletion not allowed"
    elif facts.get("deletion_allowed") is True:
        deletion = "deletion allowed"
    elif facts.get("destroy_scheduled_duration"):
        deletion = f"destroy delay {_text(facts['destroy_scheduled_duration'], 20)}"
    elif facts.get("recovery_level"):
        deletion = _text(facts.get("recovery_level"), 40)
    elif facts.get("deletion_time"):
        deletion = f"deletion scheduled {_text(facts['deletion_time'], 25)}"
    spec = facts.get("key_spec") or facts.get("kty") or facts.get("type") or facts.get("object_type") \
        or (f"{facts.get('key_class')} {facts.get('key_type') or ''}".strip() if facts.get("key_class") else "") \
        or facts.get("algorithm_desc")
    state = facts.get("key_state") or facts.get("state") or facts.get("status") \
        or ("enabled" if node_type == "managed_key" and facts.get("store") in ("pkcs11", "vault_transit") else "")
    base.update({
        "specification": _text(spec, 60),
        "algorithm": _algorithm_size(algorithm or facts.get("key_type") or facts.get("algorithm"),
                                     key_size or facts.get("length")),
        "usage": _text(usage, 80),
        "protection": protection,
        "state": _text(state, 40),
        "rotation": rotation,
        "rotation_detail": detail,
        "deletion_protection": deletion,
        "attrs": {"rotation": rotation, "store": _text(facts.get("store"), 30)},
    })
    if facts.get("store") and node_type == "managed_key":
        base["native_type"] = f"{_STORES.get(str(facts['store']), facts['store'])} key"
    return base


def _key_store(base: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    store = str(facts.get("store") or "")
    vendor = facts.get("token_model") or facts.get("library_manufacturer") or facts.get("vendor") \
        or facts.get("custom_key_store_type") or facts.get("wrl_type")
    version = facts.get("library_version") or facts.get("protocol_version") or facts.get("cryptoki_version")
    objects = facts.get("objects")
    count = sum(v for v in objects.values() if isinstance(v, int)) if isinstance(objects, Mapping) else facts.get("keys")
    state = facts.get("connection_state") or facts.get("status") or facts.get("wallet_status") \
        or ("logged in" if facts.get("logged_in") is True else "")
    base.update({"native_type": f"{_STORES.get(store, store or 'key store')} key store", "store": store,
                 "vendor": _text(vendor, 80), "version": _text(version, 40), "state": _text(state, 40),
                 "objects": count if isinstance(count, int) else None})
    return base


def _storage(base: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    resource = _text(facts.get("resource"), 120) or base["name"]
    kind, native = "object_store", "Storage resource"
    for pattern, mapped, label in _STORAGE_KINDS:
        if pattern.search(resource):
            kind, native = mapped, label
            break
    if "default_encryption" in facts:  # EBS encryption by default: a region-wide setting for new volumes
        encrypted = _tri(facts.get("default_encryption"))
        management, customer = ("account default key", None)
    else:
        encrypted = _tri(facts.get("encrypted"))
        management, customer = _key_management(facts.get("kms_key_id") or facts.get("catalog_kms_key_id"),
                                               sse=facts.get("sse_algorithm"))
        if facts.get("key_source") and str(facts["key_source"]).casefold() == "microsoft.storage":
            management, customer = "provider-managed (Microsoft.Storage)", False
    if encrypted is True and not management:
        management = "not stated"
    elif encrypted is False:
        management = "none"  # nothing is encrypted, so no key manages it
    verdict = _at_rest(encrypted, customer)
    layer = {"object_store": "service", "block_volume": "volume", "relational_db": "service",
             "k8s_secrets_etcd": "service", "data_warehouse": "service", "disk_encryption": "volume",
             "backup": "backup"}.get(kind, "service")
    layers = {layer: verdict}
    if facts.get("tls_only_policy") is True:
        layers["transport"] = ENCRYPTED
    basis = [f"encrypted={str(encrypted).lower() if encrypted is not None else 'not read'}"]
    if facts.get("tls_only_policy") is not None:
        basis.append(f"TLS-only bucket policy {'yes' if facts['tls_only_policy'] else 'no'}")
    if facts.get("incomplete"):
        basis.append("settings not fully read")
    if kind == "k8s_secrets_etcd":  # the Kubernetes secrets register: first provider, custody, weakness
        base.update({"first_provider": "KMS envelope encryption" if encrypted else (
                         "identity (no envelope encryption)" if encrypted is False else "not read"),
                     "custody": management or ("none" if encrypted is False else ""),
                     "weakness": "" if encrypted else "Kubernetes secrets not envelope-encrypted with a KMS key"})
    base.update({"kind": kind, "native_type": native, "address": base["name"] or resource, "verdict": verdict,
                 "at_rest": verdict, "layers": layers, "key_management": management, "basis": "; ".join(basis),
                 "attrs": {"resource": resource, "kms_key_id": _text(facts.get("kms_key_id"), 200),
                           **({"directive": "EBS encryption by default",
                               "value_class": "on" if encrypted else ("off" if encrypted is False else "not read")}
                              if kind == "disk_encryption" else {})}})
    return base


def _glue_catalog(base: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    mode = str(facts.get("catalog_encryption_mode") or "").upper()
    encrypted = True if mode and mode != "DISABLED" else (False if mode == "DISABLED" else None)
    management, customer = _key_management(facts.get("catalog_kms_key_id"))
    verdict = _at_rest(encrypted, customer if customer is not None else (True if encrypted else None))
    base.update({"kind": "data_warehouse", "native_type": "Glue Data Catalog", "verdict": verdict, "at_rest": verdict,
                 "layers": {"service": verdict}, "key_management": management or ("none" if encrypted is False else ""),
                 "basis": f"CatalogEncryptionMode={mode or 'not read'}"})
    return base


def _db_encryption(base: dict[str, Any], facts: dict[str, Any], algorithm: Any, key_size: Any) -> dict[str, Any]:
    engine = str(facts.get("engine") or "").casefold()
    scope = str(facts.get("scope") or "database")
    encrypted = _tri(facts.get("encrypted"))
    verdict = ENCRYPTED if encrypted else (NOT_ENCRYPTED if encrypted is False else UNKNOWN)
    label = _DB_LABEL.get(engine, engine or "Database")
    what = {"database": "TDE", "tablespace": "tablespace TDE", "column": "column encryption"}.get(scope, scope)
    directive = f"{what}: " + (_text(facts.get("tde_state"), 30) or ("encrypted" if encrypted else
                                                                    ("not encrypted" if encrypted is False else "not read")))
    base.update({"kind": _DB_KIND.get(engine, "relational_db"), "provider": base["provider"],
                 "native_type": f"{label} {what}", "verdict": verdict, "at_rest": verdict,
                 "layers": {"database": verdict},
                 "key_management": "none" if encrypted is False else (_text(facts.get("encryptor_type"), 40) or (
                     _algorithm_size(algorithm or facts.get("algorithm_desc"), key_size) if encrypted else "")),
                 "basis": directive,
                 "attrs": {"engine": label, "directive": directive,
                           "cipher": _algorithm_size(algorithm or facts.get("algorithm_desc"), key_size),
                           "key_source": _text(facts.get("encryptor_type"), 40)}})
    return base


def _database_config(base: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any] | None:
    """A self-managed database server's declared at-rest settings (MySQL, PostgreSQL, MongoDB, Redis).  A cloud
    database's parameter group (``source: aws``) is left out: its storage_encryption row is the store."""
    engine = str(facts.get("engine") or "").casefold()
    if facts.get("source") in _CLOUDS or facts.get("parameter_group") or engine not in (
            "mysql", "mariadb", "postgres", "postgresql", "mongodb", "redis"):
        return None
    label = _DB_LABEL.get(engine, engine)
    verdict, directive, management = UNKNOWN, "", ""
    unknown_reason = ""
    if engine in ("mysql", "mariadb"):
        values = _facts(facts.get("variables"))
        keyring = facts.get("keyring_plugins")
        tables = facts.get("encrypted_tables")
        default = str(values.get("default_table_encryption") or "").upper()
        if (isinstance(tables, list) and tables) or (default == "ON" and keyring):
            verdict = ENCRYPTED
        elif keyring == [] and not tables:
            verdict = NOT_ENCRYPTED
        else:
            unknown_reason = "attribute_not_modeled"
        directive = (f"default_table_encryption={default or 'not read'}; keyring "
                     f"{'none' if keyring == [] else ', '.join(map(str, keyring or [])) or 'not read'}; "
                     f"binlog_encryption={values.get('binlog_encryption') or 'not read'}")
        management = "keyring: " + (", ".join(map(str, keyring)) if keyring else "none")
    elif engine in ("postgres", "postgresql"):
        extensions = [str(e.get("name")) for e in facts.get("extensions") or [] if isinstance(e, Mapping)]
        unknown_reason = "layer_not_observable"
        directive = "no built-in encryption at rest; " + (
            "pgcrypto installed (column-level capability)" if "pgcrypto" in extensions else "pgcrypto not installed")
    elif engine == "mongodb":
        options = facts.get("options")
        if isinstance(options, Mapping):
            enabled = options.get("security.enableEncryption")
            verdict = ENCRYPTED if enabled is True else NOT_ENCRYPTED
            directive = f"security.enableEncryption={str(enabled).lower() if enabled is not None else 'not set'}"
            if options.get("security.encryptionCipherMode"):
                directive += f"; {options['security.encryptionCipherMode']}"
        else:
            unknown_reason = "attribute_not_modeled"
            directive = "startup options not read"
    elif engine == "redis":
        unknown_reason = "layer_not_observable"
        directive = "no built-in encryption at rest (RDB/AOF files are plain); disk layer not observed"
    transport = ""
    settings = _facts(facts.get("settings"))
    tls = facts.get("tls") if isinstance(facts.get("tls"), bool) else (
        True if str(settings.get("ssl") or "").casefold() == "on" else (False if settings.get("ssl") == "off" else None))
    if tls is True:
        transport = ENCRYPTED
    elif tls is False:
        transport = NOT_ENCRYPTED
    layers = {"database": verdict}
    if transport:
        layers["transport"] = transport
    if verdict == NOT_ENCRYPTED and not management:
        management = "none"
    base.update({"kind": _DB_KIND.get(engine, "relational_db"), "native_type": f"{label} server settings",
                 "verdict": verdict, "at_rest": verdict, "layers": layers, "key_management": management,
                 "basis": directive, "unknown_reason": unknown_reason if verdict == UNKNOWN else "",
                 "attrs": {"engine": label, "directive": directive}})
    return base


def _disk(base: dict[str, Any], facts: dict[str, Any], algorithm: Any, key_size: Any) -> dict[str, Any]:
    bitlocker = facts.get("source") == "bitlocker"
    if bitlocker:
        status = str(facts.get("status") or "").casefold()
        method = str(facts.get("method") or algorithm or "")
        encrypted = False if status == "fullydecrypted" or method.casefold() in ("", "none") else True
        cipher, source = method, f"BitLocker protection {facts.get('protection') or 'not read'}"
    else:
        encrypted = _tri(facts.get("encrypted"))
        if encrypted is None:
            encrypted = True if (facts.get("cipher") or facts.get("container") or algorithm) else None
        cipher = _text(facts.get("cipher") or algorithm, 60)
        source = f"LUKS{facts['luks_version']}" if facts.get("luks_version") else ("LUKS" if facts.get("container") else "")
    verdict = ENCRYPTED if encrypted else (NOT_ENCRYPTED if encrypted is False else UNKNOWN)
    base.update({"kind": "disk_encryption", "native_type": "BitLocker volume" if bitlocker else "dm-crypt / LUKS volume",
                 "verdict": verdict, "at_rest": verdict, "layers": {"volume": verdict},
                 "key_management": "none" if encrypted is False else source, "basis": f"cipher {cipher or 'not read'}",
                 "attrs": {"device": _text(facts.get("mount") or facts.get("device") or base["name"], 80),
                           "cipher": _algorithm_size(cipher, key_size if not bitlocker else None),
                           "key_source": source}})
    return base


def _managed_tls(node_type: str, base: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    """A cloud load balancer listener, CDN distribution or API domain: its declared TLS policy (D6 managed TLS)."""
    offered = [str(p) for p in facts.get("protocols") or [] if isinstance(p, str)]
    minimum = _text(facts.get("min_version") or facts.get("min_tls_version") or facts.get("minimum_protocol_version"), 20)
    minimum = {"TLS_1_0": "TLSv1.0", "TLS_1_1": "TLSv1.1", "TLS_1_2": "TLSv1.2", "TLSv1": "TLSv1.0",
               "TLSv1_2016": "TLSv1.0", "TLSv1.1_2016": "TLSv1.1", "TLSv1.2_2018": "TLSv1.2",
               "TLSv1.2_2019": "TLSv1.2", "TLSv1.2_2021": "TLSv1.2"}.get(minimum, minimum)
    if not offered and minimum in _TLS_ORDER:
        offered = list(_TLS_ORDER[_TLS_ORDER.index(minimum):])
    if offered and not minimum:
        ranked = [p for p in _TLS_ORDER if p in offered]
        minimum = ranked[0] if ranked else ""
    plaintext = facts.get("tls") is False
    protocols = {key: ("offered" if name in offered else ("not_offered" if offered or plaintext else "unknown"))
                 for name, key in _TLS_KEYS.items()}
    ciphers = [str(c) for c in facts.get("ciphers") or [] if isinstance(c, str)]
    weak = [{"suite": c, "reasons": ["obsolete"]} for c in ciphers if _OBSOLETE_SUITE.search(c)]
    weak += [{"suite": c, "reasons": ["static_rsa"]} for c in ciphers
             if not _OBSOLETE_SUITE.search(c) and c.upper().startswith(("TLS_RSA_", "AES", "RSA"))]
    policy = facts.get("ssl_policy") or facts.get("security_policy") or facts.get("cipher_suite") \
        or facts.get("minimum_protocol_version") or facts.get("cipher_suite_set") or facts.get("profile") or ""
    listener = facts.get("listener") or (f"port {facts['port']}" if facts.get("port") else "")
    endpoint = base["name"] or base["location"]
    ranked = [p for p in _TLS_ORDER if p in offered]
    base.update({
        "kind": "tls_endpoint",
        "native_type": {"load_balancer_tls": "Load balancer listener", "cdn_tls": "CDN distribution",
                        "api_tls": "API domain"}[node_type],
        "policy": _text(policy, 80) + (" (provider default)" if facts.get("default_policy") is True else ""),
        "protocol_version": _label(minimum),
        "listener": _text(listener, 40),
        "transport": NOT_ENCRYPTED if plaintext else (ENCRYPTED if offered or minimum else UNKNOWN),
        "verdict": NOT_ENCRYPTED if plaintext else (ENCRYPTED if offered or minimum else UNKNOWN),
        "net": {
            "endpoint": endpoint, "evidence": EVIDENCE, "protocols": protocols,
            "min": "plaintext (no TLS)" if plaintext else _label(minimum),
            "max": _label(ranked[-1]) if ranked else "", "weak_suites": weak,
            "kx": {"curves": [str(g) for g in facts.get("pq_groups") or [] if isinstance(g, str)]},
            "fs": "RSA key exchange accepted" if facts.get("static_rsa_kex") else "",
            "downgrade": "", "policy": _text(policy, 80), "listener": _text(listener, 40),
        },
    })
    return base


def _label(version: str) -> str:
    return ("TLS " + version[4:]) if version.startswith("TLSv") else version


def _secret(node_type: str, base: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    provider = base["provider"]
    if node_type == "key_vault":
        service = "Azure Key Vault"
        rotation, detail = "not_applicable", "vault"
        management = "soft delete " + ("on" if facts.get("soft_delete_enabled") else "off") + \
            "; purge protection " + ("on" if facts.get("purge_protection") else "off")
    else:
        service = "AWS Systems Manager parameter" if facts.get("service") == "ssm" else \
            _SECRET_SERVICE.get(provider, "Secret store")
        if facts.get("service") == "ssm":
            rotation, detail = "not_applicable", f"{facts.get('parameter_type') or 'parameter'}"
        else:
            rotation, detail = _rotation(facts)
        key, _customer = _key_management(facts.get("kms_key_id"))
        management = key or ("none (plain String)" if facts.get("parameter_type") == "String" else "")
    base.update({"kind": "secret_store", "native_type": service, "service": service,
                 "rotation": rotation, "rotation_detail": _text(detail, 60), "key_management": management,
                 "expires": _text(facts.get("expires"), 25), "attrs": {"rotation": rotation}})
    return base


def _cloud_ca(base: dict[str, Any], facts: dict[str, Any], algorithm: Any, key_size: Any) -> dict[str, Any]:
    subject = _text(facts.get("subject"), 200)
    base.update({"kind": "certificate_policy", "native_type": "Private CA", "service": "Private CA",
                 "address": subject or base["address"],
                 "key_algorithm": _algorithm_size(algorithm or facts.get("key_alg"), key_size),
                 "key_management": _text(facts.get("kms_key_id") or facts.get("kms_key_version"), 120)
                 or ("provider-held CA key" if base["provider"] in _CLOUDS else ""),
                 "rotation": "not_applicable", "rotation_detail": _text(facts.get("status"), 30),
                 "expires": _text(facts.get("not_after"), 25), "attrs": {"rotation": "not_applicable"}})
    return base


_LANES = {"kms_key": "sources_keys", "managed_key": "sources_keys", "key_store": "sources_keys",
          "storage_encryption": "sources_cloud", "glue_catalog": "sources_cloud", "load_balancer_tls": "sources_cloud",
          "cdn_tls": "sources_cloud", "api_tls": "sources_cloud", "cloud_secret": "sources_cloud",
          "key_vault": "sources_cloud", "cloud_ca": "sources_cloud", "db_encryption": "sources_database",
          "database_config": "sources_database", "disk_encryption": "sources_host"}
MAPPED_TYPES = frozenset(_LANES)


def posture_fact(node_type: str, facts: Any, *, fact_id: str, name: Any = None, location: Any = None,
                 algorithm: Any = None, key_size: Any = None, impact: Any = None, finding_codes: Iterable[Any] = (),
                 source_label: str = "", source_kind: str = "") -> dict[str, Any] | None:
    """One stored Sources asset as a posture fact, or ``None`` when no posture register reads its type.  PURE.

    ``fact_id`` must be unique within the team view (``sources:<job>:<identity>``); ``source_label`` is printed in the
    Source column ("Sources run #52 · AWS production"); the resource id goes in ``location``."""
    if node_type not in MAPPED_TYPES:
        return None
    data = _facts(facts)
    where = _text(location, 500)
    title = _text(name, 200)
    provider = provider_of(node_type, data, where, source_kind)
    base = _base(node_type, fact_id=fact_id, kind=node_type, provider=provider, native=node_type, name=title,
                 location=where, source_label=source_label, impact=impact, codes=list(finding_codes or ()),
                 facts=data, lane=_LANES[node_type])
    if node_type in ("kms_key", "managed_key"):
        base["kind"] = "kms_key"
        return _key(node_type, base, data, algorithm, key_size)
    if node_type == "key_store":
        base["kind"] = "key_store"
        return _key_store(base, data)
    if node_type == "storage_encryption":
        return _storage(base, data)
    if node_type == "glue_catalog":
        return _glue_catalog(base, data)
    if node_type == "db_encryption":
        return _db_encryption(base, data, algorithm, key_size)
    if node_type == "database_config":
        return _database_config(base, data)
    if node_type == "disk_encryption":
        return _disk(base, data, algorithm, key_size)
    if node_type in ("load_balancer_tls", "cdn_tls", "api_tls"):
        return _managed_tls(node_type, base, data)
    if node_type in ("cloud_secret", "key_vault"):
        return _secret(node_type, base, data)
    return _cloud_ca(base, data, algorithm, key_size)  # cloud_ca


# ----------------------------------------------------------------------------------------------- D10 components
_SONAME = re.compile(r"\.so\.([0-9][0-9.]*)$")
_STATUS = (("LIB_KNOWN_CVE", "known CVE range"), ("LIB_EOL", "end of life"),
           ("LIB_DELETED_IN_USE", "deleted library still loaded"), ("LIB_STATIC", "statically linked"))


def purl_identity(purl: Any) -> str:
    """A package URL without its qualifiers and subpath (``pkg:deb/debian/libssl3@3.0.13``), case-folded."""
    text = _text(purl, 300)
    return text.split("?", 1)[0].split("#", 1)[0].casefold() if text.startswith("pkg:") else ""


def library_component(node_type: str, facts: Any, *, name: Any = None, location: Any = None,
                      finding_codes: Iterable[Any] = ()) -> dict[str, Any] | None:
    """A ``crypto_library`` (an installed package) or ``process_library`` (a library a process maps) as a third-party
    component: ``{name, version, purl, ecosystem, status, codes, where}``.  PURE.  ``None`` for any other type."""
    if node_type not in LIBRARY_TYPES:
        return None
    data = _facts(facts)
    codes = [str(c) for c in finding_codes or () if isinstance(c, str)]
    if node_type == "crypto_library":
        title = _text(data.get("name") or name, 120)
        version = _text(data.get("version"), 60)
        ecosystem = _text(data.get("package_manager") or data.get("source"), 30)
        where = _text(data.get("image") or location, 200)
    else:
        lib = _text(data.get("lib") or location, 200)
        title = lib.rsplit("/", 1)[-1] or _text(name, 120)
        version = ""
        ecosystem = "mapped by a process"
        where = f"{_text(data.get('process') or name, 60)} ({lib})" if lib else _text(name, 60)
    if not title:
        return None
    status = [label for code, label in _STATUS if code in codes]
    return {"name": title, "version": version, "purl": _text(data.get("purl"), 300), "ecosystem": ecosystem,
            "status": "; ".join(status), "codes": tuple(codes), "where": where}
