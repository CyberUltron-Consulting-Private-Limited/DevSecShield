"""A CBOM Sources fixture with every asset type the team deliverables D6, D9 and D10 read.

The facts are the shapes the collectors store (``aws_collect``, ``gcp_collect`` / ``gcp_tls``, ``azure_collect`` /
``azure_arm``, ``oci_collect``, the scan node's ``hsm_pkcs11`` / ``kmip`` / ``mssql`` / ``oracle`` / ``database`` /
``linux_ssh`` / ``windows_winrm`` / ``container_images`` collectors), most copied from staging run #50 / #51 / #52
(23 Nov 2026) with account ids and host names replaced.  Each asset is judged by the real classifier
(``classify.classify``) and turned into a results[] row by the real ``collections_view.node_row``, so the roll-up
receives exactly what ``load_sources_result`` would give it.

``build()`` returns ``(rows, collections)`` for ``cbom_team_rollup.merge_collections``.
"""

from __future__ import annotations

import datetime as dt
from types import SimpleNamespace
from typing import Any

from backend.utilities.cbom_sources import classify as C
from backend.utilities.cbom_sources.collections_view import Collection, SourcesRow, code_impacts, node_row

OBSERVED = dt.datetime(2026, 11, 23, 9, 30, tzinfo=dt.timezone.utc)
ACCOUNT = "111122223333"

# source name -> (source kind, run id, assets)
SOURCES: dict[str, tuple[str, int, list[dict[str, Any]]]] = {
    "AWS production": ("aws_account", 52, [
        {"type": "kms_key", "name": "payments-cmk", "algorithm": "SYMMETRIC_DEFAULT", "key_size": 256,
         "location": f"arn:aws:kms:ap-south-1:{ACCOUNT}:key/1567c185-9c09-49eb-974c-49d1987b7195",
         "facts": {"key_spec": "SYMMETRIC_DEFAULT", "key_usage": "ENCRYPT_DECRYPT", "key_manager": "CUSTOMER",
                   "key_state": "Enabled", "origin": "AWS_KMS", "rotation_enabled": False, "rotation_status": "off",
                   "multi_region": False}},
        {"type": "kms_key", "name": "imported-no-material", "algorithm": "SYMMETRIC_DEFAULT", "key_size": 256,
         "location": f"arn:aws:kms:ap-south-1:{ACCOUNT}:key/042b9ee8-fe08-40a3-9e21-dec83d597319",
         "facts": {"key_spec": "SYMMETRIC_DEFAULT", "key_usage": "ENCRYPT_DECRYPT", "key_manager": "CUSTOMER",
                   "key_state": "PendingImport", "origin": "EXTERNAL", "rotation_enabled": None,
                   "rotation_status": "not applicable", "key_materials": []}},
        {"type": "storage_encryption", "name": "payments-ledger",
         "location": "arn:aws:s3:::payments-ledger",
         "facts": {"resource": "S3 bucket payments-ledger", "encrypted": True, "sse_algorithm": "aws:kms",
                   "kms_key_id": f"arn:aws:kms:ap-south-1:{ACCOUNT}:key/1567c185", "tls_only_policy": True}},
        {"type": "storage_encryption", "name": "public-assets",
         "location": "arn:aws:s3:::public-assets",
         "facts": {"resource": "S3 bucket public-assets", "encrypted": False, "tls_only_policy": False}},
        {"type": "storage_encryption", "name": "vol-09d6979c2af92f0e5",
         "location": f"arn:aws:ec2:ap-south-1:{ACCOUNT}:volume/vol-09d6979c2af92f0e5",
         "facts": {"resource": "EBS volume vol-09d6979c2af92f0e5", "encrypted": False, "size_gib": 50,
                   "kms_key_id": None, "volume_type": "gp3", "attached_to": ["i-04e883934d8f1e3e3"],
                   "internet_facing": True, "exposure_basis": "EC2 instance has a public IP address"}},
        {"type": "storage_encryption", "name": "EBS encryption by default (ap-south-1)",
         "location": f"arn:aws:ec2:ap-south-1:{ACCOUNT}:ebs-encryption-by-default",
         "facts": {"resource": "EBS default", "default_encryption": False}},
        {"type": "storage_encryption", "name": "proxy-platform-postgres",
         "location": f"arn:aws:rds:ap-south-1:{ACCOUNT}:db:proxy-platform-postgres",
         "facts": {"resource": "RDS postgres proxy-platform-postgres", "encrypted": True,
                   "kms_key_id": f"arn:aws:kms:ap-south-1:{ACCOUNT}:key/1567c185", "engine": "postgres",
                   "internet_facing": False, "exposure_basis": "RDS PubliclyAccessible=false"}},
        {"type": "storage_encryption", "name": "EKS payments secrets",
         "location": f"arn:aws:eks:ap-south-1:{ACCOUNT}:cluster/payments",
         "facts": {"resource": "EKS cluster payments Kubernetes secrets", "encrypted": False, "version": "1.30"}},
        {"type": "glue_catalog", "name": "Glue Data Catalog (ap-south-1)",
         "location": f"arn:aws:glue:ap-south-1:{ACCOUNT}:catalog",
         "facts": {"catalog_encryption_mode": "DISABLED", "catalog_kms_key_id": None,
                   "connection_password_encryption": False}},
        {"type": "load_balancer_tls", "name": "ComplianceShield-LB:80", "protocol": "HTTP",
         "location": f"arn:aws:elasticloadbalancing:ap-south-1:{ACCOUNT}:listener/app/ComplianceShield-LB/3a7d/fa4b",
         "facts": {"tls": False, "port": 80, "internet_facing": True,
                   "exposure_basis": "application ComplianceShield-LB scheme internet-facing"}},
        {"type": "load_balancer_tls", "name": "ComplianceShield-LB:443", "protocol": "HTTPS",
         "location": f"arn:aws:elasticloadbalancing:ap-south-1:{ACCOUNT}:listener/app/ComplianceShield-LB/3a7d/9c1e",
         "facts": {"ssl_policy": "ELBSecurityPolicy-2016-08", "protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
                   "ciphers": ["ECDHE-RSA-AES128-GCM-SHA256", "AES128-GCM-SHA256", "DES-CBC3-SHA"],
                   "static_rsa_kex": True, "certificates": [], "internet_facing": True}},
        {"type": "cdn_tls", "name": "d3lg18b01vnyjz.cloudfront.net", "protocol": "TLS",
         "location": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E3GA6W1ZM687LP",
         "facts": {"min_version": "TLSv1.0", "minimum_protocol_version": "TLSv1", "default_certificate": True,
                   "pq_group_supported": True, "pq_groups": [], "internet_facing": True}},
        {"type": "api_tls", "name": "api.payments.example", "protocol": "TLS",
         "location": "arn:aws:apigateway:ap-south-1::/domainnames/api.payments.example",
         "facts": {"security_policy": "TLS_1_2", "protocols": ["TLSv1.2", "TLSv1.3"], "min_version": "TLSv1.2",
                   "endpoint_types": ["REGIONAL"], "internet_facing": True}},
        {"type": "cloud_secret", "name": "rds-db-credentials/payments",
         "location": f"arn:aws:secretsmanager:ap-south-1:{ACCOUNT}:secret:rds-db-credentials/payments-sky7kF",
         "facts": {"rotation_enabled": False, "kms_key_id": "aws/secretsmanager", "last_rotated": None}},
        {"type": "cloud_secret", "name": "/payments/db_password",
         "location": f"arn:aws:ssm:ap-south-1:{ACCOUNT}:parameter/payments/db_password",
         "facts": {"service": "ssm", "parameter_type": "String", "kms_key_id": None, "tier": "Standard",
                   "secret_like_name": True}},
        {"type": "cloud_ca", "name": "CN=ZeroShield-AWS-PCA-Test", "algorithm": "RSA", "key_size": 2048,
         "location": f"arn:aws:acm-pca:ap-south-1:{ACCOUNT}:certificate-authority/ca429b08",
         "facts": {"key_alg": "RSA_2048", "sig_alg": "SHA256WITHRSA", "status": "ACTIVE", "ca_type": "ROOT",
                   "not_after": "2027-11-17T11:49:20Z", "not_before": "2026-11-17T10:49:20Z", "is_ca": True,
                   "source": "aws"}},
    ]),
    "GCP project": ("gcp_project", 52, [
        {"type": "kms_key", "name": "key-symmetric-unrotated", "algorithm": "AES", "key_size": 256,
         "location": "projects/acme-cbom/locations/asia-south1/keyRings/ring/cryptoKeys/key-symmetric-unrotated",
         "facts": {"provider": "gcp", "key_spec": "SYMMETRIC_DEFAULT", "provider_algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION",
                   "purpose": "ENCRYPT_DECRYPT", "key_usage": "ENCRYPT_DECRYPT", "protection_level": "SOFTWARE",
                   "hsm_backed": False, "key_manager": "CUSTOMER", "key_state": "Enabled", "rotation_enabled": False,
                   "rotation_period": None, "destroy_scheduled_duration": "2592000s"}},
        {"type": "storage_encryption", "name": "acme-exports",
         "location": "//storage.googleapis.com/projects/_/buckets/acme-exports",
         "facts": {"provider": "gcp", "resource": "Cloud Storage bucket acme-exports", "encrypted": True,
                   "kms_key_id": "google-managed", "location": "ASIA-SOUTH1"}},
        {"type": "load_balancer_tls", "name": "web-https-proxy", "protocol": "HTTPS",
         "location": "https://www.googleapis.com/compute/v1/projects/acme-cbom/global/targetHttpsProxies/web",
         "facts": {"provider": "gcp", "ssl_policy": None, "default_policy": True, "min_tls_version": "TLS_1_0",
                   "protocols": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"], "ciphers": [],
                   "internet_facing": True}},
        {"type": "cloud_secret", "name": "dummy-api-key-with-expiry",
         "location": "projects/749998518357/secrets/dummy-api-key-with-expiry",
         "facts": {"provider": "gcp", "rotation_enabled": False, "rotation_period": None,
                   "kms_key_id": "google-managed", "replication": "automatic", "expires": "2027-01-12T12:50:14Z"}},
    ]),
    "Azure subscription": ("azure_subscription", 52, [
        {"type": "kms_key", "name": "tde-protector", "algorithm": "RSA", "key_size": 3072,
         "location": "https://acme-kv.vault.azure.net/keys/tde-protector",
         "facts": {"provider": "azure", "vault": "acme-kv", "key_spec": "RSA-HSM 3072", "kty": "RSA-HSM",
                   "key_ops": ["wrapKey", "unwrapKey"], "hsm_backed": True, "key_manager": "CUSTOMER",
                   "key_state": "Enabled", "rotation_enabled": True, "rotation_interval": "P90D",
                   "recovery_level": "Recoverable+Purgeable"}},
        {"type": "storage_encryption", "name": "acmelogs",
         "location": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acmelogs",
         "facts": {"provider": "azure", "resource": "Storage account acmelogs", "encrypted": True,
                   "key_source": "Microsoft.Storage", "kms_key_id": "microsoft-managed"}},
        {"type": "cloud_secret", "name": "db-conn",
         "location": "https://acme-kv.vault.azure.net/secrets/db-conn",
         "facts": {"provider": "azure", "vault": "acme-kv", "enabled": True, "expires": None,
                   "rotation_enabled": None}},
        {"type": "key_vault", "name": "acme-kv",
         "location": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/acme-kv",
         "facts": {"provider": "azure", "sku": "premium", "soft_delete_enabled": True, "purge_protection": False,
                   "public_network_access": "Enabled", "internet_facing": True}},
    ]),
    "OCI tenancy": ("oci_tenancy", 52, [
        {"type": "kms_key", "name": "oci-master", "algorithm": "AES", "key_size": 256,
         "location": "oci://ap-mumbai-1/kms/ocid1.key.oc1.ap-mumbai-1.aaaa",
         "facts": {"provider": "oci", "key_spec": "SYMMETRIC_DEFAULT", "protection_level": "HSM", "hsm_backed": True,
                   "key_manager": "CUSTOMER", "key_state": "Enabled", "rotation_enabled": None,
                   "auto_rotation_supported": False, "vault": "acme-vault"}},
        {"type": "storage_encryption", "name": "oci-backups",
         "location": "oci://ap-mumbai-1/objectstorage/ns/oci-backups",
         "facts": {"provider": "oci", "resource": "Object Storage bucket oci-backups", "encrypted": True,
                   "kms_key_id": "oracle-managed"}},
        {"type": "load_balancer_tls", "name": "oci-lb:443", "protocol": "HTTP",
         "location": "oci://ap-mumbai-1/loadbalancer/ocid1.lb/listener/https",
         "facts": {"provider": "oci", "listener": "https", "port": 443, "protocols": ["TLSv1.2"],
                   "cipher_suite": "oci-modern-ssl-cipher-suite-v1", "ciphers": ["ECDHE-RSA-AES256-GCM-SHA384"],
                   "static_rsa_kex": False}},
        {"type": "cloud_secret", "name": "oci-db-password",
         "location": "oci://ap-mumbai-1/secrets/ocid1.vaultsecret.oc1",
         "facts": {"provider": "oci", "kms_key_id": "ocid1.key.oc1.ap-mumbai-1.aaaa", "rotation_enabled": True,
                   "rotation_period": "P30D"}},
    ]),
    "HashiCorp Vault": ("key_manager", 52, [
        {"type": "managed_key", "name": "legacy-rsa", "algorithm": "RSA", "key_size": 2048,
         "location": "https://10.232.0.32:8200/transit/keys/legacy-rsa",
         "facts": {"type": "rsa-2048", "exportable": True, "allow_plaintext_backup": True, "deletion_allowed": False,
                   "auto_rotate_period": 0, "auto_rotate_period_s": 0, "store": "vault_transit", "mount": "transit",
                   "key_class": "private", "versions": 1}},
        {"type": "key_store", "name": "Vault transit transit", "location": "https://10.232.0.32:8200/transit",
         "facts": {"store": "vault_transit", "mount": "transit", "keys": 3}},
    ]),
    "HSM token lab-a": ("hsm", 52, [
        {"type": "managed_key", "name": "aes256-data", "algorithm": "AES", "key_size": 256,
         "location": "pkcs11:softhsm/lab-a/secret/aes256-data",
         "facts": {"store": "pkcs11", "key_class": "secret", "key_type": "AES", "sensitive": False,
                   "extractable": False, "encrypt": True, "decrypt": True, "sign": True, "verify": True,
                   "module": "softhsm", "token_serial": "036179330f17f131"}},
        {"type": "key_store", "name": "lab-a", "location": "pkcs11:softhsm/lab-a",
         "facts": {"store": "pkcs11", "module": "softhsm", "library_manufacturer": "SoftHSM", "library_version": "2.6",
                   "cryptoki_version": "2.40", "token_label": "lab-a", "token_model": "SoftHSM v2",
                   "logged_in": True, "objects": {"PUBLIC_KEY": 2, "SECRET_KEY": 2, "PRIVATE_KEY": 2}}},
    ]),
    "KMIP lab": ("key_manager", 52, [
        {"type": "managed_key", "name": "lab-3des", "algorithm": "3DES", "key_size": 192,
         "location": "kmip://10.232.0.31:5696/3",
         "facts": {"uid": "3", "object_type": "Symmetric Key", "algorithm": "3DES", "length": 192,
                   "usage": ["Encrypt", "Decrypt"], "state": "Pre-Active", "sensitive": False, "store": "kmip",
                   "key_class": "secret", "key_state": "Pre-Active"}},
        {"type": "key_store", "name": "PyKMIP 0.10.0 Software Server", "location": "kmip://10.232.0.31:5696",
         "facts": {"store": "kmip", "protocol_version": "2.0", "vendor": "PyKMIP 0.10.0 Software Server",
                   "objects": {"Symmetric Key": 3, "Public Key": 1, "Private Key": 1}}},
    ]),
    "SQL Server 2022": ("databases", 52, [
        {"type": "db_encryption", "name": "labdb", "algorithm": "AES", "key_size": 256,
         "location": "10.232.0.22:1433/labdb#tde",
         "facts": {"engine": "mssql", "scope": "database", "database": "labdb", "state": "ONLINE",
                   "encrypted": True, "tde_state": "encrypted", "encryptor_type": "CERTIFICATE"}},
        {"type": "managed_key", "name": "LabTdes", "algorithm": "3DES", "key_size": 128,
         "location": "10.232.0.22:1433/labdb#symmetric_key/LabTdes",
         "facts": {"store": "mssql", "engine": "mssql", "database": "labdb", "key_class": "secret",
                   "algorithm_desc": "TRIPLE_DES"}},
    ]),
    "Oracle 23": ("databases", 52, [
        {"type": "db_encryption", "name": "USERS", "location": "10.232.0.23:1521/USERS#tde",
         "facts": {"engine": "oracle", "scope": "tablespace", "tablespace": "USERS", "encrypted": False,
                   "algorithm_desc": None}},
    ]),
    "MySQL 8.4": ("databases", 52, [
        {"type": "database_config", "name": "MySQL 8.4.13", "protocol": "mysql", "location": "10.232.0.21:3306",
         "facts": {"engine": "mysql", "variables": {"default_table_encryption": "OFF", "binlog_encryption": "OFF",
                                                     "require_secure_transport": "OFF", "version": "8.4.13"},
                   "keyring_plugins": [], "encrypted_tables": [], "encrypted_tables_visible_only": True}},
    ]),
    "PostgreSQL 16": ("databases", 52, [
        {"type": "database_config", "name": "PostgreSQL 16.15", "location": "10.232.0.20:5432",
         "facts": {"engine": "postgres", "settings": {"ssl": "on", "ssl_min_protocol_version": "TLSv1.2",
                                                      "password_encryption": "scram-sha-256"},
                   "extensions": [{"name": "plpgsql", "version": "1.0"}, {"name": "pgcrypto", "version": "1.3"}]}},
    ]),
    "MongoDB 7": ("databases", 52, [
        {"type": "database_config", "name": "MongoDB 7.0.12", "protocol": "mongodb", "location": "10.232.0.24:27017",
         "facts": {"engine": "mongodb", "version": "7.0.12", "tls": True, "tls_verified": True,
                   "options": {"net.tls.mode": "requireTLS", "security.authorization": "enabled"},
                   "auth_required": True}},
    ]),
    "Redis 7": ("databases", 52, [
        {"type": "database_config", "name": "Redis 7.2.4", "protocol": "redis", "location": "10.232.0.25:6379",
         "facts": {"engine": "redis", "info": {"redis_version": "7.2.4"}, "tls": False}},
    ]),
    "Linux web server": ("linux_servers", 52, [
        {"type": "disk_encryption", "name": "data_crypt", "algorithm": "aes-xts-plain64", "key_size": 512,
         "location": "/dev/mapper/data_crypt",
         "facts": {"name": "data_crypt", "cipher": "aes-xts-plain64", "effective_key_bits": 512,
                   "device": "/dev/sdb1", "luks_version": 2}},
        {"type": "crypto_library", "name": "libssl3t64", "location": "package:libssl3t64",
         "facts": {"name": "libssl3t64", "version": "3.0.13-0ubuntu3.16", "source": "package"}},
        {"type": "process_library", "name": "sshd", "location": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
         "facts": {"exe": "/usr/sbin/sshd", "lib": "/usr/lib/x86_64-linux-gnu/libcrypto.so.3", "pids": [1],
                   "deleted": False, "ports": [22], "process": "sshd"}},
    ]),
    "Windows file server": ("windows_servers", 52, [
        {"type": "disk_encryption", "name": "D:", "algorithm": "XtsAes128", "location": "bitlocker:D:",
         "facts": {"mount": "D:", "method": "XtsAes128", "status": "FullyEncrypted", "protection": "On",
                   "source": "bitlocker"}},
    ]),
    "Lab registry images": ("container_registry", 52, [
        {"type": "crypto_library", "name": "libcrypto1.1", "location": "package:libcrypto1.1",
         "facts": {"name": "libcrypto1.1", "version": "1.1.1w-r1", "source": "container_image",
                   "package_manager": "apk", "image": "registry.lab/alpine:3.16",
                   "purl": "pkg:apk/alpine/libcrypto1.1@1.1.1w-r1?arch=x86_64&distro=alpine-3.16.9"}},
    ]),
    "Lab registry mirror": ("container_registry", 52, [  # the same package in a second registry: one component
        {"type": "crypto_library", "name": "libcrypto1.1", "location": "package:libcrypto1.1",
         "facts": {"name": "libcrypto1.1", "version": "1.1.1w-r1", "source": "container_image",
                   "package_manager": "apk", "image": "mirror.lab/alpine:3.16",
                   "purl": "pkg:apk/alpine/libcrypto1.1@1.1.1w-r1?arch=aarch64&distro=alpine-3.16.9"}},
    ]),
    # the scan node's read-only AD collector (#488): shapes from a Samba 4.25 AD DC (review 6031264030), the domain at
    # level 4 with a krbtgt key from 2025, one account per enctype case; the LDAPS endpoint is D7's (probed), and D6
    # prints its posture beside the domain (#488 review D6 hook-up)
    "Corp Active Directory": ("active_directory", 52, [
        {"type": "ad_domain", "name": "corp.test", "protocol": "kerberos", "location": "ad:corp.test",
         "facts": {"domain": "corp.test", "naming_context": "DC=corp,DC=test", "domain_functional_level": 4,
                   "domain_functional_level_name": "Windows Server 2008 R2", "forest_functional_level": 4,
                   "forest_functional_level_name": "Windows Server 2008 R2",
                   "krbtgt_password_last_set": "2025-01-01T00:00:00Z", "krbtgt_enc_types": [],
                   "dc_operating_systems": ["Windows Server 2016 Datacenter 10.0 (14393)"],
                   "accounts": {"domain_controller_total": 1, "domain_controller_rc4_enabled": 1,
                                "domain_controller_aes_enabled": 1, "krbtgt_total": 1, "krbtgt_dc_default": 1,
                                "service_account_total": 5, "service_account_rc4_enabled": 2,
                                "service_account_rc4_only": 1, "service_account_des_enabled": 1,
                                "service_account_dc_default": 2, "service_account_aes_enabled": 1,
                                "computer_total": 12, "computer_dc_default": 4},
                   "samples": {"service_account_rc4_only": ["svc-rc4only"],
                               "service_account_dc_default": ["svc-sql", "svc-zero"]},
                   "enrollment_services": [], "read_from": "dc1.corp.test", "truncated": [],
                   "ldap_signing": "not_readable", "ldap_channel_binding": "not_readable"}},
        {"type": "kerberos_account", "name": "DC1$", "algorithm": "AES256-CTS-HMAC-SHA1-96", "protocol": "kerberos",
         "location": "ad:corp.test/domain_controller/DC1$",
         "facts": {"account_type": "domain_controller", "enc_types": ["RC4-HMAC", "AES128-CTS-HMAC-SHA1-96",
                                                                     "AES256-CTS-HMAC-SHA1-96"],
                   "enc_types_value": 28, "enc_types_source": "attribute", "use_des_key_only": False,
                   "des_enabled": False, "rc4_enabled": True, "aes_enabled": True, "rc4_only": False,
                   "dc_default": False, "weak": True, "account": "DC1$", "dns_host_name": "dc1.corp.test",
                   "password_last_set": "2026-10-30T08:00:00Z", "domain": "corp.test"}},
        {"type": "kerberos_account", "name": "krbtgt", "protocol": "kerberos", "location": "ad:corp.test/krbtgt/krbtgt",
         "facts": {"account_type": "krbtgt", "enc_types": [], "enc_types_value": None, "enc_types_source": "default",
                   "use_des_key_only": False, "des_enabled": False, "rc4_enabled": None, "aes_enabled": None,
                   "rc4_only": None, "dc_default": True, "weak": False, "account": "krbtgt",
                   "password_last_set": "2025-01-01T00:00:00Z", "domain": "corp.test",
                   "judged_by": "domain_functional_level_and_key_age"}},
        {"type": "kerberos_account", "name": "svc-rc4only", "algorithm": "RC4-HMAC", "protocol": "kerberos",
         "location": "ad:corp.test/service_account/svc-rc4only",
         "facts": {"account_type": "service_account", "enc_types": ["RC4-HMAC"], "enc_types_value": 4,
                   "enc_types_source": "attribute", "use_des_key_only": False, "des_enabled": False,
                   "rc4_enabled": True, "aes_enabled": False, "rc4_only": True, "dc_default": False, "weak": True,
                   "account": "svc-rc4only", "password_last_set": "2026-03-02T10:00:00Z", "domain": "corp.test"}},
        {"type": "kerberos_account", "name": "svc-legacy", "algorithm": "RC4-HMAC", "protocol": "kerberos",
         "location": "ad:corp.test/service_account/svc-legacy",
         "facts": {"account_type": "service_account", "enc_types": ["DES-CBC-CRC", "DES-CBC-MD5", "RC4-HMAC"],
                   "enc_types_value": 7, "enc_types_source": "attribute", "use_des_key_only": False,
                   "des_enabled": True, "rc4_enabled": True, "aes_enabled": False, "rc4_only": False,
                   "dc_default": False, "weak": True, "account": "svc-legacy",
                   "password_last_set": "2026-03-02T10:00:00Z", "domain": "corp.test"}},
        {"type": "kerberos_account", "name": "svc-sql", "protocol": "kerberos",
         "location": "ad:corp.test/service_account/svc-sql",
         "facts": {"account_type": "service_account", "enc_types": [], "enc_types_value": None,
                   "enc_types_source": "default", "use_des_key_only": False, "des_enabled": False,
                   "rc4_enabled": None, "aes_enabled": None, "rc4_only": None, "dc_default": True, "weak": False,
                   "account": "svc-sql", "password_last_set": "2026-03-02T10:00:00Z", "domain": "corp.test"}},
        {"type": "kerberos_account", "name": "svc-zero", "protocol": "kerberos",
         "location": "ad:corp.test/service_account/svc-zero",
         "facts": {"account_type": "service_account", "enc_types": [], "enc_types_value": 0,
                   "enc_types_source": "default", "use_des_key_only": False, "des_enabled": False,
                   "rc4_enabled": None, "aes_enabled": None, "rc4_only": None, "dc_default": True, "weak": False,
                   "account": "svc-zero", "password_last_set": "2026-03-02T10:00:00Z", "domain": "corp.test"}},
        {"type": "tls_endpoint", "name": "LDAP LDAPS dc1.corp.test:636", "algorithm": "TLS_AES_256_GCM_SHA384",
         "location": "dc1.corp.test:636",
         "facts": {"service": "ldap", "ldap_tls_mode": "ldaps", "negotiated_version": "TLSv1.3",
                   "negotiated_group": "X25519", "tls": True,
                   "versions": {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": True},
                   "weak_ciphers_accepted": {"obsolete": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
                                             "static_rsa": ["TLS_RSA_WITH_AES_128_GCM_SHA256"]}}},
    ]),
    "Lab network": ("network", 52, [  # a probed endpoint: SOW D7, never a D6 / D9 row
        {"type": "tls_endpoint", "name": "HTTPS 10.232.0.101:443", "algorithm": "TLS_AES_256_GCM_SHA384",
         "location": "10.232.0.101:443",
         "facts": {"service": "tls", "negotiated_version": "TLSv1.3", "negotiated_group": "X25519",
                   "versions": {"SSLv3": False, "TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": True,
                                "TLSv1.3": True},
                   "weak_ciphers_accepted": {"static_rsa": ["TLS_RSA_WITH_AES_128_GCM_SHA256"]}, "tls": True}},
    ]),
}

# what each mapped type must become (posture_mapper), for the per-type tests
MAPPED_KIND = {
    "kms_key": "kms_key", "managed_key": "kms_key", "key_store": "key_store", "glue_catalog": "data_warehouse",
    "load_balancer_tls": "tls_endpoint", "cdn_tls": "tls_endpoint", "api_tls": "tls_endpoint",
    "cloud_secret": "secret_store", "key_vault": "secret_store", "cloud_ca": "certificate_policy",
    "db_encryption": "relational_db", "disk_encryption": "disk_encryption",
    "kerberos_account": "kerberos_account", "ad_domain": "ad_domain",
}


def assets() -> list[tuple[str, str, int, dict[str, Any]]]:
    """``(source name, source kind, run id, asset)`` for every fixture asset."""
    return [(name, kind, run, asset) for name, (kind, run, items) in SOURCES.items() for asset in items]


def build() -> tuple[list[SourcesRow], list[Collection]]:
    rows: list[SourcesRow] = []
    collections: list[Collection] = []
    asset_id = 9000
    for job, (name, (kind, run, items)) in enumerate(SOURCES.items(), start=400):
        ref = f"src-{job}"
        collection = Collection(run_id=run, job_id=job, source_ref=ref, source_name=name, source_kind=kind,
                                observed_at=OBSERVED, asset_count=len(items),
                                endpoints_probed=sum(1 for a in items if a["type"] in ("tls_endpoint",)))
        collections.append(collection)
        for index, item in enumerate(items):
            asset_id += 1
            judged = C.classify(item["type"], item.get("algorithm"), item.get("key_size"), item.get("protocol"),
                                item["facts"], OBSERVED.replace(tzinfo=None))
            stored = SimpleNamespace(
                id=asset_id, asset_type=item["type"], cdx_type=judged["cdx_type"], name=item.get("name"),
                algorithm=item.get("algorithm"), location=item["location"], key_size=item.get("key_size"),
                protocol=item.get("protocol"), quantum_vulnerable=judged["quantum_vulnerable"], facts=item["facts"])
            view = {"impact": judged["impact"], "finding_codes": judged["finding_codes"], "finding": judged["finding"],
                    "impacts": judged["impacts"]}
            rows.append(SourcesRow(row=node_row(stored, collection, view), collection=collection,
                                   identity=f"node|{ref}|key|{index}", node_type=item["type"],
                                   target=item["location"], facts=dict(item["facts"]),
                                   asset_key=f"{ref}-{index}", code_impacts=code_impacts(view)))
    return rows, collections
