"""Cloud collector finding codes (WP4): AWS Glue, RDS parameter groups, Azure Key Vault.

Rules: backend/utilities/cbom_sources/classify_ext/cloud.py (Glue, Key Vault) and classify.py (database_config).
"""
from kb_text import entry

V_GLUE_CATALOG = [{"label": "Data Catalog encryption settings (no secrets)",
                   "command": "aws glue get-data-catalog-encryption-settings --query DataCatalogEncryptionSettings"}]
V_GLUE_CONNECTION = [{"label": "Connection properties without the password",
                      "command": "aws glue get-connection --name {name} --hide-password --query 'Connection.ConnectionProperties | keys(@)'"}]
V_RDS_PARAMS = [{"label": "Effective RDS parameters",
                 "command": "aws rds describe-db-parameters --db-parameter-group-name <group> --query \"Parameters[?ParameterName=='rds.accepted_password_auth_method' || ParameterName=='password_encryption' || ParameterName=='rds.force_ssl'].[ParameterName,ParameterValue]\""}]
V_KEY_VAULT = [{"label": "Vault protection settings",
                "command": "az keyvault show --name {name} --query '{softDelete:properties.enableSoftDelete, purgeProtection:properties.enablePurgeProtection, publicNetworkAccess:properties.publicNetworkAccess, defaultAction:properties.networkAcls.defaultAction}'"}]

entry("GLUE_CATALOG_UNENCRYPTED", title="Glue Data Catalog not encrypted with KMS", category="cloud", default_impact="Medium",
      description="The AWS Glue Data Catalog in this region has CatalogEncryptionMode DISABLED, so its metadata (databases, table "
                  "definitions, and connection definitions with their properties) is not encrypted with a KMS key you control.",
      attack="Catalog metadata, including connection definitions, is readable to any principal with Glue read access and is "
             "not covered by a KMS key policy or by CloudTrail records of key use.",
      cwe=["CWE-311"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["at_rest"],
      remediation={"summary": "Turn on Data Catalog encryption (SSE-KMS) and connection password encryption in the Glue console "
                              "(Data Catalog settings) or with aws glue put-data-catalog-encryption-settings.", "steps": [
          {"platform": "AWS CLI", "how": "aws glue put-data-catalog-encryption-settings --data-catalog-encryption-settings "
                                         "'EncryptionAtRest={CatalogEncryptionMode=SSE-KMS,SseAwsKmsKeyId=<key arn>},"
                                         "ConnectionPasswordEncryption={ReturnConnectionPasswordEncrypted=true,AwsKmsKeyId=<key arn>}'"}]},
      verify=V_GLUE_CATALOG, references=["https://docs.aws.amazon.com/glue/latest/dg/encrypt-glue-data-catalog.html"])
entry("GLUE_PLAINTEXT_PASSWORD", title="Glue connection password stored in plain text", category="cloud", default_impact="High",
      description="A Glue connection keeps its database password in the connection itself (no Secrets Manager SECRET_ID) and the "
                  "password was not encrypted: connection password encryption was off when the connection was created or last "
                  "updated, so GetConnection returns it in clear text.",
      attack="Any principal allowed glue:GetConnection(s) (read-only auditors included) can read the database password and "
             "log in to the database directly.",
      cwe=["CWE-312", "CWE-522"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["key_mgmt", "at_rest"],
      remediation={"summary": "Store the credentials in Secrets Manager and reference them from the connection (SECRET_ID); "
                              "turn on connection password encryption; rotate the database password, because it was readable.",
                   "steps": [
          {"platform": "AWS Glue", "how": "Edit the connection, choose 'Use AWS Secrets Manager' for credentials and pick the secret, then save"},
          {"platform": "Data Catalog", "how": "Glue console > Data Catalog settings > Encrypt connection passwords (symmetric KMS key)"}]},
      verify=V_GLUE_CONNECTION, references=["https://docs.aws.amazon.com/glue/latest/dg/encrypt-connection-passwords.html"])
entry("GLUE_JDBC_NO_TLS", title="Glue JDBC connection does not enforce TLS", category="cloud", default_impact="Medium",
      description="The Glue JDBC connection has JDBC_ENFORCE_SSL unset or false and its URL does not require TLS, so Glue jobs "
                  "may connect to the database without TLS and without checking the server's certificate.",
      attack="On the network path between Glue and the database, credentials and query results can be read or changed.",
      cwe=["CWE-319", "CWE-295"], owasp=["crypto", "misconfig"], cves=[], standards=["NIST SP 800-52 Rev. 2"], compliance=["in_transit"],
      remediation={"summary": "Set 'Require SSL connection' on the connection (JDBC_ENFORCE_SSL=true) and, for a private CA, "
                              "CUSTOM_JDBC_CERT; also require TLS on the database itself.", "steps": []},
      verify=V_GLUE_CONNECTION, references=["https://docs.aws.amazon.com/glue/latest/webapi/API_Connection.html"])
entry("DB_MD5_ACCEPTED", title="Database still accepts md5 password authentication", category="database", default_impact="Medium",
      description="RDS for PostgreSQL rds.accepted_password_auth_method is md5+scram, so roles whose password is stored as an "
                  "MD5 hash can still log in with the md5 method instead of SCRAM-SHA-256.",
      attack="An md5 hash (salted only with the role name) taken from a backup or pg_authid can be replayed as the password, "
             "and md5 challenge-response captures are cheap to brute-force.",
      cwe=["CWE-916", "CWE-328"], owasp=["crypto", "auth"], cves=[], standards=["RFC 7677"], compliance=["auth"],
      remediation={"summary": "Reset every role's password with password_encryption = scram-sha-256, then set "
                              "rds.accepted_password_auth_method = scram in the parameter group.", "steps": [
          {"platform": "RDS PostgreSQL", "how": "aws rds modify-db-parameter-group --db-parameter-group-name <group> --parameters "
                                                "ParameterName=rds.accepted_password_auth_method,ParameterValue=scram,ApplyMethod=immediate"}]},
      verify=V_RDS_PARAMS, references=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL_Password_Encryption_configuration.html"])
entry("KV_SOFT_DELETE_OFF", title="Key Vault soft delete off", category="cloud", default_impact="High",
      description="The Azure Key Vault has soft delete disabled, so a deleted key, secret or certificate is removed immediately.",
      attack="One delete call (by a compromised or careless principal) destroys keys and makes the data they protect unrecoverable.",
      cwe=["CWE-320"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Enable soft delete and purge protection on the vault (az keyvault update --enable-purge-protection true).",
                   "steps": []}, verify=V_KEY_VAULT, references=[])
entry("KV_NO_PURGE_PROTECTION", title="Key Vault purge protection off", category="cloud", default_impact="Medium",
      description="The Azure Key Vault has soft delete but not purge protection, so a soft-deleted key can be purged before its "
                  "retention period ends.",
      attack="An insider or compromised principal can delete and then purge keys, permanently destroying the data they protect.",
      cwe=["CWE-320"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "az keyvault update --name {name} --enable-purge-protection true (it cannot be turned off again).",
                   "steps": []}, verify=V_KEY_VAULT, references=[])
entry("KV_PUBLIC_NETWORK", title="Key Vault open to every network", category="cloud", default_impact="Low",
      description="The Azure Key Vault allows public network access and its firewall default action is Allow.",
      attack="Anyone who obtains a token for the vault can use it from any network; the vault firewall does not limit where keys "
             "and secrets are reached from.",
      cwe=["CWE-668"], owasp=["misconfig"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Set the vault firewall default action to Deny and allow only your networks or a private endpoint "
                              "(az keyvault update --default-action Deny).", "steps": []}, verify=V_KEY_VAULT, references=[])

NODE_CODES = ["GLUE_CATALOG_UNENCRYPTED", "GLUE_PLAINTEXT_PASSWORD", "GLUE_JDBC_NO_TLS", "DB_MD5_ACCEPTED",
              "KV_SOFT_DELETE_OFF", "KV_NO_PURGE_PROTECTION", "KV_PUBLIC_NETWORK"]
