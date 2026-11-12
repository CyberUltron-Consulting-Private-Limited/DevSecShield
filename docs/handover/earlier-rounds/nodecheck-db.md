# Database collector vs lab ground truth (zs-pg, zs-pg-notls, zs-mysql, zs-redis, zs-mongo)

Run with the node CLI against fork B's lab (TLS verified against lab/ca/root.crt, require_tls=true, least-privilege logins).

| GT item | expected | node result | pass |
|---|---|---|---|
| zs-pg 10.77.0.40:5432 tls-endpoint | STARTTLS, TLS1.3, RSA-2048 sha256 cert | TLSv1.3 TLS_AES_256_GCM_SHA384 group prime256v1; leaf RSA 2048 sha256WithRSAEncryption; root RSA 3072 | yes |
| zs-pg role legacy_app md5 hash | superuser only -> report setting + HBA instead | coverage "role password hash types: denied (permission denied for table pg_authid)"; HBA methods {trust 1, scram 3, md5 1} | yes |
| zs-pg pg_hba line4 md5 | detect | hba_rules include host legacy_app md5 | yes |
| zs-pg password_encryption scram-sha-256 | no-finding (correct value) | settings.password_encryption = scram-sha-256 | yes |
| zs-pg pgcrypto extension | detect | extensions: plpgsql, pgcrypto 1.3 | yes |
| zs-pg-notls 10.77.0.44 | require_tls: TLS unavailable, password NOT sent | target status tls_unavailable "the server does not offer TLS; the password was not sent"; job failure (refund path); no connection from zs_cbom in the server log | yes |
| zs-mysql 10.77.0.41:3306 tls-endpoint | require_secure_transport ON, TLS1.2/1.3, EC P-256 cert | TLSv1.3; leaf EC 256 (secp256r1); variables require_secure_transport ON, tls_version TLSv1.2,TLSv1.3 | yes |
| zs-mysql user legacy@% mysql_native_password | detect | users list: legacy -> mysql_native_password (plugins: native 1, caching_sha2 6) | yes |
| zs-mysql user zs_cbom caching_sha2 | no-finding | zs_cbom -> caching_sha2_password | yes |
| zs-mysql default_table_encryption OFF | detect | default_table_encryption OFF, binlog/redo/undo encryption OFF, no keyring plugin | yes |
| zs-mysql authentication_string | never read | query selects user, host, plugin, ssl_type only; secret files mysql_root/mysql_zs_cbom appear 0 times in output | yes |
| zs-redis 10.77.0.42:6379 tls-endpoint | TLS only, TLSv1.2/1.3 | TLSv1.3; tls-port 6379, port 0, tls-protocols "TLSv1.2 TLSv1.3", tls-auth-clients no | yes |
| zs-redis requirepass | must never appear | only explicit tls-* names requested; redis_default / redis_zs_cbom secrets appear 0 times | yes |
| zs-mongo 10.77.0.43:27017 tls-endpoint | requireTLS, TLS1_0/1_1 disabled, RSA-3072 | TLSv1.3; leaf RSA 3072; options net.tls.mode requireTLS, disabledProtocols TLS1_0,TLS1_1 | yes |
| zs-mongo security.authorization enabled, no encryption at rest | detect | security.authorization enabled; security.enableEncryption absent | yes |
| zs-mongo legacy SCRAM-SHA-1 user | not readable with clusterMonitor | not reported (no usersInfo call) | yes (no-finding) |

Connection tests (test_connection): pg, mysql, redis, mongo -> ready; pg-notls -> tls_unavailable.
