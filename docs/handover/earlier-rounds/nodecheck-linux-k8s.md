# Linux, Kubernetes and database collectors vs lab ground truth

## zs-u22 (Ubuntu 22.04, Tier 2, node key, TOFU)

Detect items found: 9/9; no-finding traps respected: 3/3; out of design scope: 7

| GT id | location | expect | pass | note |
|---|---|---|---|---|
| HST-U-001 | /opt/payments/conf/server.key | detect | yes | private-key |
| HST-U-002 | /opt/payments/conf/server.crt | detect | yes | certificate |
| HST-U-003 | /etc/pki/legacy/ca-md5.crt | detect | yes | certificate |
| HST-U-004 | /home/deploy/.ssh/id_rsa | detect | yes | private-key |
| HST-U-005 | /home/deploy/.ssh/id_ed25519 | detect | yes | private-key |
| HST-U-006 | /home/deploy/.ssh/authorized_keys | detect | yes | public-key |
| HST-U-007 | /opt/legacy-app/keystore.jks | detect | yes | keystore |
| HST-U-008 | /opt/legacy-app/truststore.p12 | detect | yes | keystore |
| HST-U-009 | 10.77.0.21:8443 | detect | n/a | tls-endpoint: not collected by design (host config/secret/code files are not read) |
| HST-U-010 | /etc/nginx/conf.d/zs-payments-8443.conf | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-U-011 | zs-stale.service:/opt/stale/libcrypto.so.3 | detect | yes | deleted library mapped to its process |
| HST-U-012 | /etc/systemd/system/zs-payments.service:Environment=AES_KEY | detect | n/a | secret: not collected by design (host config/secret/code files are not read) |
| HST-U-013 | /opt/payments/openssl.cnf | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-U-014 | /opt/legacy-app/java.security.override | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-U-015 | /usr/local/bin/legacy-encrypt.sh:5 | detect | n/a | custom-crypto: not collected by design (host config/secret/code files are not read) |
| HST-U-016 | /etc/cron.d/zs-payments-backup:2 | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-U-017 | /etc/ssl/certs | no-finding | yes | certificate |
| HST-U-018 | /opt/payments/docs/README.md | no-finding | yes | private-key |
| HST-U-019 | /opt/payments/conf/server.pub | no-finding | yes | public-key |

## zs-al2023 (Amazon Linux 2023, hostile profile, Tier 2)

Detect items found: 16/16; no-finding traps respected: 9/9; out of design scope: 7

| GT id | location | expect | pass | note |
|---|---|---|---|---|
| HST-A-001 | /etc/crypto-policies/config | detect | yes | crypto policy |
| HST-A-002 | /opt/payments/conf/server.key | detect | yes | private-key |
| HST-A-003 | /opt/payments/conf/server.crt | detect | yes | certificate |
| HST-A-004 | /etc/pki/legacy/ca-md5.crt | detect | yes | certificate |
| HST-A-005 | /home/deploy/.ssh/id_rsa | detect | yes | private-key |
| HST-A-006 | /home/deploy/.ssh/id_ed25519 | detect | yes | private-key |
| HST-A-007 | /home/deploy/.ssh/authorized_keys | detect | yes | public-key |
| HST-A-008 | /opt/legacy-app/keystore.jks | detect | yes | keystore |
| HST-A-009 | /opt/legacy-app/truststore.p12 | detect | yes | keystore |
| HST-A-010 | 10.77.0.22:8443 | detect | n/a | tls-endpoint: not collected by design (host config/secret/code files are not read) |
| HST-A-011 | /etc/nginx/conf.d/zs-payments-8443.conf | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-A-012 | zs-stale.service:/opt/stale/libcrypto.so.3 | detect | yes | deleted library mapped to its process |
| HST-A-013 | /etc/systemd/system/zs-payments.service:Environment=AES_KEY | detect | n/a | secret: not collected by design (host config/secret/code files are not read) |
| HST-A-014 | /opt/payments/openssl.cnf | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-A-015 | /opt/legacy-app/java.security.override | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-A-016 | /usr/local/bin/legacy-encrypt.sh:5 | detect | n/a | custom-crypto: not collected by design (host config/secret/code files are not read) |
| HST-A-017 | /etc/cron.d/zs-payments-backup:2 | detect | n/a | config: not collected by design (host config/secret/code files are not read) |
| HST-A-018 | /etc/pki/ca-trust/extracted/pem | no-finding | yes | certificate |
| HST-A-019 | /opt/payments/docs/README.md | no-finding | yes | private-key |
| HST-A-020 | /opt/payments/conf/server.pub | no-finding | yes | public-key |
| HST-A-021 | /opt/hostile/server.key | no-finding | yes | hostile file |
| HST-A-022 | /opt/hostile/huge.pem | no-finding | yes | hostile file |
| HST-A-023 | /opt/hostile/loop | no-finding | yes | hostile file |
| HST-A-024 | /opt/hostile/locked/server.key | no-finding | yes | hostile file |
| HST-A-025 | /opt/hostile/names/$(touch /tmp/zs_pwned_HST).pem | detect | yes | hostile file |
| HST-A-026 | /opt/hostile/names/`id`.key | detect | yes | hostile file |
| HST-A-027 | /opt/hostile/names/zs-newline\ninjected.crt | detect | yes | hostile file |
| HST-A-028 | /opt/hostile/names/--help.pem | detect | yes | hostile file |
| HST-A-029 | /opt/hostile/xss/plt07-subject.crt | detect | yes | hostile file |
| HST-A-030 | /opt/hostile/ansi/ansi-comment.pem | detect | yes | hostile file |
| HST-A-031 | /usr/local/bin/openssl | no-finding | yes | hostile file |
| HST-A-032 | /usr/local/bin/ss | no-finding | yes | hostile file |

## zs-k3s (Tier 2 kubeconfig; ConfigMaps from Tier 1 run)

Detect items found: 18/21; no-finding traps respected: 0/0; out of design scope: 5

| GT id | location | expect | pass | note |
|---|---|---|---|---|
| K8S-SEC-tls-weak | k8s://zs-lab/secret/tls-weak | detect | yes | TLS secret |
| K8S-SEC-opaque-with-pem | k8s://zs-lab/secret/opaque-with-pem | detect | NO | TLS secret |
| K8S-CM-app-config | k8s://zs-lab/configmap/app-config | detect | yes | configmap cert/key |
| K8S-ENV-AES_KEY | k8s://zs-lab/deployment/legacy-api#containers/legacy-api/env/AES_KEY | detect | n/a | alg-usage: not collected by design |
| K8S-ENV-HMAC_SECRET | k8s://zs-lab/deployment/legacy-api#containers/legacy-api/env/HMAC_SECR | detect | n/a | alg-usage: not collected by design |
| K8S-IMG-legacy-api | k8s://zs-lab/deployment/legacy-api#containers/legacy-api/image | detect | n/a | dependency: not collected by design |
| K8S-ING-legacy-api-tls-weak | k8s://zs-lab/ingress/legacy-api#tls/tls-weak | detect | yes | ingress TLS |
| K8S-OBS-001 | k8s://kube-system/secret/k3s-serving | detect | yes | TLS secret |
| K8S-OBS-002 | k8s://kube-system/secret/zs-cbom-tier1-token | detect | NO | TLS secret |
| K8S-OBS-003 | k8s://kube-system/secret/zs-cbom-tier2-token | detect | NO | TLS secret |
| K8S-OBS-004 | k8s://cert-manager/configmap/kube-root-ca.crt | detect | yes | configmap cert/key |
| K8S-OBS-005 | k8s://default/configmap/kube-root-ca.crt | detect | yes | configmap cert/key |
| K8S-OBS-006 | k8s://kube-node-lease/configmap/kube-root-ca.crt | detect | yes | configmap cert/key |
| K8S-OBS-007 | k8s://kube-public/configmap/kube-root-ca.crt | detect | yes | configmap cert/key |
| K8S-OBS-008 | k8s://kube-system/configmap/extension-apiserver-authentication | detect | yes | configmap cert/key |
| K8S-OBS-009 | k8s://kube-system/configmap/kube-root-ca.crt | detect | yes | configmap cert/key |
| K8S-OBS-010 | k8s://zs-lab/configmap/kube-root-ca.crt | detect | yes | configmap cert/key |
| K8S-SEC-rsa-2048-tls | k8s://zs-lab/secret/rsa-2048-tls | detect | yes | TLS secret |
| K8S-SEC-ecdsa-256-tls | k8s://zs-lab/secret/ecdsa-256-tls | detect | yes | TLS secret |
| K8S-SEC-tls-expired | k8s://zs-lab/secret/tls-expired | detect | yes | TLS secret |
| K8S-CM-CERT-rsa-2048 | k8s://zs-lab/certificate/rsa-2048 | detect | yes | cert-manager Certificate |
| K8S-CM-CERT-ecdsa-256 | k8s://zs-lab/certificate/ecdsa-256 | detect | yes | cert-manager Certificate |
| K8S-ING-modern-api-rsa-2048-tls | k8s://zs-lab/ingress/modern-api#tls/rsa-2048-tls | detect | yes | ingress TLS |
| K8S-ING-modern-api-tls-expired | k8s://zs-lab/ingress/modern-api#tls/tls-expired | detect | yes | ingress TLS |
| K8S-RBAC-product-tier1 | k8s://zs-cbom/serviceaccount/zs-cbom | no-finding | n/a | config: not collected by design |
| K8S-RBAC-product-tier2 | k8s://zs-cbom-t2/serviceaccount/zs-cbom | no-finding | n/a | config: not collected by design |

