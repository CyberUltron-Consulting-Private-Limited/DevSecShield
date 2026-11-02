# Supported formats

File names select a class. The coverage table then names the native types the verdict engine consults. Terraform and CloudFormation names for one row share one semantic rule.

## File classes

<!-- table:file-classes -->
| path | class |
| --- | --- |
| main.tf | terraform |
| main.tf.json | terraform |
| dev.tfvars | terraform |
| Dockerfile | dockerfile |
| docker-compose.yml | compose |
| sshd_config | ssh |
| postgresql.conf | database |
| pg_hba.conf | database |
| my.cnf | database |
| mongod.conf | database |
| elasticsearch.yml | database |
| redis.conf | database |
| crypttab | disk |
| schema.sql | sql |
| CODEOWNERS | business |
| cbom-mapping.yaml | business |
| nginx.conf | web-server |
| httpd.conf | web-server |
| haproxy.cfg | web-server |
| envoy.yaml | web-server |
| server.xml | application-server |
| app.py | source |
| deploy.sh | shell |

## Skipped directories

These directory names are skipped at any depth, by every lane of a code scan (one shared walk that never follows a
symbolic link). `build`, `dist`, `node_modules` and `vendor` are third-party or build output: the scan option
"Scan vendored and build directories" reads them too. What a scan left out is reported as `crypto:coverage:*`
properties on the CBOM.

<!-- table:skip-dirs -->
| name |
| --- |
| .aws-sam |
| .git |
| .hg |
| .mypy_cache |
| .next |
| .nuxt |
| .pytest_cache |
| .serverless |
| .svn |
| .terraform |
| .terragrunt-cache |
| .tox |
| .venv |
| __pycache__ |
| build |
| cdk.out |
| dist |
| node_modules |
| site-packages |
| target |
| vendor |
| venv |

## Database settings

<!-- table:db-settings -->
| software | setting | treatment |
| --- | --- | --- |
| elasticsearch | xpack.security.enabled | layer |
| elasticsearch | xpack.security.http.ssl.cipher_suites | cipher_list |
| elasticsearch | xpack.security.http.ssl.client_authentication | client_auth |
| elasticsearch | xpack.security.http.ssl.enabled | layer |
| elasticsearch | xpack.security.http.ssl.supported_protocols | protocol_set |
| elasticsearch | xpack.security.http.ssl.verification_mode | verification |
| elasticsearch | xpack.security.transport.ssl.cipher_suites | cipher_list |
| elasticsearch | xpack.security.transport.ssl.client_authentication | client_auth |
| elasticsearch | xpack.security.transport.ssl.enabled | layer |
| elasticsearch | xpack.security.transport.ssl.supported_protocols | protocol_set |
| elasticsearch | xpack.security.transport.ssl.verification_mode | verification |
| mariadb | aria_encrypt_tables | layer |
| mariadb | encrypt_binlog | layer |
| mariadb | encrypt_tmp_files | layer |
| mariadb | file_key_management | evidence |
| mariadb | innodb_encrypt_log | layer |
| mariadb | innodb_encrypt_tables | layer |
| mariadb | plugin_load_add | evidence |
| mariadb | require_secure_transport | layer |
| mariadb | skip_ssl | layer |
| mariadb | ssl | layer |
| mariadb | ssl_ca | attr:ca_declared |
| mariadb | ssl_cert | cert_link |
| mariadb | ssl_cipher | cipher_list |
| mariadb | ssl_key | attr:key_file_declared |
| mariadb | tls_version | protocol_set |
| mongodb | net.ssl.CAFile | attr:ca_declared |
| mongodb | net.ssl.allowConnectionsWithoutCertificates | client_auth |
| mongodb | net.ssl.allowInvalidCertificates | verification |
| mongodb | net.ssl.allowInvalidHostnames | verification |
| mongodb | net.ssl.certificateKeyFile | cert_link |
| mongodb | net.ssl.disabledProtocols | protocol_set |
| mongodb | net.ssl.mode | layer |
| mongodb | net.tls.CAFile | attr:ca_declared |
| mongodb | net.tls.allowConnectionsWithoutCertificates | client_auth |
| mongodb | net.tls.allowInvalidCertificates | verification |
| mongodb | net.tls.allowInvalidHostnames | verification |
| mongodb | net.tls.certificateKeyFile | cert_link |
| mongodb | net.tls.disabledProtocols | protocol_set |
| mongodb | net.tls.mode | layer |
| mongodb | security.enableEncryption | layer |
| mongodb | security.encryptionCipherMode | attr:encryption_cipher_mode |
| mongodb | security.encryptionKeyFile | evidence |
| mongodb | security.kmip | evidence |
| mysql | binlog_encryption | layer |
| mysql | default_table_encryption | layer |
| mysql | early-plugin-load | evidence |
| mysql | early_plugin_load | evidence |
| mysql | innodb_encrypt_log | layer |
| mysql | innodb_encrypt_tables | layer |
| mysql | keyring_* | evidence |
| mysql | plugin-load-add | evidence |
| mysql | plugin_load_add | evidence |
| mysql | require_secure_transport | layer |
| mysql | skip_ssl | layer |
| mysql | ssl | layer |
| mysql | ssl_ca | attr:ca_declared |
| mysql | ssl_cert | cert_link |
| mysql | ssl_cipher | cipher_list |
| mysql | ssl_key | attr:key_file_declared |
| mysql | tls_version | protocol_set |
| postgresql | host | layer |
| postgresql | hostgssenc | layer |
| postgresql | hostnossl | layer |
| postgresql | hostssl | layer |
| postgresql | ssl | layer |
| postgresql | ssl_cert_file | cert_link |
| postgresql | ssl_ciphers | cipher_list |
| postgresql | ssl_dh_params_file | dh_file |
| postgresql | ssl_ecdh_curve | curves |
| postgresql | ssl_key_file | attr:key_file_declared |
| postgresql | ssl_max_protocol_version | protocol_set |
| postgresql | ssl_min_protocol_version | protocol_set |
| postgresql | ssl_prefer_server_ciphers | attr:prefer_server_ciphers |
| redis | port | layer |
| redis | tls-auth-clients | client_auth |
| redis | tls-ciphers | cipher_list |
| redis | tls-ciphersuites | cipher_list |
| redis | tls-cluster | attr:tls_cluster |
| redis | tls-port | layer |
| redis | tls-prefer-server-ciphers | attr:prefer_server_ciphers |
| redis | tls-protocols | protocol_set |
| redis | tls-replication | attr:tls_replication |

## Coverage table

<!-- table:coverage -->
| id | provider | kind | terraform | cloudformation | kubernetes | compose |
| --- | --- | --- | --- | --- | --- | --- |
| aws.acm | aws | certificate_policy | aws_acm_certificate | AWS::CertificateManager::Certificate | - | - |
| aws.acmpca | aws | certificate_policy | aws_acmpca_certificate_authority | AWS::ACMPCA::CertificateAuthority | - | - |
| aws.alb.listener | aws | tls_endpoint | aws_alb_listener | - | - | - |
| aws.ami.copy | aws | backup | aws_ami_copy | - | - | - |
| aws.apigw | aws | tls_endpoint | aws_api_gateway_domain_name | AWS::ApiGateway::DomainName | - | - |
| aws.apigwv2 | aws | tls_endpoint | aws_apigatewayv2_domain_name | AWS::ApiGatewayV2::DomainName | - | - |
| aws.backup.vault | aws | backup | aws_backup_vault | AWS::Backup::BackupVault | - | - |
| aws.cloudfront | aws | tls_endpoint | aws_cloudfront_distribution | AWS::CloudFront::Distribution | - | - |
| aws.cloudtrail | aws | log_store | aws_cloudtrail | AWS::CloudTrail::Trail | - | - |
| aws.db.snapshot_copy | aws | backup | aws_db_snapshot_copy | - | - | - |
| aws.docdb | aws | relational_db | aws_docdb_cluster | AWS::DocDB::DBCluster | - | - |
| aws.dynamodb | aws | nosql_db | aws_dynamodb_table | AWS::DynamoDB::Table | - | - |
| aws.ebs.default | aws | block_volume | aws_ebs_encryption_by_default | - | - | - |
| aws.ebs.default_key | aws | block_volume | aws_ebs_default_kms_key | - | - | - |
| aws.ebs.snapshot_copy | aws | backup | aws_ebs_snapshot_copy | - | - | - |
| aws.ebs.volume | aws | block_volume | aws_ebs_volume | AWS::EC2::Volume | - | - |
| aws.ec2.instance | aws | block_volume | aws_instance | AWS::EC2::Instance | - | - |
| aws.ec2.launch_configuration | aws | block_volume | aws_launch_configuration | AWS::AutoScaling::LaunchConfiguration | - | - |
| aws.ec2.launch_template | aws | block_volume | aws_launch_template | AWS::EC2::LaunchTemplate | - | - |
| aws.efs | aws | file_system | aws_efs_file_system | AWS::EFS::FileSystem | - | - |
| aws.eks | aws | k8s_secrets_etcd | aws_eks_cluster | AWS::EKS::Cluster | - | - |
| aws.elasticache | aws | cache | aws_elasticache_replication_group | AWS::ElastiCache::ReplicationGroup | - | - |
| aws.elasticsearch | aws | search_index | aws_elasticsearch_domain | AWS::Elasticsearch::Domain | - | - |
| aws.elb | aws | tls_endpoint | aws_elb | AWS::ElasticLoadBalancing::LoadBalancer | - | - |
| aws.firehose | aws | data_stream | aws_kinesis_firehose_delivery_stream | AWS::KinesisFirehose::DeliveryStream | - | - |
| aws.kinesis | aws | data_stream | aws_kinesis_stream | AWS::Kinesis::Stream | - | - |
| aws.kms.alias | aws | kms_key | aws_kms_alias | AWS::KMS::Alias | - | - |
| aws.kms.external | aws | kms_key | aws_kms_external_key | - | - | - |
| aws.kms.grant | aws | kms_key | aws_kms_grant | - | - | - |
| aws.kms.key | aws | kms_key | aws_kms_key | AWS::KMS::Key | - | - |
| aws.kms.replica | aws | kms_key | aws_kms_replica_key | - | - | - |
| aws.lb.listener | aws | tls_endpoint | aws_lb_listener | AWS::ElasticLoadBalancingV2::Listener | - | - |
| aws.lb.ssl_policy | aws | tls_endpoint | aws_lb_ssl_negotiation_policy | - | - | - |
| aws.logs | aws | log_store | aws_cloudwatch_log_group | AWS::Logs::LogGroup | - | - |
| aws.memorydb | aws | cache | aws_memorydb_cluster | AWS::MemoryDB::Cluster | - | - |
| aws.mq | aws | message_queue | aws_mq_broker | AWS::AmazonMQ::Broker | - | - |
| aws.msk | aws | data_stream | aws_msk_cluster | AWS::MSK::Cluster | - | - |
| aws.neptune | aws | relational_db | aws_neptune_cluster | AWS::Neptune::DBCluster | - | - |
| aws.opensearch | aws | search_index | aws_opensearch_domain | AWS::OpenSearchService::Domain | - | - |
| aws.rds.cluster | aws | relational_db | aws_rds_cluster | AWS::RDS::DBCluster | - | - |
| aws.rds.instance | aws | relational_db | aws_db_instance | AWS::RDS::DBInstance | - | - |
| aws.redshift | aws | data_warehouse | aws_redshift_cluster | AWS::Redshift::Cluster | - | - |
| aws.redshift.serverless | aws | data_warehouse | aws_redshiftserverless_namespace | AWS::RedshiftServerless::Namespace | - | - |
| aws.s3 | aws | object_store | aws_s3_bucket | AWS::S3::Bucket | - | - |
| aws.s3.policy | aws | object_store | aws_s3_bucket_policy | AWS::S3::BucketPolicy | - | - |
| aws.s3.sse | aws | object_store | aws_s3_bucket_server_side_encryption_configuration | - | - | - |
| aws.secretsmanager | aws | secret_store | aws_secretsmanager_secret | AWS::SecretsManager::Secret | - | - |
| aws.sns | aws | message_topic | aws_sns_topic | AWS::SNS::Topic | - | - |
| aws.sqs | aws | message_queue | aws_sqs_queue | AWS::SQS::Queue | - | - |
| aws.ssm | aws | secret_store | aws_ssm_parameter | AWS::SSM::Parameter | - | - |
| azure.aks | azure | k8s_secrets_etcd | azurerm_kubernetes_cluster | - | - | - |
| azure.apim | azure | tls_endpoint | azurerm_api_management | - | - | - |
| azure.appgw | azure | tls_endpoint | azurerm_application_gateway | - | - | - |
| azure.cert | azure | certificate_policy | azurerm_key_vault_certificate | - | - | - |
| azure.cosmos | azure | nosql_db | azurerm_cosmosdb_account | - | - | - |
| azure.disk | azure | block_volume | azurerm_managed_disk | - | - | - |
| azure.disk.set | azure | block_volume | azurerm_disk_encryption_set | - | - | - |
| azure.eh | azure | data_stream | azurerm_eventhub_namespace | - | - | - |
| azure.frontdoor | azure | tls_endpoint | azurerm_cdn_frontdoor_custom_domain | - | - | - |
| azure.kv.secret | azure | secret_store | azurerm_key_vault_secret | - | - | - |
| azure.mssql | azure | relational_db | azurerm_mssql_server | - | - | - |
| azure.mssql.db | azure | relational_db | azurerm_mssql_database | - | - | - |
| azure.mssql.tde | azure | relational_db | azurerm_mssql_server_transparent_data_encryption | - | - | - |
| azure.mysql | azure | relational_db | azurerm_mysql_flexible_server | - | - | - |
| azure.pg | azure | relational_db | azurerm_postgresql_flexible_server | - | - | - |
| azure.recovery | azure | backup | azurerm_recovery_services_vault | - | - | - |
| azure.redis | azure | cache | azurerm_redis_cache | - | - | - |
| azure.sb | azure | message_queue | azurerm_servicebus_namespace | - | - | - |
| azure.storage | azure | object_store | azurerm_storage_account | - | - | - |
| azure.storage.cmk | azure | object_store | azurerm_storage_account_customer_managed_key | - | - | - |
| azure.synapse | azure | data_warehouse | azurerm_synapse_workspace | - | - | - |
| azure.vault | azure | kms_key | azurerm_key_vault | - | - | - |
| azure.vault.hsm | azure | kms_key | azurerm_key_vault_managed_hardware_security_module | - | - | - |
| azure.vault.key | azure | kms_key | azurerm_key_vault_key | - | - | - |
| azure.vm.linux | azure | block_volume | azurerm_linux_virtual_machine | - | - | - |
| azure.vm.windows | azure | block_volume | azurerm_windows_virtual_machine | - | - | - |
| azure.web.linux | azure | tls_endpoint | azurerm_linux_web_app | - | - | - |
| azure.web.windows | azure | tls_endpoint | azurerm_windows_web_app | - | - | - |
| compose.cassandra | compose | nosql_db | - | - | - | cassandra |
| compose.elastic | compose | search_index | - | - | - | elasticsearch |
| compose.kafka | compose | data_stream | - | - | - | kafka |
| compose.memcached | compose | cache | - | - | - | memcached |
| compose.mongo | compose | nosql_db | - | - | - | mongo |
| compose.mysql | compose | relational_db | - | - | - | mysql |
| compose.opensearch | compose | search_index | - | - | - | opensearch |
| compose.postgres | compose | relational_db | - | - | - | postgres |
| compose.rabbitmq | compose | message_queue | - | - | - | rabbitmq |
| compose.redis | compose | cache | - | - | - | redis |
| gcp.bigtable | gcp | nosql_db | google_bigtable_instance | - | - | - |
| gcp.bq | gcp | data_warehouse | google_bigquery_dataset | - | - | - |
| gcp.ca | gcp | certificate_policy | google_privateca_certificate_authority | - | - | - |
| gcp.disk | gcp | block_volume | google_compute_disk | - | - | - |
| gcp.filestore | gcp | file_system | google_filestore_instance | - | - | - |
| gcp.gcs | gcp | object_store | google_storage_bucket | - | - | - |
| gcp.gke | gcp | k8s_secrets_etcd | google_container_cluster | - | - | - |
| gcp.https | gcp | tls_endpoint | google_compute_target_https_proxy | - | - | - |
| gcp.instance | gcp | block_volume | google_compute_instance | - | - | - |
| gcp.kms.binding | gcp | kms_key | google_kms_crypto_key_iam_binding | - | - | - |
| gcp.kms.key | gcp | kms_key | google_kms_crypto_key | - | - | - |
| gcp.kms.member | gcp | kms_key | google_kms_crypto_key_iam_member | - | - | - |
| gcp.kms.ring | gcp | kms_key | google_kms_key_ring | - | - | - |
| gcp.logging | gcp | log_store | google_logging_project_bucket_config | - | - | - |
| gcp.pubsub | gcp | message_topic | google_pubsub_topic | - | - | - |
| gcp.redis | gcp | cache | google_redis_instance | - | - | - |
| gcp.sm | gcp | secret_store | google_secret_manager_secret | - | - | - |
| gcp.snapshot | gcp | block_volume | google_compute_snapshot | - | - | - |
| gcp.spanner | gcp | relational_db | google_spanner_database | - | - | - |
| gcp.sql | gcp | relational_db | google_sql_database_instance | - | - | - |
| gcp.ssl | gcp | tls_endpoint | google_compute_ssl_policy | - | - | - |
| k8s.apiserver | k8s | k8s_secrets_etcd | - | - | {'group': '', 'kind': 'Pod'} | - |
| k8s.encryptionconfig | k8s | k8s_secrets_etcd | - | - | {'group': 'apiserver.config.k8s.io', 'kind': 'EncryptionConfiguration'} | - |
| k8s.ingress | k8s | tls_endpoint | - | - | {'group': 'networking.k8s.io', 'kind': 'Ingress'} | - |
| k8s.pvc | k8s | block_volume | - | - | {'group': '', 'kind': 'PersistentVolumeClaim'} | - |
| k8s.secret | k8s | secret_store | - | - | {'group': '', 'kind': 'Secret'} | - |
| k8s.service | k8s | tls_endpoint | - | - | {'group': '', 'kind': 'Service'} | - |
| k8s.statefulset | k8s | block_volume | - | - | {'group': 'apps', 'kind': 'StatefulSet'} | - |
| k8s.storageclass | k8s | k8s_storage_class | - | - | {'group': 'storage.k8s.io', 'kind': 'StorageClass'} | - |

