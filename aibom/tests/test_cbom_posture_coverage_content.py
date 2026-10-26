"""Shipped coverage contains every native type in Table R10-A."""

from aibom.cbom.posture.coverage import load_coverage

TERRAFORM = {
    "aws_kms_key",
    "aws_kms_external_key",
    "aws_kms_replica_key",
    "aws_kms_alias",
    "aws_kms_grant",
    "aws_s3_bucket",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_policy",
    "aws_ebs_volume",
    "aws_ebs_encryption_by_default",
    "aws_ebs_default_kms_key",
    "aws_instance",
    "aws_launch_template",
    "aws_launch_configuration",
    "aws_efs_file_system",
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_docdb_cluster",
    "aws_neptune_cluster",
    "aws_dynamodb_table",
    "aws_elasticache_replication_group",
    "aws_memorydb_cluster",
    "aws_opensearch_domain",
    "aws_elasticsearch_domain",
    "aws_sqs_queue",
    "aws_sns_topic",
    "aws_mq_broker",
    "aws_kinesis_stream",
    "aws_kinesis_firehose_delivery_stream",
    "aws_msk_cluster",
    "aws_redshift_cluster",
    "aws_redshiftserverless_namespace",
    "aws_backup_vault",
    "aws_ebs_snapshot_copy",
    "aws_db_snapshot_copy",
    "aws_ami_copy",
    "aws_secretsmanager_secret",
    "aws_ssm_parameter",
    "aws_cloudwatch_log_group",
    "aws_cloudtrail",
    "aws_eks_cluster",
    "aws_lb_listener",
    "aws_alb_listener",
    "aws_elb",
    "aws_lb_ssl_negotiation_policy",
    "aws_cloudfront_distribution",
    "aws_api_gateway_domain_name",
    "aws_apigatewayv2_domain_name",
    "aws_acm_certificate",
    "aws_acmpca_certificate_authority",
    "azurerm_key_vault",
    "azurerm_key_vault_key",
    "azurerm_key_vault_managed_hardware_security_module",
    "azurerm_storage_account",
    "azurerm_storage_account_customer_managed_key",
    "azurerm_managed_disk",
    "azurerm_disk_encryption_set",
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "azurerm_mssql_server",
    "azurerm_mssql_database",
    "azurerm_mssql_server_transparent_data_encryption",
    "azurerm_postgresql_flexible_server",
    "azurerm_mysql_flexible_server",
    "azurerm_cosmosdb_account",
    "azurerm_redis_cache",
    "azurerm_servicebus_namespace",
    "azurerm_eventhub_namespace",
    "azurerm_synapse_workspace",
    "azurerm_recovery_services_vault",
    "azurerm_key_vault_secret",
    "azurerm_kubernetes_cluster",
    "azurerm_application_gateway",
    "azurerm_cdn_frontdoor_custom_domain",
    "azurerm_api_management",
    "azurerm_linux_web_app",
    "azurerm_windows_web_app",
    "azurerm_key_vault_certificate",
    "google_kms_key_ring",
    "google_kms_crypto_key",
    "google_kms_crypto_key_iam_binding",
    "google_kms_crypto_key_iam_member",
    "google_storage_bucket",
    "google_compute_disk",
    "google_compute_instance",
    "google_compute_snapshot",
    "google_filestore_instance",
    "google_sql_database_instance",
    "google_spanner_database",
    "google_bigtable_instance",
    "google_redis_instance",
    "google_pubsub_topic",
    "google_bigquery_dataset",
    "google_secret_manager_secret",
    "google_logging_project_bucket_config",
    "google_container_cluster",
    "google_compute_ssl_policy",
    "google_compute_target_https_proxy",
    "google_privateca_certificate_authority",
}

PAIRS = {
    "aws_db_instance": "AWS::RDS::DBInstance",
    "aws_rds_cluster": "AWS::RDS::DBCluster",
    "aws_s3_bucket": "AWS::S3::Bucket",
    "aws_kms_key": "AWS::KMS::Key",
    "aws_ebs_volume": "AWS::EC2::Volume",
}


def _names(table) -> set[str]:
    found: set[str] = set()
    for rule in table.rules:
        for syntax, names in rule.native.items():
            if syntax == "kubernetes":
                continue
            found.update(names)
    return found


def test_table_covers_r10a_and_keeps_terraform_with_cloudformation() -> None:
    table = load_coverage()
    found = _names(table)
    assert found >= TERRAFORM
    for rule in table.rules:
        assert any(rule.consulted.values())
    by_tf = {}
    for rule in table.rules:
        for name in rule.native.get("terraform", ()):
            by_tf[name] = rule
    for terraform, cloudformation in PAIRS.items():
        rule = by_tf[terraform]
        assert cloudformation in rule.native["cloudformation"]
