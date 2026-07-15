resource "aws_bedrock_model_invocation_logging_configuration" "logs" {}
resource "aws_sagemaker_endpoint" "triage" { endpoint_config_name = "x" }
