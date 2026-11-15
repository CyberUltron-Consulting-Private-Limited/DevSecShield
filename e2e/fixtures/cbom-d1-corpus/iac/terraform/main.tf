resource "aws_lb_listener" "web" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:ap-south-1:111122223333:loadbalancer/app/web/abc"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"          # T1 allows TLS 1.0
  certificate_arn   = "arn:aws:acm:ap-south-1:111122223333:certificate/abc"
  default_action { type = "forward" target_group_arn = "x" }
}
resource "aws_kms_key" "data" {
  description         = "data key"
  enable_key_rotation = false                              # T2 rotation off
}
resource "aws_db_instance" "pay" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  storage_encrypted = false                                # T3 RDS unencrypted
}
resource "aws_ebs_volume" "v" {
  availability_zone = "ap-south-1a"
  size              = 10
  encrypted         = false                                # T4 EBS unencrypted
}
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 1024                                         # T5 RSA-1024
}
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  viewer_certificate {
    acm_certificate_arn      = "arn:aws:acm:us-east-1:111122223333:certificate/def"
    minimum_protocol_version = "TLSv1"                     # T6 TLS 1.0 at the edge
    ssl_support_method       = "sni-only"
  }
}
resource "azurerm_storage_account" "sa" {
  name = "sa" resource_group_name = "rg" location = "westeurope" account_tier = "Standard" account_replication_type = "LRS"
  min_tls_version = "TLS1_0"                               # T7 Azure storage TLS 1.0
}
