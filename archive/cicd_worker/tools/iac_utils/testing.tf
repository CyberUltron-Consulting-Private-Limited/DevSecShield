terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = "us-east-1"
  # DO NOT PUT REAL CREDENTIALS HERE - use environment variables or a test profile.
}

# ---------- Insecure IAM role and instance profile (AdministratorAccess attached) ----------
resource "aws_iam_role" "insecure_ec2_role" {
  name = "insecure-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

# ATTACH a highly privileged managed policy (AdministratorAccess) - insecure
resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.insecure_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "insecure_profile" {
  name = "insecure-instance-profile"
  role = aws_iam_role.insecure_ec2_role.name
}

# ---------- Publicly readable (and unencrypted) S3 bucket ----------
resource "aws_s3_bucket" "public_bucket" {
  bucket = "tfsec-testing-public-bucket-example-12345"
  acl    = "public-read"        # public read access - insecure

  website {
    index_document = "index.html"
  }

  # No server-side encryption configuration (SSE) intentionally omitted
}

# ---------- Wide-open security group ----------
resource "aws_security_group" "wide_open" {
  name        = "wide-open-sg"
  description = "Allows everything from the Internet - intentionally insecure"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]   # everything allowed - BAD
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------- EC2 instance with vulnerable settings ----------
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "vulnerable_instance" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.insecure_profile.name
  vpc_security_group_ids = [aws_security_group.wide_open.id]
  key_name               = "insecure-key"   # no public key resource; placeholder

  # Associate public IP (so it's reachable from internet)
  associate_public_ip_address = true

  # root block device explicitly unencrypted - insecure
  root_block_device {
    volume_type = "gp2"
    volume_size = 8
    encrypted   = false     # NO encryption - insecure
  }

  # Metadata options: allow IMDSv1 by not requiring tokens (http_tokens = "optional")
  # This is less secure than requiring IMDSv2 (http_tokens = "required")
  metadata_options {
    http_tokens = "optional"
    http_endpoint = "enabled"
  }

  # user_data containing a hard-coded secret and weak practice (plain-text password)
  user_data = <<-EOF
              #!/bin/bash
              echo "CREDS=AKIAEXAMPLEFAKEKEY" >> /etc/environment
              echo "DB_PASSWORD=SuperSecretPassword123!" >> /etc/environment
              # create a local user with a weak password (for testing only)
              useradd -m insecureuser
              echo "insecureuser:password" | chpasswd
              EOF

  tags = {
    Name = "vulnerable-ec2"
    Env  = "testing"
  }
}

# ---------- Unused/embedded private key file (insecure pattern if used) ----------
# This is an example to simulate a private key being stored as plaintext in code.
# DON'T put real keys here - it's intentionally insecure.
resource "local_file" "private_key_example" {
  content  = <<KEY
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAexamplefakekeydata...
-----END RSA PRIVATE KEY-----
KEY
  filename = "${path.module}/insecure_private_key.pem"
}

# ---------- Output for convenience ----------
output "instance_public_ip" {
  value = aws_instance.vulnerable_instance.public_ip
  description = "Public IP of the intentionally vulnerable EC2 (for testing only)"
}

output "s3_bucket_name" {
  value = aws_s3_bucket.public_bucket.bucket
}
