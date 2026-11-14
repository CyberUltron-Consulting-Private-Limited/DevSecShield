# ZeroShield CBOM scan node AMI: Ubuntu 24.04 LTS + Docker + the scan-node image + a systemd unit that starts it with
# the settings EC2 user data writes to /etc/zs-node/env (the "Add scan node" wizard shows that cloud-config).
#
#   packer init ami.pkr.hcl
#   packer build -var region=ap-south-1 -var node_image_archive=scan-node-1.0.0.tar.gz ami.pkr.hcl
#
# The image comes from the file (Add scan node > Download scan node image, or scripts/release/scan_node_image.sh):
# the build instance loads it with `docker load` and pulls nothing. Customers get this template as the "AMI build
# kit" download (scripts/release/node_artifacts.py), its defaults set to the server's node version (README.md).

packer {
  required_version = ">= 1.10.0"
  required_plugins {
    amazon = {
      version = ">= 1.3.0"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "instance_type" {
  type    = string
  default = "t3.small"
}

variable "node_image_archive" {
  type        = string
  default     = "scan-node-1.0.0.tar.gz"
  description = "The scan-node image file (docker save archive), copied to the build instance and loaded there."
}

variable "node_image" {
  type        = string
  default     = "localhost/zeroshield/cbom-scan-node:1.0.0"
  description = "The image name the archive loads as (docker load); the AMI runs it."
}

variable "subnet_id" {
  type    = string
  default = ""
}

locals {
  version   = regex_replace(var.node_image, "^.*:", "")
  timestamp = formatdate("YYYYMMDDhhmm", timestamp())
}

source "amazon-ebs" "scan_node" {
  region        = var.region
  instance_type = var.instance_type
  subnet_id     = var.subnet_id == "" ? null : var.subnet_id
  ami_name      = "zeroshield-cbom-scan-node-${local.version}-${local.timestamp}"
  ami_description = "ZeroShield CBOM scan node ${local.version} (Ubuntu 24.04, Docker)"
  ssh_username  = "ubuntu"
  imds_support  = "v2.0"
  encrypt_boot  = true

  # Canonical's Ubuntu 24.04 LTS (Noble) images: owner 099720109477, gp3 root volume naming used since 23.10.
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"]
    most_recent = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 16
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name        = "zeroshield-cbom-scan-node"
    NodeVersion = local.version
  }
}

build {
  sources = ["source.amazon-ebs.scan_node"]

  provisioner "file" {
    sources     = ["files/zs-node-run", "files/zs-scan-node.service"]
    destination = "/tmp/"
  }

  provisioner "file" {
    source      = var.node_image_archive
    destination = "/tmp/zs-node-image.tar.gz"
  }

  provisioner "shell" {
    execute_command  = "sudo -E sh '{{ .Path }}'"
    environment_vars = ["NODE_IMAGE=${var.node_image}", "NODE_IMAGE_ARCHIVE=/tmp/zs-node-image.tar.gz"]
    script           = "scripts/install.sh"
  }
}
