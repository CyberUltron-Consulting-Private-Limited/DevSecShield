# ZeroShield CBOM scan node OVA (VMware): Ubuntu 24.04 LTS cloud image + Docker + the scan-node image + open-vm-tools.
# At first boot zs-ovf-env turns the vApp properties set at deploy time (zs.api_url, zs.registration_token,
# zs.https_proxy, zs.mode) into /etc/zs-node/env, which zs-scan-node.service reads.
#
#   packer init ova.pkr.hcl
#   packer build -var node_image_archive=scan-node-1.0.0.tar.gz -var build_password="$(openssl rand -hex 16)" ova.pkr.hcl
#   (needs KVM and qemu-img)
#
# Output: output-ova/zeroshield-cbom-scan-node-<version>.ova (scripts/make-ova.sh: streamOptimized VMDK + OVF with
# vApp properties + SHA-256 manifest). The image comes from the file (Add scan node > Download scan node image): the
# build VM loads it with `docker load` and pulls nothing. Customers get this template as the "OVA build kit" download
# (scripts/release/node_artifacts.py), its defaults set to the server's node version (README.md).

packer {
  required_version = ">= 1.10.0"
  required_plugins {
    qemu = {
      version = ">= 1.1.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

variable "node_image_archive" {
  type        = string
  default     = "scan-node-1.0.0.tar.gz"
  description = "The scan-node image file (docker save archive), copied to the build VM and loaded there."
}

variable "node_image" {
  type        = string
  default     = "localhost/zeroshield/cbom-scan-node:1.0.0"
  description = "The image name the archive loads as (docker load); the OVA runs it."
}

variable "ubuntu_image_url" {
  type        = string
  default     = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
  description = "Ubuntu 24.04 LTS cloud image (qcow2)."
}

variable "ubuntu_checksum" {
  type        = string
  default     = "file:https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"
  description = "Checked against Canonical's SHA256SUMS (verify its signature, SHA256SUMS.gpg, for a release build)."
}

variable "build_password" {
  type        = string
  sensitive   = true
  description = "Temporary password of the build user for Packer's SSH session; removed before the image is sealed."
}

variable "disk_size" {
  type    = string
  default = "16G"
}

locals {
  version = regex_replace(var.node_image, "^.*:", "")
}

source "qemu" "scan_node" {
  iso_url          = var.ubuntu_image_url
  iso_checksum     = var.ubuntu_checksum
  disk_image       = true
  disk_size        = var.disk_size
  format           = "qcow2"
  accelerator      = "kvm"
  headless         = true
  cpus             = 2
  memory           = 2048
  net_device       = "virtio-net"
  disk_interface   = "virtio"
  output_directory = "output-ova"
  vm_name          = "zeroshield-cbom-scan-node-${local.version}.qcow2"
  # NoCloud seed for the build only: lets Packer log in once; install.sh runs `cloud-init clean` afterwards
  cd_label = "cidata"
  cd_content = {
    "meta-data" = "instance-id: zs-build\nlocal-hostname: zs-scan-node\n"
    "user-data" = <<-EOT
      #cloud-config
      ssh_pwauth: true
      chpasswd:
        expire: false
        users:
          - {name: ubuntu, password: "${var.build_password}", type: text}
    EOT
  }
  ssh_username     = "ubuntu"
  ssh_password     = var.build_password
  ssh_timeout      = "20m"
  shutdown_command = "sudo shutdown -P now"
}

build {
  sources = ["source.qemu.scan_node"]

  provisioner "file" {
    sources     = ["files/zs-node-run", "files/zs-scan-node.service", "files/zs-ovf-env", "files/zs-ovf-env.service"]
    destination = "/tmp/"
  }

  provisioner "file" {
    source      = var.node_image_archive
    destination = "/tmp/zs-node-image.tar.gz"
  }

  provisioner "shell" {
    execute_command  = "echo '${var.build_password}' | sudo -S -E sh '{{ .Path }}'"
    environment_vars = ["NODE_IMAGE=${var.node_image}", "NODE_IMAGE_ARCHIVE=/tmp/zs-node-image.tar.gz", "OVA=1"]
    script           = "scripts/install.sh"
  }

  # seal: no password login for the build user, password SSH off again
  provisioner "shell" {
    execute_command = "echo '${var.build_password}' | sudo -S sh '{{ .Path }}'"
    inline = [
      "passwd -d ubuntu && passwd -l ubuntu",
      "rm -f /etc/ssh/sshd_config.d/50-cloud-init.conf",
    ]
  }

  post-processor "shell-local" {
    inline = ["sh scripts/make-ova.sh output-ova/zeroshield-cbom-scan-node-${local.version}.qcow2 ${local.version}"]
  }
}
