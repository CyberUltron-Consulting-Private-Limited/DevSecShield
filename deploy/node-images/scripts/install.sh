#!/bin/sh
# Provision an Ubuntu 24.04 image as a ZeroShield CBOM scan node appliance (used by ami.pkr.hcl and ova.pkr.hcl).
#   NODE_IMAGE           image to run (localhost/zeroshield/cbom-scan-node:<version>, the name the archive loads as)
#   NODE_IMAGE_ARCHIVE   the `docker save` archive on the build VM (the Packer templates copy it there), loaded; without
#                        it the image is pulled from a registry the build VM can reach
#   OVA=1                also install open-vm-tools and the vApp-properties reader (zs-ovf-env)
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y upgrade
apt-get install -y --no-install-recommends docker.io ca-certificates
if [ "${OVA:-0}" = "1" ]; then
  apt-get install -y --no-install-recommends open-vm-tools python3
  install -m 0755 /tmp/zs-ovf-env /usr/local/sbin/zs-ovf-env
  install -m 0644 /tmp/zs-ovf-env.service /etc/systemd/system/zs-ovf-env.service
  systemctl enable zs-ovf-env.service
fi
systemctl enable --now docker
if [ -n "${NODE_IMAGE_ARCHIVE:-}" ]; then
  docker load -i "$NODE_IMAGE_ARCHIVE"
  rm -f "$NODE_IMAGE_ARCHIVE"
  docker image inspect "$NODE_IMAGE" >/dev/null 2>&1 ||
    { echo "install.sh: the archive did not load $NODE_IMAGE (set node_image to the name docker load printed)" >&2; exit 1; }
else
  docker pull "$NODE_IMAGE"
fi
install -d -m 0700 /etc/zs-node
printf '%s\n' "$NODE_IMAGE" > /etc/zs-node/image
chmod 0644 /etc/zs-node/image
install -m 0755 /tmp/zs-node-run /usr/local/sbin/zs-node-run
install -m 0644 /tmp/zs-scan-node.service /etc/systemd/system/zs-scan-node.service
systemctl enable zs-scan-node.service
# the image must not carry this build's identity: settings, SSH host keys and cloud-init state are made at first boot
rm -f /etc/zs-node/env /etc/ssh/ssh_host_*
cloud-init clean --logs --seed
truncate -s 0 /etc/machine-id
apt-get clean
rm -rf /var/lib/apt/lists/*
