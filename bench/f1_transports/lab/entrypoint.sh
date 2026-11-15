#!/bin/sh
# Lab target start: this container's own host keys, the scan node's public key for zs-cbom, then sshd.
set -eu
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A >/dev/null
if [ -n "${ZS_NODE_PUB:-}" ] && ! grep -qxF "$ZS_NODE_PUB" /home/zs-cbom/.ssh/authorized_keys 2>/dev/null; then
  printf '%s\n' "$ZS_NODE_PUB" > /home/zs-cbom/.ssh/authorized_keys
  chown zs-cbom:zs-cbom /home/zs-cbom/.ssh/authorized_keys
  chmod 0600 /home/zs-cbom/.ssh/authorized_keys
fi
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
