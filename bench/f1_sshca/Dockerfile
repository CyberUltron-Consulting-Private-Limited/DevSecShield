# A throw-away Linux server for the F1.4 SSH CA proof: OpenSSH sshd, a zs-cbom user with NO authorized_keys (the
# only way in is a certificate from the ZeroShield SSH CA), host keys generated at start, sshd logging to stderr.
# The proof mounts /etc/ssh/zs-cbom (trusted keys, KRL, principals) and the sshd-config template from the API.
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server openssl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --shell /bin/bash zs-cbom \
 && rm -f /etc/ssh/ssh_host_*
CMD ["/bin/sh", "-c", "ssh-keygen -A >/dev/null && mkdir -p /run/sshd && exec /usr/sbin/sshd -D -e"]
