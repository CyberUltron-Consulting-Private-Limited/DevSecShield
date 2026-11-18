# A throw-away Linux server for the F1.4 SSH CA proof (bench/f1_sshca/sshd_proof.py): OpenSSH sshd and a zs-cbom user
# with NO authorized_keys, so the only way in is a certificate from the ZeroShield SSH CA.  The proof mounts the
# sshd-config template the API serves and an empty /etc/ssh/zs-cbom; the trust-fetch script the API serves fills it
# (trusted CA keys, KRL, principals) from the machine read path with a trust token, using curl and ssh-keygen.
#
# sshd runs as zs-cbom itself (no root in the container): a non-root sshd can only log its own user in, which is exactly
# the login the proof tests, and it applies TrustedUserCAKeys, RevokedKeys, AuthorizedPrincipalsFile, source-address
# and the validity window the same way (auth2-pubkey.c).  Port 2222; host key generated at start; logs to stderr.
#
# The package is pinned (hadolint DL3008).  When Debian replaces it, look up the new version with
#   docker run --rm debian:trixie-slim sh -c 'apt-get update -qq && apt-cache policy openssh-server curl'
FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server=1:10.0p1-7+deb13u4 curl=8.14.1-2+deb13u7 \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_* \
 && useradd --uid 1000 --create-home --shell /bin/bash zs-cbom \
 && usermod -p '*' zs-cbom \
 && install -d -o zs-cbom -g zs-cbom -m 0700 /home/zs-cbom/hostkey \
 && printf 'Port 2222\nHostKey /home/zs-cbom/hostkey/ssh_host_ed25519_key\nPidFile none\nUsePAM no\n' \
      > /etc/ssh/sshd_config.d/00-lab.conf
USER 1000:1000
EXPOSE 2222
CMD ["/bin/sh", "-c", "ssh-keygen -q -t ed25519 -N '' -f /home/zs-cbom/hostkey/ssh_host_ed25519_key && exec /usr/sbin/sshd -D -e"]
