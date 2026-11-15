# CB-02 Ubuntu host (issue #93). The other lab targets stay on the Alpine image. This one runs OpenSSH as
# root so the product's Tier-2 sudoers file works: sudo is setuid, and gen.py does not set no-new-privileges
# on this container. Planted files are copied to root-owned paths by the entrypoint.
# Package versions are the candidates from this base image on 2026-11-15. A moved pin is the same failure
# the Alpine images already have: update the version and rebuild.
ARG REGISTRY=mirror.gcr.io/library
FROM ${REGISTRY}/ubuntu:24.04@sha256:2198e4c65076e9cb0b3d695219df667c0e3b0072da64ca3c2648aca17dcecaf5

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server=1:9.6p1-3ubuntu13.20 \
      sudo=1.9.15p5-3ubuntu5.24.04.4 \
      openssl=3.0.13-0ubuntu3.16 \
      ca-certificates=20260816ubuntu0.24.04.2 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 zs-cbom \
 && useradd -u 10001 -g zs-cbom -d /home/zs-cbom -s /bin/bash -m zs-cbom \
 && sed -i 's/^zs-cbom:!:/zs-cbom:*:/' /etc/shadow \
 && install -d -m 0755 /run/sshd /var/log/cb02 /srv/cbom-lab /etc/ssh/cb02

COPY --chmod=0755 entrypoints/ /usr/local/bin/

HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD ["/usr/local/bin/cb02-health"]
ENTRYPOINT ["/usr/local/bin/cb02-entry"]
