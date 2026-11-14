# CB-02 lab target image: every TLS, SSH and listener target of the CBOM lab runs from this one image, each with
# the files and the entrypoint gen.py wrote for it (mounted read-only at /lab). Built by `gen.py build`.
#   OpenSSL 3.5 (ML-KEM groups, ML-DSA keys), nginx linked to it, OpenSSH 10 (mlkem768x25519-sha256), socat.
# Behind a TLS-intercepting build proxy, pass its CA as a BuildKit secret (it is never written into the image):
#   docker build --secret id=build_ca,src=<ca.pem> --build-arg HTTPS_PROXY=... -f images/target.Dockerfile .
ARG REGISTRY=mirror.gcr.io/library
FROM ${REGISTRY}/alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export SSL_CERT_FILE=/run/secrets/build_ca; fi \
 && apk add --no-cache \
      openssl=3.5.9-r0 \
      nginx=1.28.3-r7 \
      openssh-server=10.0_p1-r11 \
      openssh-sftp-server=10.0_p1-r11 \
      socat=1.8.1.3-r0 \
 && addgroup -g 10001 zs-cbom \
 && adduser -D -u 10001 -G zs-cbom -h /home/zs-cbom -s /bin/sh zs-cbom \
 && sed -i 's/^zs-cbom:!:/zs-cbom:*:/' /etc/shadow \
 && install -d -o zs-cbom -g zs-cbom -m 0755 /srv/cbom-lab /var/log/cb02 /run/cb02 /etc/ssh/cb02 /logs \
 && install -d -o zs-cbom -g zs-cbom -m 0700 /home/zs-cbom/.ssh

COPY --chmod=0755 entrypoints/ /usr/local/bin/

# Every target runs unprivileged; Docker lets a container bind ports below 1024 without root
# (net.ipv4.ip_unprivileged_port_start=0 is its default).
USER 10001:10001
WORKDIR /home/zs-cbom
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD ["/usr/local/bin/cb02-health"]
ENTRYPOINT ["/usr/local/bin/cb02-entry"]
