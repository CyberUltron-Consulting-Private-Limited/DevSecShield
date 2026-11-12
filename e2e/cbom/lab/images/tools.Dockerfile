# CB-02 lab tools image: the generator (gen.py) and the independent self-check tools (oracle rule O-3).
#   generator:  OpenSSL 3.5, ssh-keygen, keytool (JRE 21), SoftHSM 2.6 + pkcs11-tool (OpenSC)
#   self-check: tlscheck (Go crypto/tls, built below), nmap 7.97 (ssl-enum-ciphers, ssh2-enum-algos), ssh-keyscan,
#               ssh-audit, psql, kubectl, keytool, pkcs11-tool, openssl x509
# None of these shares code with the scan node's collectors (Python cryptography/paramiko, `openssl s_client`),
# except `openssl x509` on generated files and the ML-DSA fallback, which the oracle records as such.
# Build context: e2e/cbom/lab. Behind a TLS-intercepting build proxy pass its CA as the BuildKit secret build_ca.
ARG REGISTRY=mirror.gcr.io/library

FROM ${REGISTRY}/golang:1.25-alpine3.22@sha256:65b4400aee0927412e9ed791a11893273a49d55df24841f7599660fb80dae464 AS tlscheck
WORKDIR /src
COPY tlscheck/go.mod tlscheck/main.go ./
# stdlib only: no module download
RUN CGO_ENABLED=0 GOFLAGS=-trimpath GOTOOLCHAIN=local go build -ldflags="-s -w" -o /out/tlscheck .

FROM ${REGISTRY}/alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN --mount=type=secret,id=build_ca,required=false \
    if [ -s /run/secrets/build_ca ]; then export SSL_CERT_FILE=/run/secrets/build_ca; fi \
 && apk add --no-cache \
      python3=3.12.16-r0 \
      openssl=3.5.9-r0 \
      openssh-client-default=10.0_p1-r11 \
      openssh-keygen=10.0_p1-r11 \
      nmap=7.97-r0 \
      nmap-scripts=7.97-r0 \
      nmap-nselibs=7.97-r0 \
      ssh-audit=3.3.0-r0 \
      openjdk21-jre-headless=21.0.11_p10-r0 \
      softhsm=2.6.1-r6 \
      opensc=0.26.0-r0 \
      postgresql16-client=16.15-r0 \
      kubectl=1.33.1-r5 \
 && addgroup -g 10001 cblab \
 && adduser -D -u 10001 -G cblab -h /home/cblab cblab

COPY --from=tlscheck /out/tlscheck /usr/local/bin/tlscheck
# gen.py is not baked in: lab.sh mounts e2e/cbom/lab read-only at /opt/cb02, so the image only carries tools.

USER 10001:10001
WORKDIR /home/cblab
HEALTHCHECK --interval=30s --timeout=5s CMD ["/usr/local/bin/tlscheck", "version"]
CMD ["sleep", "infinity"]
