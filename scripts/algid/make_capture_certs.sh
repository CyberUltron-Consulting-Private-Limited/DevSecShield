#!/bin/sh
# Make one certificate per public-key algorithm OpenSSL 3.5 can generate, for capture_openssl_text.py. Run inside
# python:3.12-slim (OpenSSL 3.5.x). Keys stay in a temporary directory and are deleted; only DER certificates are
# written to $1. KEM keys cannot self-sign, so their certificates are issued by a throwaway RSA key.
set -eu
out=$1; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ca.key 2>/dev/null
mk() { # name genpkey-args...
  n=$1; shift
  openssl genpkey "$@" -out "$n.key" 2>/dev/null
  if openssl req -x509 -new -key "$n.key" -subj "/CN=$n" -days 1 -outform DER -out "$out/$n.der" 2>/dev/null; then :
  else
    openssl pkey -in "$n.key" -pubout -out "$n.pub" 2>/dev/null
    openssl x509 -new -subj "/CN=$n" -force_pubkey "$n.pub" -key ca.key -days 1 -outform DER -out "$out/$n.der"
  fi
}
mk rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
mk rsa-pss -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048
openssl genpkey -genparam -algorithm DSA -pkeyopt dsa_paramgen_bits:2048 -out dsa.param 2>/dev/null
mk dsa -paramfile dsa.param
for c in P-256 P-384 P-521 brainpoolP256r1 secp256k1; do mk "ec-$c" -algorithm EC -pkeyopt ec_paramgen_curve:$c; done
mk sm2 -algorithm SM2
for a in ED25519 ED448 X25519 X448; do mk "$(echo $a | tr A-Z a-z)" -algorithm $a; done
for p in 44 65 87; do mk "mldsa$p" -algorithm ML-DSA-$p; done
for p in 512 768 1024; do mk "mlkem$p" -algorithm ML-KEM-$p; done
for h in SHA2 SHAKE; do for s in 128s 128f 192s 192f 256s 256f; do mk "slh-$h-$s" -algorithm SLH-DSA-$h-$s; done; done
ls "$out" | wc -l
