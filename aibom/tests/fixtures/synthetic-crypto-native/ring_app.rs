// Synthetic ring fixture (C3). ring encodes each algorithm in a SCREAMING
// constant under aead / digest / signature. Kept separate from the RustCrypto
// fixture so ring's assets (which share display names with RustCrypto's) are
// attributable to ring rather than collapsed under dedup.
use ring::{aead, digest, signature};

fn ring_backend() {
    let _alg = &aead::AES_256_GCM;                   // -> AES-256-GCM (ring)
    let _cc = &aead::CHACHA20_POLY1305;              // -> ChaCha20-Poly1305 (ring)
    let _d = digest::SHA256;                         // -> SHA-256 (ring)
    let _sig = &signature::ED25519;                  // -> Ed25519 (ring)
    let _ec = &signature::ECDSA_P256_SHA256_ASN1;    // -> ECDSA + SECP256R1 (ring)
    let _rsa = &signature::RSA_PKCS1_2048_8192_SHA256; // -> RSA + PKCS1-v1_5 (ring)
}
