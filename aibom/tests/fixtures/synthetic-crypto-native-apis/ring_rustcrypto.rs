// C3 fixture — Rust: ring module constants + RustCrypto fused types. Both are
// spellings the global lane misses: `Aes256Gcm`/`ChaCha20Poly1305` have no word
// boundary before the mode, and `ECDSA_P384_*`/`HMAC_SHA256` end in `_`.
use ring::{aead, digest, signature, hmac, pbkdf2};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use sha2::Sha256;
use rsa::RsaPrivateKey;

fn ring_aead() {
    let alg = &aead::AES_256_GCM;
    let sig = &signature::ED25519;
    let ec = &signature::ECDSA_P384_SHA384_ASN1_SIGNING;
    let h = hmac::HMAC_SHA256;
    static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
    let d = digest::SHA256;
}

fn rustcrypto() {
    let cipher = Aes256Gcm::new(key);
    let aead = ChaCha20Poly1305::new(key);
    let mut hasher = Sha256::new();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
}
