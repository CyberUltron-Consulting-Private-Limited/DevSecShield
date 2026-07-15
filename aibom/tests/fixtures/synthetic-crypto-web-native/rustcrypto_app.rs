// Synthetic RustCrypto fixture for the C3 call-expression scanner. RustCrypto
// exposes algorithms as types (AEAD type carries the key size + mode); kept in a
// separate file from ring_app.rs so the AES-GCM / SHA assets do not collide on
// (name, location) with the ring ones.
use aes_gcm::Aes256Gcm;
use sha2::Sha512;
use rsa::RsaPrivateKey;
use hmac::Hmac;
use sha2::Sha256;

fn rc_aead(key: &[u8]) {
    let cipher = Aes256Gcm::new(key.into());   // AES-256 + GCM
}

fn rc_digest() {
    let mut h = Sha512::new();                 // SHA-512
}

fn rc_mac() {
    type HmacSha256 = Hmac::<Sha256>;          // HMAC
}

fn rc_rsa(rng: &mut impl rand::RngCore) {
    let priv_key = RsaPrivateKey::new(rng, 2048).unwrap();  // RSA
}
