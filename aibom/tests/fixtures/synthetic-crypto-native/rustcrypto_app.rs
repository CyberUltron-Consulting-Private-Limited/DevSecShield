// Synthetic RustCrypto fixture (C3). RustCrypto encodes the algorithm in a
// CamelCase type; the key size is a suffix (`Aes256Gcm`) or an argument
// (`RsaPrivateKey::new(rng, 2048)`). A bare-token scan could not recover
// AES-256-GCM or RSA-2048 or the P-256 curve.
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use sha2::{Sha256, Sha512};
use rsa::RsaPrivateKey;
use ed25519_dalek::SigningKey;
use p256::ecdsa::SigningKey as P256Signing;
use hmac::Hmac;

fn rustcrypto(rng: &mut impl RngCore) {
    let _aead = Aes256Gcm::new(key);                    // -> AES-256-GCM
    let _cc = ChaCha20Poly1305::new(key);               // -> ChaCha20-Poly1305
    let _h = Sha256::new();                             // -> SHA-256
    let _h2 = Sha512::new();                            // -> SHA-512
    let _rsa = RsaPrivateKey::new(rng, 2048).unwrap();  // -> RSA-2048
    let _ed = SigningKey::generate(rng);                // -> Ed25519 (ed25519_dalek)
    let _p = P256Signing::random(rng);                  // -> ECDSA + SECP256R1 (p256)
    let _mac = Hmac::<Sha256>::new_from_slice(secret);  // -> HMAC
}
