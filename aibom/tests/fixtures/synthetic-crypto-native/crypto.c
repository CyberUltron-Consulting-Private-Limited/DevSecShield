/* Synthetic OpenSSL (C/C++) fixture (C3). The EVP function name encodes the
 * algorithm + key size + mode; the RSA key size and EC curve NID live in the
 * call arguments. A bare-identifier regex could not recover AES-256-GCM vs
 * AES-128-CBC, nor the RSA-2048 size, nor the SECP256R1 curve. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

void ciphers(void) {
  const EVP_CIPHER *a = EVP_aes_256_gcm();     /* -> AES-256-GCM */
  const EVP_CIPHER *b = EVP_aes_128_cbc();     /* -> AES-128-CBC */
  const EVP_CIPHER *c = EVP_des_ede3_cbc();    /* -> 3DES-CBC */
  const EVP_CIPHER *d = EVP_chacha20_poly1305(); /* -> ChaCha20-Poly1305 */
}

void digests(void) {
  const EVP_MD *m1 = EVP_sha256();  /* -> SHA-256 */
  const EVP_MD *m2 = EVP_md5();     /* -> MD5 */
  SHA1_Init(&ctx);                  /* -> SHA-1 (legacy call) */
}

void keys(void) {
  RSA *rsa = RSA_new();
  RSA_generate_key_ex(rsa, 2048, e, NULL);            /* -> RSA-2048 */
  EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); /* -> ECDSA + SECP256R1 */
  HMAC(EVP_sha256(), key, klen, data, dlen, out, &ol); /* -> HMAC */
}
