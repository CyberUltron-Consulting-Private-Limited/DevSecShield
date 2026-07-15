/* Synthetic OpenSSL (C) fixture for the C3 call-expression scanner.
 * The EVP function name packs algorithm + key size + mode; the RSA key size and
 * the EC curve NID are bound from the call arguments. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>

void encrypt_gcm(void) {
    const EVP_CIPHER *c = EVP_aes_256_gcm();   /* AES-256 + GCM */
}

void encrypt_legacy(void) {
    const EVP_CIPHER *c = EVP_des_ede3_cbc();  /* 3DES + CBC */
}

void hash_strong(void) {
    const EVP_MD *m = EVP_sha384();            /* SHA-384 */
}

void hash_weak(void) {
    const EVP_MD *m = EVP_md5();               /* MD5 */
}

void gen_rsa(EVP_PKEY_CTX *ctx) {
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072);   /* RSA-3072 */
}

void gen_ec(void) {
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_secp521r1);  /* ECDSA P-521 */
}

void mac(void) {
    HMAC_CTX *h = HMAC_CTX_new();   /* HMAC */
}
