/* C3 fixture — OpenSSL EVP (C/C++). The EVP fn name packs algorithm + key size
 * + mode (EVP_aes_256_gcm / EVP_des_ede3_cbc), and the `_` before a digest
 * family (EVP_sha384) breaks the global `\bSHA-?384\b` token. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>

void encrypt_aead(void) {
    const EVP_CIPHER *c = EVP_aes_256_gcm();
    EVP_CipherInit_ex(ctx, c, NULL, key, iv, 1);
}

void legacy_cipher(void) {
    const EVP_CIPHER *c = EVP_des_ede3_cbc();
    EVP_CipherInit_ex(ctx, c, NULL, key, iv, 1);
}

void hashes(void) {
    const EVP_MD *m1 = EVP_sha384();
    const EVP_MD *m2 = EVP_md5();
}

void keygen(void) {
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 3072);
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp384r1);
}

void mac(void) {
    HMAC_CTX *h = HMAC_CTX_new();
}
