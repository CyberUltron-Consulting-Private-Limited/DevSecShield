/* Synthetic OpenSSL (C/C++) crypto usage (C3 fixture).
 * The EVP_* function name packs algorithm + key size + mode into one token. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

void encrypt_gcm(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);   /* AES-256-GCM */
}
void legacy_cbc(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);   /* AES-128-CBC */
}
void legacy_3des(EVP_CIPHER_CTX *ctx) {
    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, NULL, NULL); /* 3DES */
}
void broken_rc4(EVP_CIPHER_CTX *ctx) {
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, NULL, NULL);        /* RC4 */
}

void hashes(void) {
    EVP_Digest(data, len, out, NULL, EVP_md5(), NULL);           /* MD5 */
    EVP_Digest(data, len, out, NULL, EVP_sha256(), NULL);        /* SHA-256 */
    SHA512_Init(&sha_ctx);                                       /* SHA-512 */
}

void keygen(EVP_PKEY_CTX *pctx) {
    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 3072);                /* RSA-3072 */
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp384r1);        /* ECDSA / secp384r1 */
}

void mac(unsigned char *key, int klen, unsigned char *d, int dlen) {
    HMAC(EVP_sha256(), key, klen, d, dlen, out, &olen);          /* HMAC */
    PKCS5_PBKDF2_HMAC(pw, plen, salt, slen, 100000, EVP_sha256(), klen, keyout); /* PBKDF2 */
}
