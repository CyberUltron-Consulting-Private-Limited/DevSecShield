#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <stdlib.h>

int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());               /* C1 TLS 1.0 */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);                    /* C2 no verification */
    SSL_CTX_set_cipher_list(ctx, "DES-CBC3-SHA:RC4-SHA:NULL-MD5");    /* C3 weak suites */
    RSA *r = RSA_new(); BIGNUM *e = BN_new(); BN_set_word(e, 3);       /* C4 e=3 */
    RSA_generate_key_ex(r, 1024, e, NULL);                             /* C5 RSA-1024 */
    unsigned char out[16]; MD5((unsigned char*)"x", 1, out);           /* C6 MD5 */
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    unsigned char key[16] = "0123456789abcdef";                        /* C7 hard-coded key */
    EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, key, NULL);         /* C8 AES-ECB */
    EVP_EncryptInit_ex(c, EVP_des_ede3_cbc(), NULL, key, NULL);        /* C9 3DES */
    srand(42); int nonce = rand();                                     /* C10 rand() */
    return nonce;
}
