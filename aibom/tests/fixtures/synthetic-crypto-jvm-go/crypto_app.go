// Go crypto fixture for C2 (stdlib crypto + golang.org/x/crypto). Every asset
// is a labeled detection target resolvable by the call-expression model: the
// package path fixes the primitive context, the call arguments supply the
// parameters. Nothing here is a real credential. This comment naming AES-256 and
// SHA-512 must NOT be inventoried — comments are stripped before scanning.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
)

func aesGCM(key, plaintext []byte) ([]byte, error) {
	// block var is created here; the mode wrapper below binds to it -> AES-GCM.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, make([]byte, 12), plaintext, nil), nil
}

func tripleDESCBC(key, iv, plaintext []byte) []byte {
	block, _ := des.NewTripleDESCipher(key) // 3DES
	mode := cipher.NewCBCEncrypter(block, iv) // -> 3DES-CBC
	out := make([]byte, len(plaintext))
	mode.CryptBlocks(out, plaintext)
	return out
}

func rsaKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048) // RSA-2048 (key size is 2nd arg)
}

func ecdsaKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) // ECDSA on P-384
}

func ed25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader) // Ed25519
}

func digest(data []byte) [32]byte {
	return sha256.Sum256(data) // SHA-256
}

func legacyDigest(data []byte) [16]byte {
	return md5.Sum(data) // MD5 (weak)
}

func authenticate(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key) // HMAC
	h.Write(msg)
	return h.Sum(nil)
}

func aead(key, nonce, msg []byte) ([]byte, error) {
	c, err := chacha20poly1305.New(key) // ChaCha20-Poly1305
	if err != nil {
		return nil, err
	}
	return c.Seal(nil, nonce, msg, nil), nil
}

func hashPassword(pw []byte) ([]byte, error) {
	return bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost) // bcrypt
}

func deriveKey(pw, salt []byte) []byte {
	return argon2.IDKey(pw, salt, 1, 64*1024, 4, 32) // Argon2
}
