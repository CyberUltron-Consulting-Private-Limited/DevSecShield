// C2 fixture — Go crypto-API usage across the stdlib crypto/* packages and
// golang.org/x/crypto. Exercises the clean-room GO_RULES detection lane.
package main

import (
	"crypto/aes"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/chacha20poly1305"
)

func stdlib(key []byte, data []byte) {
	block, _ := aes.NewCipher(key)
	weak, _ := des.NewCipher(key)
	stream, _ := rc4.NewCipher(key)
	_ = md5.New()
	_ = sha256.New()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	sig, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _, _, _, _ = block, weak, stream, priv, sig
}

func xcrypto(pw []byte, salt []byte, key []byte) {
	_, _ = bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
	_ = argon2.IDKey(pw, salt, 1, 65536, 4, 32)
	_, _ = chacha20poly1305.New(key)
}
