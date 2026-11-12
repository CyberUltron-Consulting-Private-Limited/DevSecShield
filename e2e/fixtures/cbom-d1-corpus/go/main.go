package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	mrand "math/rand"
	"net/http"
)

func main() {
	key, _ := rsa.GenerateKey(rand.Reader, 1024) // G1 RSA-1024
	_ = key
	b, _ := des.NewTripleDESCipher([]byte("123456789012345678901234")) // G2 3DES + G3 hard-coded key
	_ = b
	h := md5.Sum([]byte("x")) // G4 MD5
	s := sha1.Sum([]byte("x")) // G5 SHA-1
	c, _ := rc4.NewCipher([]byte("secretkey")) // G6 RC4
	fmt.Println(h, s, c, mrand.Int()) // G7 math/rand
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,          // G8 verification off
		MinVersion:         tls.VersionTLS10, // G9 TLS 1.0
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_RC4_128_SHA}, // G10 weak suites
	}}
	_ = tr
}
