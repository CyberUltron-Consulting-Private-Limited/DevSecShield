// Synthetic .NET System.Security.Cryptography usage (C3 fixture).
using System.Security.Cryptography;

namespace Crypto {
    public class CryptoApp {
        public void SymmetricSuite() {
            var gcm = new AesGcm(key);                       // AES-GCM
            var aes = Aes.Create();                          // AES
            aes.Mode = CipherMode.CBC;                       // AES-CBC
            var td = TripleDES.Create();                     // 3DES
            var des = new DESCryptoServiceProvider();        // DES (weak)
            var rc2 = new RC2CryptoServiceProvider();        // RC2 (weak)
        }

        public void Hashes() {
            var md5 = MD5.Create();                          // MD5 (broken)
            var sha1 = SHA1.Create();                        // SHA-1 (weak)
            var sha256 = SHA256.Create();                    // SHA-256
            var mac = new HMACSHA512(key);                   // HMAC (+ SHA-512)
        }

        public void Asymmetric() {
            var rsa = RSA.Create(2048);                      // RSA-2048
            var rsa2 = new RSACryptoServiceProvider(1024);   // RSA-1024 (weak)
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384); // ECDSA / nistP384
            var kdf = new Rfc2898DeriveBytes(pw, salt, 100000); // PBKDF2
        }
    }
}
