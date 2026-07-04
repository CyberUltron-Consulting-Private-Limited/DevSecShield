// Synthetic .NET fixture for the C3 call-expression scanner. The cipher mode and
// key size are set on the AES variable across statements (CipherMode / KeySize),
// the RSA key size is a constructor argument, and the EC curve is a named-curve
// argument — each bound from the call, not a bare token.
using System;
using System.Security.Cryptography;

public class CryptoApp
{
    public void EncryptGcm(byte[] key)
    {
        using var aes = new AesGcm(key);            // AES + GCM
    }

    public void EncryptCbc()
    {
        using var aes = Aes.Create();               // AES
        aes.KeySize = 256;                          // key size bound to the var
        aes.Mode = CipherMode.CBC;                  // mode bound to the var
    }

    public void LegacyTripleDes()
    {
        using var t = new TripleDESCryptoServiceProvider();  // 3DES
    }

    public void HashStrong()
    {
        using var h = SHA384.Create();              // SHA-384
    }

    public void HashWeak()
    {
        using var h = MD5.Create();                 // MD5
    }

    public void Mac()
    {
        using var m = new HMACSHA256();             // HMAC
    }

    public void GenRsa()
    {
        using var rsa = RSA.Create(2048);           // RSA-2048
    }

    public void GenEc()
    {
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);  // ECDSA P-521
    }

    public void Kdf(byte[] pw, byte[] salt)
    {
        using var k = new Rfc2898DeriveBytes(pw, salt, 100000);  // PBKDF2
    }
}
