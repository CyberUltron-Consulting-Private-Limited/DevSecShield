using System;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

namespace Bank {
  public class Crypto {
    public byte[] Md5(byte[] d) { using (var m = MD5.Create()) return m.ComputeHash(d); }       // N1 MD5
    public byte[] Sha1(byte[] d) { return new SHA1Managed().ComputeHash(d); }                     // N2 SHA-1
    public ICryptoTransform Des(byte[] k) { var d = new DESCryptoServiceProvider(); d.Mode = CipherMode.ECB; return d.CreateEncryptor(k, k); } // N3 DES ECB
    public ICryptoTransform Tdes() { var t = TripleDES.Create(); return t.CreateEncryptor(); }  // N4 3DES
    public RSA WeakRsa() { return new RSACryptoServiceProvider(1024); }                           // N5 RSA-1024
    public byte[] Pkcs1(RSA r, byte[] d) { return r.Encrypt(d, RSAEncryptionPadding.Pkcs1); }    // N6 PKCS#1 v1.5
    public void TrustAll() {
      ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;          // N7 validation off
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;                            // N8 TLS 1.0
    }
    public int Token() { return new Random().Next(); }                                            // N9 System.Random
    static readonly byte[] Key = Encoding.ASCII.GetBytes("0123456789abcdef");                   // N10 hard-coded key
    public Aes HardAes() { var a = Aes.Create(); a.Key = Key; a.IV = new byte[16]; return a; }   // N11 zero IV
    public byte[] Rfc2898(string p, byte[] salt) { return new Rfc2898DeriveBytes(p, salt, 1000).GetBytes(32); } // N12 PBKDF2-SHA1 1000 iters
  }
}
