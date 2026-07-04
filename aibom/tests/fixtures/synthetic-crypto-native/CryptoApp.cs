// Synthetic .NET System.Security.Cryptography fixture (C3). .cs is NOT in the
// line-regex scanner's language set, so C3 is the ONLY scanner that inventories
// C#. The RSA key size (RSA.Create(2048)), the EC named curve, and the block
// cipher mode (CipherMode.ECB — a weakness signal for C6) all bind from
// arguments / assignments, not the class name alone.
using System.Security.Cryptography;

public class CryptoApp
{
    public void Symmetric()
    {
        var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;                 // -> AES-ECB (mode bound to the AES asset)
        var tdes = TripleDES.Create();             // -> 3DES
        var gcm = new AesGcm(key);                 // -> AES-GCM
    }

    public void Asymmetric()
    {
        var rsa = RSA.Create(2048);                // -> RSA-2048
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384); // -> ECDSA + SECP384R1
    }

    public void Digests()
    {
        var sha = SHA256.Create();                 // -> SHA-256
        var md5 = MD5.Create();                    // -> MD5
        var mac = new HMACSHA256(key);             // -> HMAC
        var kdf = new Rfc2898DeriveBytes(pw, salt, 100000); // -> PBKDF2
    }
}
