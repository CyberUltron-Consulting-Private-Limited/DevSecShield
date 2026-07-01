// C3 fixture — .NET System.Security.Cryptography. Provider class names
// (RSACryptoServiceProvider / TripleDESCryptoServiceProvider) end the algorithm
// token with `Crypto...`, so the global `\bRSA\b`/`\bTripleDES\b` never fire; and
// a `using (var aes = Aes.Create())` statement must be scanned, not skipped as an
// import directive.
using System.Security.Cryptography;

public static class DotNetCrypto
{
    public static void Symmetric()
    {
        // `using (...)` statement (not an import) — its Aes.Create() must scan.
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
        }
        var tdes = new TripleDESCryptoServiceProvider();
    }

    public static void Asymmetric()
    {
        var rsa = new RSACryptoServiceProvider(2048);
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    }

    public static void Hashing()
    {
        var sha = SHA256.Create();
        var weak = MD5.Create();
        var mac = new HMACSHA256(key);
    }

    public static void Kdf()
    {
        var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000);
    }
}
