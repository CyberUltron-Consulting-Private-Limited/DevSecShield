"""CB-28: .NET, C (OpenSSL), Terraform and ingress-nginx detectors.

Also the C# ``TrustAll()`` false positive.

Each case writes a small file to a temporary directory and runs the worker's call
(:func:`aibom.integrations.cbom_devsecshield.scan_crypto_to_devsecshield`); the
assertions read the result rows the
product stores: the file, the row's line and its finding codes. The positive cases are
the R2 corpus items (N6, N8,
N10-N12, C3, C4, C7, T5, T7, K1, K2); the negative cases are the shapes a line reader
gets wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield


def _rows(tmp_path: Path, files: dict[str, str]) -> set[tuple[str, int, str]]:
    for rel, body in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    run = scan_crypto_to_devsecshield(str(tmp_path), level=4)
    out = set()
    for row in run.get("results") or []:
        for code in row.get("finding_codes") or []:
            out.add(
                (
                    Path(str(row.get("location") or "")).name,
                    int(row.get("line") or 0),
                    code,
                )
            )
    return out


CS = """using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;
namespace Bank {
  public class Crypto {
    public byte[] Pkcs1(RSA r, byte[] d) {
      return r.Encrypt(d, RSAEncryptionPadding.Pkcs1); }
    public void TrustAll() {
      ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
    }
    static readonly byte[] Key = Encoding.ASCII.GetBytes("0123456789abcdef");
    public Aes HardAes() { var a = Aes.Create(); a.Key = Key; a.IV = new byte[16];
      return a; }
    byte[] Kdf(string p, byte[] s) { return new Rfc2898DeriveBytes(p, s, 1000)
      .GetBytes(8); }
    byte[] KdfD(string p, byte[] s) { return new Rfc2898DeriveBytes(p, s).GetBytes(8); }
  }
}
"""

C = """#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_cipher_list(ctx, "DES-CBC3-SHA:RC4-SHA:NULL-MD5");
    RSA *r = RSA_new(); BIGNUM *e = BN_new(); BN_set_word(e, 3);
    RSA_generate_key_ex(r, 2048, e, NULL);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    unsigned char key[16] = "0123456789abcdef";
    EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, key, NULL);
    return 0;
}
"""

TF = """resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 1024
}
resource "azurerm_storage_account" "sa" {
  name = "sa"
  min_tls_version = "TLS1_0"
}
"""

K8S = """apiVersion: v1
kind: ConfigMap
metadata:
  name: ingress-nginx-controller
data:
  ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2"
  ssl-ciphers: "DES-CBC3-SHA:RC4-SHA"
"""


def test_dotnet_items(tmp_path):
    rows = _rows(tmp_path, {"Crypto.cs": CS})
    assert ("Crypto.cs", 8, "WEAK_PADDING") in rows  # N6 PKCS#1 v1.5 encryption
    assert ("Crypto.cs", 10, "WEAK_PROTOCOL") in rows  # N8 SecurityProtocolType.Tls
    assert ("Crypto.cs", 12, "HARDCODED_KEY") in rows  # N10 a 16-character literal
    assert ("Crypto.cs", 13, "STATIC_IV") in rows  # N11 sixteen zero bytes
    assert ("Crypto.cs", 15, "WEAK_KDF_ITERATIONS") in rows  # N12 1,000 iterations
    assert ("Crypto.cs", 17, "WEAK_KDF_ITERATIONS") in rows  # the default (1,000)
    # NFP1: the C# method name TrustAll() is not a Java trust-all trust manager
    assert not [r for r in rows if r[2] == "TLS_VERIFICATION_DISABLED"]


def test_c_items(tmp_path):
    rows = _rows(tmp_path, {"tls_client.c": C})
    assert ("tls_client.c", 6, "WEAK_CIPHER_SUITE") in rows  # C3
    assert ("tls_client.c", 7, "WEAK_RSA_EXPONENT") in rows  # C4 e = 3
    assert ("tls_client.c", 10, "HARDCODED_KEY") in rows  # C7


def test_terraform_items(tmp_path):
    rows = _rows(tmp_path, {"main.tf": TF})
    assert ("main.tf", 3, "WEAK_ALGORITHM") in rows or (
        "main.tf",
        3,
        "WEAK_KEY_SIZE",
    ) in rows  # T5 RSA-1024
    assert ("main.tf", 7, "WEAK_PROTOCOL") in rows  # T7 Azure storage TLS 1.0


def test_ingress_nginx_configmap_items(tmp_path):
    rows = _rows(tmp_path, {"ingress.yaml": K8S})
    assert ("ingress.yaml", 6, "WEAK_PROTOCOL") in rows  # K1
    assert ("ingress.yaml", 7, "WEAK_CIPHER_SUITE") in rows  # K2


@pytest.mark.parametrize(
    "rel,body",
    [
        # a mapped or compared protocol is not a configured one
        (
            "Map.cs",
            "class M { string N(System.Security.Authentication.SslProtocols p) {"
            " switch (p) {\n"
            '  case SslProtocols.Tls: return "1.0"; } return p == SslProtocols.Tls11'
            ' ? "1.1" : ""; } }\n',
        ),
        # TLS 1.2 / 1.3 only
        (
            "Ok.cs",
            "class O { void S() { System.Net.ServicePointManager.SecurityProtocol = "
            "SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13; } }\n",
        ),
        # enough iterations
        (
            "Kdf.cs",
            "class K { byte[] D(string p, byte[] s) { return new Rfc2898DeriveBytes(p,"
            " s, 600000, "
            "HashAlgorithmName.SHA256).GetBytes(32); } }\n",
        ),
        # OAEP
        (
            "Oaep.cs",
            "class R { byte[] E(RSA r, byte[] d) { return r.Encrypt(d,"
            " RSAEncryptionPadding.OaepSHA256); } }\n",
        ),
        # a cipher list that only removes the weak suites
        (
            "ok.c",
            "#include <openssl/ssl.h>\nvoid f(SSL_CTX *ctx) {"
            " SSL_CTX_set_cipher_list(ctx, "
            '"HIGH:!aNULL:!MD5:!RC4:-3DES"); }\n',
        ),
        # e = 65537
        (
            "rsa.c",
            "#include <openssl/rsa.h>\nvoid g(RSA *r, BIGNUM *e) { BN_set_word(e,"
            " RSA_F4); "
            "RSA_generate_key_ex(r, 3072, e, NULL); }\n",
        ),
        # a commented-out call
        (
            "old.c",
            '#include <openssl/ssl.h>\nvoid h(SSL_CTX *ctx) {\n  /*'
            ' SSL_CTX_set_cipher_list(ctx, "RC4-SHA"); */\n'
            '  // SSL_CTX_set_cipher_list(ctx, "RC4-SHA");\n}\n',
        ),
        # current Terraform settings
        (
            "ok.tf",
            'resource "tls_private_key" "k" {\n  algorithm = "RSA"\n  rsa_bits ='
            ' 4096\n}\n'
            'resource "azurerm_storage_account" "s" {\n  name = "s"\n '
            ' min_tls_version = "TLS1_2"\n}\n',
        ),
        # an ingress-nginx ConfigMap on TLS 1.2 and 1.3 with AEAD suites
        (
            "cm.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name:"
            " ingress-nginx-controller\ndata:\n"
            '  ssl-protocols: "TLSv1.2 TLSv1.3"\n  ssl-ciphers:'
            ' "ECDHE-RSA-AES128-GCM-SHA256"\n',
        ),
    ],
)
def test_not_reported(tmp_path, rel, body):
    codes = {code for _, _, code in _rows(tmp_path, {rel: body})}
    assert (
        codes
        & {
            "WEAK_PROTOCOL",
            "WEAK_KDF_ITERATIONS",
            "WEAK_PADDING",
            "WEAK_CIPHER_SUITE",
            "WEAK_RSA_EXPONENT",
            "WEAK_KEY_SIZE",
            "WEAK_ALGORITHM",
        }
        == set()
    )


def test_the_java_trust_all_pattern_still_reads_java(tmp_path):
    body = (
        "import javax.net.ssl.*;\nclass T { static SSLSocketFactory f() throws"
        " Exception {\n"
        '  SSLContext c = SSLContext.getInstance("TLS"); c.init(null, new'
        ' TrustManager[]{ new TrustAllCerts() }, null);\n'
        "  return c.getSocketFactory(); } }\n"
    )
    assert "TLS_VERIFICATION_DISABLED" in {
        code for _, _, code in _rows(tmp_path, {"T.java": body})
    }
