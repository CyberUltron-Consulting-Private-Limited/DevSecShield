"""In-house code fixes (no model): rules rewrite only the detected line, diffs carry real line numbers."""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.utilities.cbom_sources import fixgen, kb_remediation  # noqa: E402


def row(snippet, line, start=1, lang="python", path="src/app.py", codes=("WEAK_ALGORITHM",), title="MD5", **kw):
    return {"snippet": snippet, "line": line, "snippet_start": start, "language": lang, "location": path,
            "finding_codes": list(codes), "title": title, "algorithm_name": title, **kw}


def fixed_line(g, n, start=1):
    return g["fixed_code"].split("\n")[n - start]


CASES = [
    # (language, title, codes, snippet line, expected fixed line)
    ("python", "MD5", ["WEAK_ALGORITHM"], "h = hashlib.md5(data).hexdigest()", "h = hashlib.sha256(data).hexdigest()"),
    ("python", "SHA-1", ["WEAK_ALGORITHM"], "d = hashes.Hash(hashes.SHA1())", "d = hashes.Hash(hashes.SHA256())"),
    ("python", "AES-ECB", ["WEAK_CIPHER_MODE"], "c = AES.new(key, AES.MODE_ECB)", "c = AES.new(key, AES.MODE_GCM)"),
    ("python", "RSA-1024", ["WEAK_KEY_SIZE"], "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)",
     "k = rsa.generate_private_key(public_exponent=65537, key_size=3072)"),
    ("python", "tls", ["TLS_VERIFICATION_DISABLED"], "r = requests.get(u, verify=False)", "r = requests.get(u, verify=True)"),
    ("python", "tls", ["TLS_VERIFICATION_DISABLED"], "ctx = ssl._create_unverified_context()",
     "ctx = ssl.create_default_context()"),
    ("java", "MD5", ["WEAK_ALGORITHM"], 'MessageDigest md = MessageDigest.getInstance("MD5");',
     'MessageDigest md = MessageDigest.getInstance("SHA-256");'),
    ("java", "AES-ECB", ["WEAK_CIPHER_MODE"], 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");',
     'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
    ("java", "AES", ["WEAK_CIPHER_MODE"], 'Cipher c = Cipher.getInstance("AES");',
     'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
    ("java", "RSA-1024", ["WEAK_KEY_SIZE"], "kpg.initialize(1024);", "kpg.initialize(3072);"),
    ("java", "SHA1withRSA", ["WEAK_ALGORITHM"], 'Signature s = Signature.getInstance("SHA1withRSA");',
     'Signature s = Signature.getInstance("SHA256withRSA");'),
    ("javascript", "SHA-1", ["WEAK_ALGORITHM"], 'const h = crypto.createHash("sha1");', 'const h = crypto.createHash("sha256");'),
    ("javascript", "3DES-CBC", ["WEAK_ALGORITHM"], "const c = crypto.createCipheriv('des-ede3-cbc', k, iv);",
     "const c = crypto.createCipheriv('aes-256-gcm', k, iv);"),
    ("typescript", "tls", ["TLS_VERIFICATION_DISABLED"], "const a = new https.Agent({ rejectUnauthorized: false });",
     "const a = new https.Agent({ rejectUnauthorized: true });"),
    ("go", "MD5", ["WEAK_ALGORITHM"], "sum := md5.Sum(data)", "sum := sha256.Sum256(data)"),
    ("go", "tls", ["TLS_VERIFICATION_DISABLED"], "cfg := &tls.Config{InsecureSkipVerify: true}",
     "cfg := &tls.Config{InsecureSkipVerify: false}"),
    ("csharp", "MD5", ["WEAK_ALGORITHM"], "using var h = MD5.Create();", "using var h = SHA256.Create();"),
    ("c", "MD5", ["WEAK_ALGORITHM"], "EVP_DigestInit_ex(ctx, EVP_md5(), NULL);", "EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);"),
    ("c", "tls", ["TLS_VERIFICATION_DISABLED"], "SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);",
     "SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);"),
    ("php", "MD5", ["WEAK_ALGORITHM"], "$h = md5($data);", "$h = hash('sha256', $data);"),
    ("php", "tls", ["TLS_VERIFICATION_DISABLED"], "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);",
     "curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);"),
    ("ruby", "MD5", ["WEAK_ALGORITHM"], "h = Digest::MD5.hexdigest(data)", "h = Digest::SHA256.hexdigest(data)"),
    ("ruby", "tls", ["TLS_VERIFICATION_DISABLED"], "http.verify_mode = OpenSSL::SSL::VERIFY_NONE",
     "http.verify_mode = OpenSSL::SSL::VERIFY_PEER"),
]


@pytest.mark.parametrize("lang,title,codes,src,want", CASES)
def test_rule_rewrites_the_detected_line(lang, title, codes, src, want):
    snippet = "# before\n" + src + "\n# after"
    g = fixgen.generate(row(snippet, 11, 10, lang=lang, codes=codes, title=title))
    assert g["available"] and g["kind"] == "code", g
    assert fixed_line(g, 11, 10) == want
    assert g["fixed_code"].split("\n")[0] == "# before" and g["fixed_code"].split("\n")[2] == "# after"
    assert "@@ -10,3 +10,3 @@" in g["diff"]
    assert 0 < g["confidence"] <= 100


def test_crlf_line_endings_are_kept():
    g = fixgen.generate(row("import hashlib\r\nh = hashlib.md5(x)\r\nprint(h)\r", 2))
    assert g["fixed_code"] == "import hashlib\r\nh = hashlib.sha256(x)\r\nprint(h)\r"
    assert g["diff"].count("\n-") == 1 and g["diff"].count("\n+") == 2  # one changed line (+ the +++ header)


def test_only_the_detected_line_changes():
    g = fixgen.generate(row("a = hashlib.md5(x)\nb = hashlib.md5(y)\n", 2))
    assert g["fixed_code"].split("\n")[:2] == ["a = hashlib.md5(x)", "b = hashlib.sha256(y)"]


def test_non_security_md5_is_not_rewritten():
    g = fixgen.generate(row("etag = hashlib.md5(body, usedforsecurity=False).hexdigest()", 1))
    assert g["kind"] == "non-security-use" and not g["available"] and g["fixed_code"] == ""


def test_password_hash_gets_a_migration_warning():
    g = fixgen.generate(row("pw_hash = hashlib.md5(password.encode()).hexdigest()", 1))
    assert any("password KDF" in w for w in g["warnings"])


def test_lock_file_is_never_edited():
    g = fixgen.generate(row('    "node_modules/node-forge": {\n      "version": "1.2.1",', 1, lang="lockfile",
                            path="package-lock.json", codes=["VULNERABLE_CRYPTO_LIBRARY"], title="node-forge@1.2.1",
                            description="node-forge 1.2.1 matches CVE-2022-24771. Fixed in 1.3.0. https://x"))
    assert g["kind"] == "dependency" and g["diff"] == "" and g["commands"] == ["npm install node-forge@^1.3.0"]


def test_requirements_pin_is_bumped():
    g = fixgen.generate(row("PyJWT==2.3.0\nrequests==2.31.0", 1, lang="pip-requirements", path="requirements.txt",
                            codes=["VULNERABLE_CRYPTO_LIBRARY"], title="pyjwt@2.3.0",
                            description="pyjwt 2.3.0 matches CVE-2022-29217. Fixed in 2.4.0. https://x"))
    assert g["fixed_code"].split("\n") == ["PyJWT>=2.4.0", "requests==2.31.0"]


def test_bouncycastle_rename_in_pom():
    snippet = ("    <dependency>\n      <groupId>org.bouncycastle</groupId>\n      <artifactId>bcprov-jdk15on</artifactId>\n"
               "      <version>1.70</version>\n    </dependency>")
    g = fixgen.generate(row(snippet, 3, lang="xml", path="pom.xml", codes=["VULNERABLE_CRYPTO_LIBRARY"],
                            title="org.bouncycastle:bcprov-jdk15on@1.70",
                            description="matches CVE-2023-33201. Fixed in 1.74. https://x"))
    assert "<artifactId>bcprov-jdk18on</artifactId>" in g["fixed_code"] and "<version>1.74</version>" in g["fixed_code"]


def test_terraform_block_fix_warns_about_replacement():
    g = fixgen.generate(row('resource "aws_db_instance" "plain" {\n  storage_encrypted = false\n}', 1,
                            lang="terraform", path="main.tf", codes=["UNENCRYPTED_AT_REST"], title="relational_db"))
    assert "storage_encrypted = true" in g["fixed_code"] and g["confidence"] <= 50
    assert any("forces replacement" in w for w in g["warnings"])


def test_no_rule_means_no_invented_code():
    g = fixgen.generate(row("x = custom_sbox_round(state)", 1, codes=["CUSTOM_CRYPTO"], title="AES (custom)"))
    assert not g["available"] and g["fixed_code"] == "" and g["diff"] == ""


def test_old_rows_without_a_snippet_say_rescan():
    g = fixgen.generate({"title": "MD5", "finding_codes": ["WEAK_ALGORITHM"], "location": "a.py"})
    assert not g["available"] and "Rescan" in g["summary"]


def test_hostile_path_is_quoted_in_the_diff_header():
    g = fixgen.generate(row("h = hashlib.md5(x)", 1, path="a\nb‮.py"))
    header = g["diff"].split("\n")[0]
    assert "\n" not in header and "‮" not in header and header.startswith('--- "a/')


def test_redacted_window_is_flagged_for_manual_apply():
    g = fixgen.generate(row('c = AES.new(b"<redacted:16>", AES.MODE_ECB)', 1, codes=["WEAK_CIPHER_MODE"], title="AES-ECB"))
    assert any("redacted" in w for w in g["warnings"])


def test_python_fixes_still_compile():
    for lang, title, codes, src, want in CASES:
        if lang == "python":
            compile(want, "<fixed>", "exec")


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_javascript_fixes_still_parse(tmp_path):
    for lang, title, codes, src, want in CASES:
        if lang in ("javascript", "typescript") and "new https.Agent" not in want:
            f = tmp_path / "x.js"
            f.write_text("const crypto=require('crypto');let k,iv;\n" + want + "\n")
            assert subprocess.run(["node", "--check", str(f)]).returncode == 0, want


def test_remediation_response_carries_fix_diff_and_demo():
    out = kb_remediation.remediation(row("import hashlib\nh = hashlib.md5(x)", 2))
    assert out["engine"] == kb_remediation.ENGINE and out["source"] == "knowledge_base"
    assert out["fix"]["fixed_code"].endswith("hashlib.sha256(x)") and out["fix"]["language"] == "python"
    assert out["diff"].startswith("--- a/src/app.py") and out["code_fix"]["rules"] == ["py-hashlib-call"]
    assert out["exploit_demo"]["family"] == "md5-collision" and "RESULT: COLLISION" in out["exploit_demo"]["poc"]["script"]
    assert "grep" in out["exploit_payload"]["payload"]  # the legacy field stays read-only commands for this asset
