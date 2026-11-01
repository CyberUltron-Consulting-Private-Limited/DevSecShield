"""Line numbers, redacted code windows, false-positive fixes and the detailed graph (round 4)."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aibom.cbom.detect import detect_crypto
from aibom.cbom.graph_detail import build_detailed
from aibom.cbom.redact import code_window, redact_line
from aibom.integrations.cbom_devsecshield import analyze_cbom_file_to_devsecshield, scan_crypto_to_devsecshield

FIX = Path(__file__).resolve().parent / "fixtures"


def _rows(root: Path) -> dict[str, dict]:
    return {r["title"]: r for r in scan_crypto_to_devsecshield(root)["results"]}


def test_line_numbers_are_exact_with_form_feeds_and_crlf(tmp_path):
    (tmp_path / "a.py").write_bytes(b"import hashlib\r\n# MD5 note\r\nx = 1\x0c\r\nh = hashlib.md5(b'x')\r\n")
    r = _rows(tmp_path)["MD5"]
    assert r["line"] == 4 and r["occurrences"] == [4] and r["language"] == "python"
    assert r["location"] == "a.py"  # bare path: identity and rollups unchanged
    assert "hashlib.md5" in r["snippet"] and r["snippet_start"] == 1


def test_every_code_supply_finding_has_a_line_and_window():
    rows = scan_crypto_to_devsecshield(FIX / "code-supply" / "vulnerable")["results"]
    for r in rows:
        assert isinstance(r.get("line"), int) and r["line"] > 0, r["title"]
        assert r.get("snippet"), r["title"]
        assert r["crypto_strength"] == "weak" and r["weak"] is True, r["title"]
    types = {r["title"]: r["algorithm_type"] for r in rows}
    assert types["pyjwt@2.3.0"] == "library" and types["relational_db:aws_db_instance.plain"] == "configuration"


def test_symlink_outside_the_root_is_never_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("import hashlib\nAPI_KEY = 'sk-live-0123456789abcdef'\nh = hashlib.md5(b'x')\n")
    repo = tmp_path / "repo"
    repo.mkdir()
    os.symlink(outside / "secret.py", repo / "link.py")
    (repo / "ok.py").write_text("import hashlib\nh = hashlib.sha1(b'x')\n")
    out = scan_crypto_to_devsecshield(repo)
    blob = json.dumps(out)
    assert "sk-live" not in blob and "API_KEY" not in blob
    for r in out["results"]:
        if r["location"] == "link.py":
            assert not r.get("snippet")


def test_secrets_are_redacted_but_algorithm_strings_kept():
    line, n = redact_line('key = b"0123456789abcdef"; c = Cipher.getInstance("AES/CBC/PKCS5Padding")')
    assert "0123456789abcdef" not in line and '"AES/CBC/PKCS5Padding"' in line and n == 1
    assert "AKIAABCDEFGHIJKLMNOP" not in redact_line("aws = 'AKIAABCDEFGHIJKLMNOP'")[0]
    assert "eyJ" not in redact_line("t = 'eyJhbGciOi.eyJzdWIiOiIx.abcdefghijkl'")[0]
    strict, _ = redact_line("IV = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10]", strict=True)
    assert "0x05" not in strict
    win = code_window("x = 1\n-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n", 1)
    assert "MIIEvQ" not in win["snippet"] and "<redacted PEM body>" in win["snippet"]
    assert "\\u202e" in redact_line("x = 'a‮b'")[0]


def test_hardcoded_key_window_is_strict(tmp_path):
    (tmp_path / "k.py").write_text(
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "KEY = b'supersecretkey16'\n"
        "c = Cipher(algorithms.AES(KEY), modes.CBC(b'1234567890abcdef'))\n")
    blob = json.dumps(scan_crypto_to_devsecshield(tmp_path)["results"])
    assert "supersecretkey16" not in blob and "1234567890abcdef" not in blob


def test_uploaded_cbom_paths_are_never_read(tmp_path):
    secret = tmp_path / "host_secret.py"
    secret.write_text("import hashlib\nPASSWORD = 'hunter2hunter2'\nh = hashlib.md5(b'x')\n")
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{
        "type": "cryptographic-asset", "name": "MD5", "bom-ref": "a",
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "hash"}},
        "evidence": {"occurrences": [{"location": str(secret), "line": 3}]},
        "properties": [{"name": "discovery:source", "value": str(secret)}, {"name": "crypto:line", "value": "3"}]}]}
    f = tmp_path / "up.json"
    f.write_text(json.dumps(doc))
    out = analyze_cbom_file_to_devsecshield(f)
    assert "hunter2" not in json.dumps(out)
    assert all(not r.get("snippet") for r in out["results"])


@pytest.mark.parametrize("lang,line", [
    ("python", 'POLICY = "All data uses AES-256 encryption at rest"'),
    ("python", 'raise ValueError("MD5 is not allowed in this codebase")'),
    ("javascript", '<p className="t">We encrypt with AES-256 and rotate keys yearly</p>'),
])
def test_prose_is_not_usage(lang, line):
    assert detect_crypto(line, lang) == []


@pytest.mark.parametrize("lang,line,key", [
    ("java", 'Cipher.getInstance("AES/CBC/PKCS5Padding")', "aes"),
    ("python", "c = AES.new(key, AES.MODE_ECB)", "aes"),
    ("python", "d = DES.new(key, DES.MODE_CBC)", "des"),
    ("python", "k = RSA.generate(1024)", "rsa"),
])
def test_api_strings_and_pycryptodome_are_usage(lang, line, key):
    assert key in [d.key for d in detect_crypto(line, lang)]


def test_svg_stroke_is_not_ipsec(tmp_path):
    (tmp_path / "chart.tsx").write_text('export const C = () => <path stroke="#ccc" strokeWidth={2} />;\n')
    titles = [r["title"] for r in scan_crypto_to_devsecshield(tmp_path)["results"]]
    assert not any("IPsec" in t for t in titles)


def test_modes_only_for_block_ciphers(tmp_path):
    (tmp_path / "A.java").write_text(
        'import javax.crypto.Cipher;\nclass A { void f() throws Exception {\n'
        '  Cipher r = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\n'
        '  javax.crypto.Mac m = javax.crypto.Mac.getInstance("HmacSHA256"); // AES-CBC elsewhere\n} }\n')
    rows = _rows(tmp_path)
    assert not any(t.startswith(("RSA-ECB", "HMAC-CBC", "SHA-256-CBC")) for t in rows)
    assert all("WEAK_CIPHER_MODE" not in r["finding_codes"] for t, r in rows.items() if t.startswith("RSA"))


def test_repo_under_a_build_directory_is_scanned(tmp_path):
    repo = tmp_path / "build" / "env" / "repo"
    repo.mkdir(parents=True)
    (repo / "a.py").write_text("import hashlib\nh = hashlib.md5(b'x')\n")
    assert "MD5" in _rows(repo)


def test_node_require_counts_as_a_library_and_links_the_graph(tmp_path):
    (tmp_path / "x.js").write_text('const crypto = require("crypto");\nconst h = crypto.createHash("sha1");\n')
    out = scan_crypto_to_devsecshield(tmp_path)
    edges = out["cbom_graph"]["edges"]
    assert any(e["rel"] == "provides" for e in edges)
    compact = out["cbom_graph_compact"]
    kinds = {n["kind"] for n in compact["nodes"]}
    assert {"family", "location", "crypto_asset", "framework"} <= kinds


@pytest.mark.parametrize("budget", [40, 120])
def test_graph_budget_holds_on_a_huge_repo(budget):
    nodes = [{"id": f"a{i}", "label": f"MD5 #{i}", "kind": "crypto_asset", "asset_type": "algorithm",
              "primitive": ["hash", "block-cipher", "pke"][i % 3], "weak": i % 7 == 0, "impact": "High",
              "location": f"pkg{i % 40}/sub{i % 5}/f{i}.py"} for i in range(5000)]
    nodes += [{"id": f"l{j}", "label": f"lib{j}", "kind": "framework", "location": "requirements.txt"} for j in range(60)]
    edges = [{"source": f"l{i % 60}", "target": f"a{i}", "rel": "provides"} for i in range(5000)]
    g = build_detailed({"nodes": nodes, "edges": edges}, max_nodes=budget)
    assert len(g["nodes"]) <= budget + 4, len(g["nodes"])
    assert g["meta"]["assets"] == 5000 and g["meta"]["shown_assets"] + g["meta"]["folded_assets"] == 5000
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    shown = [n for n in g["nodes"] if n.get("kind") == "crypto_asset" and not n.get("cluster")]
    assert all(n.get("weak") for n in shown) or len(shown) >= 5000 // 7  # riskiest first
    assert len(json.dumps(g)) < 200_000


def test_key_literal_in_source_gets_a_strict_window_and_key_files_none(tmp_path):
    (tmp_path / "fernet_hardcoded.py").write_text(
        "from cryptography.fernet import Fernet\n"
        "KEY = b\"ZmVybmV0LWtleS1mb3ItdGVzdGluZy0xMjM0NTY3ODkwYWI=\"\n"
        "def f():\n    return Fernet(KEY)\n")
    (tmp_path / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n")
    out = scan_crypto_to_devsecshield(tmp_path)
    blob = json.dumps(out)
    assert "ZmVybmV0LWtleS1mb3I" not in blob and "MIIEvQIBADAN" not in blob
    hard = [r for r in out["results"] if "HARDCODED_KEY" in (r.get("finding_codes") or [])]
    assert hard and all(r.get("snippet") and "<redacted:" in r["snippet"] for r in hard
                        if r["location"].endswith(".py"))
    assert all(not r.get("snippet") for r in out["results"] if r["location"].endswith(".key"))


def test_cyclonedx_evidence_occurrences_carry_file_and_line(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nx = 1\nh = hashlib.md5(b'x')\ng = hashlib.md5(b'y')\n")
    doc = scan_crypto_to_devsecshield(tmp_path)["cbom_json"]
    doc = json.loads(doc) if isinstance(doc, str) else doc
    md5 = next(c for c in doc["components"] if c.get("name") == "MD5")
    assert md5["evidence"]["occurrences"] == [{"location": "a.py", "line": 3}, {"location": "a.py", "line": 4}]


def test_key_file_gets_the_line_of_its_pem_armour(tmp_path):
    # the occurrence pass used to blank "-----BEGIN ..." as a SQL "--" comment, so key files had no line
    pem = (FIX / "synthetic-crypto-certs-harden" / "server.key").read_text()
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy" / "server.key").write_text("# staging TLS key\n\n" + pem)
    rows = [r for r in scan_crypto_to_devsecshield(tmp_path)["results"] if r["location"].endswith("server.key")]
    assert rows and all(r.get("line") == 3 for r in rows), [(r["title"], r.get("line")) for r in rows]
    assert "MII" not in json.dumps(rows)  # the window around a key never carries key bytes


def test_code_scan_only_languages_are_labelled(tmp_path):
    # Groovy, Perl, VB.NET, SQL, Dockerfile.* and #! scripts are scanned; their findings must say which language
    (tmp_path / "Crypto.groovy").write_text('import java.security.MessageDigest\ndef h = MessageDigest.getInstance("MD5")\n')
    (tmp_path / "digest.pl").write_text("use Digest::MD5 qw(md5_hex);\nmy $h = md5_hex($data);\n")
    (tmp_path / "Dockerfile.build").write_text("FROM debian:12\nRUN openssl enc -aes-128-ecb -in a -out b -K 00 \n")
    (tmp_path / "cryptohelper").write_text("#!/bin/bash\nopenssl enc -rc4 -in \"$1\" -out \"$1.enc\" -pass pass:x\n")
    rows = scan_crypto_to_devsecshield(tmp_path)["results"]
    langs = {r["location"]: r.get("language") for r in rows if r.get("line")}
    assert langs.get("Crypto.groovy") == "groovy" and langs.get("digest.pl") == "perl"
    assert langs.get("Dockerfile.build") == "dockerfile" and langs.get("cryptohelper") == "shell", langs
