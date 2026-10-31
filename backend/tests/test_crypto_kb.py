"""Offline crypto knowledge base: coverage of every finding code, sourced mappings, library versions, signed bundles."""
from __future__ import annotations

import base64
import datetime as dt
import json
import pathlib
import re
import socket

import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import crypto_kb as kb  # noqa: E402
BACKEND_KB = ROOT / "backend/utilities/cbom_sources"
AIBOM_KB = ROOT / "aibom/src/aibom/cbom"


@pytest.fixture(autouse=True)
def _fresh_kb(monkeypatch):
    for name in ("CBOM_KB_BUNDLE", "CBOM_KB_BUNDLE_SIG", "CBOM_KB_PUBKEYS"):
        monkeypatch.delenv(name, raising=False)
    kb.load.cache_clear()
    yield
    kb.load.cache_clear()


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("the knowledge base must not open network connections")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_both_copies_are_identical():
    assert (BACKEND_KB / "crypto_kb.py").read_bytes() == (AIBOM_KB / "crypto_kb.py").read_bytes()
    assert (BACKEND_KB / "data/crypto_kb.json").read_bytes() == (AIBOM_KB / "data/crypto_kb.json").read_bytes()


def test_shipped_file_is_reproducible_from_sources(tmp_path):
    import subprocess
    import sys
    shipped = json.loads((BACKEND_KB / "data/crypto_kb.json").read_text())
    out = tmp_path / "kb.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/crypto_kb/build_kb.py"), shipped["kb_version"], str(out)],
                   check=True, capture_output=True)
    assert out.read_bytes() == (BACKEND_KB / "data/crypto_kb.json").read_bytes()


def _classifier_codes() -> set[str]:
    src = (BACKEND_KB / "classify.py").read_text()
    codes = set(re.findall(r'out\.add\(\s*"([A-Z0-9_]+)"', src))
    for label in ("SSLv2", "SSLv3", "TLS1.0", "TLS1.1"):
        codes |= {f"PROTO_{label.replace('.', '')}", f"MIN_{label.replace('.', '')}"}
    codes |= set(re.findall(r'"(SSH_[A-Z0-9_]+)", "(?:Critical|High|Medium|Low)"', src))
    return codes


def test_every_classifier_code_has_an_entry():
    missing = sorted(c for c in _classifier_codes() if kb.entry("node", c) is None)
    assert not missing


def test_every_code_scan_code_has_an_entry():
    src = "\n".join(p.read_text() for p in (AIBOM_KB).glob("*.py"))
    codes = set(re.findall(r'^([A-Z_]{4,}) *= *"\1"', src, re.M))
    posture = (AIBOM_KB / "posture/findings.py").read_text()
    block = posture.split("POSTURE_CODES = frozenset(", 1)[1].split(")", 1)[0]
    codes |= set(re.findall(r'"([A-Z_]+)"', block))
    assert len(codes) > 25
    missing = sorted(c for c in codes if kb.entry("code", c) is None)
    assert not missing


def test_every_reference_resolves():
    data = kb.load()
    for ns in ("node", "code"):
        for code, e in data["findings"][ns].items():
            assert e["cwe"], code
            for c in e["cwe"]:
                assert data["cwe"].get(c), (code, c)
            for cid in e["cves"] + [c for r in e["cve_rules"] for c in r["cves"]]:
                rec = data["cves"][cid]
                assert rec["url"] == f"https://nvd.nist.gov/vuln/detail/{cid}" and rec["summary"]
            assert e["owasp_2021"] and e["owasp_2025"], code
            for key in e["compliance"]:
                assert data["compliance"][key], (code, key)
                for ref in data["compliance"][key]:
                    assert ref["source"].startswith("https://"), ref
            assert e["remediation"]["summary"]


def test_every_entry_explains_itself():
    """Each entry is read on its own in the UI and PDF: no 'As OTHER_CODE.' shorthand, no empty explanation."""
    data = kb.load()
    for ns in ("node", "code"):
        for code, e in data["findings"][ns].items():
            for field in ("title", "description", "attack"):
                text = (e.get(field) or "").strip()
                assert len(text) >= 20 or field == "title", (ns, code, field, text)
                assert not re.match(r"^(As|See) [A-Z_]{3,}\b", text), (ns, code, field, text)


def test_owasp_labels_match_the_product_enum():
    enum_file = (ROOT / "RabbitMQ/worker/helpers/context/enums.py").read_text()
    for item in kb.load()["owasp"]["2021"].values():
        assert f'"{item["label"]}"' in enum_file, item["label"]


def test_owasp_mapping_follows_official_cwe_lists():
    weak = kb.entry("node", "WEAK_CIPHER")
    assert {o["id"] for o in weak["owasp_2021"]} == {"A02:2021", "A05:2021"}
    assert any(o["id"] == "A04:2025" and "CWE-327" in o["basis"] for o in weak["owasp_2025"])
    lib = kb.entry("node", "LIB_EOL")
    assert any(o["id"] == "A06:2021" for o in lib["owasp_2021"]) and any(o["id"] == "A03:2025" for o in lib["owasp_2025"])


def test_render_fills_context_and_matches_cves_from_evidence(no_network):
    out = kb.render("node", ["WEAK_CIPHER", "PROTO_SSLv3"], context={"host": "db.example.com", "port": 8443},
                    evidence="Endpoint accepts weak ciphers (DES-CBC3-SHA, RC4-MD5)",
                    texts={"WEAK_CIPHER": "Endpoint accepts weak ciphers (DES-CBC3-SHA, RC4-MD5)"})
    weak, ssl3 = out
    assert {c["id"] for c in weak["cves"]} == {"CVE-2013-2566", "CVE-2015-2808", "CVE-2016-2183"}
    assert weak["observed"].startswith("Endpoint accepts")
    assert "nmap --script ssl-enum-ciphers -p 8443 db.example.com" in [v["command"] for v in weak["verify"]]
    assert [c["id"] for c in ssl3["cves"]] == ["CVE-2014-3566"]
    assert ssl3["cwe"][0] == {"id": "CWE-327", "name": "Use of a Broken or Risky Cryptographic Algorithm",
                              "url": "https://cwe.mitre.org/data/definitions/327.html"}
    assert any(r["framework"] == "RBI" for r in ssl3["compliance"])


def test_render_never_injects_shell_from_context():
    """Values from scanned systems end up in commands people paste into a shell: an unsafe value is never altered
    into something else and never added; the placeholder stays for the user to fill in."""
    out = kb.render("node", ["KEY_READABLE"], context={"path": "/tmp/x'; rm -rf / #"})
    cmds = " ".join(v["command"] for v in out[0]["verify"])
    assert "rm -rf" not in cmds and "'<path>'" in cmds
    out = kb.render("node", ["PROTO_TLS10"], context={"host": "example.com -oN /home/admin/.bashrc", "port": "443"})
    cmds = " ".join(v["command"] for v in out[0]["verify"])
    assert "-oN" not in cmds and "<host>" in cmds
    out = kb.render("node", ["KMS_NO_ROTATION"], context={"resource": "k --endpoint-url http://attacker.example/"})
    assert "attacker" not in out[0]["verify"][0]["command"]
    out = kb.render("node", ["PROTO_TLS10"], context={"host": "[2001:db8::1]", "port": 443})
    assert "[2001:db8::1]:443" in " ".join(v["command"] for v in out[0]["verify"])
    out = kb.render("node", ["PROTO_TLS10"], context={"host": "bücher.example", "port": "443; id"})
    cmds = " ".join(v["command"] for v in out[0]["verify"])
    assert "xn--bcher-kva.example" in cmds and "; id" not in cmds and "<port>" in cmds
    out = kb.render("node", ["KEY_READABLE"], context={"path": "-rf /etc/ssl/k.pem"})
    assert "'./-rf /etc/ssl/k.pem'" in " ".join(v["command"] for v in out[0]["verify"])


def test_kb_version_order_is_numeric():
    assert kb._version_key("2026.10.31.10") > kb._version_key("2026.10.31.9")
    assert kb._version_key("2026.11.15.1") > kb._version_key("2026.11.5.1")
    assert kb._version_key("2026.10.31.2") > kb._version_key("2026.9.30.1")
    assert kb._version_key("not-a-version") < kb._version_key("2020.1.1.1")


def test_cve_ids_in_stored_text_are_only_taken_for_advisory_findings():
    text = "openssl 3.0.2 is past end of life; in triage: CVE-2022-3602, CVE-2022-3786"
    assert kb.cves_for("node", "LIB_EOL", text) == [] or all(c["matched_on"] != "reported by the scanner"
                                                             for c in kb.cves_for("node", "LIB_EOL", text))
    adv = kb.cves_for("code", "VULNERABLE_CRYPTO_LIBRARY", "pyopenssl 0.13 GHSA-x: CVE-2018-1000807")
    assert any(c["id"] == "CVE-2018-1000807" for c in adv)


def test_algorithm_specific_fix_reaches_the_panel():
    rsa = kb.render("code", ["WEAK_ALGORITHM"], title="RSA-1024")[0]["remediation"]
    md5 = kb.render("code", ["WEAK_ALGORITHM"], title="MD5")[0]["remediation"]
    assert "RSA-3072" in rsa["summary"] and any("3072" in s["how"] for s in rsa["steps"])
    assert "SHA-256" in md5["summary"] and not any("3072" in s["how"] for s in md5["steps"])
    assert kb.summary_fix("code", ["WEAK_ALGORITHM"], "RSA-1024") == rsa["summary"]


def test_render_keeps_unknown_placeholders_visible_and_skips_unknown_codes():
    out = kb.render("node", ["COVERAGE_DENIED", "PROTO_TLS10"])
    assert [o["code"] for o in out] == ["PROTO_TLS10"]
    assert "-p <port> <host>" in out[0]["verify"][0]["command"]


@pytest.mark.parametrize("a,b,expected", [
    ("1.1.1w", "1.1.1k", 1), ("1.1.1", "1.1.1a", -1), ("0.9.8zh", "0.9.8z", 1), ("9.6p1", "9.6", 1), ("9.3p2", "9.3p1", 1), ("1.0.2p", "1.0.2o", 1),
    ("3.0", "3.0.0", 0), ("3.0.13", "3.0.2", 1), ("1.0.2zm", "1.0.2zk", 1),
])
def test_version_order(a, b, expected):
    assert kb.compare_versions(a, b) == expected


@pytest.mark.parametrize("pkg,ver,upstream", [
    ("openssl", "3.0.2-0ubuntu1.15", "3.0.2"), ("openssl-libs", "1:3.0.7-27.el9", "3.0.7"),
    ("openssh-server", "1:8.9p1-3ubuntu0.10", "8.9p1"), ("openssl", "3.0.11-1~deb12u2", "3.0.11"),
    ("openssl", "3.1.4-r5", "3.1.4"),
])
def test_upstream_version(pkg, ver, upstream):
    assert kb.library_status(pkg, ver)["upstream_version"] == upstream


def test_library_status_matches_nvd_and_cna_ranges_and_eol():
    today = dt.date(2026, 10, 31)
    s = kb.library_status("openssl", "3.0.2-0ubuntu1.15", today=today)
    assert "CVE-2022-3602" in s["cves"] and "CVE-2025-9230" in s["cves"]  # NVD range + CNA range
    assert s["eol"]["branch"] == "3.0" and s["eol"]["passed"] is True
    fixed = kb.library_status("openssl", "3.0.18", today=today)
    assert "CVE-2025-9230" not in fixed["cves"] and "CVE-2022-3602" not in fixed["cves"]
    assert kb.library_status("openssl", "3.5.4", today=today)["eol"]["passed"] is False
    ssh = kb.library_status("openssh-server", "1:9.6p1-3ubuntu13.5", today=today)
    assert "CVE-2024-6387" in ssh["cves"] and "CVE-2023-48795" not in ssh["cves"]
    assert kb.library_status("zlib1g", "1.2.13") is None


# ------------------------------------------------------------------------------------------ signed update bundles
def _keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, base64.b64encode(pub).decode()


def _bundle(tmp_path, key, version="2099.01.01.1", tamper=False):
    data = json.loads((BACKEND_KB / "data/crypto_kb.json").read_text())
    data["kb_version"] = version
    raw = json.dumps(data).encode()
    path = tmp_path / "kb.json"
    path.write_bytes(raw + (b" " if tamper else b""))
    (tmp_path / "kb.json.sig").write_text(base64.b64encode(key.sign(raw)).decode())
    return path


def test_signed_newer_bundle_is_used(tmp_path, monkeypatch, no_network):
    key, pub = _keypair()
    monkeypatch.setenv("CBOM_KB_BUNDLE", str(_bundle(tmp_path, key)))
    monkeypatch.setenv("CBOM_KB_PUBKEYS", "AAAA," + pub)
    assert kb.version() == "2099.01.01.1"


@pytest.mark.parametrize("case", ["tampered", "wrong_key", "no_keys", "older", "missing_sig"])
def test_bad_bundles_fall_back_to_builtin(tmp_path, monkeypatch, case, caplog):
    key, pub = _keypair()
    other, other_pub = _keypair()
    builtin = json.loads((BACKEND_KB / "data/crypto_kb.json").read_text())["kb_version"]
    path = _bundle(tmp_path, key, version="2000.01.01.1" if case == "older" else "2099.01.01.1",
                   tamper=case == "tampered")
    if case == "missing_sig":
        (tmp_path / "kb.json.sig").unlink()
    monkeypatch.setenv("CBOM_KB_BUNDLE", str(path))
    if case != "no_keys":
        monkeypatch.setenv("CBOM_KB_PUBKEYS", other_pub if case == "wrong_key" else pub)
    assert kb.version() == builtin
    assert "ignoring update bundle" in caplog.text


def test_sign_tool_round_trip(tmp_path):
    import subprocess
    import sys
    tool = ROOT / "scripts/crypto_kb/sign.py"
    pub = subprocess.run([sys.executable, str(tool), "keygen", str(tmp_path / "k.pem")], check=True,
                         capture_output=True, text=True).stdout.strip()
    target = tmp_path / "kb.json"
    target.write_bytes((BACKEND_KB / "data/crypto_kb.json").read_bytes())
    subprocess.run([sys.executable, str(tool), "sign", str(tmp_path / "k.pem"), str(target)], check=True,
                   capture_output=True)
    ok = subprocess.run([sys.executable, str(tool), "verify", str(target), pub], capture_output=True, text=True)
    assert ok.returncode == 0 and "signature OK" in ok.stdout
    target.write_bytes(target.read_bytes() + b"\n")
    bad = subprocess.run([sys.executable, str(tool), "verify", str(target), pub], capture_output=True, text=True)
    assert bad.returncode != 0
    assert oct((tmp_path / "k.pem").stat().st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------------------- remediation from the KB
def test_kb_remediation_has_the_panel_shape_and_no_model(no_network):
    from backend.utilities.cbom_sources.kb_remediation import remediation
    row = {"title": "TLS", "description": "Weak transport protocol TLS 1.0: TLS below 1.2 / SSL is deprecated",
           "impact": "Critical", "location": "nginx/conf.d/site.conf:14",
           "finding_codes": ["WEAK_CIPHER_SUITE", "WEAK_PROTOCOL"], "suggested_fix": "x"}
    out = remediation(row, "code")
    assert out["status"] == "completed" and out["source"] == "knowledge_base" and out["kb_version"] == kb.version()
    assert set(out["fix"]) == {"description", "original_code", "fixed_code", "language", "confidence",
                               "validation_notes", "references"}
    assert set(out["exploit_payload"]) == {"description", "payload", "impact_demonstration", "prerequisites",
                                           "difficulty", "attack_vector"}
    assert out["exploit_payload"]["difficulty"] == "easy"
    assert "nginx/conf.d/site.conf" in out["exploit_payload"]["payload"]
    assert "ssl_protocols TLSv1.2 TLSv1.3" in out["fix"]["fixed_code"]
    assert [d["code"] for d in out["details"]] == ["WEAK_CIPHER_SUITE", "WEAK_PROTOCOL"]
    assert any(c["id"] == "CVE-2011-3389" for d in out["details"] for c in d["cves"])


def test_kb_remediation_for_clean_inventory_and_quantum_note_last():
    from backend.utilities.cbom_sources.kb_remediation import explain, remediation
    clean = remediation({"title": "SHA-256", "finding_codes": []})
    assert clean["status"] == "completed" and clean["details"] == [] and clean["exploit_payload"] is None
    codes = [d["code"] for d in explain({"title": "RSA-1024", "finding_codes": ["QUANTUM_VULNERABLE", "WEAK_ALGORITHM"]})]
    assert codes == ["WEAK_ALGORITHM", "QUANTUM_VULNERABLE"]


def test_node_assets_render_host_and_port():
    from backend.utilities.cbom_sources.kb_remediation import remediation
    out = remediation({"title": "db.example.com:5432", "location": "db.example.com:5432", "impact": "High",
                       "finding_codes": ["DB_TLS_OPTIONAL"]}, "node")
    assert "-p 5432 db.example.com" in out["exploit_payload"]["payload"]
