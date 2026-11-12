"""Unit tests of the CB-02 lab generator, oracle formatter and self-check (no Docker needed).

Collected in CI through backend/tests/test_cbom_e2e_lab.py; also runnable alone:
    python3 -m pytest e2e/cbom/lab/tests -q
Live proofs (real containers) are `gen.py up/selfcheck/negative`; their evidence is linked from the PR.
"""
from __future__ import annotations

import ast
import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

LAB = Path(__file__).resolve().parents[1]
FIX = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(LAB))

import importlib.util  # noqa: E402

import labcheck as selfcheck  # noqa: E402
import labgen  # noqa: E402
import labspec as S  # noqa: E402
import oraclefmt  # noqa: E402

_spec = importlib.util.spec_from_file_location("cb02_lab_gen", LAB / "gen.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


# ---------------------------------------------------------------- catalogue and compose
def test_catalogue_is_valid() -> None:
    assert S.validate_catalogue() == []


def test_catalogue_rejects_duplicates_and_unknown_names() -> None:
    bad = [dict(S.by_id("z01")), dict(S.by_id("z01"))]
    bad[1]["suites"] = ["TLS_NOT_A_SUITE"]
    bad[1]["versions"] = ["TLSv1.2"]
    problems = S.validate_catalogue(bad)
    assert any("duplicate id z01" in p for p in problems)
    assert any("already used" in p for p in problems)
    assert any("TLS_NOT_A_SUITE" in p for p in problems)


def test_catalogue_never_uses_reserved_addresses() -> None:
    reserved = {S.NODE_IP, S.TOOLS_IP, S.NGINX_IP, S.NETWORK["gateway"]}
    assert not reserved & {t.get("ip") for t in S.TARGETS}
    assert all(int(t["ip"].rsplit(".", 1)[1]) >= 16 for t in S.TARGETS if t.get("ip"))  # INTERFACES v2: >= .16


def test_compose_file_is_generated_from_the_catalogue() -> None:
    assert (LAB / "compose.yml").read_text() == gen.compose_text()
    text = gen.compose_text()
    for t in S.TARGETS:
        if t.get("ip"):
            assert f"container_name: cb02-{t['id']}" in text
            assert f"ipv4_address: {t['ip']}" in text
    assert "external: true" in text and S.TOOLS_IP in text


# ---------------------------------------------------------------- O-1 independence
def test_lab_imports_nothing_from_the_product() -> None:
    banned = ("backend", "aibom", "scan_node", "zs_scan_node", "frontend", "utilities")
    for path in sorted(LAB.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for n in names:
                assert n.split(".")[0] not in banned, f"{path.name} imports {n} (rule O-1)"


# ---------------------------------------------------------------- O-5 frozen oracle
def _run_dir(tmp_path: Path) -> Path:
    (tmp_path / "oracle" / "facts").mkdir(parents=True)
    (tmp_path / "lab").mkdir()
    (tmp_path / "oracle" / "facts" / "z01.json").write_text('{"a": 1}\n')
    (tmp_path / "oracle" / "run1.json").write_text('{"b": 2}\n')
    (tmp_path / "lab" / "gen.json").write_text(json.dumps({"run_id": "t", "profiles": ["core"]}))
    return tmp_path


def test_oracle_hash_is_stable_and_detects_an_edit(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    h1 = gen.record_oracle_hash(run, "run1")
    assert gen.oracle_hash(run) == h1  # SHA256SUMS itself is not hashed
    ns = gen.argparse.Namespace(run_dir=str(run), verify=h1, accept_change=False, reason=None)
    assert gen.cmd_hash(ns) == 0
    (run / "oracle" / "facts" / "z01.json").write_text('{"a": 2}\n')
    assert gen.oracle_hash(run) != h1
    assert gen.cmd_hash(ns) == 2


def test_selfcheck_refuses_an_oracle_edited_after_generation(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    gen.record_oracle_hash(run, "run1")
    (run / "oracle" / "run1.json").write_text('{"b": 3}\n')
    assert selfcheck.main(run) == 2
    report = json.loads((run / "lab" / "selfcheck.json").read_text())
    assert "oracle changed" in report["error"]


# ---------------------------------------------------------------- parsers of independent tool output
def test_nmap_ssl_enum_ciphers_parser() -> None:
    suites = selfcheck.parse_nmap_ciphers((FIX / "nmap-ssl-z02.xml").read_text())
    want = sorted(S.by_id("z02")["suites"])
    assert suites == {"TLSv1.0": want, "TLSv1.1": want, "TLSv1.2": want}


def test_nmap_ssh2_enum_algos_parser_and_markers() -> None:
    algs = selfcheck.parse_nmap_ssh((FIX / "nmap-ssh-legacy.xml").read_text())
    t = S.by_id("sshd-legacy")
    assert selfcheck.strip_markers(algs["kex_algorithms"]) == t["kex"]
    assert any(selfcheck.SSH_MARKERS.match(a) for a in algs["kex_algorithms"])  # the markers are really there
    assert algs["mac_algorithms"] == t["macs"]
    assert sorted(algs["server_host_key_algorithms"]) == sorted(t["host_key_algorithms"])


def test_keyscan_parser() -> None:
    keys = selfcheck.parse_keyscan((FIX / "keyscan-legacy.txt").read_text())
    assert set(keys) == {"ssh-rsa", "ssh-ed25519"}


def test_keytool_parser() -> None:
    entries = labgen.parse_keytool((FIX / "keytool-legacy-jks.txt").read_text())
    assert [(e["alias"], e["type"], e["key_algorithm"], e["key_bits"], e["signature_algorithm"]) for e in entries] == [
        ("app", "PrivateKeyEntry", "RSA", 2048, "SHA256withRSA"),
        ("legacy-ca", "trustedCertEntry", "RSA", 1024, "SHA1withRSA")]
    assert all(len(e["cert_sha256"]) == 64 for e in entries)


def test_pkcs11_tool_parser() -> None:
    objs = labgen.parse_pkcs11_objects((FIX / "pkcs11-tok-a.txt").read_text())
    summary = sorted((o["label"], o["class"], o["key_type"], o["bits"], o["extractable"]) for o in objs)
    assert ("aes-128-wrap", "Secret Key", "AES", 128, True) in summary
    assert ("rsa-2048-signing", "Public Key", "RSA", 2048, False) in summary
    assert ("ec-p256-signing", "Public Key", "EC", 256, False) in summary
    assert ("rsa-2048-signing", "Private Key", "RSA", None, False) in summary


def _xlsx(rows: list[list[tuple[str, str]]]) -> bytes:
    """A minimal .xlsx: rows of (cell type, value) with inline strings, numbers and TRUE()/FALSE() formulas."""
    cells = []
    for r, row in enumerate(rows, start=1):
        cs = []
        for c, (kind, value) in zip("ABCDEFG", row):
            ref = f"{c}{r}"
            if kind == "s":
                cs.append(f'<c r="{ref}" t="inlineStr"><is><t>{value}</t></is></c>')
            elif kind == "f":
                cs.append(f'<c r="{ref}" t="b"><f>{value}</f><v>{1 if value.startswith("TRUE") else 0}</v></c>')
            else:
                cs.append(f'<c r="{ref}"><v>{value}</v></c>')
        cells.append(f'<row r="{r}">{"".join(cs)}</row>')
    sheet = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
             + "".join(cells) + "</sheetData></worksheet>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()


def test_xlsx_label_reader(tmp_path: Path) -> None:
    p = tmp_path / "labels.xlsx"
    p.write_bytes(_xlsx([
        [("s", "Properties"), ("s", "Files"), ("s", "Code"), ("s", "Vulnerability Exists?")],
        [("s", "Basic"), ("s", "ACase1.java"), ("s", "1.1.1"), ("f", "TRUE()"), ("s", "Static key")],
        [("s", ""), ("s", "BCorrected"), ("s", "1.1.2"), ("f", "FALSE()")],
        [("s", "Advanced"), ("s", "CCase1.java\nC1.java"), ("s", "1.8.1"), ("n", "1"), ("s", "ECB")],
        [("s", ""), ("s", ""), ("s", ""), ("s", "")],
    ]))
    rows = labgen.read_xlsx_labels(p)
    assert [(r["files"], r["vulnerable"], r["group"]) for r in rows] == [
        (["ACase1.java"], True, "Basic"), (["BCorrected.java"], False, "Basic"),
        (["CCase1.java", "C1.java"], True, "Advanced")]


# ---------------------------------------------------------------- oracle formatting (CB-01 interface)
def _tls_facts() -> dict:
    cert = {"sha256": "ab" * 32, "subject": "CN=z02.lab", "issuer": "CN=z02.lab", "serial": "01",
            "not_before": "2026-11-11T00:00:00Z", "not_after": "2027-12-14T00:00:00Z",
            "signature_algorithm": "sha1WithRSAEncryption", "key_algorithm": "RSA", "key_bits": 1024, "curve": None}
    return {"target": "z02", "kind": "tls", "profile": "core", "world": "closed", "address": "10.231.0.18", "port": 443,
            "aliases": ["z02.lab"], "container": "cb02-z02",
            "expect": {"versions": {"TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": False},
                       "suites": {"TLSv1.0": ["TLS_RSA_WITH_AES_128_CBC_SHA"],
                                  "TLSv1.2": ["TLS_RSA_WITH_AES_128_CBC_SHA"]},
                       "tls13_suites": [], "groups": ["secp256r1", "x25519"], "sni_names": [], "sni_required": False,
                       "certificates": [cert]},
            "provenance": {}}


def test_run_oracle_uses_cb01_normal_forms() -> None:
    o = _tls_facts()
    run = oraclefmt.run_oracle([o], "run1", "2026-11-12T00:00:00Z", "abc", "core", {"z02": "S-zoo"})
    assert run["schema"] == "zs-cbom-oracle/1"
    tgt = run["targets"][0]
    ep = next(a for a in tgt["assets"] if a["asset_type"] == "tls_endpoint")
    assert ep["location"] == "10.231.0.18:443"
    assert ep["expect"]["protocol_versions"] == ["TLSv1", "TLSv1.2"]
    assert ep["expect"]["groups"] == ["X25519", "secp256r1"]
    assert "codes_exclude" not in ep  # TLS 1.0 is on: no "must not flag TLS 1.0"
    cert = next(a for a in tgt["assets"] if a["asset_type"] == "certificate")
    assert cert["expect"]["quantum_vulnerable"] is True and cert["expect"]["key_size"] == 1024
    assert cert["expect"]["fingerprint_sha256"] == "ab" * 32 and cert["join"] == "fingerprint_sha256"


def test_ml_dsa_certificate_is_not_quantum_vulnerable_and_carries_its_ledger_row() -> None:
    o = _tls_facts()
    o["target"] = "z05b"
    o["expect"]["certificates"][0].update(key_algorithm="ML-DSA-65", key_bits=None, signature_algorithm="ML-DSA-65")
    assets, _ = oraclefmt.assets_for(o)
    cert = next(a for a in assets if a["asset_type"] == "certificate")
    assert cert["expect"]["algorithm"] == "ML-DSA-65"
    assert cert["expect"]["quantum_vulnerable"] is False
    assert cert["known_fail"] == "KF-3"


def test_canary_listener_is_a_must_not_appear_row_and_lab_json_lists_never_scan() -> None:
    canary = {"target": "canary", "kind": "listener", "profile": "core", "world": "closed", "address": "10.231.0.33",
              "port": 443, "aliases": ["cbom-e2e-canary"], "container": "cb02-canary",
              "expect": {"role": "canary"}, "provenance": {}}
    control = {**canary, "target": "control", "address": "10.231.0.34", "aliases": ["cbom-e2e-control"],
               "container": "cb02-control", "expect": {"role": "control"}}
    assets, mna = oraclefmt.assets_for(canary)
    assert assets == [] and {"asset_type": "tls_endpoint", "location": "10.231.0.33:443"} in mna
    lab = oraclefmt.lab_json([canary, control], "t", "c", "core", S.NETWORK, S.NODE_IP)
    assert lab["never_scan"] == ["cbom-e2e-canary"]
    assert [x["log"] for x in lab["listeners"]] == ["lab/listeners/canary.jsonl", "lab/listeners/control.jsonl"]
    assert any(s["name"] == "S-canary" for s in lab["sources"])


# ---------------------------------------------------------------- self-check verdict rules
def test_target_disagrees_on_a_failed_check_or_an_unsatisfied_control() -> None:
    t = selfcheck.Target("z01")
    t.check("z01/tls", "groups", "tool", ["x25519"], ["x25519"])
    assert t.result()["agree"] is True
    t.control("TLSv1.0 refused", "z16", False, "control target absent")
    assert t.result()["agree"] is False


def test_controls_need_the_positive_on_the_named_target() -> None:
    facts = {"z01": {"kind": "tls", "expect": {"versions": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False,
                                                            "TLSv1.3": True}, "groups": ["x25519", "secp256r1"]}}}
    ctx = type("C", (), {"observed": {"z16": {"versions": {"TLSv1.0": True}}, "z05": {"groups": ["X25519MLKEM768"]}}})()
    results = {"z01": selfcheck.Target("z01")}
    selfcheck.apply_controls(results, facts, ctx)
    by = {c["negative"]: c["satisfied"] for c in results["z01"].controls}
    assert by["TLSv1.0 refused"] is True          # z16 showed TLS 1.0 to the same tool
    assert by["TLSv1.1 refused"] is False         # z02 was not observed in this capture
    assert by["group X25519MLKEM768 absent"] is True


def test_small_helpers() -> None:
    assert selfcheck.hba_address("0.0.0.0/0") == "0.0.0.0/0.0.0.0"
    assert selfcheck.hba_address(None) == ""
    pem = "-----BEGIN CERTIFICATE-----\nAAEC\n-----END CERTIFICATE-----\n"
    assert selfcheck.pem_certs(pem) == ["ae4b3280e56e2faf83f414a6e3dabe9d5fbe18976544c05fed121accb85b53fc"]
    with pytest.raises(KeyError):
        S.by_id("nope")


# ---------------------------------------------------------------- review 5873265185 (PR #79): fails first on 67d2beb
def _ns(run: Path, **kw) -> object:
    base = {"run_dir": str(run), "verify": None, "accept_change": False, "reason": None}
    return gen.argparse.Namespace(**{**base, **kw})


def test_hash_is_read_only_and_never_blesses_an_edited_oracle(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    gen.record_oracle_hash(run, step="run1")                       # what generate() does
    recorded = json.loads((run / "lab" / "gen.json").read_text())["oracle_sha256"]
    (run / "oracle" / "run1.json").write_text('{"b": "edited"}\n')
    assert gen.cmd_hash(_ns(run)) == 2                               # read-only: reports the mismatch
    assert json.loads((run / "lab" / "gen.json").read_text())["oracle_sha256"] == recorded
    assert selfcheck.main(run) == 2                                  # still refused after `hash`


def test_accepting_an_oracle_change_needs_a_reason_and_is_logged(tmp_path: Path) -> None:
    run = _run_dir(tmp_path)
    gen.record_oracle_hash(run, step="run1")
    (run / "oracle" / "run1.json").write_text('{"b": "edited"}\n')
    assert gen.cmd_hash(_ns(run, accept_change=True)) == 1           # no reason: refused
    assert gen.cmd_hash(_ns(run, accept_change=True, reason="CB-05 asked for z02 groups x25519")) == 0
    gj = json.loads((run / "lab" / "gen.json").read_text())
    assert gj["oracle_sha256"] == oraclefmt.oracle_hash(run)
    change = gj["oracle_changes"][-1]
    assert change["reason"].startswith("CB-05") and change["old"] != change["new"]
    assert (run / "lab" / "oracle-changes.log").read_text().count("CB-05 asked") == 1


P11TOOL = """Object 0:
\tType: Public key (RSA-2048)
\tLabel: rsa-2048-signing
\tFlags: CKA_WRAP/UNWRAP;
\tID: 01

Object 1:
\tType: Secret key
\tLabel: aes-128-wrap
\tFlags: CKA_WRAP/UNWRAP; CKA_EXTRACTABLE; CKA_SENSITIVE;
\tID: 03

Object 2:
\tType: Private key (EC/ECDSA-SECP256R1)
\tLabel: ec-p256-signing
\tFlags: CKA_WRAP/UNWRAP; CKA_PRIVATE; CKA_NEVER_EXTRACTABLE; CKA_SENSITIVE;
\tID: 02

Object 3:
\tType: Private key (RSA-2048)
\tLabel: rsa-2048-signing
\tFlags: CKA_WRAP/UNWRAP; CKA_PRIVATE; CKA_NEVER_EXTRACTABLE; CKA_SENSITIVE;
\tID: 01
"""  # real p11tool 3.8.13 output shape (URL lines dropped)


def test_hsm_observation_uses_an_independent_reader_and_the_catalogue() -> None:
    import labread as R
    objs = selfcheck.parse_p11tool(P11TOOL)
    assert [(o["label"], o["class"], o["key_type"], o["bits"], o["extractable"]) for o in objs] == [
        ("aes-128-wrap", "Secret Key", None, None, True), ("ec-p256-signing", "Private Key", "EC", 256, False),
        ("rsa-2048-signing", "Private Key", "RSA", 2048, False)]
    store = R.softhsm_object(_softhsm_object(4, 0x1F, label=b"aes-128-wrap", value_len=16, extractable=True))
    objs = [{**o, "key_type": store["key_type"], "bits": store["bits"]} if o["class"] == "Secret Key" else o for o in objs]
    requested = S.by_id("softhsm")["tokens"][0]["objects"]
    assert selfcheck.hsm_mismatches(requested, objs) == []
    inverted = [{**o, "extractable": not o["extractable"]} for o in objs]   # mutation C, seen through any reader
    assert len(selfcheck.hsm_mismatches(requested, inverted)) == 3


def test_tls12_groups_are_observed_for_targets_without_tls13() -> None:
    groups = selfcheck.parse_nmap_kex((FIX / "nmap-ssl-z02.xml").read_text())
    assert groups == {"TLSv1.0": ["secp256r1"], "TLSv1.1": ["secp256r1"], "TLSv1.2": ["secp256r1"]}
    assert selfcheck.legacy_groups_agree(["secp256r1"], groups) is True
    assert selfcheck.legacy_groups_agree(["x25519"], groups) is False        # mutation B on z02
    x = (FIX / "nmap-ssl-z02.xml").read_text().replace(">secp256r1<", ">ecdh_x25519<")
    assert selfcheck.parse_nmap_kex(x)["TLSv1.2"] == ["x25519"]              # nmap's name for the IANA x25519


class _FakeCtx:
    """Canned tool output for the ML-DSA fallback (no Docker)."""

    def __init__(self) -> None:
        self.observed, self.tool_versions = {}, {}

    def tlscheck(self, *args: str) -> dict:
        return {"tool": "tlscheck", "versions": {v: False for v in S.VERSIONS}}

    def exec(self, *cmd: str, **kw):
        return type("R", (), {"stdout": "Cipher is (NONE)", "stderr": "", "returncode": 1})()

    def save(self, name: str, text: str) -> str:
        return name


def test_ml_dsa_fallback_rows_are_marked_not_independent() -> None:
    o = {"target": "z05b", "address": "10.231.0.21", "port": 443,
         "expect": {"versions": {v: v == "TLSv1.3" for v in S.VERSIONS}, "groups": ["x25519"],
                    "certificates": [{"sha256": "00", "key_algorithm": "ML-DSA-65"}]}}
    t = selfcheck.check_tls_mldsa(_FakeCtx(), o, selfcheck.Target("z05b"))
    fallback = [c for c in t.checks if "s_client" in c["tool"]]
    assert fallback and all(c["independent"] is False and c["not_independent_reason"] for c in fallback)
    assert all(c["independent"] is True for c in t.checks if "s_client" not in c["tool"])


def test_lab_json_marks_every_deferred_part() -> None:
    lab = oraclefmt.lab_json([], "t", "c", "core", S.NETWORK, S.NODE_IP)
    parts = {d["part"]: d for d in lab["deferred"]}
    assert set(parts) >= {"idp", "receiver", "ubuntu-tier2", "k8s"}
    for d in parts.values():
        assert d["deferred"] is True and d["reason"] and d["gate"] and d["issue_draft"].endswith("issue-deferred.md")
    assert parts["idp"]["address"] == "10.231.0.42" and "G7" in parts["idp"]["gate"]


def test_bench_line_cells_beyond_the_file_are_flagged_unreliable() -> None:
    assert labgen.lines_unreliable("43720", 40) is True        # an Excel date serial, not a line
    assert labgen.lines_unreliable("16, 22", 40) is False
    assert labgen.lines_unreliable("11", 40) is False
    assert labgen.lines_unreliable("", 40) is False


def test_bench_counts_are_pinned_from_an_independent_read() -> None:
    pinned = S.BENCH_PINNED
    assert (pinned["cases"], pinned["vulnerable"], pinned["secure"]) == (171, 136, 35)
    assert (pinned["judgeable"], pinned["judgeable_vulnerable"]) == (170, 135)


def test_image_identity_follows_the_build_inputs(tmp_path: Path) -> None:
    import shutil
    copy = tmp_path / "lab"
    for sub in ("images", "entrypoints", "tlscheck"):
        shutil.copytree(LAB / sub, copy / sub)
    before = gen.image_inputs_hash(copy)
    (copy / "entrypoints" / "cb02-entry").write_text((copy / "entrypoints" / "cb02-entry").read_text() + "\n# x\n")
    assert gen.image_inputs_hash(copy) != before


def test_lab_sshd_targets_exempt_the_lab_but_one_keeps_the_default_penalties() -> None:
    sshd = [t for t in S.TARGETS if t["kind"] in ("ssh", "host")]
    default = [t for t in sshd if t.get("penalties") == "default"]
    assert len(default) == 1 and default[0]["profile"] == "psp"
    # review 5874442142: only the self-check is exempt there; the burst runs from the throwaway source .12
    assert default[0]["penalty_exempt"] == S.TOOLS_IP + "/32" and S.BURST_IP not in default[0]["penalty_exempt"]
    for t in sshd:
        if t not in default:
            assert t.get("penalty_exempt") == S.NETWORK["subnet"]


def test_forcecommand_file_is_cross_checked_against_the_container_log() -> None:
    a = {"ts": "t", "user": "zs-cbom", "peer": "10.231.0.2", "command": "id"}
    b = {**a, "command": "uname -a"}
    assert selfcheck.forcecommand_missing([a, b], [a, b]) == []
    assert selfcheck.forcecommand_missing([a], [a, b]) == [b]          # a truncated file is caught


def test_no_stale_lab_sh_references_and_no_session_ca_default() -> None:
    for path in [*LAB.rglob("*.py"), *LAB.glob("images/*"), *LAB.glob("entrypoints/*")]:
        if "tests" in path.parts:
            continue
        assert "lab.sh" not in path.read_text(), path
    assert ".ccr" not in (LAB / "gen.py").read_text()


# ---------------------------------------------------------------- review 5874442142 (PR #79): fail first on edd3cef
def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    head = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + head + body


def _der_int(v: int) -> bytes:
    return _der(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))


RSA_OID = bytes.fromhex("06092a864886f70d010101")


def _pkcs8_rsa(bits: int) -> str:
    """A structurally valid PKCS#8 RSA key whose modulus has `bits` bits (not a usable key: no key material)."""
    n = (1 << (bits - 1)) | 1
    rsa = _der(0x30, b"".join(_der_int(x) for x in (0, n, 65537, 3, 5, 7, 11, 13, 17)))
    info = _der(0x30, _der_int(0) + _der(0x30, RSA_OID + b"\x05\x00") + _der(0x04, rsa))
    import base64
    return "-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(info).decode() + "-----END PRIVATE KEY-----\n"


def _softhsm_object(cls: int, key_type: int, *, label: bytes = b"", value_len: int | None = None,
                    modulus_bits: int | None = None, extractable: bool | None = None) -> bytes:
    import struct
    out = struct.pack(">Q", 7)
    out += struct.pack(">QQQ", 0x0, 2, cls) + struct.pack(">QQQ", 0x3, 3, len(label)) + label
    out += struct.pack(">QQQ", 0x100, 2, key_type)
    if value_len is not None:
        out += struct.pack(">QQQ", 0x161, 2, value_len)
    if modulus_bits is not None:
        out += struct.pack(">QQQ", 0x121, 2, modulus_bits)
    if extractable is not None:
        out += struct.pack(">QQ", 0x162, 1) + bytes([255 if extractable else 0])
    return out + struct.pack(">QQQ", 0x40000600, 5, 0)


def _certs() -> tuple[list[bytes], dict]:
    import labread as R
    ders = R.pem_blocks((FIX / "certs-z01-chain.crt.txt").read_text()) + R.pem_blocks((FIX / "cert-z05b-mldsa.crt.txt").read_text())
    facts = json.loads((FIX / "certs-openssl-facts.json").read_text())
    return ders, facts["z01"] + facts["z05b"]


def test_x509_reader_agrees_with_the_generators_openssl_facts() -> None:
    import labread as R
    ders, facts = _certs()
    for der, want in zip(ders, facts):
        got = R.x509_facts(der)
        assert got["fingerprint_sha256"] == want["sha256"]
        assert int(got["serial"], 16) == int(want["serial"], 16)
        assert got["signature_algorithm_oid"] == R.sig_oid(want["signature_algorithm"])
        assert R.name_key(got["subject"]) == R.name_key(want["subject"])
        assert R.name_key(got["issuer"]) == R.name_key(want["issuer"])
        assert (got["not_before"], got["not_after"]) == (want["not_before"], want["not_after"])
        assert got["algorithm"] == want["key_algorithm"].upper()
        assert got["key_size"] == want["key_bits"] and got["curve"] == want["curve"]


def test_pkcs8_jks_softhsm_and_ssh_readers() -> None:
    import struct
    import hashlib
    import labread as R
    assert R.pkcs8_facts(_pkcs8_rsa(1024)) == {"algorithm": "RSA", "key_size": 1024}
    ders, _ = _certs()
    body = struct.pack(">III", 0xFEEDFEED, 2, 2)
    for tag, alias, der in ((2, b"legacy-ca", ders[1]), (1, b"app", ders[0])):
        body += struct.pack(">I", tag) + struct.pack(">H", len(alias)) + alias + b"\0" * 8
        if tag == 1:
            body += struct.pack(">I", 3) + b"key" + struct.pack(">I", 1)
        body += struct.pack(">H", 5) + b"X.509" + struct.pack(">I", len(der)) + der
    data = body + hashlib.sha1("pw".encode("utf-16-be") + b"Mighty Aphrodite" + body).digest()
    jks = R.jks_entries(data, "pw")
    assert jks["integrity"] is True and R.jks_entries(data, "wrong")["integrity"] is False
    assert [(e["alias"], e["type"]) for e in jks["entries"]] == [("legacy-ca", "trustedCertEntry"), ("app", "PrivateKeyEntry")]
    sec = R.softhsm_object(_softhsm_object(4, 0x1F, label=b"aes-256-decoy", value_len=32, extractable=False))
    assert sec == {"class": "Secret Key", "key_type": "AES", "bits": 256, "extractable": False, "label": "aes-256-decoy"}
    pub = R.softhsm_object(_softhsm_object(2, 0x0, label=b"rsa-2048-signing", modulus_bits=2048))
    assert (pub["class"], pub["key_type"], pub["bits"]) == ("Public Key", "RSA", 2048)
    keys = selfcheck.parse_keyscan((FIX / "keyscan-legacy.txt").read_text())
    facts = {t: R.ssh_key_facts(b) for t, b in keys.items()}
    # ssh-keygen -l -E sha256 of the same blobs (OpenSSH 10), the generator's tool, as the expected values
    assert facts["ssh-rsa"] == {"type": "ssh-rsa", "bits": 1024,
                                "fingerprint_sha256": "SHA256:OsWusYCjoOOWIvBLpqiIIPIMh33qWpMWBgkiuYANhBs"}
    assert facts["ssh-ed25519"]["fingerprint_sha256"] == "SHA256:wb+k1OEAfP4bGyvPjpv5aUr+su+GH/dN5vPNrq4BQEs"
    assert selfcheck.parse_banner((FIX / "keyscan-legacy.txt").read_text()) == ["SSHv2"]


def _hsm_facts() -> dict:
    objs = labgen.parse_pkcs11_objects((FIX / "pkcs11-tok-a.txt").read_text())
    return {"target": "softhsm", "kind": "softhsm", "profile": "hsm", "world": "closed", "address": None, "port": None,
            "aliases": [], "container": None, "provenance": {},
            "expect": {"tokens": [{"label": "cb02-tok-a", "objects": objs}]}}


def test_hsm_private_key_size_comes_from_the_public_object() -> None:
    assets, _ = oraclefmt.assets_for(_hsm_facts())
    by = {a["oracle_id"]: a["expect"] for a in assets}
    assert by["softhsm/cb02-tok-a/rsa-2048-signing/Private Key"]["key_size"] == 2048    # was null (oraclefmt:134)
    assert by["softhsm/cb02-tok-a/ec-p256-signing/Private Key"]["key_size"] == 256
    assert by["softhsm/cb02-tok-a/aes-128-wrap/Secret Key"]["key_size"] == 128
    assert not any(k.endswith("/Public Key") for k in by)


def test_endpoint_rows_state_quantum_vulnerable_from_the_key_exchange() -> None:
    v13 = {v: v == "TLSv1.3" for v in S.VERSIONS}
    assert oraclefmt.tls_endpoint_qv(v13, ["x25519", "secp256r1"]) is True            # z01
    assert oraclefmt.tls_endpoint_qv(v13, ["X25519MLKEM768"]) is False               # z05: hybrid only
    assert oraclefmt.tls_endpoint_qv(v13, ["X25519MLKEM768", "x25519"]) is False     # z05b: mixed (v7 #2)
    legacy = {v: v != "TLSv1.3" for v in S.VERSIONS}
    assert oraclefmt.tls_endpoint_qv(legacy, ["secp256r1"]) is True                   # z02: no PQ below TLS 1.3
    assert oraclefmt.tls_endpoint_qv(v13, None) is None
    with pytest.raises(ValueError):
        oraclefmt.tls_endpoint_qv(v13, ["brainpoolP256r1"])                           # fail closed
    assert oraclefmt.ssh_endpoint_qv(S.by_id("sshd-legacy")["kex"]) is True
    assert oraclefmt.ssh_endpoint_qv(S.by_id("sshd-pq")["kex"]) is False
    assert oraclefmt.ssh_endpoint_qv(S.by_id("host")["kex"]) is False
    run = oraclefmt.run_oracle([_tls_facts()], "run1", "t", "c", "core", {})
    ep = next(a for a in run["targets"][0]["assets"] if a["asset_type"] == "tls_endpoint")
    assert ep["expect"]["quantum_vulnerable"] is True


def test_planted_weak_suites_are_must_report_rows() -> None:
    for tid in ("z02", "z16"):
        t = S.by_id(tid)
        assert t["must_report"]["cipher_suites"] and set(t["must_report"]["cipher_suites"]) <= set(t["suites"])
    o = _tls_facts()
    o["expect"]["must_report"] = {"cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"]}
    ep = next(a for a in oraclefmt.assets_for(o)[0] if a["asset_type"] == "tls_endpoint")
    assert ep["must_report"] == {"cipher_suites": ["TLS_RSA_WITH_AES_128_CBC_SHA"]}
    o["expect"]["must_report"] = {"cipher_suites": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]}   # not accepted: refused
    with pytest.raises(ValueError):
        oraclefmt.assets_for(o)
    bad = [{**S.by_id("z16"), "must_report": {"cipher_suites": ["TLS_RSA_WITH_AES_256_CBC_SHA"]}}]
    assert any("must_report" in p for p in S.validate_catalogue(bad))


def _facts_for(*ids: str) -> list[dict]:
    out = []
    for tid in ids:
        t = S.by_id(tid)
        e = {"role": t["role"]} if t["kind"] == "listener" else {"versions": {}, "suites": {}, "groups": None,
                                                               "sni_names": t.get("sni", []), "certificates": []}
        out.append({"target": tid, "kind": t["kind"], "profile": t["profile"], "world": t["world"],
                    "address": t.get("ip"), "port": t.get("port"), "aliases": t.get("aliases", [f"{tid}.lab"]),
                    "expect": e})
    return out


def test_ranges_classify_every_address_of_every_scanned_range() -> None:
    facts = _facts_for("z01", "z02", "z04", "z05", "z05b", "z09", "z16", "canary", "control")
    ranges = {r["cidr"]: r for r in oraclefmt.ranges_for(facts)}
    zoo = ranges["10.231.0.16/28"]
    assert zoo["source"] == "S-zoo" and zoo["never_scan"] == []
    assert zoo["empty_addresses"] == ["10.231.0.23", "10.231.0.24", "10.231.0.25", "10.231.0.27", "10.231.0.28",
                                      "10.231.0.29", "10.231.0.30"]
    can = ranges["10.231.0.32/30"]
    assert can == {"source": "R-canary", "cidr": "10.231.0.32/30", "empty_addresses": [], "never_scan": ["10.231.0.33"]}
    # a wave target inside the range is a member (sshd-psp .28; run 2's z08 .25 and control-tls .34)
    more = facts + _facts_for("z08")
    more = [f for f in more if f["target"] != "control"] + _facts_for("control-tls")
    srcs, by = oraclefmt.sources_for(more)
    assert by["z08"] == "S-zoo" and by["control-tls"] == "S-canary"
    assert "10.231.0.25" not in {r["cidr"]: r for r in oraclefmt.ranges_for(more)}["10.231.0.16/28"]["empty_addresses"]
    assert any(s["name"] == "R-canary" for s in srcs)


def test_target_reports_independent_and_unverified_keys() -> None:
    assets = {"z01/tls": {"expect": {"protocol_versions": ["TLSv1.3"], "groups": ["X25519"], "cipher_suites": []},
                          "must_report": {"cipher_suites": ["x"]}}}
    t = selfcheck.Target("z01", assets)
    t.expect("z01/tls", "protocol_versions", "go", ["TLSv1.3"])
    t.expect("z01/tls", "groups", "s_client", ["X25519"], independent=False, reason="same library as the node")
    assert t.expect("z01/tls", "curve", "go", "P-256") is None                     # not asserted: no row
    r = t.result()
    assert r["agree"] is True and r["verified_independently"] is False
    assert r["independent_keys"] == {"z01/tls": ["protocol_versions"]}
    assert r["unverified_keys"] == {"z01/tls": ["cipher_suites", "groups", "must_report"]}
    assert r["checks"][0]["verifies"] == [{"oracle_id": "z01/tls", "key": "protocol_versions"}]
    t.expect("z01/tls", "cipher_suites", "nmap", ["TLS_AES_128_GCM_SHA256"])     # a disagreement verifies nothing
    assert t.result()["agree"] is False and "cipher_suites" in t.result()["unverified_keys"]["z01/tls"]


def test_tls12_groups_are_probed_one_per_handshake_and_compared_for_equality() -> None:
    def ok(g: str) -> dict:
        return {"ok": True, "group": g, "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}

    static = {"ok": True, "group": "", "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA"}   # group refused
    probes = {"x25519": static, "secp256r1": ok("secp256r1"), "secp384r1": static, "secp521r1": {"ok": False}}
    assert selfcheck.legacy_groups_accepted(probes) == ["secp256r1"]
    probes["x25519"] = ok("x25519")                                                  # E2: prime256v1:X25519
    assert selfcheck.legacy_groups_accepted(probes) == ["secp256r1", "x25519"]
    assert selfcheck.iana_suite("TLS_AKE_WITH_AES_128_GCM_SHA256") == "TLS_AES_128_GCM_SHA256"


def _tls_run(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    o = {**_tls_facts(), "facts": "oracle/facts/z02.json"}
    (run / "oracle" / "facts").mkdir(parents=True)
    (run / "oracle" / "facts" / "z02.json").write_text(json.dumps(o))
    (run / "oracle" / "facts" / "index.json").write_text(json.dumps({"targets": [{"target": "z02",
                                                                                  "facts": "oracle/facts/z02.json"}]}))
    oraclefmt.write_all(run, [o], [], step="run1", generated_at="2026-11-12T00:00:00Z", commit="abc", wave="core",
                        network=S.NETWORK, node_ip=S.NODE_IP)
    return run


def test_run_file_is_rebuilt_from_the_facts_and_an_accepted_edit_fails(tmp_path: Path) -> None:
    run = _tls_run(tmp_path)
    current = json.loads((run / "oracle" / "run1.json").read_text())
    assert oraclefmt.oracle_diff(current, oraclefmt.rebuild_run(run, "run1")) == {}
    current["generated_at"] = "2030-01-01T00:00:00Z"                                # ignored
    tls = next(a for a in current["targets"][0]["assets"] if a["oracle_id"] == "z02/tls")
    tls["expect"]["groups"] = ["X25519"]                                            # mutation B, original form
    (run / "oracle" / "run1.json").write_text(json.dumps(current))
    diff = oraclefmt.oracle_diff(current, oraclefmt.rebuild_run(run, "run1"))
    assert list(diff) == ["z02"] and any("groups" in p for p in diff["z02"])
    t = selfcheck.check_oracle_file(run, "run1", {"z02": selfcheck.Target("z02")})
    assert t.result()["agree"] is False


def test_drift_is_a_pure_function_of_the_facts() -> None:
    def tls(tid, ip, sha):
        return {"target": tid, "address": ip, "port": 443, "expect": {"certificates": [{"sha256": sha}]}}
    run1 = {"z02": tls("z02", "10.231.0.18", "a"), "z04": tls("z04", "10.231.0.19", "old"),
            "host": {"target": "host", "address": "10.231.0.40", "expect": {"files": [
                {"path": "/srv/cbom-lab/keys/legacy-rsa1024.key", "kind": "private_key"}]}}}
    run2 = {**run1, "z04": tls("z04", "10.231.0.19", "new"), "z08": tls("z08", "10.231.0.25", "z"),
            "control-tls": tls("control-tls", "10.231.0.34", "c")}
    rows = oraclefmt.drift(run1, run2, S.RUN2_CHANGES)
    assert rows[0] == {"change": "resolved", "code": "PROTO_TLS10", "location": "10.231.0.18:443"}
    assert {"change": "cert_renewed", "location": "10.231.0.19:443", "old_sha256": "old", "new_sha256": "new"} in rows
    assert {"change": "removed_asset", "asset_type": "private_key", "location": "10.231.0.40",
            "path": "/srv/cbom-lab/keys/legacy-rsa1024.key"} in rows
    assert [r["location"] for r in rows if r["change"] == "new_asset"] == ["10.231.0.25:443", "10.231.0.34:443"]


def test_listener_logs_route_lab_peers_out_of_the_product_log(tmp_path: Path) -> None:
    import datetime as dt
    import subprocess
    g = labgen.Gen(tmp_path, dt.datetime(2026, 11, 12, tzinfo=dt.timezone.utc), "t", None, None)
    o = g.listener_target(S.by_id("control"))
    assert o["expect"]["lab_accept_log"] == "lab/listeners/control.lab.jsonl"
    script = (tmp_path / "lab" / "targets" / "control" / "accept.sh").read_text().replace("/logs/", f"{tmp_path}/")
    for peer in ("10.231.0.11", "10.231.0.12", "127.0.0.1", "10.231.0.3"):
        subprocess.run(["sh", "-c", script], env={"SOCAT_PEERADDR": peer, "SOCAT_PEERPORT": "4", "SOCAT_SOCKADDR": "x",
                                                  "SOCAT_SOCKPORT": "443", "PATH": "/usr/bin:/bin"}, check=True)
    product = [json.loads(x) for x in (tmp_path / "control.jsonl").read_text().splitlines()]
    lab = [json.loads(x) for x in (tmp_path / "control.lab.jsonl").read_text().splitlines()]
    assert [r["peer"] for r in product] == ["10.231.0.3:4"]
    assert [r["peer"].split(":")[0] for r in lab] == ["10.231.0.11", "10.231.0.12", "127.0.0.1"]
    assert "/lab/listen.sh" in gen.compose_text()
    lab_json = oraclefmt.lab_json([o], "t", "c", "core", S.NETWORK, S.NODE_IP)
    assert lab_json["listeners"][0]["lab_log"] == "lab/listeners/control.lab.jsonl"
    assert lab_json["lab_addresses"] == [S.TOOLS_IP, S.BURST_IP]


def test_cert_rows_compare_every_asserted_certificate_key() -> None:
    import labread as R
    ders, facts = _certs()
    cert = {**facts[0], "self_issued": False, "san": []}
    o = {**_tls_facts(), "target": "z01"}
    o["expect"]["certificates"] = [cert]
    asset = next(a for a in oraclefmt.assets_for(o)[0] if a["oracle_id"] == "z01/cert[0]")
    t = selfcheck.Target("z01", {"z01/cert[0]": asset})
    selfcheck.cert_rows(t, "z01/cert[0]", R.x509_facts(ders[0]), "labread")
    r = t.result()
    assert r["agree"] is True and r["unverified_keys"] == {}
    assert set(r["independent_keys"]["z01/cert[0]"]) == set(asset["expect"])
    asset["expect"]["key_size"] = 384                                                # a wrong oracle value
    t2 = selfcheck.Target("z01", {"z01/cert[0]": asset})
    selfcheck.cert_rows(t2, "z01/cert[0]", R.x509_facts(ders[0]), "labread")
    assert t2.result()["agree"] is False


def test_keystore_entries_compare_signature_algorithms_by_oid() -> None:
    import labread as R
    ders, _ = _certs()
    obs = selfcheck.keystore_entry("app", "PrivateKeyEntry", ders[1])
    assert obs["signature_algorithm"] == "1.2.840.113549.1.1.11"
    oracle = [{"alias": "app", "type": "PrivateKeyEntry", "key_algorithm": "RSA", "key_bits": obs["key_bits"],
               "signature_algorithm": "SHA256withRSA", "cert_sha256": obs["cert_sha256"]}]
    assert selfcheck.norm_entries(oracle) == selfcheck.norm_entries([obs])
    assert selfcheck.norm_entries([{**oracle[0], "key_bits": obs["key_bits"] + 1}]) != selfcheck.norm_entries([obs])  # D2
    text = ("Bag Attributes\n    friendlyName: app\n    localKeyID: 01 02\n" + (FIX / "certs-z01-chain.crt.txt").read_text()
            .split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\nBag Attributes\n    friendlyName: ca\n"
            "    Trusted key usage (Oracle): Any Extended Key Usage (2.5.29.37.0)\n" + (FIX / "cert-z05b-mldsa.crt.txt").read_text())
    assert [(n, t) for n, t, _ in selfcheck.parse_p12_bags(text)] == [("app", "PrivateKeyEntry"), ("ca", "trustedCertEntry")]
    assert R.sig_oid("SHA1withRSA") == R.sig_oid("sha1WithRSAEncryption")


def test_deferred_parts_point_at_the_filed_issue() -> None:
    assert S.DEFERRED_ISSUE == "#93"
    assert all(d["issue"] == "#93" for d in oraclefmt.lab_json([], "t", "c", "core", S.NETWORK, S.NODE_IP)["deferred"])


def test_negative_proofs_cover_the_review_mutations() -> None:
    import labnegative
    assert {"z02-extra-group"} <= set(labnegative.VARIANTS)
    assert {"hsm-parser-inverted", "hsm-parser-bits", "keytool-bits"} <= set(labnegative.PARSER_MUTATIONS)
    for m in labnegative.PARSER_MUTATIONS.values():
        assert m["old"] in (LAB / m["file"]).read_text()          # every mutation anchor still exists
    assert "z02-extra-group" in labgen.VARIANTS


def test_psp_burst_counts_banners_and_accepts_a_still_penalised_source() -> None:
    log = "drop connection #0 from [10.231.0.12]:60454 on [10.231.0.28]:22 penalty: connections without attempting auth"
    assert selfcheck.burst_verdict({"banner": 17, "dropped": 23}, log, True)[0] is True
    # second self-check within the penalty: every connection dropped, sshd logs nothing new, .11 still served
    ok, how = selfcheck.burst_verdict({"banner": 0, "dropped": 40}, "", True)
    assert ok is True and "still penalised" in how
    assert selfcheck.burst_verdict({"banner": 0, "dropped": 40}, "", False)[0] is False      # sshd down, not a penalty
    assert selfcheck.burst_verdict({"banner": 40, "dropped": 0}, "", True)[0] is False       # no penalty at all
    assert selfcheck.burst_verdict({"banner": 10, "dropped": 30}, log.replace(".12", ".13"), True)[0] is False
    assert "banner" in selfcheck.BURST and "dropped" in selfcheck.BURST
