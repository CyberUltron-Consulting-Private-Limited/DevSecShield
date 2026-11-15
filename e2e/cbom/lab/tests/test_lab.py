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


def test_control_listener_expects_one_not_tls_coverage_row_and_no_tls_asset() -> None:
    """CB-12 (#110, INTERFACES CB-12 v1 §5a): the control listener closes without TLS, so the product writes one
    coverage row (status not_tls, scope the port) and never a tls_endpoint (KF-5)."""
    control = {"target": "control", "kind": "listener", "profile": "core", "world": "closed", "address": "10.231.0.34",
               "port": 443, "aliases": ["cbom-e2e-control"], "container": "cb02-control",
               "expect": {"role": "control"}, "provenance": {}}
    assets, mna = oraclefmt.assets_for(control)
    assert [(a["oracle_id"], a["asset_type"], a["location"], a["expect"]) for a in assets] == [
        ("control/not_tls", "coverage", "10.231.0.34", {"status": "not_tls", "scope": ["10.231.0.34:443"]})]
    assert mna == [{"asset_type": "tls_endpoint", "location": "10.231.0.34:443"},
                   {"asset_type": "certificate", "location": "10.231.0.34:443"}]


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
        self.run = Path("/nonexistent-run")

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


# ---------------------------------------------------------------- review 5878784465 (PR #79 round 4): fail first on 5ba718c
PENALTY = "drop connection #0 from [10.231.0.12]:60454 on [10.231.0.28]:22 penalty: connections without attempting auth"


def _burst(port: int) -> dict:
    import subprocess
    res = subprocess.run([sys.executable, "-c", selfcheck.BURST.format(addr="127.0.0.1", port=port)],
                         capture_output=True, text=True, timeout=200, check=True)
    return json.loads(res.stdout.strip().splitlines()[-1])


def test_psp_burst_counts_eof_apart_from_errors_and_needs_a_penalty_for_the_source() -> None:
    import socket
    import threading
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed = probe.getsockname()[1]
    probe.close()
    counts = _burst(closed)                                  # the reviewer's closed-port case: 40 refused connections
    assert (counts["banner"], counts["eof"], counts["error"]) == (0, 0, 40)
    assert selfcheck.burst_verdict(counts, "", "", True)[0] is False
    assert selfcheck.burst_verdict(counts, "", PENALTY, True)[0] is False
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)

    def drop_all() -> None:                                  # what a penalised source sees: connected, then EOF
        for _ in range(40):
            c, _a = srv.accept()
            c.close()
    th = threading.Thread(target=drop_all, daemon=True)
    th.start()
    counts = _burst(srv.getsockname()[1])
    th.join(20)
    srv.close()
    assert counts == {"banner": 0, "eof": 40, "refused": 0, "error": 0, "other": 0}
    assert selfcheck.burst_verdict(counts, "", "", True)[0] is False                  # no penalty ever logged for .12
    ok, how = selfcheck.burst_verdict(counts, "", PENALTY, True)                      # full log: penalised earlier
    assert ok is True and "still penalised" in how
    assert selfcheck.burst_verdict(counts, "", PENALTY, False)[0] is False            # .11 not served either
    assert selfcheck.burst_verdict(counts, "", PENALTY.replace("[10.231.0.12]", "[10.231.0.120]"), True)[0] is False
    assert selfcheck.burst_verdict({**counts, "eof": 39, "error": 1}, "", PENALTY, True)[0] is False
    during = {"banner": 17, "eof": 23, "refused": 0, "error": 0, "other": 0}           # penalty logged in this burst
    assert selfcheck.burst_verdict(during, PENALTY, PENALTY, True)[0] is True
    assert selfcheck.burst_verdict({**during, "eof": 0, "error": 23}, PENALTY, PENALTY, True)[0] is False
    assert selfcheck.burst_verdict({**during, "banner": 40, "eof": 0}, "", PENALTY, True)[0] is False


def _serve(payload: bytes) -> dict:
    """Burst against a local server that answers every connection with ``payload`` and closes."""
    import socket
    import threading
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)

    def answer() -> None:
        for _ in range(40):
            c, _a = srv.accept()
            c.sendall(payload)
            c.close()
    th = threading.Thread(target=answer, daemon=True)
    th.start()
    counts = _burst(srv.getsockname()[1])
    th.join(20)
    srv.close()
    return counts


def test_psp_burst_counts_sshds_own_refusal_as_dropped() -> None:
    """Live at 12a7f8c (2026-11-14, OpenSSH 10.0): a penalised source is not closed silently, sshd writes
    "Not allowed at this time" first. Counted as ``other``, the burst read 17 banners + 23 other and the positive
    control failed on a psp that was working (selfcheck exit 2). The refusal is sshd's own; any other payload is not."""
    counts = _serve(b"Not allowed at this time\r\n")
    assert counts == {"banner": 0, "eof": 0, "refused": 40, "error": 0, "other": 0}
    live = {"banner": 17, "eof": 0, "refused": 23, "error": 0, "other": 0}            # ev79/run-psp, burst from .12
    assert selfcheck.burst_verdict(live, PENALTY, PENALTY, True)[0] is True
    assert selfcheck.burst_verdict(live, "", "", True)[0] is False                    # no penalty logged: not proven
    ok, how = selfcheck.burst_verdict(counts, "", PENALTY, True)
    assert ok is True and "still penalised" in how and "40 refused by sshd" in how
    junk = _serve(b"HTTP/1.1 400 Bad Request\r\n")
    assert (junk["other"], junk["refused"], junk["other_samples"][0]) == (40, 0, repr(b"HTTP/1.1 400 Bad Request\r\n"))
    assert selfcheck.burst_verdict(junk, PENALTY, PENALTY, True)[0] is False
    assert selfcheck.burst_verdict({**live, "other": 1}, PENALTY, PENALTY, True)[0] is False


def test_hsm_token_objects_equal_the_run_files_managed_keys_both_ways(tmp_path: Path) -> None:
    objs = selfcheck.p11tool_objects(P11TOOL)
    assert objs == [("aes-128-wrap", "Secret Key"), ("ec-p256-signing", "Private Key"),
                    ("rsa-2048-signing", "Private Key"), ("rsa-2048-signing", "Public Key")]
    ids = ["softhsm/cb02-tok-a/aes-128-wrap/Secret Key", "softhsm/cb02-tok-a/ec-p256-signing/Private Key",
           "softhsm/cb02-tok-a/rsa-2048-signing/Private Key"]
    full = selfcheck.Target("softhsm", {i: {"expect": {}} for i in ids})
    assert selfcheck.token_set_row(full, "cb02-tok-a", objs, "p11tool") is True
    dropped = selfcheck.Target("softhsm", {i: {"expect": {}} for i in ids if "aes-128" not in i})   # hsm-parser-drop
    assert selfcheck.token_set_row(dropped, "cb02-tok-a", objs, "p11tool") is False
    extra = P11TOOL + "\nObject 4:\n\tType: Data\n\tLabel: stray\n\tID: 09\n"        # nothing is skipped
    assert selfcheck.token_set_row(full, "cb02-tok-a", selfcheck.p11tool_objects(extra), "p11tool") is False
    assert selfcheck.token_set_row(full, "cb02-tok-a", selfcheck.p11tool_objects(""), "p11tool") is False
    import labnegative
    m = labnegative.PARSER_MUTATIONS["hsm-parser-drop"]
    assert m["target"] == "softhsm" and m["key"] == selfcheck.TOKEN_SET_KEY and m["old"] in (LAB / m["file"]).read_text()
    listing = (FIX / "pkcs11-tok-a.txt").read_text()
    mutant = tmp_path / "labgen_mutant.py"
    mutant.write_text((LAB / m["file"]).read_text().replace(m["old"], m["new"], 1))
    spec = importlib.util.spec_from_file_location("labgen_mutant", mutant)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert any(o["label"] == "aes-128-wrap" for o in labgen.parse_pkcs11_objects(listing))
    assert not any(o["label"] == "aes-128-wrap" for o in mod.parse_pkcs11_objects(listing))  # the mutation drops it


def test_quantum_vulnerability_cites_the_final_nist_ir_8547() -> None:
    src = oraclefmt.QV_SOURCE
    assert "https://doi.org/10.6028/NIST.IR.8547" in src and "ipd" not in src
    for part in ("2.1.1", "2.1.2", "4.1.1 Table 2", "4.1.2 Table 4", "FIPS 203", "FIPS 204"):
        assert part in src, part
    assert "DSA" not in oraclefmt.QUANTUM_VULNERABLE          # not in IR 8547 (only inside ML-DSA, SLH-DSA, ECDSA, EdDSA)
    for name in ("oraclefmt.py", "README.md"):
        text = (LAB / name).read_text()
        assert "8547 ipd" not in text and "sections 3-4" not in text and "§3-4" not in text, name


def test_name_key_tells_names_apart_and_cert_rows_catch_a_wrong_subject() -> None:   # L3
    import labread as R
    assert R.name_key("CN=a") != R.name_key("CN=b")
    assert R.name_key("cn=a,o=B") == R.name_key("CN=a,O=B") and R.name_key("CN=a,O=b") != R.name_key("CN=a,O=B")
    ders, facts = _certs()
    o = {**_tls_facts(), "target": "z01"}
    o["expect"]["certificates"] = [facts[0]]
    asset = next(a for a in oraclefmt.assets_for(o)[0] if a["oracle_id"] == "z01/cert[0]")
    for key, wrong in (("subject", "CN=other.lab"), ("issuer", "CN=Other CA,O=ZeroShield CBOM lab")):
        t = selfcheck.Target("z01", {"z01/cert[0]": {**asset, "expect": {**asset["expect"], key: wrong}}})
        selfcheck.cert_rows(t, "z01/cert[0]", R.x509_facts(ders[0]), "labread")
        assert t.result()["agree"] is False, key


def test_pkcs8_ec_and_eddsa_key_sizes() -> None:                                       # L8, L10
    import base64
    import labread as R
    ec_oid, p256 = bytes.fromhex("06072a8648ce3d0201"), bytes.fromhex("06082a8648ce3d030107")
    inner = _der(0x30, _der_int(1) + _der(0x04, b"\x01" * 32))
    info = _der(0x30, _der_int(0) + _der(0x30, ec_oid + p256) + _der(0x04, inner))
    pem = "-----BEGIN PRIVATE KEY-----\n" + base64.encodebytes(info).decode() + "-----END PRIVATE KEY-----\n"
    assert R.pkcs8_facts(pem) == {"algorithm": "EC", "key_size": 256}
    for oid, n, bits in ((b"\x2b\x65\x70", 32, 256), (b"\x2b\x65\x71", 57, 456)):     # RFC 8410: Ed25519, Ed448
        spki = _der(0x30, _der(0x06, oid)) + _der(0x03, b"\x00" + b"\x02" * n)
        got = R._spki(spki)
        assert got["key_size"] == bits and got["algorithm"] in ("ED25519", "ED448")


def test_ranges_check_sees_a_held_empty_address_and_classifies_never_scan() -> None:  # C9, C14
    zoo = {"source": "S-zoo", "cidr": "10.231.0.16/30", "empty_addresses": ["10.231.0.18"], "never_scan": []}
    oracle = {"targets": [{"address": "10.231.0.17"}], "ranges": [zoo]}
    held = selfcheck.check_ranges(oracle, {"10.231.0.17": "cb02-z01", "10.231.0.18": "rv-stray"}).result()
    assert held["agree"] is False
    row = next(c for c in held["checks"] if c["key"] == "empty addresses hold no container")
    assert row["observed"] == {"10.231.0.18": "rv-stray"}
    assert selfcheck.check_ranges(oracle, {"10.231.0.17": "cb02-z01"}).result()["agree"] is True
    canary = {"targets": [{"address": "10.231.0.34"}],
              "ranges": [{"source": "R-canary", "cidr": "10.231.0.32/30", "empty_addresses": [], "never_scan": ["10.231.0.33"]}]}
    assert selfcheck.check_ranges(canary, {"10.231.0.34": "cb02-control"}).result()["agree"] is True


def test_must_report_row_needs_every_suite_accepted() -> None:                         # C13
    oid = "z02/tls"
    t = selfcheck.Target("z02", {oid: {"expect": {}, "must_report": {"cipher_suites": ["A", "B"]}}})
    selfcheck.must_report_row(t, oid, ["A"], "nmap")
    assert t.result()["agree"] is False
    t = selfcheck.Target("z02", {oid: {"expect": {}, "must_report": {"cipher_suites": ["A", "B"]}}})
    selfcheck.must_report_row(t, oid, ["A", "B", "C"], "nmap")
    assert t.result()["agree"] is True and t.result()["independent_keys"] == {oid: ["must_report"]}


def test_oracle_diff_sees_edited_ranges_and_the_rebuild_fails_the_target(tmp_path: Path) -> None:  # O6, C5
    run = _tls_run(tmp_path)
    current = json.loads((run / "oracle" / "run1.json").read_text())
    current["ranges"] = [{"source": "S-zoo", "cidr": "10.231.0.16/28", "empty_addresses": [], "never_scan": []}]
    assert "ranges" in oraclefmt.oracle_diff(current, oraclefmt.rebuild_run(run, "run1")).get("", [])
    tls = next(a for a in current["targets"][0]["assets"] if a["oracle_id"] == "z02/tls")
    tls["expect"]["groups"] = ["X25519"]
    (run / "oracle" / "run1.json").write_text(json.dumps(current))
    results = {"z02": selfcheck.Target("z02")}
    selfcheck.check_oracle_file(run, "run1", results)
    assert results["z02"].result()["agree"] is False                                 # propagated to the target


def test_legacy_group_cross_check_refuses_an_empty_observation() -> None:              # C10
    assert selfcheck.legacy_groups_agree(["secp256r1"], {}) is False
    assert selfcheck.legacy_groups_agree(["secp256r1"], {"TLSv1.2": []}) is False


def test_endpoint_verdict_needs_tls13_and_classifies_every_ssh_pq_name() -> None:     # O1, O4
    legacy = {v: v != "TLSv1.3" for v in S.VERSIONS}
    assert oraclefmt.tls_endpoint_qv(legacy, ["X25519MLKEM768"]) is True              # no PQ group below TLS 1.3
    for k in ("sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "mlkem768x25519-sha256"):
        assert oraclefmt.ssh_endpoint_qv([k]) is False, k


def test_every_planted_weak_suite_is_must_report() -> None:                            # S2
    for t in S.TARGETS:
        if t["kind"] != "tls":
            continue
        weak = sorted(s for s in t["suites"] if "_CBC_" in s or s.startswith("TLS_RSA_WITH_"))
        assert sorted((t.get("must_report") or {}).get("cipher_suites", [])) == weak, t["id"]


def test_listener_logs_are_created_at_up(tmp_path: Path) -> None:                     # G2
    import datetime as dt
    g = labgen.Gen(tmp_path, dt.datetime(2026, 11, 12, tzinfo=dt.timezone.utc), "t", None, None)
    o = g.listener_target(S.by_id("canary"))
    labgen.touch_listener_logs(tmp_path, [o])
    for name in (o["expect"]["accept_log"], o["expect"]["lab_accept_log"]):
        p = tmp_path / name
        assert p.exists() and p.read_text() == "" and p.stat().st_mode & 0o666 == 0o666


def test_listener_runs_only_from_the_generated_listen_sh(tmp_path: Path) -> None:     # nit: dead listener branch
    import subprocess
    assert not (LAB / "entrypoints" / "cb02-accept").exists()
    (tmp_path / "role.env").write_text("TARGET=canary\nROLE=listener\nPORT=443\n")
    script = (LAB / "entrypoints" / "cb02-entry").read_text().replace("/lab/role.env", str(tmp_path / "role.env"))
    res = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10, check=False)
    assert res.returncode == 64 and "/lab/listen.sh" in res.stderr


def test_readme_names_the_tools_the_self_check_uses() -> None:                         # nit: README tool names
    text = (LAB / "README.md").read_text()
    assert "ssh-keygen -l" not in text and "keytool, openssl x509" not in text
    rows = {r.split("|")[2].strip(): r for r in text.splitlines() if r.startswith("| core |")}
    assert "labread" in rows["sshd-legacy"] and "ssh-audit" in rows["sshd-legacy"]
    assert "labread JKS reader" in rows["host"] and "openssl pkcs12" in rows["host"]


def test_image_inputs_are_per_image(tmp_path: Path) -> None:                           # an entrypoint edit keeps tools
    import shutil
    copy = tmp_path / "lab"
    for sub in ("images", "entrypoints", "tlscheck"):
        shutil.copytree(LAB / sub, copy / sub)
    before = {k: gen.image_inputs_hash(k, copy) for k in gen.IMAGES}
    (copy / "entrypoints" / "cb02-entry").write_text((copy / "entrypoints" / "cb02-entry").read_text() + "\n# x\n")
    mid = {k: gen.image_inputs_hash(k, copy) for k in gen.IMAGES}
    assert mid["target"] != before["target"] and mid["tools"] == before["tools"]
    (copy / "tlscheck" / "main.go").write_text((copy / "tlscheck" / "main.go").read_text() + "\n// x\n")
    after = {k: gen.image_inputs_hash(k, copy) for k in gen.IMAGES}
    assert after["tools"] != mid["tools"] and after["target"] == mid["target"]


# ---------------------------------------------------------------- #75 asks (review 5878413538): INTERFACES v7.3
NOW = "2026-11-12T08:00:00Z"


def _cert(**kw) -> dict:
    base = {"sha256": "cd" * 32, "subject": "CN=x.lab", "issuer": "CN=CBOM Lab Targets CA,O=ZeroShield CBOM lab",
            "serial": "02", "not_before": "2026-11-11T08:00:00Z", "not_after": "2027-12-14T08:00:00Z",
            "signature_algorithm": "sha256WithRSAEncryption", "key_algorithm": "RSA", "key_bits": 2048, "curve": None}
    return {**base, **kw}


def _codes(assets: list[dict], oid: str) -> tuple[list, list, str | None]:
    a = next(x for x in assets if x["oracle_id"] == oid)
    return a.get("codes_include", []), a.get("codes_exclude", []), a.get("impact_min")


def _ssh_facts(tid: str, kex: list[str], host_keys: list[tuple[str, int]]) -> dict:
    return {"target": tid, "kind": "ssh", "profile": "core", "world": "closed", "address": "10.231.0.23", "port": 22,
            "aliases": [], "container": f"cb02-{tid}", "provenance": {},
            "expect": {"kex": kex, "host_key_algorithms": [], "ciphers": [], "macs": [],
                       "host_keys": [{"type": t, "bits": b, "fingerprint_sha256": "SHA256:x"} for t, b in host_keys]}}


def test_planted_weaknesses_carry_the_specs_codes_and_an_impact_floor() -> None:
    a, _ = oraclefmt.assets_for(_tls_facts(), NOW)          # z02: TLS 1.0 + static-RSA CBC, RSA-1024 SHA-1 self-signed
    inc, exc, imp = _codes(a, "z02/tls")
    assert (inc, imp) == (["PROTO_TLS10", "STATIC_RSA_KEX"], "Low") and "NO_PQ_KEX" not in exc
    assert not {"PROTO_TLS11", "CBC_ACCEPTED"} & set(inc + exc)   # no spec name (O-1): judged by versions/must_report
    inc, exc, imp = _codes(a, "z02/cert[0]")
    assert (inc, imp) == (["CERT_SELF_SHA1", "RSA_LT_2048"], "Low") and exc == ["CERT_EXPIRED"]
    z04 = {**_tls_facts(), "target": "z04", "address": "10.231.0.19"}
    z04["expect"] = {**z04["expect"], "versions": {v: v in ("TLSv1.2", "TLSv1.3") for v in S.VERSIONS},
                     "suites": {"TLSv1.2": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}, "groups": ["x25519"],
                     "certificates": [_cert(not_before="2024-10-13T08:00:00Z", not_after="2025-10-08T08:00:00Z"),
                                      _cert(subject="CN=CBOM Lab Targets CA,O=ZeroShield CBOM lab")]}
    a, _ = oraclefmt.assets_for(z04, NOW)
    inc, exc, imp = _codes(a, "z04/cert[0]")
    assert (inc, imp) == (["CERT_EXPIRED"], "Low") and exc == ["CERT_SELF_SHA1", "RSA_LT_2048"]
    inc, exc, imp = _codes(a, "z04/cert[1]")                 # the lab CA: self-signed, but SHA-256 and valid
    assert (inc, imp) == ([], None) and exc == ["CERT_EXPIRED", "CERT_SELF_SHA1", "RSA_LT_2048"]
    inc, exc, imp = _codes(a, "z04/tls")
    assert (inc, imp) == ([], None) and exc == ["PROTO_TLS10", "STATIC_RSA_KEX"]
    z05b = {**_tls_facts(), "target": "z05b"}
    z05b["expect"] = {**z04["expect"], "versions": {v: v == "TLSv1.3" for v in S.VERSIONS}, "suites": {},
                      "groups": ["X25519MLKEM768", "x25519"],
                      "certificates": [_cert(key_algorithm="ML-DSA-65", key_bits=None, signature_algorithm="ML-DSA-65",
                                             subject="CN=z05b.lab", issuer="CN=z05b.lab")]}
    a, _ = oraclefmt.assets_for(z05b, NOW)
    assert "NO_PQ_KEX" in _codes(a, "z05b/tls")[1]           # DA §4.4 KF-3: false NO_PQ_KEX on z05b
    assert _codes(a, "z05b/cert[0]") == ([], ["CERT_EXPIRED", "CERT_SELF_SHA1", "RSA_LT_2048"], None)
    a, _ = oraclefmt.assets_for(_ssh_facts("sshd-legacy", S.by_id("sshd-legacy")["kex"],
                                           [("ssh-rsa", 1024), ("ssh-ed25519", 256)]), NOW)
    assert _codes(a, "sshd-legacy/ssh") == (["RSA_LT_2048", "SSH_NO_PQ_KEX"], [], "Low")
    a, _ = oraclefmt.assets_for(_ssh_facts("sshd-pq", ["mlkem768x25519-sha256"], [("ssh-ed25519", 256)]), NOW)
    assert _codes(a, "sshd-pq/ssh") == ([], ["RSA_LT_2048", "SSH_NO_PQ_KEX"], None)
    a, _ = oraclefmt.assets_for(_ssh_facts("x", ["curve25519-sha256"], [("ssh-ed25519", 256)]), NOW)
    assert _codes(a, "x/ssh") == (["SSH_NO_PQ_KEX"], ["RSA_LT_2048"], None)  # a future-risk code alone: no floor


def test_host_files_databases_and_hsm_keys_carry_their_planted_codes() -> None:
    host = _ssh_facts("host", S.by_id("host")["kex"], [("ssh-rsa", 3072), ("ssh-ed25519", 256)])
    host.update(kind="host", address="10.231.0.40")
    host["expect"]["files"] = [
        {"path": "/srv/cbom-lab/keys/legacy-rsa1024.key", "kind": "private_key", "key_algorithm": "RSA", "key_bits": 1024},
        {"path": "/srv/cbom-lab/certs/expired-rsa2048.crt", "kind": "certificate",
         "certificate": _cert(subject="CN=expired-rsa2048.lab", not_before="2024-10-13T08:00:00Z",
                              not_after="2025-10-08T08:00:00Z")},
        {"path": "/srv/cbom-lab/certs/selfsigned-sha1.crt", "kind": "certificate",
         "certificate": _cert(subject="CN=selfsigned-sha1.lab", issuer="CN=selfsigned-sha1.lab",
                              signature_algorithm="sha1WithRSAEncryption")}]
    a, _ = oraclefmt.assets_for(host, NOW)
    assert _codes(a, "host:/srv/cbom-lab/keys/legacy-rsa1024.key") == (["RSA_LT_2048"], [], "Low")
    assert _codes(a, "host:/srv/cbom-lab/certs/expired-rsa2048.crt")[0::2] == (["CERT_EXPIRED"], "Low")
    assert _codes(a, "host:/srv/cbom-lab/certs/selfsigned-sha1.crt")[0::2] == (["CERT_SELF_SHA1"], "Low")
    assert _codes(a, "host/ssh") == ([], ["RSA_LT_2048", "SSH_NO_PQ_KEX"], None)
    ca_sha1 = {**host, "expect": {**host["expect"], "files": [{"path": "/srv/cbom-lab/certs/ca-sha1.crt",
                                                                "kind": "certificate",
                                                                "certificate": _cert(signature_algorithm="sha1WithRSAEncryption")}]}}
    assert "CERT_SELF_SHA1" in _codes(oraclefmt.assets_for(ca_sha1, NOW)[0], "host:/srv/cbom-lab/certs/ca-sha1.crt")[1]
    pg = {"target": "pg-tls", "kind": "postgres", "profile": "core", "world": "closed", "address": "10.231.0.41",
          "port": 5432, "aliases": [], "container": "cb02-pg-tls", "provenance": {},
          "expect": {"ssl": "off", "hba": [{"type": "hostssl", "database": "all", "user": "cbom_md5",
                                            "address": "0.0.0.0/0", "method": "md5"}]}}
    a, _ = oraclefmt.assets_for(pg, NOW)
    assert _codes(a, "pg-tls/auth") == (["DB_MD5_ACCEPTED"], [], "Low")
    pg["expect"]["hba"][0]["method"] = "scram-sha-256"
    assert _codes(oraclefmt.assets_for(pg, NOW)[0], "pg-tls/auth") == ([], ["DB_MD5_ACCEPTED"], None)
    my = {**pg, "target": "mysql-notls", "kind": "mysql",
          "expect": {"users": {"cbom_native": "mysql_native_password", "cbom_reader": "caching_sha2_password"},
                     "tls": {"ssl_supported": False}, "tls_version": ""}}
    assert _codes(oraclefmt.assets_for(my, NOW)[0], "mysql-notls/auth") == (["DB_NATIVE_PW"], [], "Low")
    a, _ = oraclefmt.assets_for(_hsm_facts(), NOW)
    assert _codes(a, "softhsm/cb02-tok-a/aes-128-wrap/Secret Key") == (["KEY_EXTRACTABLE"], [], "Low")
    assert _codes(a, "softhsm/cb02-tok-a/rsa-2048-signing/Private Key") == ([], ["KEY_EXTRACTABLE"], None)
    codes = oraclefmt.CODE_SOURCES
    assert set(codes) == {"PROTO_TLS10", "STATIC_RSA_KEX", "CERT_EXPIRED", "RSA_LT_2048", "CERT_SELF_SHA1",
                          "SSH_NO_PQ_KEX", "DB_MD5_ACCEPTED", "DB_NATIVE_PW", "KEY_EXTRACTABLE", "NO_PQ_KEX"}
    assert all(("DEVILS-ADVOCATE" in v or "E2E-PLAN" in v) for v in codes.values())


def test_codes_follow_the_run_step(tmp_path: Path) -> None:
    run = _tls_run(tmp_path)                                  # run_oracle states the codes against generated_at
    cur = json.loads((run / "oracle" / "run1.json").read_text())
    tls = next(a for a in cur["targets"][0]["assets"] if a["oracle_id"] == "z02/tls")
    assert tls["codes_include"] == ["PROTO_TLS10", "STATIC_RSA_KEX"] and tls["impact_min"] == "Low"
    assert oraclefmt.oracle_diff(cur, oraclefmt.rebuild_run(run, "run1")) == {}
    assert cur["codes_source"] == oraclefmt.CODE_SOURCES                         # every code cites the spec


class _MldsaCtx(_FakeCtx):
    """s_client completes TLS 1.3 and prints the served certificate (canned); the run dir holds the generated file."""

    def __init__(self, run: Path, served_pem: str) -> None:
        super().__init__()
        self.run, self.pem = run, served_pem

    def exec(self, *cmd: str, **kw):
        import re
        line = " ".join(cmd)
        group = re.search(r"-groups (\S+)", line)
        if "-tls1_3" in line and not group:
            out = "CONNECTED(00000003)\nServer certificate\n" + self.pem + "\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        elif group and group.group(1) in ("X25519MLKEM768", "X25519"):
            out = "CONNECTED(00000003)\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n"
        else:
            out = "Cipher is (NONE)"
        return type("R", (), {"stdout": out, "stderr": "", "returncode": 0})()


def _z05b(tmp_path: Path, generated_pem: str) -> tuple[dict, selfcheck.Target, _MldsaCtx]:
    served = (FIX / "cert-z05b-mldsa.crt.txt").read_text()
    facts = json.loads((FIX / "certs-openssl-facts.json").read_text())["z05b"]
    o = {**_tls_facts(), "target": "z05b", "address": "10.231.0.21"}
    o["expect"] = {**o["expect"], "versions": {v: v == "TLSv1.3" for v in S.VERSIONS}, "suites": {},
                   "tls13_suites": sorted(S.TLS13_SUITES), "groups": ["X25519MLKEM768", "x25519"],
                   "certificates": facts}
    d = tmp_path / "lab" / "targets" / "z05b"
    d.mkdir(parents=True)
    (d / "cert.pem").write_text(generated_pem)
    assets, _ = oraclefmt.assets_for(o, NOW)
    return o, selfcheck.Target("z05b", {a["oracle_id"]: a for a in assets}), _MldsaCtx(tmp_path, served)


def test_ml_dsa_certificate_keys_are_verified_when_the_served_der_is_the_generated_file(tmp_path: Path) -> None:
    served = (FIX / "cert-z05b-mldsa.crt.txt").read_text()
    o, t, ctx = _z05b(tmp_path, served)
    r = selfcheck.check_tls_mldsa(ctx, o, t).result()
    cert_keys = sorted(t.assets["z05b/cert[0]"]["expect"])
    assert r["agree"] is True and r["independent_keys"]["z05b/cert[0]"] == cert_keys
    assert "z05b/cert[0]" not in r["unverified_keys"]
    assert sorted(r["unverified_keys"]["z05b/tls"]) == ["cipher_suites", "groups", "protocol_versions", "quantum_vulnerable"]
    other = (FIX / "certs-z01-chain.crt.txt").read_text().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    o, t, ctx = _z05b(tmp_path / "b", other)                # served bytes differ from the generated file
    r = selfcheck.check_tls_mldsa(ctx, o, t).result()
    assert sorted(r["unverified_keys"]["z05b/cert[0]"]) == cert_keys and r["agree"] is False


def test_standards_tables_are_closed_and_complete() -> None:
    iana_pq = {"MLKEM512": 512, "MLKEM768": 513, "MLKEM1024": 514, "SecP256r1MLKEM512": 4585, "MLKEM512X25519": 4586,
               "SecP256r1MLKEM768": 4587, "X25519MLKEM768": 4588, "SecP384r1MLKEM1024": 4589,
               "curveSM2MLKEM768": 4590, "MLKEM1024X448": 4591, "X25519Kyber768Draft00": 25497,
               "SecP256r1Kyber768Draft00": 25498}
    for name, code in iana_pq.items():
        assert oraclefmt.TLS_GROUP_CODE[name] == code and oraclefmt.tls_group_pq(name) is True, name
    for name in ("x25519", "x448", "secp256r1", "secp521r1", "ffdhe2048", "ffdhe8192", "curveSM2"):
        assert oraclefmt.tls_group_pq(name) is False, name
    assert set(oraclefmt.TLS_GROUP_CODE) == set(oraclefmt.TLS_GROUP_PQ)
    v13 = {v: v == "TLSv1.3" for v in S.VERSIONS}
    with pytest.raises(ValueError):
        oraclefmt.tls_group_pq("brainpoolP256r1tls13")
    assert oraclefmt.derive_tls_qv(v13, ["x25519", "brainpoolP256r1tls13"]) is None   # not derived, never classical
    assert oraclefmt.derive_tls_qv(v13, ["MLKEM1024X448"]) is False
    assert oraclefmt.derive_tls_qv(v13, ["x25519"]) is True
    for k in ("mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384", "sntrup761x25519-sha512",
              "sntrup761x25519-sha512@openssh.com", "mlkem512-sha256", "mlkem768-sha256", "mlkem1024-sha384"):
        assert oraclefmt.ssh_kex_pq(k) is True, k
    for k in ("curve25519-sha256", "curve448-sha512", "diffie-hellman-group1-sha1", "rsa2048-sha256"):
        assert oraclefmt.ssh_kex_pq(k) is False, k
    with pytest.raises(ValueError):
        oraclefmt.ssh_kex_pq("x-unknown-kex@example.com")
    assert oraclefmt.derive_ssh_qv(["curve25519-sha256", "x-unknown-kex@example.com"]) is None
    with pytest.raises(ValueError):
        selfcheck.classical_groups(["x25519", "brainpoolP256r1tls13"])
    assert selfcheck.classical_groups(["X25519MLKEM768", "x25519"]) == ["x25519"]
    assert selfcheck.ssh_pq_kex(["mlkem768nistp256-sha256", "curve25519-sha256", "x-new"]) == ["mlkem768nistp256-sha256"]
    assert "startswith((\"mlkem\", \"sntrup\"))" not in (LAB / "labgen.py").read_text() + (LAB / "labcheck.py").read_text()


# ---------------------------------------------------------------- 2026-11-14: tools image no longer built (CB-36 run)
def test_lab_images_pin_every_package_exactly_and_every_base_by_digest() -> None:
    """Alpine keeps only the newest build per branch, so the tools image stopped building when postgresql16-client
    moved 16.15-r0 -> 16.16-r0. Pins stay exact (the image is reproducible or fails loudly); images/apk-pins.sh checks
    them against the repository. Every installed package carries a pin and every FROM a digest."""
    import re
    for name in ("tools", "target"):
        text = (LAB / "images" / f"{name}.Dockerfile").read_text()
        froms = re.findall(r"^FROM (\S+)", text, re.M)
        assert froms and all("@sha256:" in f for f in froms), froms
        block = text.split("apk add --no-cache", 1)[1].split("&&", 1)[0]
        pkgs = [w for w in block.replace("\\", " ").split() if w]
        assert pkgs and all(re.fullmatch(r"[a-z0-9][a-z0-9.+_-]*=[0-9][\w.+-]*", p) for p in pkgs), pkgs
    assert "postgresql16-client=16.16-r0" in (LAB / "images" / "tools.Dockerfile").read_text()
    script = (LAB / "images" / "apk-pins.sh").read_text()
    assert "tools.Dockerfile" in script and "target.Dockerfile" in script and "exit $rc" in script
