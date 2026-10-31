"""Each implemented mutant must fail the assertion that describes correct behaviour."""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from support.mutants import MUTANTS, apply  # noqa: E402

Killer = Callable[[], None]

_SCAN = None


def _two_fact_scan():
    global _SCAN
    if _SCAN is None:
        from aibom.cbom.pipeline import scan_crypto

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "main.tf").write_text(
                'resource "aws_s3_bucket" "logs" {}\n'
                'resource "aws_db_instance" "plain" {\n'
                "  storage_encrypted = false\n"
                "}\n",
                encoding="utf-8",
            )
            _SCAN = scan_crypto(root)
    return _SCAN


def _kill_m01() -> None:
    from aibom.cbom.posture import defaults

    row = defaults.load_registry().by_id["aws.kinesis.encryption_type"]
    assert row.effect == "NOT_ENCRYPTED"


def _kill_m02() -> None:
    from aibom.cbom.posture import verdict

    assert verdict.tri_state("UNKNOWN") != "pass"


def _kill_m03() -> None:
    from aibom.cbom.posture.hcl import Unresolved as HclUnresolved
    from aibom.cbom.posture.resolve import Resolved, Scope, Unresolved, VarDecl, _hcl

    node = HclUnresolved("variable", "x", ())
    scope = Scope(variables={"x": VarDecl("x", Resolved(True), overridden=True)})
    assert isinstance(_hcl(node, scope), Unresolved)


def _kill_m04() -> None:
    from aibom.cbom.posture.resolve import Absent
    from aibom.cbom.posture.verdict import LayerCase, assess_layer

    got = assess_layer(
        LayerCase(sources=(Absent(),), effect="ENCRYPTED", row_id="row")
    )
    assert got.verdict == "ENCRYPTED_PROVIDER_DEFAULT"


def _kill_m05() -> None:
    from aibom.cbom.posture.extract_terraform import assess_sources
    from aibom.cbom.posture.resolve import Unresolved

    got = assess_sources(
        (Unresolved("variable_no_default"), Unresolved("unresolved_expression")),
        None,
    )
    assert got.reason == "variable_no_default"


def _suites(spec: str) -> tuple[str, ...]:
    from aibom.cbom.posture.ciphers import evaluate_cipher_list
    from aibom.cbom.posture.defaults import load_registry

    return evaluate_cipher_list(spec, load_registry()).suites


def _kill_m06() -> None:
    assert _suites("RC4:!RC4:RC4") == ()


def _kill_m07() -> None:
    assert "TLS_RSA_WITH_RC4_128_SHA" in _suites("RC4:-RC4:RC4")


def _kill_m08() -> None:
    assert "TLS_RSA_WITH_RC4_128_SHA" not in _suites("ALL:@SECLEVEL=2")


def _kill_m09() -> None:
    from aibom.cbom.posture.extract_terraform import extract_terraform

    text = 'resource "aws_db_instance" "db" {\n  count = 0\n}\n'
    assert extract_terraform(text, "main.tf") == ()


def _kill_m10() -> None:
    from aibom.cbom.posture.extract_kubernetes import _first_provider

    found = _first_provider([{"aescbc": {}}, {"kms": {}}])
    assert found is not None and found[0] == "aescbc"


def _kill_m11() -> None:
    from aibom.cbom.posture.extract_databases import _loopback

    assert _loopback("127.0.0.1") is True


def _kill_m12() -> None:
    from aibom.cbom.posture.xmlsafe import _unsafe_doctype

    assert _unsafe_doctype('<!DOCTYPE foo SYSTEM "bar">') is True


def _kill_m13() -> None:
    from aibom.cbom.posture.diagnostics import DiagnosticSink
    from aibom.cbom.posture.yamlsafe import parse_yaml

    sink = DiagnosticSink()
    parse_yaml("a: &a 1\nb: *a\nc: *a\n", path="a.yml", sink=sink, alias_limit=1)
    assert [item.code for item in sink.stored()] == ["alias_cap"]


def _kill_m14() -> None:
    from aibom.cbom.posture.model import is_hidden_path

    assert is_hidden_path("db_password") is True


def _kill_m15() -> None:
    from aibom.cbom.posture.model import fact_id

    left = fact_id("relational_db", "aws", "aws_db_instance", "db", "a.tf")
    right = fact_id("relational_db", "aws", "aws_db_instance", "db", "b.tf")
    assert left != right


def _ordered_ids(block: dict) -> list[str]:
    facts = block["facts"]
    ordered = sorted(
        facts,
        key=lambda row: (
            str(row["kind"]),
            str(row["path"]),
            int(row["line"]),
            str(row["address"]),
            str(row["id"]),
        ),
    )
    return [str(row["id"]) for row in ordered]


def _kill_m16() -> None:
    from aibom.cbom.posture.assemble import build_posture_block

    block = build_posture_block(_two_fact_scan())
    assert [str(row["id"]) for row in block["facts"]] == _ordered_ids(block)


def _kill_m17() -> None:
    from aibom.score import scorer

    assert scorer._calibration_cap({"A": 8.0}, {"max_raw": 112}) == 112


def _kill_m18() -> None:
    from aibom.cbom.pipeline import scan_crypto
    from aibom.cbom.posture.assemble import build_posture_block

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        (root / "main.tf").write_text(
            'resource "aws_kinesis_stream" "events" {}\n'
            'resource "aws_s3_bucket" "logs" {}\n',
            encoding="utf-8",
        )
        block = build_posture_block(scan_crypto(root))
    assert block["facts"][0]["kind"] == "data_stream"


def _kill_m21() -> None:
    from aibom.cbom.posture.resolve import Resolved
    from aibom.cbom.posture.verdict import LayerCase, assess_layer

    got = assess_layer(LayerCase(sources=(Resolved("maybe"),)))
    assert got.verdict == "UNKNOWN"


def _kill_m22() -> None:
    from aibom.cbom.posture.verdict import resource_verdict

    layers = {"service": "ENCRYPTED_PROVIDER_DEFAULT", "backup": "ENCRYPTED_DECLARED"}
    assert resource_verdict(layers, transport_only=False) == "ENCRYPTED_DECLARED"


def _kill_m23() -> None:
    from aibom.cbom.posture.hcl import Unresolved as HclUnresolved
    from aibom.cbom.posture.resolve import Scope, Unresolved, _hcl

    node = HclUnresolved("variable", "missing", ())
    assert isinstance(_hcl(node, Scope()), Unresolved)


def _kill_m24() -> None:
    from aibom.cbom.posture.resolve import Absent
    from aibom.cbom.posture.verdict import LayerCase, assess_layer

    got = assess_layer(
        LayerCase(
            sources=(Absent(),),
            effect="ENCRYPTED",
            version_dependent=True,
            version_pinned=False,
            row_id="nginx",
        )
    )
    assert got.reason == "provider_version_dependent"


def _kill_m25() -> None:
    from aibom.cbom.posture.resolve import Absent
    from aibom.cbom.posture.verdict import LayerCase, assess_layer

    got = assess_layer(
        LayerCase(
            sources=(Absent(),),
            effect="NOT_ENCRYPTED",
            assessable=False,
            row_id="ebs",
        )
    )
    assert got.verdict == "UNKNOWN"


def _kill_m26() -> None:
    from aibom.cbom.posture.extract_common import listener_reader

    got = listener_reader(plaintext=True, redirect=True)
    assert got.verdict == "ENCRYPTED_DECLARED"


def _kill_m27() -> None:
    from aibom.cbom.posture.assemble import validations_for

    assert validations_for(3) == 1


def _kill_m34() -> None:
    from aibom.cbom.posture.assemble import estimate_fact, n_pre

    kept = n_pre([estimate_fact() for _ in range(4_000)])
    assert kept == 3_390


def _kill_m35() -> None:
    from aibom.cbom.posture.assemble import reduce_record

    record = reduce_record(["parse-node"])
    assert "tree" not in record


def _kill_m28() -> None:
    from aibom.cbom.posture.context import PostureSink

    with tempfile.TemporaryDirectory() as raw:
        sink = PostureSink(Path(raw))
        assert sink.index() is sink.index()


def _kill_m29() -> None:
    from aibom.cbom.posture.diagnostics import DiagnosticSink

    sink = DiagnosticSink()
    sink.add("parse_error", "main.tf", 1)
    sink.add("parse_error", "main.tf", 1)
    assert len(sink.stored()) == 1


def _kill_m30() -> None:
    from aibom.cbom.posture.context import PostureSink

    class SoftTimeLimitExceeded(Exception):
        pass

    with tempfile.TemporaryDirectory() as raw:
        sink = PostureSink(Path(raw))
        with pytest.raises(SoftTimeLimitExceeded), sink.guard("lane"):
            raise SoftTimeLimitExceeded()


def _kill_m31() -> None:
    from aibom.cbom.posture import jsonsafe

    assert "finditer" not in jsonsafe.json_scan.__code__.co_names


def _kill_m33() -> None:
    import time

    from aibom.cbom.posture import textscan

    text = "/* " * 12_000
    started = time.perf_counter()
    textscan.blank_spans(text, (("/*", "*/"),), unterminated="skip")
    assert time.perf_counter() - started < 0.05


def _kill_m39() -> None:
    from aibom.cbom.posture.diagnostics import DiagnosticSink
    from aibom.cbom.posture.yamlsafe import parse_yaml

    stream = "a: 1\nb: 2\nc: 3\n---\nok: 1\n---\nz: 2\n"
    sink = DiagnosticSink()
    docs = parse_yaml(stream, path="s.yml", sink=sink, node_limit=3)
    assert docs == [{"ok": 1}, {"z": 2}]


def _kill_m40() -> None:
    from aibom.cbom.posture.diagnostics import DiagnosticSink
    from aibom.cbom.posture.yamlsafe import LineDict, parse_yaml

    docs = parse_yaml("a: 1\n", path="a.yml", sink=DiagnosticSink())
    assert docs is not None and isinstance(docs[0], LineDict)


def _kill_m41() -> None:
    from aibom.cbom.posture.context import PostureSink

    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw)
        (root / "extra.conf").write_text("ssl = on\n", encoding="utf-8")
        sink = PostureSink(root)
        assert sink.read_included("extra.conf", "server_config") is not None
        assert sink.files_parsed == 1


def _kill_m32() -> None:
    from aibom.cbom.posture import hcl

    assert "(?![*/])" in hcl._TOKEN_RE.pattern


def _kill_m36() -> None:
    from aibom.cbom.posture.findings import derive_findings

    fact = type("Fact", (), {"verdict": "UNKNOWN"})()
    assert "UNENCRYPTED_AT_REST" not in derive_findings(fact, {"at_rest": True})


def _kill_m37() -> None:
    from aibom.cbom.posture.extract_databases import _plaintext

    assert _plaintext(("host", "10.1.1.1", "reject", 1)) is False


def _kill_m42() -> None:
    from aibom.emit import cyclonedx

    assert cyclonedx._family_of("AES-256") == "aes"


def _kill_m43() -> None:
    from aibom.cbom.posture.coverage import CoverageError, RefSpec, _hidden

    consulted = {"terraform": frozenset({"secret_id"})}
    refs = (RefSpec("secret_id", "secret_ref"),)
    try:
        _hidden(consulted, refs, frozenset(), "row")
    except CoverageError as exc:
        raise AssertionError(str(exc)) from exc


def _kill_m50() -> None:
    from aibom.cbom.posture.coverage import _consulted

    class _Row:
        when = {"terraform": {"engine_mode": ("provisioned",)}}
        unless_attrs: dict[str, tuple[str, ...]] = {}

    consulted = _consulted(
        {"terraform": ()}, {}, (), (), (), None, (_Row(),)
    )
    assert "engine_mode" in consulted["terraform"]


def _kill_m51() -> None:
    from aibom.cbom.posture.resolve import Absent, Resolved
    from aibom.cbom.posture.verdict import LayerCase, assess_layer

    got = assess_layer(
        LayerCase(
            sources=(Absent(),),
            effect="ENCRYPTED",
            override_value=Resolved(False),
            row_id="row",
        )
    )
    assert got.verdict == "NOT_ENCRYPTED"


def _kill_m45() -> None:
    from dataclasses import replace

    from aibom.cbom.posture.assemble import build_posture_block
    from aibom.cbom.posture.context import CbomScanResult, PostureSidecar
    from aibom.cbom.posture.model import ImportRecord
    from aibom.model.component import MetadataComponent

    long = "V" * 200
    side = replace(
        PostureSidecar.empty(),
        lanes=("posture_tls_import",),
        imports=(
            ImportRecord(
                path="out.json",
                tool="testssl",
                tool_version=long,
                scan_started=long,
                scan_finished=long,
            ),
        ),
    )
    result = CbomScanResult(subject=MetadataComponent(name="import"), posture=side)
    row = build_posture_block(result)["imports"][0]
    assert row["tool_version"] == "V" * 128
    assert row["scan_started"] == "V" * 128
    assert row["scan_finished"] == "V" * 128


def _kill_m53() -> None:
    from aibom.cbom.posture.extract_servers import extract_servers

    text = "server {\n  listen 443 ssl;\n  listen [::]:80;\n}\n"
    fact = extract_servers(text, "nginx.conf")[0]
    listen = [item.value for item in fact.basis if item.name == "listen"]
    assert listen == ["443,[::]:80"]


def _kill_m46() -> None:
    from aibom.cbom.posture.extract_servers import extract_servers

    text = "<VirtualHost *:443>\nSSLProtocol TLSv1.2 TLSv1.3\n</VirtualHost>\n"
    fact = extract_servers(text, "httpd.conf")[0]
    basis = {item.name: item.value for item in fact.basis}
    assert basis["protocols"] == "TLSv1.2,TLSv1.3"
    assert basis["protocol_min"] == "TLSv1.2"


def _kill_m47() -> None:
    from aibom.cbom.posture.extract_servers import server_facts

    files = {
        "nginx.conf": "http {\n  include conf.d/x.conf;\n}\n",
        "conf.d/x.conf": "server {\n  listen 443 ssl;\n}\n",
    }
    assert len(server_facts(files)) == 1


def _kill_m52() -> None:
    from aibom.cbom.posture.resolve import policy_exposure

    statement = {
        "Principal": "*",
        "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-1"}},
    }
    assert policy_exposure(statement) == "restricted"


def _kill_m38() -> None:
    from aibom.cbom.posture.resolve import gcp_binding_exposure

    exposure, conditional = gcp_binding_exposure(["allUsers"], {"title": "only-prod"})
    assert exposure == "public"
    assert conditional is True


def _kill_m44() -> None:
    from aibom.cbom.posture.findings import derive_findings

    fact = type("Fact", (), {"verdict": "UNKNOWN"})()
    codes = derive_findings(
        fact,
        {
            "KMS_KEY_ROTATION_DISABLED": True,
            "KMS_KEY_ROTATION_DISABLED:unresolved": True,
        },
    )
    assert "KMS_KEY_ROTATION_DISABLED" not in codes


def _kill_m48() -> None:
    from aibom.cbom.posture.extract_databases import pg_transport

    assert pg_transport("on", None).verdict == "UNKNOWN"


def _kill_m49() -> None:
    from aibom.cbom.posture.extract_databases import pg_transport

    hba = (("host", "127.0.0.1", "md5", 1),)
    assert pg_transport("on", hba).verdict == "UNKNOWN"


KILLERS: dict[str, Killer] = {
    "M01": _kill_m01,
    "M02": _kill_m02,
    "M03": _kill_m03,
    "M04": _kill_m04,
    "M05": _kill_m05,
    "M06": _kill_m06,
    "M07": _kill_m07,
    "M08": _kill_m08,
    "M09": _kill_m09,
    "M10": _kill_m10,
    "M11": _kill_m11,
    "M12": _kill_m12,
    "M13": _kill_m13,
    "M14": _kill_m14,
    "M15": _kill_m15,
    "M16": _kill_m16,
    "M17": _kill_m17,
    "M18": _kill_m18,
    "M21": _kill_m21,
    "M22": _kill_m22,
    "M23": _kill_m23,
    "M24": _kill_m24,
    "M25": _kill_m25,
    "M26": _kill_m26,
    "M27": _kill_m27,
    "M28": _kill_m28,
    "M29": _kill_m29,
    "M30": _kill_m30,
    "M31": _kill_m31,
    "M32": _kill_m32,
    "M34": _kill_m34,
    "M35": _kill_m35,
    "M33": _kill_m33,
    "M39": _kill_m39,
    "M40": _kill_m40,
    "M41": _kill_m41,
    "M42": _kill_m42,
    "M43": _kill_m43,
    "M36": _kill_m36,
    "M38": _kill_m38,
    "M37": _kill_m37,
    "M44": _kill_m44,
    "M45": _kill_m45,
    "M46": _kill_m46,
    "M47": _kill_m47,
    "M48": _kill_m48,
    "M49": _kill_m49,
    "M50": _kill_m50,
    "M51": _kill_m51,
    "M52": _kill_m52,
    "M53": _kill_m53,
}

GAPS: frozenset[str] = frozenset()


@pytest.mark.parametrize("mutant_id", sorted(KILLERS))
def test_mutant_fails_the_behaviour_it_changes(
    mutant_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    killer = KILLERS[mutant_id]
    killer()
    apply(monkeypatch, mutant_id)
    try:
        killer()
    except BaseException as exc:
        if exc.__class__.__name__ not in {"AssertionError", "Failed"}:
            raise
        return
    raise AssertionError(f"{mutant_id} left the assertion true")


def test_mutant_ids_cover_the_engine_set() -> None:
    assert set(KILLERS) | set(GAPS) == set(MUTANTS)
    assert set(KILLERS).isdisjoint(GAPS)
