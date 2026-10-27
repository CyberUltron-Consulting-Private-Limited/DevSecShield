"""T-CON: drift locks around the team-wide CBOM deliverables registry (WP4, plan 6.3).

Every test here pins one fact that lives in TWO places, so a change to either side fails loudly
instead of silently shipping a document or a menu that disagrees with the rest of the product:

* registry <-> frontend (T-CON-1): the slug list, numbers and titles of ``CBOM_DELIVERABLES`` in
  ``frontend/utils/backend_api.ts``, the download file name in ``cbom/page.tsx`` and the field
  names of the manifest types;
* authored text <-> existing product constants (T-CON-2): both disclaimers;
* authored text <-> ``frameworkLabels.ts`` and the engine's 13 CBOM frameworks (T-CON-3);
* authored text <-> every finding code the engine put into the fixtures (T-CON-4);
* authored timeline sentences <-> the engine's own wording (T-CON-5);
* authored scanner table <-> the engine registry, including the three unwired modules (T-CON-6);
* registry <-> ``REPORT_META`` page chrome (T-CON-7).

The engine side is read three ways, none of which imports the ``aibom`` package (the backend
environment does not install it): the committed fixtures (``cbom_team_rollup_scans.json``,
``cbom_scanner_registry.json``), the plain text of ``aibom/src/aibom/cbom/*`` and the frontend
files as text.  No DB, no network, no language model, no wall clock.
"""
from __future__ import annotations

import json
import re
import sys
import types
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import ScanHead, fold_scans  # noqa: E402
from backend.utilities.pdf import (  # noqa: E402
    cbom_assurance_register_pdf,
    cbom_board_report_pdf,
    cbom_cert_register_pdf,
    cbom_data_at_rest_pdf,
    cbom_infra_posture_pdf,
    cbom_methodology_pdf,
    cbom_network_tls_pdf,
    cbom_pqc_roadmap_pdf,
    cbom_scope_register_pdf,
)
from backend.utilities.pdf import cbom_deliverable_text as authored  # noqa: E402
from backend.utilities.pdf.cbom_deliverables import (  # noqa: E402
    DELIVERABLES,
    REASON_NO_SCANS,
    DeliverableSpec,
    HeadsSummary,
    build_manifest,
    deliverable_filename,
    summarize_heads,
)
from backend.utilities.pdf.report_branding import REPORT_META  # noqa: E402

UTC = timezone.utc
FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)

# The nine documents, in menu order.  Literals on purpose: the registry must not be able to
# "agree with itself" after an accidental edit.
EXPECTED = [
    ("scope-baseline-register", 1, "Scope Baseline & Asset Population Register"),
    ("methodology-evidence-plan", 3, "Cryptographic Discovery Methodology & Evidence Plan"),
    (
        "infrastructure-cloud-encryption-posture",
        5,
        "Infrastructure & Cloud Encryption Posture",
    ),
    (
        "network-tls-protocol-assessment",
        6,
        "Network, TLS & Crypto Protocol Assessment",
    ),
    ("certificate-estate-register", 7, "Certificate Estate Register"),
    (
        "data-at-rest-encryption-assessment",
        9,
        "Data-at-Rest Encryption Assessment",
    ),
    (
        "third-party-assurance-register",
        10,
        "Third-Party Cryptographic Assurance & Attestation Register",
    ),
    ("pqc-migration-roadmap", 15, "PQC Migration Roadmap"),
    (
        "board-executive-report",
        16,
        "Board / IT Strategy Committee Regulatory & Executive Report",
    ),
]
RENDERERS = {
    "scope-baseline-register": (cbom_scope_register_pdf, "DELIVERABLE_NUMBER"),
    "methodology-evidence-plan": (cbom_methodology_pdf, "NUMBER"),
    "infrastructure-cloud-encryption-posture": (cbom_infra_posture_pdf, "DOCUMENT_NUMBER"),
    "network-tls-protocol-assessment": (cbom_network_tls_pdf, "DOCUMENT_NUMBER"),
    "certificate-estate-register": (cbom_cert_register_pdf, "NUMBER"),
    "data-at-rest-encryption-assessment": (cbom_data_at_rest_pdf, "DOCUMENT_NUMBER"),
    "third-party-assurance-register": (cbom_assurance_register_pdf, "DOCUMENT_NUMBER"),
    "pqc-migration-roadmap": (cbom_pqc_roadmap_pdf, "NUMBER"),
    "board-executive-report": (cbom_board_report_pdf, "DELIVERABLE_NUMBER"),
}
DATA_DEPENDENT = {
    "infrastructure-cloud-encryption-posture",
    "network-tls-protocol-assessment",
    "certificate-estate-register",
    "data-at-rest-encryption-assessment",
    "pqc-migration-roadmap",
    "board-executive-report",
}


# ---------------------------------------------------------------------------------------------
# Readers
# ---------------------------------------------------------------------------------------------
def _read(relative: str, *, needs_frontend: bool = False, needs_engine: bool = False) -> str:
    """Text of a repo file.  A missing file FAILS (a rename is drift), except when the whole
    sibling tree is absent (a backend-only checkout), where the cross-tree pin is skipped."""
    path = _REPO_ROOT / relative
    if not path.is_file():
        if needs_frontend and not (_REPO_ROOT / "frontend").is_dir():
            pytest.skip("frontend/ is not part of this checkout")
        if needs_engine and not (_REPO_ROOT / "aibom" / "src").is_dir():
            pytest.skip("aibom/src is not part of this checkout")
        pytest.fail(f"{relative} does not exist: the contract it pins has moved")
    return path.read_text(encoding="utf-8")


def _fixture() -> dict:
    return json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))


def _registry() -> dict:
    return json.loads((FIXTURES / "cbom_scanner_registry.json").read_text(encoding="utf-8"))


def _scan_blobs() -> list[dict]:
    return [s["scan_data"] for s in _fixture()["scans"] if isinstance(s.get("scan_data"), dict)]


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _fold_team_one():
    data = _fixture()
    scans = [s for s in data["scans"] if s["team_id"] == 1 and s["scan_type"] == "cbom"]
    heads = [
        ScanHead(
            id=s["id"],
            team_id=s["team_id"],
            scan_type=s["scan_type"],
            title=s["title"],
            status=s["status"],
            created_at=_ts(s["created_at"]),
            last_updated=_ts(s["last_updated"]),
            scan_metadata=s["scan_metadata"],
        )
        for s in scans
    ]
    blobs = {s["id"]: s["scan_data"] for s in scans}
    return fold_scans(
        heads,
        lambda ids: {i: blobs[i] for i in ids if i in blobs},
        team_id=1,
        team_name=data["team"]["name"],
        now=NOW,
    )


# ---------------------------------------------------------------------------------------------
# Registry integrity (what T-CON-1 / T-CON-7 compare everything else against)
# ---------------------------------------------------------------------------------------------
def test_registry_lists_the_six_documents_in_menu_order():
    assert [(s.slug, s.number, s.title) for s in DELIVERABLES.values()] == EXPECTED
    assert list(DELIVERABLES) == [slug for slug, _n, _t in EXPECTED]
    assert all(isinstance(spec, DeliverableSpec) for spec in DELIVERABLES.values())


def test_registry_keys_are_the_slugs_and_slugs_are_url_safe():
    for key, spec in DELIVERABLES.items():
        assert key == spec.slug
        assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", key), key
    assert len({s.number for s in DELIVERABLES.values()}) == 9
    assert len({s.title for s in DELIVERABLES.values()}) == 9


@pytest.mark.parametrize("slug", [e[0] for e in EXPECTED])
def test_each_entry_wires_its_own_renderer(slug):
    module, number_attr = RENDERERS[slug]
    spec = DELIVERABLES[slug]
    assert spec.build is module.build_pdf
    assert spec.report_key == module.REPORT_KEY
    printed_number = getattr(module, number_attr)
    assert spec.number == printed_number, "registry number != the number the PDF prints"
    assert spec.data_dependent is (slug in DATA_DEPENDENT)


def test_only_the_data_dependent_documents_go_unavailable_without_scans():
    empty = HeadsSummary(scans_total=0, eligible=0, sources=0, failure=0, not_completed=0)
    manifest = build_manifest(1, NOW, empty)
    flags = {item["slug"]: (item["available"], item["reason"]) for item in manifest["deliverables"]}
    for slug in DELIVERABLES:
        if slug in DATA_DEPENDENT:
            assert flags[slug] == (False, REASON_NO_SCANS), slug
        else:
            assert flags[slug] == (True, None), slug
    assert REASON_NO_SCANS.strip() and "scan" in REASON_NO_SCANS.lower()


# ---------------------------------------------------------------------------------------------
# T-CON-1: frontend <-> registry
# ---------------------------------------------------------------------------------------------
_FE_API = "frontend/utils/backend_api.ts"
_FE_PAGE = "frontend/app/[team_id]/cbom/page.tsx"
_FE_ITEM = re.compile(
    r'\{\s*slug:\s*"(?P<slug>[^"]+)"\s*,\s*number:\s*(?P<number>\d+)\s*,'
    r'\s*title:\s*"(?P<title>[^"]+)"\s*\}'
)


def _fe_deliverables() -> list[tuple[str, int, str]]:
    ts = _read(_FE_API, needs_frontend=True)
    found = re.search(r"export const CBOM_DELIVERABLES = \[(.*?)\] as const;", ts, re.S)
    assert found, "CBOM_DELIVERABLES is no longer an exported const array"
    return [(m["slug"], int(m["number"]), m["title"]) for m in _FE_ITEM.finditer(found.group(1))]


def test_frontend_menu_equals_the_backend_registry():
    assert _fe_deliverables() == [
        (spec.slug, spec.number, spec.title) for spec in DELIVERABLES.values()
    ]


def test_frontend_download_name_matches_the_server_file_name():
    page = _read(_FE_PAGE, needs_frontend=True)
    assert "`cbom-${slug}-team${teamId}-${yyyymmdd}.pdf`" in page
    assert "toISOString().slice(0, 10)" in page, "the client date must stay the UTC date"
    for spec in DELIVERABLES.values():
        name = deliverable_filename(spec, 7, date(2026, 10, 19))
        assert name == f"cbom-{spec.slug}-team7-20261019.pdf"


def _strip_ts_comments(text: str) -> str:
    return re.sub(r"//[^\n]*", "", re.sub(r"/\*.*?\*/", "", text, flags=re.S))


def _ts_interface_fields(ts: str, name: str) -> tuple[set[str], set[str]]:
    """(all field names, optional field names) of ``export interface <name> { ... }``."""
    start = ts.index(f"export interface {name} {{")
    open_at = ts.index("{", start)
    depth, end = 0, open_at
    for end in range(open_at, len(ts)):
        depth += {"{": 1, "}": -1}.get(ts[end], 0)
        if depth == 0:
            break
    body = _strip_ts_comments(ts[open_at + 1 : end])
    fields = re.findall(r"\b([A-Za-z_]\w*)(\??)\s*:", body)
    return {n for n, _o in fields}, {n for n, o in fields if o}


def test_frontend_manifest_types_match_the_backend_manifest_shape():
    ts = _read(_FE_API, needs_frontend=True)
    summary = HeadsSummary(scans_total=3, eligible=2, sources=2, failure=1, not_completed=0)
    manifest = build_manifest(1, NOW, summary)

    top_fields, top_optional = _ts_interface_fields(ts, "CbomDeliverablesManifest")
    backend_top = {
        "team_id",
        "generated_at",
        "basis",
        "deliverables",
        *manifest["basis"],
        *manifest["basis"]["excluded"],
    }
    assert top_fields == backend_top
    assert top_optional == set()
    assert set(manifest) == {"team_id", "generated_at", "basis", "deliverables"}
    assert set(manifest["basis"]) == {"eligible", "included_hint", "sources", "excluded"}
    assert set(manifest["basis"]["excluded"]) == {"failure", "not_completed"}

    item_fields, item_optional = _ts_interface_fields(ts, "CbomDeliverableManifestItem")
    for item in manifest["deliverables"]:
        assert set(item) == item_fields
        assert item["format"] == "pdf"
    assert item_optional == {"reason"}, "only `reason` may be omitted by the backend contract"


# ---------------------------------------------------------------------------------------------
# T-CON-2: disclaimers mirror the existing product constants
# ---------------------------------------------------------------------------------------------
def test_disclaimers_equal_the_existing_product_constants():
    from backend.utilities.dashboard import rbi_posture
    from backend.utilities.pdf import certin_compliance_pdf

    assert authored.CERTIN_DISCLAIMER == certin_compliance_pdf._CERTIN_DISCLAIMER
    assert authored.RBI_BOM_DISCLAIMER == rbi_posture._ADVISORY_DISCLAIMER
    assert authored.DISCLAIMER_PARAGRAPHS[:2] == (
        certin_compliance_pdf._CERTIN_DISCLAIMER,
        rbi_posture._ADVISORY_DISCLAIMER,
    )
    scope = authored.SCOPE_OF_METHOD.lower()
    assert "static analysis" in scope and "live-network" in scope
    assert authored.METHOD_LIMITS[2] == (
        "Declared KMS and HSM settings in configuration are assessed. Live HSM firmware, "
        "custodianship, and escrow are not inspected."
    )
    assert authored.METHOD_LIMITS[3].startswith(
        "Data-at-rest encryption is assessed from declared configuration only"
    )
    assert authored.MANUAL_DISCOVERY_ITEMS[2] == (
        "Data-at-rest encryption",
        "Whether stored data is actually encrypted. Declared settings are assessed in "
        "document #9 and are not proof of operation.",
    )


def test_no_ai_bom_disclaimer_leaks_into_the_authored_text():
    """The persisted run-object carries the AIBOM/FDA/HIPAA disclaimer (plan F-05); it must
    never be the text a CBOM document prints."""
    printed = " ".join(authored.DISCLAIMER_PARAGRAPHS)
    for banned in ("FDA", "HIPAA", "AI BOM", "AIBOM disclaimer", "clinithread"):
        assert banned not in printed, banned
    for blob in _scan_blobs():
        compliance = blob.get("cbom_compliance")
        if isinstance(compliance, dict) and isinstance(compliance.get("disclaimer"), str):
            assert compliance["disclaimer"] not in printed


# ---------------------------------------------------------------------------------------------
# T-CON-3: framework labels
# ---------------------------------------------------------------------------------------------
def _fe_framework_labels() -> dict[str, str]:
    ts = _read("frontend/components/compliance/frameworkLabels.ts", needs_frontend=True)
    block = ts.split("FRAMEWORK_LABELS", 1)[1].split("};", 1)[0]
    return dict(re.findall(r'^\s+(\w+):\s*"([^"]+)",', block, re.M))


def test_framework_labels_cover_every_fixture_framework_and_equal_the_frontend():
    in_fixture: set[str] = set()
    for blob in _scan_blobs():
        compliance = blob.get("cbom_compliance")
        if isinstance(compliance, dict):
            in_fixture |= {k for k in compliance if k != "disclaimer"}
    registry = _registry()["frameworks"]
    assert len(registry) == 13
    assert in_fixture == set(registry)
    assert set(authored.FRAMEWORK_LABELS) == set(registry)
    frontend = _fe_framework_labels()
    for key in registry:
        assert authored.FRAMEWORK_LABELS[key] == frontend[key], key


def test_pooled_frameworks_of_a_real_view_come_in_engine_order():
    view = _fold_team_one()
    assert [pool.framework for pool in view.frameworks] == _registry()["frameworks"]
    assert all(authored.framework_label(pool.framework) for pool in view.frameworks)


# ---------------------------------------------------------------------------------------------
# T-CON-4: finding codes
# ---------------------------------------------------------------------------------------------
def _fixture_finding_codes() -> set[str]:
    codes: set[str] = set()
    blobs = [*_scan_blobs()]
    legacy = FIXTURES / "cbom_export_scandata.json"
    blobs.append(json.loads(legacy.read_text(encoding="utf-8")))
    for blob in blobs:
        for row in blob.get("results") or []:
            if isinstance(row, dict):
                codes |= {c for c in row.get("finding_codes") or [] if isinstance(c, str)}
        distributions = blob.get("cbom_distributions") or {}
        codes |= set((distributions.get("weakness") or {}).keys())
        for step in (distributions.get("pqc") or {}).get("migration") or []:
            codes |= {c for c in step.get("finding_codes") or [] if isinstance(c, str)}
    return codes


def test_every_finding_code_in_the_fixtures_has_a_label_and_a_specific_action():
    codes = _fixture_finding_codes()
    assert {"QUANTUM_VULNERABLE", "WEAK_ALGORITHM", "EXPIRED_CERTIFICATE"} <= codes
    for code in sorted(codes):
        assert code in authored.FINDING_LABELS, code
        assert authored.finding_label(code) != code, code
        assert code in authored.FINDING_ACTIONS, code
        assert authored.finding_action(code) != authored.GENERIC_FINDING_ACTION, code


def test_every_code_the_engine_can_raise_is_labelled():
    """Codes are read from the engine source text, not from a fixture, so a NEW engine code
    cannot reach a document as a bare constant."""
    raised: set[str] = set()
    for relative in ("aibom/src/aibom/cbom/weakness.py", "aibom/src/aibom/cbom/pqc.py"):
        # The engine declares each code as ``NAME = "NAME"`` (the back-reference keeps this exact).
        source = _read(relative, needs_engine=True)
        raised |= set(re.findall(r'^([A-Z][A-Z_]+) = "\1"\s*$', source, re.M))
    assert {"WEAK_ALGORITHM", "QUANTUM_VULNERABLE", "EXPIRED_CERTIFICATE"} <= raised
    assert len(raised) >= 16
    missing = sorted(code for code in raised if code not in authored.FINDING_LABELS)
    assert missing == [], f"engine raises codes the documents cannot label: {missing}"
    unactioned = sorted(code for code in raised if code not in authored.FINDING_ACTIONS)
    assert unactioned == [], f"engine raises codes with no recommended action: {unactioned}"


# ---------------------------------------------------------------------------------------------
# T-CON-5: post-quantum timeline sentences
# ---------------------------------------------------------------------------------------------
def test_timeline_strings_occur_verbatim_in_every_fixture_migration_row():
    descriptions = [
        step["description"]
        for blob in _scan_blobs()
        for step in ((blob.get("cbom_distributions") or {}).get("pqc") or {}).get("migration") or []
    ]
    assert descriptions, "the fixture must carry post-quantum migration rows"
    for description in descriptions:
        assert authored.CNSA_2_0_SENTENCE in description
        assert authored.PINNED_ENGINE_NIST_TIMELINE in description
    pinned = _registry()["pqc_timeline"]
    assert pinned == {
        "cnsa": authored.CNSA_2_0_SENTENCE,
        "nist": authored.PINNED_ENGINE_NIST_TIMELINE,
    }


def test_timeline_strings_equal_the_engine_source_text():
    source = _read("aibom/src/aibom/cbom/pqc.py", needs_engine=True)

    def literal(name: str) -> str:
        found = re.search(rf"^{name}\s*=\s*\(\s*((?:\"[^\"\n]*\"\s*)+)\)", source, re.M)
        assert found, f"{name} is no longer a parenthesised string literal in pqc.py"
        return "".join(re.findall(r'"([^"\n]*)"', found.group(1)))

    assert literal("_TIMELINE") == authored.PINNED_ENGINE_NIST_TIMELINE
    assert literal("_CNSA_TIMELINE") == authored.CNSA_2_0_SENTENCE


def test_the_printed_timeline_carries_the_cnsa_sentence_and_the_draft_qualified_nist_rows():
    printed = " ".join(row.milestone for row in authored.PQC_TIMELINE_ROWS)
    assert authored.CNSA_2_0_SENTENCE in printed
    assert authored.PINNED_ENGINE_NIST_TIMELINE not in printed, "over-simplified engine wording"
    nist_rows = [row for row in authored.PQC_TIMELINE_ROWS if "8547" in row.source]
    assert nist_rows and all(row.status == "Draft" for row in nist_rows)


# ---------------------------------------------------------------------------------------------
# T-CON-6: scanner table
# ---------------------------------------------------------------------------------------------
def test_authored_scanner_list_equals_the_registry_fixture():
    registry = _registry()
    assert [(s.name, s.order) for s in authored.CBOM_SCANNERS] == [
        (s["name"], s["order"]) for s in registry["scanners"]
    ]
    assert len(authored.CBOM_SCANNERS) == 16
    described = (s.discovers for s in authored.CBOM_SCANNERS)
    printed = " ".join([authored.CBOM_SCANNER_INTRO, *described])
    unwired_names = (
        *registry["unregistered_scanner_modules"],
        "jvm_go",
        "native_crypto",
        "web_native",
    )
    for unwired in unwired_names:
        assert unwired not in printed.lower()


def test_scanner_registry_fixture_equals_the_engine_source():
    scanners = _read("aibom/src/aibom/cbom/scanners/__init__.py", needs_engine=True)
    wired = re.search(r"from aibom\.cbom\.scanners import \((.*?)\)", scanners, re.S)
    assert wired, "scanners/__init__.py no longer imports its modules in one block"
    modules = re.findall(r"^\s+(\w+),", wired.group(1), re.M)
    assert len(modules) == 16
    found: list[tuple[str, int]] = []
    for module in modules:
        text = _read(f"aibom/src/aibom/cbom/scanners/{module}.py", needs_engine=True)
        name = re.findall(r'^\s+name = "([a-z_]+)"\s*$', text, re.M)
        order = re.findall(r"^\s+order = (\d+)\b", text, re.M)
        assert len(name) == 1 and len(order) == 1, module
        found.append((name[0], int(order[0])))
    registry = _registry()
    assert sorted(found, key=lambda pair: pair[1]) == [
        (s["name"], s["order"]) for s in registry["scanners"]
    ]
    on_disk = {p.stem for p in (_REPO_ROOT / "aibom/src/aibom/cbom/scanners").glob("*_scan.py")}
    assert on_disk - set(modules) == set(registry["unregistered_scanner_modules"])


# ---------------------------------------------------------------------------------------------
# T-CON-7: page chrome
# ---------------------------------------------------------------------------------------------
_META_FIELDS = {"title", "subtitle", "footer_label", "kicker", "intro", "how_to_read"}


def test_all_six_report_meta_keys_exist_and_belong_to_the_registry():
    keys = [spec.report_key for spec in DELIVERABLES.values()]
    assert keys == [
        "cbom_scope_register",
        "cbom_methodology",
        "cbom_infra_posture",
        "cbom_network_tls",
        "cbom_cert_register",
        "cbom_data_at_rest",
        "cbom_assurance_register",
        "cbom_pqc_roadmap",
        "cbom_board_report",
    ]
    assert len(set(keys)) == 9
    labels = []
    for spec in DELIVERABLES.values():
        meta = REPORT_META[spec.report_key]
        assert set(meta) >= _META_FIELDS, spec.slug
        assert all(str(meta[f]).strip() for f in _META_FIELDS), spec.slug
        assert spec.title == meta["title"]
        assert spec.description == meta["intro"]
        labels.append(meta["footer_label"])
    assert len(set(labels)) == 9, "every document must print its own footer label"
    assert "SAST" not in " ".join(labels)


# ---------------------------------------------------------------------------------------------
# Manifest builder (pure): summarize_heads / build_manifest
# ---------------------------------------------------------------------------------------------
def _head(scan_id, *, status="success", team_id=1, scan_type="cbom", title="t", meta=None):
    return ScanHead(
        id=scan_id,
        team_id=team_id,
        scan_type=scan_type,
        title=title,
        status=status,
        created_at=NOW,
        last_updated=NOW,
        scan_metadata=meta,
    )


def _repo(url, branch="main"):
    return {"repo_url": url, "branch": branch, "zip_file_used": False, "cbom_file_used": False}


def test_summarize_heads_counts_by_status_and_sources_by_identity():
    heads = [
        _head(1, meta=_repo("https://github.com/Acme/pay.git")),
        _head(2, meta=_repo("https://user:secret@github.com/acme/pay/")),  # same source as #1
        _head(3, meta=_repo("https://github.com/acme/pay", branch="release")),  # other branch
        _head(4, title="Lab", meta={"zip_file_used": True}),
        _head(5, title="LAB", meta={"zip_file_used": True}),  # same zip title, slugged
        _head(6, title="up.json", meta={"cbom_file_used": True}),
        _head(7, meta=None, title="orphan"),  # no metadata: its own source (scan:7)
        _head(8, status="failure", meta=_repo("https://github.com/acme/never-succeeded")),
        _head(9, status="started"),
        _head(10, status="retry"),
        _head(11, status="pending"),
        _head(12, status="NOT_STARTED"),
        _head(13, status="something-new"),
        _head(14, status=" SUCCESS ", meta=_repo("https://github.com/acme/pay")),  # folded status
    ]
    summary = summarize_heads(heads, team_id=1)
    # sources: pay@main (heads 1, 2, 14), pay@release, zip "lab" (heads 4, 5), the uploaded file
    # and the metadata-less scan #7; the failed scan's repository is not a source (never succeeded)
    assert summary == HeadsSummary(
        scans_total=14, eligible=8, sources=5, failure=1, not_completed=5
    )


def test_summarize_heads_ignores_other_teams_other_types_and_repeated_ids():
    heads = [
        _head(1),
        _head(1),  # the same scan id twice
        _head(2, team_id=2),
        _head(3, scan_type="sbom_sca"),
        _head(4, scan_type=" CBOM "),
    ]
    assert summarize_heads(heads, team_id=1) == HeadsSummary(
        scans_total=2, eligible=2, sources=2, failure=0, not_completed=0
    )
    assert summarize_heads([], team_id=1) == HeadsSummary(0, 0, 0, 0, 0)


def test_summarize_heads_survives_sparse_and_odd_objects():
    odd = [
        types.SimpleNamespace(id=1, team_id=1, scan_type="cbom", status="success"),
        types.SimpleNamespace(id=2, team_id=1, scan_type="cbom", status=None, title=None),
        types.SimpleNamespace(id=None, team_id=1, scan_type="cbom", status="success",
                              title=5, scan_metadata="not-a-mapping"),
        types.SimpleNamespace(),  # not a head at all: belongs to no team
    ]  # fmt: skip
    summary = summarize_heads(odd, team_id=1)
    assert (summary.scans_total, summary.eligible, summary.not_completed) == (3, 2, 1)


def test_build_manifest_formats_the_time_in_utc_and_carries_no_urls():
    summary = HeadsSummary(scans_total=1, eligible=1, sources=1, failure=0, not_completed=0)
    ist = timezone(timedelta(hours=5, minutes=30))
    assert build_manifest(1, datetime(2026, 10, 19, 17, 58, 7, tzinfo=ist), summary)[
        "generated_at"
    ] == "2026-10-19T12:28:07Z"
    assert build_manifest(1, datetime(2026, 10, 19, 12, 28), summary)["generated_at"] == (
        "2026-10-19T12:28:00Z"
    )
    assert "http" not in json.dumps(build_manifest(1, NOW, summary))


def test_a_manifest_row_is_exactly_the_registry_row():
    summary = HeadsSummary(scans_total=1, eligible=1, sources=1, failure=0, not_completed=0)
    rows = build_manifest(1, NOW, summary)["deliverables"]
    assert [r["slug"] for r in rows] == list(DELIVERABLES)
    for row, spec in zip(rows, DELIVERABLES.values(), strict=True):
        assert row == {
            "slug": spec.slug,
            "number": spec.number,
            "title": spec.title,
            "description": spec.description,
            "format": "pdf",
            "available": True,
            "reason": None,
        }
