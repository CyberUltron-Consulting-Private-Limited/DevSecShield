"""Business mapping uses the versioned file and CODEOWNERS separately."""

import json

from aibom.cbom.posture.business import load_mapping, matched_linkage, owner_hint
from aibom.cbom.posture.limits import GlobBudget


def test_unknown_key_is_a_note_and_known_fields_remain() -> None:
    text = (
        "version: 1\n"
        "entries:\n"
        "- system: payments\n"
        "  owner: app\n"
        "  ticket: ABC\n"
    )
    loaded = load_mapping(text, "cbom-mapping.yaml")
    link = matched_linkage(loaded, "bucket", "main.tf", "object_store", GlobBudget())
    assert link is not None
    assert link.system == "payments"
    assert link.owner == "app"
    assert link.source == "mapping_file"
    assert loaded.notes[0].code == "mapping_unknown_key"


def test_a_scalar_document_is_invalid() -> None:
    loaded = load_mapping("payments\n", "cbom-mapping.yaml")
    assert loaded.entries == ()
    assert loaded.notes[0].code == "mapping_entry_invalid"


def test_a_version_other_than_one_ignores_the_file() -> None:
    loaded = load_mapping("version: 2\ndefaults:\n  system: billing\n", "map.yaml")
    assert loaded.entries == ()
    assert loaded.defaults == {}
    assert loaded.notes[-1].code == "mapping_file_ignored"


def test_later_entry_overrides_one_field() -> None:
    text = (
        "version: 1\n"
        "defaults:\n"
        "  system: billing\n"
        "  owner: platform\n"
        "entries:\n"
        "- match:\n"
        "    path: apps/pay/*\n"
        "  owner: payments\n"
    )
    loaded = load_mapping(text, "cbom-mapping.yaml")
    budget = GlobBudget()
    pay = matched_linkage(loaded, "bucket", "apps/pay/main.tf", "object_store", budget)
    other = matched_linkage(loaded, "bucket", "apps/hr/main.tf", "object_store", budget)
    assert pay is not None and other is not None
    assert pay.owner == "payments"
    assert pay.system == "billing"
    assert other.owner == "platform"


def test_every_selector_must_match() -> None:
    text = (
        "version: 1\n"
        "entries:\n"
        "- match:\n"
        "    kind: object_store\n"
        "    path: main.tf\n"
        "  system: billing\n"
    )
    loaded = load_mapping(text, "cbom-mapping.yaml")
    missed = matched_linkage(loaded, "bucket", "main.tf", "relational_db", GlobBudget())
    hit = matched_linkage(loaded, "bucket", "main.tf", "object_store", GlobBudget())
    assert missed is None
    assert hit is not None and hit.system == "billing"


def test_control_characters_are_removed_and_text_is_cut() -> None:
    raw = "A\x00" + ("B" * 300)
    text = "version: 1\ndefaults:\n  system: " + json.dumps(raw) + "\n"
    loaded = load_mapping(text, "cbom-mapping.yaml")
    assert loaded.defaults["system"] == "A" + ("B" * 255)


def test_entries_past_the_limit_are_counted_and_not_invalid() -> None:
    document = {"version": 1, "entries": [{"system": "a"} for _ in range(10_001)]}
    loaded = load_mapping(json.dumps(document), "cbom-mapping.json")
    assert len(loaded.entries) == 10_000
    assert loaded.dropped == 1
    assert all(note.code != "mapping_entry_invalid" for note in loaded.notes)


def test_github_codeowners_wins_over_the_root_file(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    github = tmp_path / ".github"
    github.mkdir()
    (github / "CODEOWNERS").write_text("* @github\n", encoding="utf-8")
    (tmp_path / "CODEOWNERS").write_text("* @root\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n',
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    bucket = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == "aws_s3_bucket"
    )
    link = json.loads(str((bucket.properties or {})["crypto:factLinkage"]))
    assert link["owner_hint"] == "@github"
    assert link["source"] == "codeowners"
    assert link["owner"] == ""


def test_codeowners_last_match_wins() -> None:
    text = "* @platform\napps/pay/ @payments\n"
    assert owner_hint(text, "apps/pay/main.tf") == "@payments"


def test_mapping_file_does_not_replace_the_codeowners_hint(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    nested = tmp_path / ".devsecshield"
    nested.mkdir()
    (nested / "cbom-mapping.yaml").write_text(
        "version: 1\ndefaults:\n  system: billing\n  owner: declared-owner\n",
        encoding="utf-8",
    )
    (tmp_path / "cbom-mapping.yaml").write_text(
        "version: 1\ndefaults:\n  system: other\n",
        encoding="utf-8",
    )
    (tmp_path / "CODEOWNERS").write_text("* @platform\n", encoding="utf-8")
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n',
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    bucket = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == "aws_s3_bucket"
    )
    link = json.loads(str((bucket.properties or {})["crypto:factLinkage"]))
    assert link["system"] == "billing"
    assert link["owner"] == "declared-owner"
    assert link["owner_hint"] == "@platform"
    assert link["source"] == "mapping_file"
    codes = {item.code for item in result.posture.diagnostics}
    assert "mapping_file_ignored" in codes
