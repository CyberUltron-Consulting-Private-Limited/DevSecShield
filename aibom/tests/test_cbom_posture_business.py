"""Business mapping rejects unknown keys and still reads CODEOWNERS."""

from aibom.cbom.posture.business import load_mapping, owner_hint


def test_unknown_key_is_a_note_and_known_fields_remain() -> None:
    text = "- system: payments\n  owner: app\n  ticket: ABC\n"
    loaded = load_mapping(text, "mapping.yaml")
    assert loaded.links[0].system == "payments"
    assert loaded.links[0].owner == "app"
    assert loaded.notes[0].code == "mapping_unknown_key"


def test_a_scalar_document_is_invalid() -> None:
    loaded = load_mapping("payments\n", "mapping.yaml")
    assert loaded.links == ()
    assert loaded.notes[0].code == "mapping_entry_invalid"


def test_codeowners_last_match_wins() -> None:
    text = "* @platform\napps/pay/ @payments\n"
    assert owner_hint(text, "apps/pay/main.tf") == "@payments"
