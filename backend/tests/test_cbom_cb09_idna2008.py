"""CB-09: internationalised host names follow IDNA 2008 (UTS #46, non-transitional) everywhere in the backend.

Python's ``"idna"`` codec is IDNA 2003: it turned ``faß.de`` into ``fass.de`` (a different, separately registered
name) and silently dropped a zero-width joiner, so the product scanned a host the customer never named (KF-7, R5 X6).

* Targets, never-scan entries, SNI names and certificate domains (all through ``targets.parse_line``) are stored as
  the IDNA 2008 A-label: ``faß.de`` is ``xn--fa-hia.de``.
* Names IDNA 2003 and 2008 read differently are refused (a zero-width joiner or non-joiner; a character IDNA 2008
  disallows) or, for the deviation letters ``ß`` and ``ς``, accepted in the 2008 form with a note the customer sees
  before saving (``/targets/count``), naming the name older software would reach instead.
* Never-scan fails closed across the two forms: a listed ``faß.lab`` also keeps ``fass.lab`` out, and a listed
  ``fass.lab`` keeps ``faß.lab`` out.
* The A-label is stored; ``idn.to_u_label`` gives the form to show (a ``.भारत`` name round-trips).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _path in (str(_REPO_ROOT), str(_REPO_ROOT / "scan_node")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from backend.utilities.cbom_sources import targets as T  # noqa: E402


def test_faß_is_stored_as_its_idna_2008_a_label():
    assert T.parse_line("faß.de") == ("host", "xn--fa-hia.de", "xn--fa-hia.de")
    assert T.parse_line("Faß.DE.") == ("host", "xn--fa-hia.de", "xn--fa-hia.de")
    assert T.parse_targets(["faß.lab", "fass.lab"]).hostnames == ["xn--fa-hia.lab", "fass.lab"]  # two names, not one


def test_greek_final_sigma_keeps_its_own_a_label():
    import idna

    name = T.parse_line("ςa.example")[1]
    assert name == idna.encode("ςa.example", uts46=True, transitional=False).decode()
    assert name != "ςa.example".encode("idna").decode()  # IDNA 2003 folds ς into σ


@pytest.mark.parametrize("raw", ["a‍b.example", "a‌b.example", "‍shop.lab"])
def test_a_name_with_a_zero_width_joiner_or_non_joiner_is_refused(raw):
    with pytest.raises(T.TargetError, match="zero-width"):
        T.parse_line(raw)
    with pytest.raises(T.TargetError, match="Line 1: .*zero-width"):
        T.parse_targets([raw])
    with pytest.raises(T.TargetError, match="Never-scan line 1: .*zero-width"):
        T.parse_exclusions([raw])


def test_a_character_idna_2008_disallows_is_refused():
    assert "☃.net".encode("idna") == b"xn--n3h.net"  # IDNA 2003 took it
    with pytest.raises(T.TargetError, match="IDNA 2008"):
        T.parse_line("☃.net")


def test_an_a_label_that_is_not_valid_punycode_is_refused():
    with pytest.raises(T.TargetError, match="punycode"):
        T.parse_line("xn--a.example")


def test_ascii_names_are_unchanged():
    assert T.parse_line("Shop.Example.COM.") == ("host", "shop.example.com", "shop.example.com")
    assert T.parse_line("_dmarc.example.com")[1] == "_dmarc.example.com"  # an underscore label stays allowed
    assert T.parse_line("xn--bcher-kva.example")[1] == "xn--bcher-kva.example"


def test_never_scan_compares_a_labels():
    excl = T.parse_exclusions(["bücher.example"])
    assert excl.hostnames == ["xn--bcher-kva.example"]
    targets = T.parse_targets(["xn--bcher-kva.example", "other.example"])
    assert T.in_scope(targets, excl)[1] == ["other.example"]


def test_never_scan_of_a_deviation_name_also_keeps_its_idna_2003_form_out():
    targets = T.parse_targets(["fass.lab", "other.lab"])
    assert T.in_scope(targets, T.parse_exclusions(["faß.lab"]))[1] == ["other.lab"]
    targets = T.parse_targets(["faß.lab", "other.lab"])
    assert T.in_scope(targets, T.parse_exclusions(["fass.lab"]))[1] == ["other.lab"]
    assert T.count_in_scope(targets, T.parse_exclusions(["fass.lab"])) == 1


def test_a_deviation_name_is_scanned_as_the_2008_name_with_a_note_naming_the_2003_one():
    parsed = T.parse_targets(["faß.lab", "bücher.lab", "plain.lab"])
    assert parsed.hostnames == ["xn--fa-hia.lab", "xn--bcher-kva.lab", "plain.lab"]
    assert len(parsed.notes) == 1
    note = parsed.notes[0]
    assert "faß.lab" in note and "xn--fa-hia.lab" in note and "fass.lab" in note and "IDNA 2008" in note


def test_the_target_count_shows_the_note_before_saving():
    from backend.routers.cbom_sources import _count_targets

    out = _count_targets({"targets": ["faß.lab"], "exclusions": ["ςa.lab"]})
    assert out["valid"] is True and out["count"] == 1
    assert len(out["notes"]) == 2 and "xn--fa-hia.lab" in out["notes"][0] and "Never-scan" in out["notes"][1]
    assert _count_targets({"targets": ["plain.lab"]})["notes"] == []


def test_the_stored_a_label_is_shown_as_its_u_label_and_round_trips():
    from backend.utilities.cbom_sources import idn

    a_label = T.parse_line("टेस्ट.भारत")[1]
    assert a_label == "xn--c2ba8etc5a.xn--h2brj9c"
    assert idn.to_u_label(a_label) == "टेस्ट.भारत"
    assert T.parse_line(idn.to_u_label(a_label))[1] == a_label
    assert idn.to_u_label("plain.example") == "plain.example"
    assert idn.to_u_label("xn--a.example") == "xn--a.example"  # not decodable: shown as stored


def test_sni_names_and_certificate_domains_use_the_same_rule():
    from fastapi import HTTPException

    from backend.routers.cbom_sources import _norm_hostnames

    assert _norm_hostnames(["faß.lab", "FASS.lab"], "sni_hostnames") == ["xn--fa-hia.lab", "fass.lab"]
    with pytest.raises(HTTPException, match="zero-width"):
        _norm_hostnames(["a‍b.lab"], "cert_domains")


# Names, as typed, and what both sides must make of them (None: refused).
AGREEMENT = ["faß.de", "Faß.DE.", "bücher.example", "ςa.example", "टेस्ट.भारत", "a‍b.example", "☃.net",
             "xn--a.example", "xn--bcher-kva.example", "shop.example.com", "_dmarc.example.com"]


def test_the_scan_node_reads_every_name_as_the_backend_stores_it():
    from backend.utilities.cbom_sources import idn as backend_idn
    from zs_scan_node import idn as node_idn

    for raw in AGREEMENT:
        try:
            want = backend_idn.to_a_label(raw.strip().rstrip("."))
        except backend_idn.IdnError:
            want = None
        try:
            got = node_idn.to_a_label(raw.strip().rstrip("."))
        except node_idn.IdnError:
            got = None
        assert got == want, raw
        if want is not None:
            assert node_idn.idna2003_form(want) == backend_idn.idna2003_form(want), raw
