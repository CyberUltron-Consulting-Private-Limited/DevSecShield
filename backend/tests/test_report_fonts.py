"""Non-Latin names and titles in PDF reports (report_fonts.py, report_options.TEXT_RANGES).

* The text rule: Windows-1252 as before, plus Latin Extended, Greek, Cyrillic and Devanagari; the same cases as the
  browser's mirror (frontend/utils/reportOptions.test.ts).
* Every code point the rule lets through has a glyph in the font it is drawn with; Windows-1252 text never loads a
  Noto font (the bytes of those reports are unchanged).
* The PDFs: a Devanagari title and a Cyrillic "Prepared for" on a scan report, a Devanagari name in a deliverable's
  masthead and control table, a Greek title on a run report, a word that switches script; each extracted with
  pdftotext (poppler, as CI installs it) exactly as typed, the conjuncts included. A by-hand visual check of the same
  output (rendered with pdftoppm and looked at) is described in the PR; these pins keep what it showed.
* Concurrency and determinism: shaped glyphs are numbered when the fonts are registered, so the same text gives the
  same bytes in any order and from parallel threads.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import re
import sys
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS / "fixtures"))

import test_pdf_export_smoke as smoke  # noqa: E402

from backend.utilities.pdf import report_fonts as RF  # noqa: E402
from backend.utilities.pdf.combined import generate_pdf_for_type, prepare_pdf_export_payload  # noqa: E402
from backend.utilities.pdf.report_context import ReportContext  # noqa: E402
from backend.utilities.pdf.report_options import (  # noqa: E402
    TEXT_RANGES,
    ReportOptionsError,
    is_cp1252,
    parse_report_options,
)

SCRIPTS = "can only use Latin, Greek, Cyrillic or Devanagari characters"
_REPO = _TESTS.parents[1]
# A child interpreter imports ``backend`` from the repository root, whatever PYTHONPATH the run has (CI's is empty).
_CHILD_ENV = {**os.environ, "PYTHONPATH": str(_REPO)}
needs_poppler = pytest.mark.skipif(shutil.which("pdftotext") is None, reason="pdftotext (poppler-utils) not installed")

HINDI = "प्रबंधन क्षेत्र"  # conjuncts प्र and क्ष, a reordered e-matra, an anusvara
MARATHI = "महाराष्ट्र राज्य सहकारी बँक"  # ष्ट्र (half + below-base ra), ज्य, chandrabindu
CYRILLIC = "ПАО Сбербанк России"
GREEK = "Ελληνική Τράπεζα"


def pdftotext(raw: bytes, tmp_path: Path, first: int = 1, last: int = 1) -> str:
    src = tmp_path / "extract.pdf"
    src.write_bytes(raw)
    out = subprocess.run(["pdftotext", "-f", str(first), "-l", str(last), "-enc", "UTF-8", str(src), "-"],
                         capture_output=True, check=True, timeout=60)
    return " ".join(out.stdout.decode("utf-8").split())


def scan_pdf(tmp_path: Path, name: str, **options: str) -> bytes:
    opts = parse_report_options(options, "scan", scan_type="sast")
    out = tmp_path / f"{name}.pdf"
    generate_pdf_for_type("sast", prepare_pdf_export_payload("sast", smoke._typical_payload("sast")), str(out),
                          ctx=ReportContext(options=opts))
    return out.read_bytes()


# ----------------------------------------------------------------------------- the text rule
@pytest.mark.parametrize("text", [
    "Łódź Bank", "Tiếng Việt", GREEK, "ПАО Сбербанк", "Қазақстан", HINDI, "Acme बैंक", MARATHI, "मऱ्याद",
    "₹ 500 crore", "x̃", "र्‍य", "क्‌ष", "Société Générale – Zürich",
])
def test_these_scripts_are_accepted(text):
    options = parse_report_options({"prepared_for": text, "title": text}, "scan", scan_type="sast")
    assert options.prepared_for == text and options.title == text


@pytest.mark.parametrize("text, message", [
    ("東京銀行", SCRIPTS),  # CJK: no font for it
    ("بنك", SCRIPTS),
    ("Acme 🏦", SCRIPTS),
    ("Ϣ", SCRIPTS),  # a Coptic letter in the Greek block: no glyph
    ("a​b", "must be one line of plain text"),  # zero-width space is still refused
    ("a⁠b", "must be one line of plain text"),  # word joiner (Cf) too: only ZWNJ and ZWJ are spelling
    ("two\nlines", "must be one line of plain text"),
])
def test_other_text_is_refused_with_the_browsers_words(text, message):
    with pytest.raises(ReportOptionsError) as err:
        parse_report_options({"prepared_for": text}, "deliverable")
    assert (err.value.field, err.value.message) == ("prepared_for", message)


def test_free_text_is_stripped_exactly_like_the_browser_strips_it():
    """STRIP_RANGES (mirrored in reportOptions.ts, which trims with it) is Python's str.strip() set, every isspace()."""
    from backend.utilities.pdf.report_options import STRIP_RANGES

    ranged = {c for low, high in STRIP_RANGES for c in range(low, high + 1)}
    assert ranged == {c for c in range(sys.maxunicode + 1) if chr(c).isspace()}
    assert 0xFEFF not in ranged
    assert parse_report_options({"prepared_for": "\u001cAcme\u0085\u001f"}, "deliverable").prepared_for == "Acme"
    assert parse_report_options({"prepared_for": "\u3000\u2028Acme\u00a0\u202f"}, "deliverable").prepared_for == "Acme"
    for text in ("\ufeffAcme", "Acme\ufeff"):  # a BOM is not whitespace: refused, in the browser too
        with pytest.raises(ReportOptionsError) as err:
            parse_report_options({"prepared_for": text}, "deliverable")
        assert err.value.message == "must be one line of plain text"


STRAY = "has a vowel sign or accent that follows no letter"


@pytest.mark.parametrize("text", ["ि", "िकल", "\u0900क", "\ua8e0क", "\ua8f1क", "\u0301abc", "Acme ि", "Acme (ं)",
                                  "5\u0303"])
def test_a_mark_that_follows_no_letter_is_refused(text):
    with pytest.raises(ReportOptionsError) as err:
        parse_report_options({"title": text}, "run")
    assert err.value.message == STRAY


@pytest.mark.parametrize("text", ["कि", "किं", "x\u0303", "Acme किं", "क\u093c\u093f", "e\u0301\u0302"])
def test_marks_after_letters_are_fine(text):
    assert parse_report_options({"title": text}, "run").title


def test_text_is_nfc_composed_before_it_is_checked_and_counted():
    assert parse_report_options({"title": "कि"}, "run").title == "कि"
    assert parse_report_options({"title": "é" * 140}, "run").title == "é" * 140


def test_every_allowed_code_point_has_a_glyph_in_the_font_that_draws_it():
    RF.ensure_registered()
    from reportlab.pdfbase import pdfmetrics

    fonts = {script: pdfmetrics.getFont(RF.FACES[(script, bold)]).face.charToGlyph
             for script in (RF.LATIN, RF.DEVANAGARI) for bold in (False, True)}
    missing = []
    for low, high in TEXT_RANGES:
        for code in range(low, high + 1):
            ((script, _chunk),) = RF.script_runs(chr(code))
            if code not in fonts[script]:
                missing.append(f"U+{code:04X} ({script})")
    assert missing == []
    for bold in (False, True):  # the bold faces cover the same code points
        regular = pdfmetrics.getFont(RF.FACES[(RF.LATIN, False)]).face.charToGlyph
        assert set(pdfmetrics.getFont(RF.FACES[(RF.LATIN, bold)]).face.charToGlyph) == set(regular)


def test_script_runs_change_font_only_where_the_letters_change_script():
    assert RF.script_runs("Acme बैंक (India) — ₹100") == [
        ("latin", "Acme "), ("devanagari", "बैंक ("), ("latin", "India) — ₹100")]
    assert RF.script_runs("(बैंक)") == [("devanagari", "(बैंक)")]  # punctuation both fonts draw follows the letters
    assert RF.script_runs("Acme-बैंक") == [("latin", "Acme-"), ("devanagari", "बैंक")]
    assert RF.script_runs("2026") == [("latin", "2026")]


def test_windows_1252_text_keeps_helvetica(tmp_path):
    assert not RF.needs_unicode_font("Société Générale – Zürich €")
    assert RF.needs_unicode_font(HINDI) and RF.needs_unicode_font("Łódź")
    assert not RF.needs_unicode_font("東京")  # refused before it gets here; never drawn with a font that lacks it
    raw = scan_pdf(tmp_path, "latin", prepared_for="Société Générale – Zürich", title="Q4 “final” review €")
    assert b"Noto" not in raw  # no TrueType font: the Windows-1252 cover is drawn as it always was


# ----------------------------------------------------------------------------- the PDFs
@needs_poppler
def test_scan_report_cover_in_devanagari_and_cyrillic(tmp_path):
    latin = scan_pdf(tmp_path, "latin", prepared_for="Acme Bank", title="Board pack")
    raw = scan_pdf(tmp_path, "deva", prepared_for=CYRILLIC, title=f"{MARATHI} — सुरक्षा पुनरावलोकन")
    text = pdftotext(raw, tmp_path)
    assert f"{MARATHI} — सुरक्षा पुनरावलोकन" in text  # conjuncts copy as typed (ToUnicode from glyph_text.json)
    assert f"Prepared for {CYRILLIC}" in text
    assert "�" not in text and not any("" <= ch <= "" for ch in text)  # no private-use leftovers
    for face in (b"NotoSans-Bold", b"NotoSansDevanagari-Bold"):
        assert face in raw
    assert b"NotoSansDevanagari-Regular" not in raw  # only the faces the cover uses are embedded
    # subsets only: a few dozen glyphs, not the 600 KB of font files
    assert len(raw) - len(latin) < 60_000, len(raw) - len(latin)


@needs_poppler
def test_a_word_that_switches_script_renders_and_extracts(tmp_path):
    raw = scan_pdf(tmp_path, "mixed", prepared_for="Acme-बैंक", title=f"{HINDI} / {GREEK}")
    text = pdftotext(raw, tmp_path)
    assert "Prepared for Acme-बैंक" in text
    assert f"{HINDI} / {GREEK}" in text


@needs_poppler
def test_markup_in_a_non_latin_name_prints_literally(tmp_path):
    name = '<font face="Courier">बैंक</font> & <b>x</b>'
    assert RF.unicode_markup(name).count("&lt;font") == 1 and "&amp;" in RF.unicode_markup(name)
    raw = scan_pdf(tmp_path, "markup", prepared_for=name)
    assert f"Prepared for {name}" in pdftotext(raw, tmp_path)  # the tags are text: no face was switched


@needs_poppler
def test_a_long_devanagari_title_wraps_inside_the_masthead(tmp_path):
    title = ("भारतीय स्टेट बैंक " * 9).strip()[:140]
    raw = scan_pdf(tmp_path, "long", title=title, prepared_for="म" * 120)
    assert title.split()[0] in pdftotext(raw, tmp_path)


@needs_poppler
def test_deliverable_masthead_and_control_table_in_devanagari(tmp_path):
    from backend.tests.test_cbom_deliverable_common import make_view
    from backend.utilities.pdf.cbom_deliverables import DELIVERABLES

    options = parse_report_options({"prepared_for": MARATHI, "label": "internal"}, "deliverable")
    ctx = ReportContext(options=options)
    spec = DELIVERABLES["scope-baseline-register"]
    raw = spec.build(make_view(), ctx=ctx)
    text = pdftotext(raw, tmp_path)
    assert f"Prepared for {MARATHI}" in text  # the masthead
    assert text.count(MARATHI) >= 2, text[:2000]  # and the control table's "Prepared for" cell, not "?"
    assert "????" not in text


@needs_poppler
def test_run_report_title_in_greek(tmp_path):
    import datetime as dt

    from backend.utilities.cbom_sources import inventory as INV
    from backend.utilities.cbom_sources import run_deliverables as RD
    from backend.utilities.pdf.cbom_run_pdf import build_run_pdf

    ctx = ReportContext(options=parse_report_options({"title": GREEK, "prepared_for": HINDI}, "run"))
    raw = build_run_pdf(run={"id": 9, "status": "done", "created_at": "2026-11-14T09:00:00Z",
                             "finished_at": "2026-11-14T09:30:00Z", "last_updated": "2026-11-14T09:30:00Z"},
                        sources=[{"name": "linux-dc"}],
                        posture={"assets": 0, "impacts": {}, "pqc_readiness_pct": 0.0, "pqc_classes": {},
                                 "exposure": {}, "mosca": {}, "top_risks": [], "compliance": []},
                        heatmap={"rows": [], "columns": [], "cells": [], "certificates": []},
                        head={"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                              "metadata": {"properties": []}},
                        findings=[], vex_states={}, provenance=[], at=dt.datetime(2026, 11, 14, 9, 30),
                        as_of_note=None, findings_cap=RD.PDF_FINDINGS_CAP, export_cap=INV.EXPORT_CAP,
                        cbom_sha256="ab" * 32, ctx=ctx)
    text = pdftotext(raw, tmp_path)
    assert GREEK in text and f"Prepared for {HINDI}" in text


# ----------------------------------------------------------------------------- determinism and threads
def test_the_same_text_gives_the_same_bytes_from_parallel_builds():
    from backend.tests.test_cbom_deliverable_common import make_view
    from backend.utilities.pdf.cbom_deliverables import DELIVERABLES

    spec = DELIVERABLES["scope-baseline-register"]
    view = make_view()
    names = [MARATHI, "Acme-बैंक", CYRILLIC, "कि लिमिटेड क्षत्रिय"]

    def build(name: str) -> bytes:
        return spec.build(view, ctx=ReportContext(options=parse_report_options({"prepared_for": name}, "deliverable")))

    sequential = [build(name) for name in names]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for _round in range(3):
            assert list(pool.map(build, names * 2)) == sequential * 2


def test_glyphs_are_numbered_at_registration_and_typed_order_codes_are_made_once():
    RF.ensure_registered()
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics

    font = pdfmetrics.getFont(RF.FACES[(RF.DEVANAGARI, True)])
    assert all(gid in font.face.glyphToChar for gid in range(font.face.numGlyphs))  # every glyph has a code up front
    style = ParagraphStyle("t", fontName="Helvetica", fontSize=9)
    RF.unicode_paragraph(MARATHI + " वार्षिक किं", style, bold=True).wrap(400, 100)
    before = dict(font.face.charToGlyph)
    RF.unicode_paragraph(MARATHI + " वार्षिक किं", style, bold=True).wrap(400, 100)
    assert dict(font.face.charToGlyph) == before  # the same words again: no new code
    pre = {c: g for c, g in before.items() if c < RF._EXTRA_CODES}
    RF.unicode_paragraph("कार्तिक धार्मिक लिमिटेड", style, bold=True).wrap(400, 100)
    after = dict(font.face.charToGlyph)
    assert {c: g for c, g in after.items() if c < RF._EXTRA_CODES} == pre  # the fonts' own codes never change
    assert all(c >= RF._EXTRA_CODES for c in set(after) - set(before))  # new ones only in the supplementary PUA


@needs_poppler
def test_reph_with_i_matra_and_i_matra_before_its_consonant_copy_as_typed(tmp_path):
    """Review 6013762056: र्Xि was extracted as Xि without the reph (वािषक) or with U+E231; कि as िक."""
    title = "वार्षिक सुरक्षा रिपोर्ट"
    raw = scan_pdf(tmp_path, "reph", title=title, prepared_for="आर्थिक कार्तिक धार्मिक लिमिटेड")
    for engine, text in extracted(raw, tmp_path).items():
        flat = " ".join(text.split())
        assert title in flat and "Prepared for आर्थिक कार्तिक धार्मिक लिमिटेड" in flat, (engine, flat[:400])
        assert_clean(engine, text)
    assert not _private_use("".join(to_unicode_targets(raw)))


def _private_use(text: str) -> list[str]:
    return [f"U+{ord(ch):04X}" for ch in text if 0xE000 <= ord(ch) <= 0xF8FF or ord(ch) >= 0xF0000]


def to_unicode_targets(raw: bytes) -> list[str]:
    """Every destination string of every ToUnicode CMap in the PDF."""
    import re

    from backend.tests.support.pdf_text import content_streams

    out = []
    for stream in content_streams(raw):
        for block in re.findall(rb"beginbfchar(.*?)endbfchar", stream, re.S):
            out += [bytes.fromhex(dst.decode()).decode("utf-16-be")
                    for dst in re.findall(rb"<[0-9A-F]{2}> <([0-9A-F]*)>", block)]
    return out


def _sweep_words() -> list[str]:
    """NFC (as report options store them) Hindi and Marathi forms: every consonant (with nukta forms, ळ, ऱ) with every vowel sign, anusvara, candrabindu,
    visarga and virama, with a reph, with a below-base ra, between consonants, and every two-consonant conjunct bare,
    with ि and with े; plus real words with stacked or reordered parts."""
    consonants = [chr(c) for c in range(0x0915, 0x093A)] + ["क़", "ख़", "ग़", "ज़", "ड़", "ढ़", "फ़", "य़", "ळ", "ऱ"]
    signs = ["", "ा", "ि", "ी", "ु", "ू", "ृ", "ॅ", "े", "ै", "ॉ", "ो", "ौ", "ं", "ँ", "ः", "िं", "ीं", "ें", "ैं",
             "ों", "ुं", "ूँ", "्"]
    words = []
    for c in consonants:
        for m in signs:
            words += [c + m, "र्" + c + m, c + "्र" + m, "क" + c + m + "क"]
    for c1 in consonants:
        for c2 in consonants:
            words += [c1 + "्" + c2, c1 + "्" + c2 + "ि", c1 + "्" + c2 + "े"]
    vowels = [chr(c) for c in range(0x0905, 0x0915)] + ["ॲ", "ॠ"]
    words += vowels + [v + "ं" for v in vowels] + ["क" + v + "क" for v in vowels]
    words += ["भाई", "मुंबई", "ऐसा", "ईमेल", "नई", "कई", "ईश्वर", "ऐतिहासिक", "मुंबई भाई", "ई\u200dमेल", "भाई\u200d",
              "बड़ा", "लड़का", "पढ़ाई", "फ़ोन", "ज़रूरी", "य़", "ऴ"]
    return [unicodedata.normalize("NFC", w) for w in words] + ["वार्षिक", "आर्थिक", "कार्तिक", "धार्मिक", "लिमिटेड", "महाराष्ट्र", "मऱ्याद", "र्\u200dय", "क्\u200cष",
                    "ॲप", "श्री", "स्त्री", "त्र्य", "कृष्ण", "हृदय", "ज्ञान", "क्षत्रिय", "कीर्ति", "सिंह", "हिंदी", "किं"]


def extracted(raw: bytes, tmp_path: Path) -> dict[str, str]:
    """The PDF's text in each extractor installed here: poppler (pdftotext, as CI installs it), pypdf and PDFium (the
    engine of Chrome's viewer, through pypdfium2); CI installs pypdf and pypdfium2 as test-only packages (ci.yml)."""
    out: dict[str, str] = {}
    path = tmp_path / "extract-all.pdf"
    path.write_bytes(raw)
    if shutil.which("pdftotext"):
        out["poppler"] = subprocess.run(["pdftotext", "-enc", "UTF-8", str(path), "-"], capture_output=True,
                                        check=True, timeout=120).stdout.decode("utf-8")
    try:
        import pypdf
    except ImportError:
        pass
    else:
        out["pypdf"] = "\n".join(page.extract_text() for page in pypdf.PdfReader(str(path)).pages)
    try:
        import pypdfium2
    except ImportError:
        pass
    else:
        document = pypdfium2.PdfDocument(str(path))
        out["pdfium"] = "\n".join(document[i].get_textpage().get_text_range() for i in range(len(document)))
        document.close()
    return out


# U+200D on the extra glyph of ई/ऐ (drawn as two glyphs), after the syllable's marks; a joiner typed elsewhere stays
_SYLLABLE_ZWJ = re.compile("([\u0908\u0910][\u0900-\u0903\u093c\u0951-\u0954]*)\u200d")


def _pypdf_word(text: str) -> str:
    """pypdf reads ToUnicode only: a glyph past a syllable's characters (ई is drawn as two) copies as U+200D, and a
    letter the font draws as its canonical equivalent (क़, ऴ, ị) as that equivalent; compared up to both (see
    fonts/README.md). A joiner the user typed is kept, so losing one fails."""
    return unicodedata.normalize("NFC", _SYLLABLE_ZWJ.sub(r"\1", text))


def assert_clean(engine: str, text: str) -> None:
    """No control character (a raw byte copied for a glyph without text; a form feed between pages is fine) and no
    private-use code point."""
    stray = [f"U+{ord(ch):04X}" for ch in text if (ord(ch) < 0x20 and ch not in "\t\n\r\f") or _private_use(ch)]
    assert stray == [], (engine, stray[:10])


def _sweep_pdf(tmp_path: Path, words: list[str], bold: bool, per_paragraph: int) -> bytes:
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate

    style = ParagraphStyle("t", fontName="Helvetica", fontSize=9, leading=14)
    out = tmp_path / f"sweep-{int(bold)}-{per_paragraph}.pdf"
    SimpleDocTemplate(str(out)).build([RF.unicode_paragraph(" ".join(words[i:i + per_paragraph]), style, bold=bold)
                                       for i in range(0, len(words), per_paragraph)])
    return out.read_bytes()


@pytest.mark.parametrize("bold", [False, True], ids=["regular", "bold"])
def test_thousands_of_devanagari_forms_extract_exactly_in_every_engine(tmp_path, bold):
    """Running text (40 forms a paragraph): poppler and PDFium give back every form exactly as typed (/ActualText);
    pypdf up to canonical equivalence (a letter the font draws precomposed or decomposed, क़ or ऴ) and a U+200D after
    ई/ऐ (``_pypdf_word``).
    No engine sees a control character or a private-use code point; no ToUnicode entry is empty."""
    words = _sweep_words()
    assert len(words) > 10_000
    raw = _sweep_pdf(tmp_path, words, bold, 40)
    targets = to_unicode_targets(raw)
    assert len(targets) > 200 and "" not in targets and not _private_use("".join(targets))
    texts = extracted(raw, tmp_path)
    if not texts:
        pytest.skip("no PDF text extractor installed")
    for engine, text in texts.items():
        assert_clean(engine, text)
        got = text.split()  # exactly as typed (review 6014645102: NFC here hid 1,679 decomposed forms)
        expected = " ".join(words).split()
        if engine == "pypdf":
            got = [_pypdf_word(w) for w in got]  # the typed text is the reference: a typed joiner must survive
        wrong = [(want, have) for want, have in zip(expected, got) if want != have]
        assert len(got) == len(expected) and wrong == [], (engine, len(got), wrong[:10])


@pytest.mark.parametrize("bold", [False, True], ids=["regular", "bold"])
def test_one_form_a_line_extracts_every_form_in_every_engine(tmp_path, bold):
    """One form a paragraph (lines close together, the layout where PDFium misjudged line ends): every engine gives
    back every form in order, exactly (pypdf up to canonical equivalence and U+200D). PDFium joins 7 of these lines
    without a break (regular weight only: a stacked conjunct with a raised e-matra), so it is checked without breaks."""
    words = _sweep_words()
    raw = _sweep_pdf(tmp_path, words, bold, 1)
    for engine, text in extracted(raw, tmp_path).items():
        assert_clean(engine, text)
        if engine == "pdfium":
            assert "".join(text.split()) == "".join("".join(w.split()) for w in words)
            continue
        tokens = " ".join(words).split()
        got = text.split()
        if engine == "pypdf":
            got = [_pypdf_word(w) for w in got]
        wrong = [(want, have) for want, have in zip(tokens, got) if want != have]
        assert len(got) == len(tokens) and wrong == [], (engine, len(got), wrong[:10])


REVIEW_WORDS = ["शुद्ध", "राष्ट्रीय", "बँक", "लिमिटेड", "त्रिवेणी", "वार्षिक", "कीर्ति", "किं", "क़िला", "मुंबई", "ईमेल",
                "ऐसा", "भाई", "बड़ा", "फ़ोन", "Thị"]


def _run_pdf(ctx) -> bytes:
    import datetime as dt

    from backend.utilities.cbom_sources import inventory as INV
    from backend.utilities.cbom_sources import run_deliverables as RD
    from backend.utilities.pdf.cbom_run_pdf import build_run_pdf

    return build_run_pdf(run={"id": 9, "status": "done", "created_at": "2026-11-14T09:00:00Z",
                              "finished_at": "2026-11-14T09:30:00Z", "last_updated": "2026-11-14T09:30:00Z"},
                         sources=[{"name": "linux-dc"}],
                         posture={"assets": 0, "impacts": {}, "pqc_readiness_pct": 0.0, "pqc_classes": {},
                                  "exposure": {}, "mosca": {}, "top_risks": [], "compliance": []},
                         heatmap={"rows": [], "columns": [], "cells": [], "certificates": []},
                         head={"serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                               "metadata": {"properties": []}},
                         findings=[], vex_states={}, provenance=[], at=dt.datetime(2026, 11, 14, 9, 30),
                         as_of_note=None, findings_cap=RD.PDF_FINDINGS_CAP, export_cap=INV.EXPORT_CAP,
                         cbom_sha256="ab" * 32, ctx=ctx)


@pytest.mark.parametrize("where", ["scan cover", "deliverable control table", "run report"])
def test_the_words_the_review_found_broken_copy_exactly_everywhere(tmp_path, where):
    """Review 6013906340: PDFium copied शुद्ध as शु\x12द्ध, राष्ट्रीय as राष्ट्र\x15ीय, ... (an empty ToUnicode entry)."""
    from backend.tests.test_cbom_deliverable_common import make_view
    from backend.utilities.pdf.cbom_deliverables import DELIVERABLES

    name = " ".join(REVIEW_WORDS[:7])
    title = " ".join(REVIEW_WORDS[7:])
    if where == "scan cover":
        raw = scan_pdf(tmp_path, "review", prepared_for=name, title=title)
    elif where == "deliverable control table":
        options = parse_report_options({"prepared_for": " ".join(REVIEW_WORDS)}, "deliverable")
        raw = DELIVERABLES["scope-baseline-register"].build(make_view(), ctx=ReportContext(options=options))
    else:
        raw = _run_pdf(ReportContext(options=parse_report_options({"prepared_for": name, "title": title}, "run")))
    assert "" not in to_unicode_targets(raw)
    texts = extracted(raw, tmp_path)
    if not texts:
        pytest.skip("no PDF text extractor installed")
    for engine, text in texts.items():
        assert_clean(engine, text)
        flat = " ".join(text.split())
        if engine == "pypdf":
            flat = _pypdf_word(flat)
        if where == "deliverable control table":
            assert flat.count(" ".join(REVIEW_WORDS)) >= 2, (engine, flat[:600])  # masthead and control table
        else:
            assert f"Prepared for {name}" in flat and title in flat, (engine, flat[:600])


def test_a_pdf_does_not_depend_on_what_the_process_built_before():
    """Typed-order codes are made on first use, so their numbers depend on history; they never reach the PDF."""
    script = (
        "import sys, hashlib\n"
        "from backend.tests.test_cbom_deliverable_common import make_view\n"
        "from backend.utilities.pdf.cbom_deliverables import DELIVERABLES\n"
        "from backend.utilities.pdf.report_context import ReportContext\n"
        "from backend.utilities.pdf.report_options import parse_report_options\n"
        "spec, view = DELIVERABLES['scope-baseline-register'], make_view()\n"
        "build = lambda n: spec.build(view, ctx=ReportContext(options=parse_report_options({'prepared_for': n}, "
        "'deliverable')))\n"
        "for name in sys.argv[1:-1]: build(name)\n"
        "print(hashlib.sha256(build(sys.argv[-1])).hexdigest())\n"
    )
    target = "वार्षिक लिमिटेड किं"

    def digest(*before: str) -> str:
        done = subprocess.run([sys.executable, "-c", script, *before, target], capture_output=True, text=True,
                              timeout=300, cwd=str(_REPO), env=_CHILD_ENV)
        assert done.returncode == 0, done.stderr[-2000:]
        return done.stdout.strip().splitlines()[-1]

    assert digest() == digest("कार्तिक धार्मिक सिंह हिंदी कीर्ति", "आर्थिक मऱ्याद") == digest("क्षत्रिय")


def test_pieces_never_leave_a_glyph_without_text():
    assert RF._pieces("कि", ["ि", "क"]) == ["क", "ि"]  # one typed character per glyph, in drawing order
    assert RF._pieces("र्षि", ["ि", "ष", "\ue231"]) == ["र", "्", "षि"]  # the rest on the last glyph
    assert RF._pieces("ि", ["\u25cc", "ि"]) == ["ि", RF.ZWJ]  # more glyphs than characters: typed first, then U+200D
    assert RF._pieces("x", ["\ue000", "y"]) == ["x", RF.ZWJ]
    for typed, defaults in (("क", ["a"]), ("कखग", ["a", "b"]), ("क", ["a", "b", "c"])):
        assert all(RF._pieces(typed, defaults)), (typed, defaults)


@needs_poppler
def test_the_extra_code_table_is_capped_and_a_full_table_never_fails_a_build(tmp_path, monkeypatch):
    """Review 6013961175: codes keyed by typed text grew without bound; past 131,072 chr() would raise in every build.
    At EXTRA_CODES_MAX a cluster keeps its own codes; the run's /ActualText still carries the typed text."""
    RF.ensure_registered()
    from reportlab.pdfbase import pdfmetrics

    font = pdfmetrics.getFont(RF.FACES[(RF.DEVANAGARI, True)])  # the face "Prepared for" names are drawn in
    monkeypatch.setattr(RF, "EXTRA_CODES_MAX", max(len(pdfmetrics.getFont(f)._extra) for f in RF.FACES.values()) + 3)
    names = [f"{c}्षि र्{c}ि" for c in "कखगघचछजझटठडढतथदधनपफबभमयलवशसह"]
    for name in names[:10]:  # more distinct clusters than the 3 codes left
        raw = scan_pdf(tmp_path, "capped", prepared_for=name)
        assert f"Prepared for {name}" in " ".join(pdftotext(raw, tmp_path).split())
    for n in range(5):  # whatever is left, filled
        font.code_for(1, f"filler {n}")
    assert len(font._extra) == RF.EXTRA_CODES_MAX and font.code_for(1, "never seen before") is None
    for name in names[10:]:  # a full table: builds still succeed and still extract as typed (/ActualText)
        raw = scan_pdf(tmp_path, "full", prepared_for=name)
        assert f"Prepared for {name}" in " ".join(pdftotext(raw, tmp_path).split())
    assert len(font._extra) == RF.EXTRA_CODES_MAX


def test_a_syllable_drawn_with_more_glyphs_than_letters_copies_as_typed():
    """Review 6014242728: ई is drawn as इ plus a reph-like mark and ऐ as ए plus a vowel sign; their glyphs' own text
    spelled इर् / एे in pdf.js, pypdf and pdfminer. The typed syllable goes on the first glyph, U+200D on the others."""
    assert RF._pieces("ई", ["इ", "र्"]) == ["ई", RF.ZWJ]
    assert RF._pieces("ऐ", ["ए", "े"]) == ["ऐ", RF.ZWJ]
    assert RF._pieces("ि", ["\u25cc", "ि"]) == ["ि", RF.ZWJ]
    # review 6014645102: a joiner typed after the syllable stays last, so the first glyph's text never ends in one
    # (pdf.js dropped such a text: ई + U+200D + मेल copied as मेल)
    assert RF._pieces("ई\u200d", ["इ", "र्"]) == ["ई", "\u200d"]
    assert RF._pieces("ई\u200c", ["इ", "र्"]) == ["ई", "\u200c"]
    assert RF._pieces("ऐ\u200d", ["ए", "े", "x"]) == ["ऐ", RF.ZWJ, "\u200d"]


def _forced_switch_builds(monkeypatch, *, locked: bool) -> int:
    """Concurrent builds with a thread switch forced inside every 16-bit font read (where the reviewer saw ReportLab's
    shared read position race); returns how many failed or differed from a serial build."""
    import contextlib
    import io
    import time

    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics, ttfonts
    from reportlab.platypus import SimpleDocTemplate

    RF.ensure_registered()
    style = ParagraphStyle("t", fontName="Helvetica", fontSize=12, leading=14)

    def build(text: str) -> bytes:
        out = io.BytesIO()
        SimpleDocTemplate(out, invariant=1).build([RF.unicode_paragraph(text, style, bold=True)])
        return out.getvalue()

    texts = ["मुंबई भाई नई", "क़ ख़ ग़ ज़ ड़ ढ़ फ़ य़ ई ऐ"]  # composite glyphs: subsetting reads their components
    serial = {t: build(t) for t in texts}
    if not locked:
        for name in RF.FACES.values():
            monkeypatch.setattr(pdfmetrics.getFont(name), "_subset_lock", contextlib.nullcontext())
    read = ttfonts.TTFontParser.read_ushort

    def switching(self):
        time.sleep(0)  # give the GIL away here, as a preemption at this point would
        return read(self)

    monkeypatch.setattr(ttfonts.TTFontParser, "read_ushort", switching)
    failed = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        for _round in range(25):
            for text, future in [(t, pool.submit(build, t)) for t in texts * 4]:
                try:
                    failed += future.result() != serial[text]
                except (KeyError, IndexError, ValueError):
                    failed += 1
    return failed


def test_concurrent_builds_subset_a_font_one_at_a_time(monkeypatch):
    """Review 6014242728: ReportLab subsets a TrueType font through a read position shared on the font object, so
    concurrent PDFs could raise KeyError/IndexError. _ReportFont.addObjects holds a per-font lock around it: 200 builds
    with forced thread switches all succeed; the same run without the lock fails (about 70 of 200 here)."""
    assert _forced_switch_builds(monkeypatch, locked=True) == 0
    assert _forced_switch_builds(monkeypatch, locked=False) > 0  # the race is real: the lock is what prevents it


def test_a_foreign_font_under_a_report_font_name_fails_loudly():
    script = (
        "from reportlab.pdfbase import pdfmetrics\n"
        "from reportlab.pdfbase.ttfonts import TTFont\n"
        "from backend.utilities.pdf import report_fonts as RF\n"
        "pdfmetrics.registerFont(TTFont('NotoSans', str(RF.FONT_DIR / 'NotoSans-Regular.ttf')))\n"
        "try:\n"
        "    RF.ensure_registered()\n"
        "except RuntimeError as exc:\n"
        "    print('refused', exc)\n"
    )
    done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=120,
                          cwd=str(_REPO), env=_CHILD_ENV)
    assert done.returncode == 0, done.stderr[-2000:]
    assert done.stdout.startswith("refused") and "'NotoSans'" in done.stdout


def test_registration_is_idempotent_and_installs_the_per_font_shaper_once():
    import reportlab.platypus.paragraph as paragraph_module

    RF.ensure_registered()
    shaper = paragraph_module.shapeFragWord
    RF._ready = False
    try:
        RF.ensure_registered()
    finally:
        RF._ready = True
    assert paragraph_module.shapeFragWord is shaper and getattr(shaper, "_zs_by_font", False)
    assert is_cp1252("Zürich €") and not is_cp1252("Łódź")
