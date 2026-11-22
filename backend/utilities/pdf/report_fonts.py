"""Fonts for the text a user types into a PDF export when Helvetica cannot draw it.

The "Prepared for" name and the custom title (``report_options``) may use Latin Extended, Greek, Cyrillic and
Devanagari (``TEXT_RANGES``). Text that is Windows-1252 keeps the report's Helvetica, through the callers' unchanged
code, so those PDFs are byte for byte what they were. Any other text is drawn with the vendored Noto fonts
(``fonts/README.md``: source, versions, OFL 1.1): Noto Sans for Latin, Greek and Cyrillic, Noto Sans Devanagari for
Hindi and Marathi. Devanagari needs complex shaping (conjuncts, reordered and stacked matras); ReportLab shapes a
paragraph with HarfBuzz (``uharfbuzz``) when its style has ``shaping=1`` and a TrueType font. ReportLab embeds only
the glyphs a PDF uses.

What this module adds to ReportLab's shaping, each for a reason found by testing:

* **One font per shaped word.** ReportLab shapes a whitespace-separated word with the font of its first fragment, so a
  word that switches font ("Acme-बैंक") failed with an AttributeError. ``_shape_by_font`` shapes such a word one font
  run at a time; a word in one font goes to ReportLab unchanged.
* **Glyphs no character maps to get fixed code points, once.** Shaping can produce such glyphs (a conjunct, a matra
  with its anusvara, a ligature); ReportLab numbers each the first time it meets it, mutating the shared font object.
  ``_ReportFont`` numbers every one of them when the font is registered (under a lock), so concurrent builds never
  race and the same text always gives the same bytes.
* **A shaped word copies and searches as it was typed, in every common viewer.** ReportLab's ToUnicode map gives a
  glyph no character maps to its private-use number, and a cluster's glyphs come out in drawing order, which is not
  the typed order in Devanagari (कि is drawn ि then क; र्षि as an i-matra-with-reph, ष and an empty mark). Viewers
  differ in what they read, so the typed text is written two ways:

  - ToUnicode (pypdf, pdfminer, pdf.js read only this). Each glyph's own text comes from ``fonts/glyph_text.json``
    (derived from the fonts' GSUB tables by ``scripts/pdf_font_glyph_text.py``). Where a cluster's glyphs, read in
    drawing order, do not spell the typed cluster, ``_copy_as_typed`` draws the same glyphs through extra codes
    whose entries do (``_pieces``: one typed character per glyph, the rest on the last; a cluster with more glyphs
    than characters, ई or ऐ, has all its text on the first glyph and U+200D on each other; a cluster whose glyphs
    spell a canonical equivalent, क़ or ị, keeps its codes and is exact in ``/ActualText``). No entry is ever empty:
    PDFium, pdf.js and MuPDF copy the raw byte of a code without text, a control character in the middle of a word.
  - ``/ActualText`` (poppler, PDFium, MuPDF read this first). ``_format_shaped`` wraps each shaped run in marked
    content carrying its typed text, so a mark raised or moved back over its consonant cannot be placed by its
    position (poppler split कूँ into कू and a stray ँ, and wrote कुं as कंु). ReportLab has no API for marked content;
    the hook is ``PDFTextObject._formatText`` for shaped runs of these fonts only. It also writes a long rightward
    move as several TJ numbers (pypdf reads one as a word gap).

  The glyphs drawn are the same (pixel for pixel). The extra codes depend only on (glyph, text), are capped per
  process (``EXTRA_CODES_MAX``) and never appear in the PDF themselves, so the bytes of a PDF do not depend on what
  was built before it. Measured on 79 strings x 2 layouts in six extractors and on 11,000+ forms in poppler, pypdf
  and PDFium (``tests/test_report_fonts.py``); what each extractor still gets wrong (U+200D in pypdf and pdfminer,
  a repeated tail in MuPDF) is listed in ``fonts/README.md``.
* **One subset at a time per font.** ReportLab writes a font's subset by reading the font file through one shared
  read position, so two PDFs embedding the same font at once could read each other's offsets; ``_ReportFont`` holds a
  lock around it.
"""
from __future__ import annotations

import json
import threading
import unicodedata
from itertools import groupby
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.lib.rl_accel import fp_str
from reportlab.pdfbase.ttfonts import SUBSETN, ShapedFragWord, ShapedStr, TTFont, _sdGuardL, makeShapedFragWord
from reportlab.pdfgen.textobject import PDFTextObject
from reportlab.platypus import Paragraph

from backend.utilities.pdf.report_options import is_cp1252, text_supported

FONT_DIR = Path(__file__).with_name("fonts")
LATIN = "latin"
DEVANAGARI = "devanagari"
# (script, bold) -> registered ReportLab font name
FACES: Dict[Tuple[str, bool], str] = {
    (LATIN, False): "NotoSans",
    (LATIN, True): "NotoSans-Bold",
    (DEVANAGARI, False): "NotoSansDevanagari",
    (DEVANAGARI, True): "NotoSansDevanagari-Bold",
}
_FILES = {
    "NotoSans": ("NotoSans-Regular.ttf", "NotoSans"),
    "NotoSans-Bold": ("NotoSans-Bold.ttf", "NotoSans"),
    "NotoSansDevanagari": ("NotoSansDevanagari-Regular.ttf", "NotoSansDevanagari"),
    "NotoSansDevanagari-Bold": ("NotoSansDevanagari-Bold.ttf", "NotoSansDevanagari"),
}
_DEVANAGARI_BLOCKS = ((0x0900, 0x097F), (0xA8E0, 0xA8FF))
# a Devanagari paragraph's lines need room for vowel signs above and below the letters
DEVANAGARI_LEADING = 1.5

_lock = threading.Lock()
_codes_lock = threading.Lock()  # extra codes are added to a shared font while documents are built
_EXTRA_CODES = 0xF0000  # Supplementary Private Use Area-A: never a character of the fonts or of typed text
# Extra codes a font may make in one process (keyed by glyph and typed text, so adversarial titles could add more and
# more). Past it a cluster keeps its own codes: the run's /ActualText (from the typed pieces, not from the codes)
# still extracts as typed in viewers that read it; only viewers that read ToUnicode alone see the glyphs' own text.
EXTRA_CODES_MAX = 32_768
_shared: frozenset[str] = frozenset()  # characters both fonts draw: they follow their neighbours' font
_ready = False


class _ReportFont(TTFont):
    """A TrueType font whose shaped-only glyphs are numbered up front and copy as their text (module docstring)."""

    def __init__(self, name: str, path: Path, glyph_text: Dict[str, str]):
        super().__init__(name, str(path))
        self._code_text: Dict[int, str] = {}
        hb = self.hbFont(1000)  # also makes ReportLab's hbAddPrivate available on this font
        face = self.face
        for gid in range(face.numGlyphs):
            if gid in face.glyphToChar:
                continue
            glyph = hb.glyph_to_string(gid)
            # the same call ReportLab makes when shaping meets the glyph: advance in font units
            code = self.hbAddPrivate(glyph, gid, hb.get_glyph_h_advance(gid))
            text = glyph_text.get(glyph)
            if text:
                self._code_text[code] = text
        self._extra: Dict[Tuple[int, str], int] = {}  # (glyph id, text) -> code (_copy_as_typed)
        # ReportLab subsets a TrueType font through a read position shared on the font file object (makeSubset seeks,
        # then reads composite glyphs' components), so two documents subsetting this font at once can read each
        # other's bytes (KeyError/IndexError). One document's subsetting at a time; it happens once per font per PDF.
        self._subset_lock = threading.Lock()

    def text_of(self, code: int) -> str:
        """What the ToUnicode map says ``code`` stands for."""
        return self._code_text.get(code, chr(code))

    def code_for(self, gid: int, text: str) -> Optional[int]:
        """A code that draws glyph ``gid`` and extracts as ``text``; made once per (glyph, text). None once the font has
        ``EXTRA_CODES_MAX`` of them (the caller keeps the glyph's own code)."""
        key = (gid, text)
        code = self._extra.get(key)
        if code is not None:
            return code
        with _codes_lock:
            code = self._extra.get(key)
            if code is None:
                if len(self._extra) >= EXTRA_CODES_MAX:
                    return None
                face = self.face
                code = _EXTRA_CODES + len(self._extra)
                face.charToGlyph[code] = gid
                face.charWidths[code] = face.charWidths[face.glyphToChar[gid][0]]
                self._code_text[code] = text
                self._extra[key] = code
        return code

    def addObjects(self, doc) -> None:
        state = self.state.get(doc)  # ReportLab drops the document's state at the end of addObjects
        with self._subset_lock:
            super().addObjects(doc)
        for index, subset in enumerate(state.subsets if state is not None else ()):
            if not any(code in self._code_text for code in subset):
                continue
            base = b"".join((SUBSETN(index), b"+", self.face.name, self.face.subfontNameX)).decode("pdfdoc")
            stream = doc.idToObject.get("toUnicodeCMap:" + base)
            if stream is not None:
                stream.content = _to_unicode_cmap(base, subset, self._code_text)


def _to_unicode_cmap(fontname: str, subset: List[int], code_text: Dict[int, str]) -> str:
    """ReportLab's ``makeToUnicodeCMap`` with the shaped-only glyphs mapped to their text (UTF-16BE, any length)."""

    def target(code: int) -> str:
        text = code_text.get(code)
        if not text:  # never an empty entry: viewers copy the raw byte for one (PDFium, pdf.js, MuPDF)
            return "%04X" % code
        return text.encode("utf-16-be").hex().upper()

    return "\n".join([
        "/CIDInit /ProcSet findresource begin", "12 dict begin", "begincmap", "/CIDSystemInfo",
        "<< /Registry (%s)" % fontname, "/Ordering (%s)" % fontname, "/Supplement 0", ">> def",
        "/CMapName /%s def" % fontname, "/CMapType 2 def", "1 begincodespacerange",
        "<00> <%02X>" % (len(subset) - 1), "endcodespacerange", "%d beginbfchar" % len(subset),
        *["<%02X> <%s>" % (i, target(code)) for i, code in enumerate(subset)],
        "endbfchar", "endcmap", "CMapName currentdict /CMap defineresource pop", "end", "end",
    ])


def _moved(data, offset: int):
    """``data`` (a ShapeData) with its cluster moved by ``offset``, keeping the typed piece it may carry."""
    moved = data._replace(cluster=data.cluster + offset)
    moved.__dict__.update(data.__dict__)
    return moved


def _shape_by_font(original):
    """ReportLab's ``shapeFragWord`` for words that switch font: each font run shaped on its own, then joined."""

    def shape(word, *args, **kwargs):
        if isinstance(word, ShapedFragWord):
            return word
        names = {frag.fontName for frag, _text in word[1:] if not hasattr(frag, "cbDefn")}
        if len(names) < 2:
            return _copy_as_typed(word, original(word, *args, **kwargs))
        runs: list[list] = []
        for frag, text in word[1:]:
            name = None if hasattr(frag, "cbDefn") else frag.fontName
            if runs and (name is None or runs[-1][0] == name):
                runs[-1][1].append((frag, text))
            else:
                runs.append([name, [(frag, text)]])
        joined = makeShapedFragWord(word)([0.0])
        offset = 0
        for _name, pairs in runs:
            texts = [(frag, text) for frag, text in pairs if not hasattr(frag, "cbDefn")]
            width = sum(pdfmetrics.stringWidth(text, frag.fontName, frag.fontSize) for frag, text in texts)
            part = _copy_as_typed([width, *pairs], original([width, *pairs], *args, **kwargs))
            for frag, text in part[1:]:
                if isinstance(text, ShapedStr):  # clusters count characters from the start of the whole word
                    text = ShapedStr(str(text), shapeData=[_moved(d, offset) for d in text.__shapeData__])
                joined.append((frag, text))
            joined[0] += part[0]
            offset += sum(len(text) for _frag, text in texts)
        return joined

    shape._zs_by_font = True
    return shape


ZWJ = "\u200d"
_JOINERS = "\u200c\u200d"  # ZERO WIDTH NON-JOINER, ZERO WIDTH JOINER


def _pieces(typed: str, defaults: List[str]) -> List[str]:
    """``typed`` cut into one piece per glyph, in drawing order: one character for each glyph but the last, the rest to
    the last; joined, the pieces are ``typed``. No piece is empty: a viewer that finds no text for a code copies the
    raw byte (PDFium, pdf.js, MuPDF).

    A cluster with more glyphs than characters (the font draws ई as इ plus a reph-like mark, ऐ as ए plus a vowel sign):
    the whole typed cluster goes on the first glyph and each further glyph gets U+200D ZERO WIDTH JOINER, so pdf.js
    copies मुंबई as typed (pypdf keeps the joiner: मुंबई + U+200D). A cluster whose glyphs already spell a canonical
    equivalent of what was typed (HarfBuzz decomposed ऴ into ळ + nukta) keeps its codes (``_copy_as_typed``); a joiner
    typed after the syllable goes on its last glyph."""
    count = len(defaults)
    if len(typed) >= count:
        return [typed[i:i + 1] for i in range(count - 1)] + [typed[count - 1:]]
    core = typed.rstrip(_JOINERS) or typed
    pieces = [core] + [ZWJ] * (count - 1)
    if core != typed:
        pieces[-1] = typed[len(core):]  # a joiner typed after the syllable stays last (pdf.js drops a text ending in one)
    return pieces


def _copy_as_typed(word, shaped):
    """``shaped`` (ReportLab's shaping of ``word``, one font) with each cluster that would extract other than typed
    drawn through ``_ReportFont.code_for`` codes whose texts, in drawing order, are the typed cluster."""
    parts = shaped[1:]
    if shaped is word or not any(isinstance(text, ShapedStr) for _frag, text in parts):
        return shaped  # nothing was substituted or moved: the characters are the typed ones
    typed = "".join(text for frag, text in word[1:] if not hasattr(frag, "cbDefn"))
    glyphs = [(k, j, d.cluster) for k, (_frag, text) in enumerate(parts) if isinstance(text, ShapedStr)
              for j, d in enumerate(text.__shapeData__) if 0 <= d.cluster < len(typed)]
    starts = sorted({cluster for _k, _j, cluster in glyphs})
    ends = dict(zip(starts, starts[1:] + [len(typed)]))
    chars = [list(text) for _frag, text in parts]
    fonts = [None if hasattr(frag, "cbDefn") else pdfmetrics.getFont(frag.fontName) for frag, _text in parts]
    def spacing(k: int, j: int) -> bool:
        return parts[k][1].__shapeData__[j].x_advance > 0

    # a cluster of marks only (an anusvara, a u-matra, a reph HarfBuzz kept apart) joins the cluster before it: what
    # the glyphs of a rewritten cluster spell is decided for the syllable as a whole
    groups: list[list] = []
    for cluster, members in groupby(glyphs, key=lambda g: g[2]):
        members = list(members)
        if groups and not any(spacing(k, j) for k, j, _c in members):
            groups[-1][1].extend(members)
            groups[-1][2] = ends[cluster]
        else:
            groups.append([cluster, members, ends[cluster]])
    changed = False
    for start, members, end in groups:
        if not all(isinstance(fonts[k], _ReportFont) for k, _j, _c in members):
            continue
        want = typed[start:end]
        shown = [fonts[k].text_of(ord(chars[k][j])) for k, j, _c in members]
        if "".join(shown) == want:
            continue  # the glyphs already spell it
        if unicodedata.normalize("NFD", "".join(shown)) == unicodedata.normalize("NFD", want):
            # a canonical equivalent (the font draws क़ U+0958, typed क + nukta, with one glyph; HarfBuzz decomposed
            # ऴ, ị): ToUnicode keeps the glyphs' own text, the run's /ActualText still carries exactly what was typed
            for n, (k, j, _c) in enumerate(members):
                parts[k][1].__shapeData__[j].typed = want if n == 0 else ""
            continue
        pieces = _pieces(want, shown)
        for n, ((k, j, _c), piece) in enumerate(zip(members, pieces)):
            font = fonts[k]
            gid = font.face.charToGlyph[ord(chars[k][j])]
            code = font.code_for(gid, piece)
            if code is not None:
                chars[k][j] = chr(code)
            # the run's /ActualText (_format_shaped): the typed cluster on its first glyph, exactly, whatever the codes
            parts[k][1].__shapeData__[j].typed = want if n == 0 else ""
        changed = True
    if not changed:
        return shaped
    out = shaped.__class__([shaped[0]])
    for (frag, text), new in zip(parts, chars):
        out.append((frag, ShapedStr("".join(new), shapeData=text.__shapeData__) if isinstance(text, ShapedStr) else text))
    return out


# The longest rightward move written as one number in a TJ array (thousandths of an em). Text extractors that read
# a TJ number past about half a space as a word gap (pypdf) would otherwise put a space after a mark that HarfBuzz
# moved back over its consonant (ककुक as "ककु क"); the same move as several smaller numbers draws the same.
_TJ_STEP = 100


def _tj_numbers(value: float) -> List[str]:
    """``value`` as TJ numbers: itself, or for a rightward move past ``_TJ_STEP`` whole steps and the remainder (the
    remainder is ``value`` plus integers, so it rounds exactly as ``value`` would)."""
    if value >= -_TJ_STEP:
        return [fp_str(value)]
    steps = int(-value // _TJ_STEP)
    rest = value + steps * _TJ_STEP
    return [str(-_TJ_STEP)] * steps + ([fp_str(rest)] if fp_str(rest) not in ("0", "-0") else [])


def _actual_text(op: str, typed: str) -> str:
    return f"/Span <</ActualText <FEFF{typed.encode('utf-16-be').hex().upper()}>>> BDC {op} EMC"


def _format_shaped(tx, text, font: "_ReportFont") -> str:
    """ReportLab's ``PDFTextObject._formatText`` for a shaped run of a report font (its shaped branch, reportlab 4.4.7,
    kept operator for operator), with two additions that change no pixel:

    * the run is wrapped in marked content whose ``/ActualText`` is its typed text (``text_of`` each code: the pieces
      ``_copy_as_typed`` gave a rewritten cluster spell it). Poppler and PDFium extract that instead of the glyphs, so
      a mark drawn before or above its consonant, or raised with a text rise, can never be misplaced or split off;
    * a rightward move longer than ``_TJ_STEP`` is written as several numbers (``_tj_numbers``), for pypdf, which reads
      the glyphs' own ToUnicode text in drawing order.
    """
    canv = tx._canvas
    state = (tx._code, tx._x, tx._y)
    try:
        tx._code = []
        R = tx._code.append
        canv_escape = canv._escape
        tmpl = None
        r0 = tx._rise
        shape_data = text.__shapeData__
        chars = str(text)
        fontsize = tx._fontsize
        parts: list = []  # the current text-showing operator's numbers and glyph bytes
        sd0 = 0
        for subset, t in font.splitString(text, canv._doc):
            cluster = None
            if subset != tx._curSubset:
                if not tmpl:
                    tmpl = f"{fp_str(fontsize)} Tf {fp_str(tx._leading)} TL"
                R(f"{font.getSubsetInternalName(subset, canv._doc)} {tmpl}")
                tx._curSubset = subset
            sd1 = sd0 + len(t)
            SD = shape_data[sd0:sd1] + _sdGuardL
            sd0 = sd1
            for i, sd in enumerate(SD):
                r = r0 + fontsize * sd.y_offset / 1000
                if cluster is None or sd.cluster < 0 or r != tx._rise:
                    if cluster is not None:
                        A = []
                        for is_text, g in groupby(filter(None, parts), lambda x: isinstance(x, bytes)):
                            A += [f"({canv_escape(b''.join(g))})"] if is_text else _tj_numbers(sum(g))
                        A = [v for v in A if v != "0"]
                        R(f"{A[0]} Tj" if len(A) == 1 and A[0].startswith("(") else f"[{' '.join(A)}] TJ")
                        if tx._rise != r0:
                            tx.setRise(r0)
                        if sd.cluster < 0:
                            break
                    if r != tx._rise:
                        tx.setRise(r)
                    cluster = sd.cluster
                    parts = []
                parts.append(-sd.x_offset)  # as ReportLab: the HarfBuzz offset, the glyph, the move to the next pen
                parts.append(bytes(chr(t[i]).encode("latin1")))
                parts.append(sd.width - sd.x_advance + sd.x_offset)
        if tx._rise != r0:
            tx.setRise(r0)
        ops = " ".join(R.__self__)
    finally:
        tx._code, tx._x, tx._y = state
    typed = "".join(d.__dict__["typed"] if "typed" in d.__dict__ else font.text_of(ord(ch))
                    for ch, d in zip(chars, shape_data))
    return _actual_text(ops, typed) if typed.strip() else ops


def _with_actual_text(original):
    """``PDFTextObject._formatText``: a shaped run of a report font goes through ``_format_shaped``; anything else is
    drawn by ReportLab exactly as before."""

    def format_text(self, text):
        if isinstance(text, ShapedStr):
            font = pdfmetrics.getFont(self._fontname)
            if isinstance(font, _ReportFont):
                return _format_shaped(self, text, font)
        return original(self, text)

    format_text._zs_actual_text = True
    return format_text


def ensure_registered() -> None:
    """Register the four fonts (and the per-font shaping) once per process; safe from any thread."""
    global _ready, _shared
    if _ready:
        return
    with _lock:
        if _ready:
            return
        import reportlab.platypus.paragraph as paragraph_module  # noqa: PLC0415

        tables = json.loads((FONT_DIR / "glyph_text.json").read_text(encoding="utf-8"))
        registered = set(pdfmetrics.getRegisteredFontNames())
        for name, (filename, family) in _FILES.items():
            if name not in registered:
                pdfmetrics.registerFont(_ReportFont(name, FONT_DIR / filename, tables[family]))
            elif not isinstance(pdfmetrics.getFont(name), _ReportFont):
                # another font under our name would draw shaped glyphs with no fixed codes and no typed text: refuse
                raise RuntimeError(f"PDF font name {name!r} is already registered to a font that is not report_fonts'")
        latin = set(pdfmetrics.getFont(FACES[(LATIN, False)]).face.charToGlyph)
        devanagari = set(pdfmetrics.getFont(FACES[(DEVANAGARI, False)]).face.charToGlyph)
        _shared = frozenset(chr(c) for c in latin & devanagari if _script_of(chr(c)) != DEVANAGARI)
        if not getattr(paragraph_module.shapeFragWord, "_zs_by_font", False):
            paragraph_module.shapeFragWord = _shape_by_font(paragraph_module.shapeFragWord)
        if not getattr(PDFTextObject._formatText, "_zs_actual_text", False):
            PDFTextObject._formatText = _with_actual_text(PDFTextObject._formatText)
        _ready = True


def _script_of(ch: str) -> str:
    code = ord(ch)
    return DEVANAGARI if any(low <= code <= high for low, high in _DEVANAGARI_BLOCKS) else LATIN


def needs_unicode_font(text: Optional[str]) -> bool:
    """True for text the report fonts draw and Helvetica cannot; Windows-1252 text keeps today's code path."""
    return bool(text) and not is_cp1252(text) and text_supported(text)


def script_runs(text: str) -> List[Tuple[str, str]]:
    """``text`` cut into (script, chunk) runs. Spaces, digits and punctuation both fonts draw join the run before
    them (the first run when they lead), so a run changes font only where the letters change script."""
    ensure_registered()
    keys: List[Optional[str]] = [None if ch in _shared else _script_of(ch) for ch in text]
    first = next((k for k in keys if k is not None), LATIN)
    runs: List[Tuple[str, str]] = []
    current = first
    for ch, key in zip(text, keys):
        current = key or current
        if runs and runs[-1][0] == current:
            runs[-1] = (current, runs[-1][1] + ch)
        else:
            runs.append((current, ch))
    return runs


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def unicode_markup(text: str, *, bold: bool = False) -> str:
    """Paragraph markup for ``text`` (escaped): each script run in its Noto face."""
    return "".join(f'<font face="{FACES[(script, bold)]}">{_escape(chunk)}</font>' for script, chunk in script_runs(text))


def unicode_paragraph(text: str, style: ParagraphStyle, *, bold: bool, before: str = "") -> Paragraph:
    """A shaped Paragraph of user ``text`` in ``style``'s size and colour. ``before`` (plain text, escaped here) is drawn
    first in the style's own font, so a label such as "Prepared for " looks as it does next to Windows-1252 text."""
    ensure_registered()
    leading = style.leading
    if any(script == DEVANAGARI for script, _chunk in script_runs(text)):
        leading = max(leading, style.fontSize * DEVANAGARI_LEADING)
    noto = ParagraphStyle(f"{style.name}+noto", parent=style, fontName=FACES[(LATIN, bold)], leading=leading,
                          shaping=1)
    lead = f'<font face="{style.fontName}">{_escape(before)}</font>' if before else ""
    return Paragraph(lead + unicode_markup(text, bold=bold), noto)


__all__ = ["DEVANAGARI", "FACES", "FONT_DIR", "LATIN", "ensure_registered", "needs_unicode_font", "script_runs",
           "unicode_markup", "unicode_paragraph"]
