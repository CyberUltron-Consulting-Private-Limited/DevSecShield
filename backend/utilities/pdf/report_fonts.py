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
* **A shaped word copies and searches as it was typed.** ReportLab's ToUnicode map gives a glyph no character maps to
  its private-use number, and a cluster's glyphs come out in drawing order, which is not the typed order in
  Devanagari (कि is drawn ि then क; र्षि is drawn as an i-matra-with-reph, ष and an empty mark). Each glyph's own text
  comes from ``fonts/glyph_text.json`` (derived from the fonts' GSUB tables by ``scripts/pdf_font_glyph_text.py``).
  Where a cluster's glyphs, read in drawing order, do not spell the typed cluster, ``_copy_as_typed`` draws the same
  glyphs through extra codes whose ToUnicode entries, read in drawing order, spell the typed cluster (``_pieces``:
  one piece per spacing glyph, so an extractor sees no gap inside the cluster). A cluster of marks only joins the one
  before it and marks carry no text, because an extractor places a raised or shifted mark by its position (it split
  कूँ into कू and a stray ँ, and wrote कुं as कंु). Tested on more than 11,000 Hindi and Marathi forms in both
  weights: pdftotext gives back exactly what was typed. The glyphs drawn are the same; the text a viewer extracts, copies or searches is what was typed. (ReportLab
  has no marked-content API for ``/ActualText``; this is the ToUnicode form of the same thing.) Those codes depend
  only on (glyph, text) and never appear in the PDF themselves, so the bytes of a PDF do not depend on what was built
  before it in the process.
"""
from __future__ import annotations

import json
import threading
from itertools import groupby
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import SUBSETN, ShapedFragWord, ShapedStr, TTFont, makeShapedFragWord
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

    def text_of(self, code: int) -> str:
        """What the ToUnicode map says ``code`` stands for."""
        return self._code_text.get(code, chr(code))

    def code_for(self, gid: int, text: str) -> int:
        """A code that draws glyph ``gid`` and extracts as ``text`` ("" for nothing); made once per (glyph, text)."""
        key = (gid, text)
        code = self._extra.get(key)
        if code is not None:
            return code
        with _codes_lock:
            code = self._extra.get(key)
            if code is None:
                face = self.face
                code = _EXTRA_CODES + len(self._extra)
                face.charToGlyph[code] = gid
                face.charWidths[code] = face.charWidths[face.glyphToChar[gid][0]]
                self._code_text[code] = text
                self._extra[key] = code
        return code

    def addObjects(self, doc) -> None:
        state = self.state.get(doc)  # ReportLab drops the document's state at the end of addObjects
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
        if code not in code_text:
            return "%04X" % code
        return code_text[code].encode("utf-16-be").hex().upper()  # "" (the rest of a cluster): extracts as nothing

    return "\n".join([
        "/CIDInit /ProcSet findresource begin", "12 dict begin", "begincmap", "/CIDSystemInfo",
        "<< /Registry (%s)" % fontname, "/Ordering (%s)" % fontname, "/Supplement 0", ">> def",
        "/CMapName /%s def" % fontname, "/CMapType 2 def", "1 begincodespacerange",
        "<00> <%02X>" % (len(subset) - 1), "endcodespacerange", "%d beginbfchar" % len(subset),
        *["<%02X> <%s>" % (i, target(code)) for i, code in enumerate(subset)],
        "endbfchar", "endcmap", "CMapName currentdict /CMap defineresource pop", "end", "end",
    ])


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
                    text = ShapedStr(str(text), shapeData=[d._replace(cluster=d.cluster + offset)
                                                           for d in text.__shapeData__])
                joined.append((frag, text))
            joined[0] += part[0]
            offset += sum(len(text) for _frag, text in texts)
        return joined

    shape._zs_by_font = True
    return shape


def _pieces(typed: str, spacing: List[bool]) -> List[str]:
    """``typed`` cut into one piece per glyph, in order: a character for each spacing glyph but the last, the rest to the
    last; marks (no advance) get nothing. Joined, the pieces are ``typed``; no spacing glyph is left without text, so
    a text extractor sees no gap (and no word break) inside the cluster."""
    slots = [i for i, wide in enumerate(spacing) if wide] or [0]
    pieces = [""] * len(spacing)
    rest = typed
    for i in slots[:-1]:
        pieces[i], rest = rest[:1], rest[1:]
    pieces[slots[-1]] = rest
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

    # a cluster of marks only (an anusvara, a u-matra, a reph HarfBuzz kept apart) joins the cluster before it, so the
    # spacing glyph it sits on carries its text: a mark that carries none leaves an extractor nothing to misplace
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
        if "".join(shown) == want and all(spacing(k, j) or not text for (k, j, _c), text in zip(members, shown)):
            continue
        pieces = _pieces(want, [spacing(k, j) for k, j, _c in members])
        for (k, j, _c), piece in zip(members, pieces):
            font = fonts[k]
            gid = font.face.charToGlyph[ord(chars[k][j])]
            chars[k][j] = chr(font.code_for(gid, piece))
        changed = True
    if not changed:
        return shaped
    out = shaped.__class__([shaped[0]])
    for (frag, text), new in zip(parts, chars):
        out.append((frag, ShapedStr("".join(new), shapeData=text.__shapeData__) if isinstance(text, ShapedStr) else text))
    return out


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
