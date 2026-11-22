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
* **Those glyphs copy as their text.** ReportLab's ToUnicode map gives them their private-use number;
  ``_ReportFont.addObjects`` maps each to the text it stands for (``fonts/glyph_text.json``, derived from the fonts'
  GSUB tables by ``scripts/pdf_font_glyph_text.py``), so ``प्रबंधन`` extracts as it was typed. Known limit: a vowel
  sign drawn before its consonant (ि) or a reph drawn after it is extracted in drawing order (PDF has no other).
"""
from __future__ import annotations

import json
import threading
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
        text = code_text.get(code)
        return text.encode("utf-16-be").hex().upper() if text else "%04X" % code

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
            return original(word, *args, **kwargs)
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
            part = original([width, *pairs], *args, **kwargs)
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
