"""Write backend/utilities/pdf/fonts/glyph_text.json: the text each shaped-only glyph of the vendored Noto fonts stands for.

A HarfBuzz-shaped run (a Devanagari conjunct, a matra with its anusvara, an "fi" ligature) uses glyphs that no character
maps to. ReportLab gives each such glyph a private-use code point, so a PDF viewer would copy or search it as U+E0xx.
``report_fonts`` writes this table into the font's ToUnicode map instead, so ``प्र`` extracts as प्र.

The table is derived from each font's GSUB: a ligature stands for its components' text, a single, alternate or first
multiple substitute for its source glyph's text, repeated to a fixed point (ligatures first, so a ligature never takes
a variant's guess). Only the lookups HarfBuzz applies count: those of the fonts' scripts, minus the old ``deva`` ones
when the font has ``dev2`` (HarfBuzz shapes with dev2, where a below-base ra is virama + ra), and the lookups their
contextual rules call. It depends only on the font files, so it is generated once and committed with them.

Run from the repository root (fontTools is a build-time tool here, not a backend dependency):

    uvx --from fonttools==4.60.1 python -I backend/scripts/pdf_font_glyph_text.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from fontTools.ttLib import TTFont

FONTS = Path(__file__).resolve().parents[1] / "utilities" / "pdf" / "fonts"
FAMILIES = {"NotoSans": ("NotoSans-Regular.ttf", "NotoSans-Bold.ttf"),
            "NotoSansDevanagari": ("NotoSansDevanagari-Regular.ttf", "NotoSansDevanagari-Bold.ttf")}
SKIP = ("NULL", "NullMark")  # empty marks: no text of their own
LEGACY = {"dev2": "deva"}  # a script tag HarfBuzz prefers -> the old tag it then ignores


def applied_lookups(gsub) -> list[int]:
    """Indices of the lookups HarfBuzz can apply: the fonts' scripts' features (legacy Indic tags dropped when the new
    tag exists), then every lookup a contextual rule of those calls."""
    scripts = {rec.ScriptTag: rec.Script for rec in gsub.ScriptList.ScriptRecord}
    ignored = {old for new, old in LEGACY.items() if new in scripts}
    features: set[int] = set()
    for tag, script in scripts.items():
        if tag in ignored:
            continue
        systems = ([script.DefaultLangSys] if script.DefaultLangSys else []) + [r.LangSys for r in script.LangSysRecord]
        for system in systems:
            features.update(system.FeatureIndex)
    todo = [i for f in sorted(features) for i in gsub.FeatureList.FeatureRecord[f].Feature.LookupListIndex]
    seen: set[int] = set()
    while todo:
        index = todo.pop()
        if index in seen:
            continue
        seen.add(index)
        lookup = gsub.LookupList.Lookup[index]
        for sub in lookup.SubTable:
            sub = sub.ExtSubTable if lookup.LookupType == 7 else sub
            for name in ("SubstLookupRecord", "ChainSubstLookupRecord"):
                todo += [rec.LookupListIndex for rec in getattr(sub, name, None) or ()]
            for name in ("SubRuleSet", "SubClassSet", "ChainSubRuleSet", "ChainSubClassSet"):
                for rule_set in getattr(sub, name, None) or ():
                    for rule in (getattr(rule_set, "SubRule", None) or getattr(rule_set, "SubClassRule", None)
                                 or getattr(rule_set, "ChainSubRule", None) or getattr(rule_set, "ChainSubClassRule", None)
                                 or ()):
                        for rec_name in ("SubstLookupRecord", "ChainSubstLookupRecord"):
                            todo += [rec.LookupListIndex for rec in getattr(rule, rec_name, None) or ()]
    return sorted(seen)


def glyph_text(path: Path) -> dict[str, str]:
    font = TTFont(str(path))
    cmap: dict[str, str] = {}
    for code, glyph in sorted(font.getBestCmap().items()):
        cmap.setdefault(glyph, chr(code))
    known = dict(cmap)
    gsub = font["GSUB"].table
    subtables = []
    for index in applied_lookups(gsub):
        lookup = gsub.LookupList.Lookup[index]
        for sub in lookup.SubTable:
            subtables.append(sub.ExtSubTable if lookup.LookupType == 7 else sub)
    changed = [False]

    def put(glyph: str, text: str) -> None:
        if glyph not in known and glyph not in SKIP:
            known[glyph] = text
            changed[0] = True

    while True:
        changed[0] = False
        for sub in subtables:
            if sub.LookupType == 4:
                for first, ligatures in sub.ligatures.items():
                    for lig in ligatures:
                        parts = [first, *lig.Component]
                        if all(p in known for p in parts):
                            put(lig.LigGlyph, "".join(known[p] for p in parts))
        if changed[0]:
            continue
        for sub in subtables:
            if sub.LookupType == 1:
                for src, dst in sub.mapping.items():
                    if src in known:
                        put(dst, known[src])
            elif sub.LookupType == 2:
                for src, dsts in sub.mapping.items():
                    if src in known and dsts:
                        put(dsts[0], known[src])
            elif sub.LookupType == 3:
                for src, alternates in sub.alternates.items():
                    if src in known:
                        for dst in alternates:
                            put(dst, known[src])
        if not changed[0]:
            break
    order = font.getGlyphOrder()
    return {g: known[g] for g in order if g in known and g not in cmap and known[g]}


def main() -> int:
    out: dict[str, dict[str, str]] = {}
    for family, files in FAMILIES.items():
        tables = [glyph_text(FONTS / name) for name in files]
        if any(t != tables[0] for t in tables[1:]):
            print(f"{family}: the weights differ; extend the table to one entry per file", file=sys.stderr)
            return 1
        out[family] = tables[0]
        print(f"{family}: {len(tables[0])} glyphs", file=sys.stderr)
    (FONTS / "glyph_text.json").write_text(json.dumps(out, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                                           encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
