# Report fonts (Noto Sans, Noto Sans Devanagari)

Used by `backend/utilities/pdf/report_fonts.py` for the text a user types into a PDF export (the "Prepared for"
name and the custom title) when it is not Windows-1252: Latin Extended, Greek, Cyrillic (Noto Sans) and Devanagari
for Hindi and Marathi (Noto Sans Devanagari, shaped with HarfBuzz through `uharfbuzz`). Text that is Windows-1252 keeps
Helvetica, so those reports are unchanged byte for byte. ReportLab embeds only the glyphs a PDF uses (a subset).

| File | Version | SHA-256 |
|---|---|---|
| `NotoSans-Regular.ttf` | 2.015 | `f3961a9cde016d41a4879aecda1474d3a36d6bf54fa0e4643de029cc2248b0e8` |
| `NotoSans-Bold.ttf` | 2.015 | `87cb2d84472a7d66da659ee47b6cdb9552326e8c128245231f191b6ac72529d9` |
| `NotoSansDevanagari-Regular.ttf` | 2.007 | `9c7d935139ea6a1e6ad9dbac4f6d27ece1e04bca8123c8888d00a0f9df4724cd` |
| `NotoSansDevanagari-Bold.ttf` | 2.007 | `ff2f76a23aad41e0608c2d7dbc4bacd247ff3bec78f0ec2a8fb106b561636e58` |

Source: the Noto project's release repository, <https://github.com/notofonts/notofonts.github.io> at commit
`c6f674cf56243b4c0b650134a9020e047eab702e` (2026-11-22), the **unhinted** TrueType builds
(`fonts/NotoSans/unhinted/ttf/` and `fonts/NotoSansDevanagari/unhinted/ttf/`; unhinted, because hinting does nothing in
a PDF and its tables would be copied into every embedded subset). The fonts are built from
<https://github.com/notofonts/latin-greek-cyrillic> and <https://github.com/notofonts/devanagari>.

License: SIL Open Font License 1.1, copied verbatim from those two repositories as `OFL-NotoSans.txt` and
`OFL-NotoSansDevanagari.txt`. The OFL allows bundling and embedding the fonts in documents; the files are unmodified
and keep their names.

`glyph_text.json` is generated from the font files by `backend/scripts/pdf_font_glyph_text.py` (its docstring has the
command): the text each glyph that no character maps to (a conjunct, a matra with its anusvara, a ligature) stands for.
Where a cluster's glyphs do not spell what was typed (a reordered ि, a reph folded into an i-matra), `report_fonts`
maps that cluster to its typed text at build time, so a shaped word copies and searches exactly as typed. Regenerate
the table whenever a font file changes.
