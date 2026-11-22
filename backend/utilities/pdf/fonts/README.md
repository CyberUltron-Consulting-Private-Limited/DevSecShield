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

## How shaped text copies, by PDF reader (known limits)

Each shaped run is drawn twice over for text extraction: the glyph codes carry a ToUnicode text (what pypdf,
pdfminer and pdf.js read) and the whole run is wrapped in `/ActualText` with the typed text (what poppler, PDFium and
MuPDF read). Checked with poppler (`pdftotext`), PDFium (`pypdfium2`), pypdf, MuPDF (PyMuPDF `get_text`), pdfminer
and pdf.js on 79 Hindi, Marathi, Vietnamese, Greek and Cyrillic test strings, each as a name and a title:

- poppler, PDFium: every string copies exactly as typed, code point for code point. A letter the font draws as its
  canonical equivalent (क़ ड़ फ़ … typed as consonant + nukta but drawn with the precomposed glyph, ऴ, ị ọ ụ ẹ drawn
  as base + U+0323) keeps the glyph's own ToUnicode text but its run's `/ActualText` still carries the typed text, so
  a byte-exact search (PDFium's own find, grep on copied text) matches `बड़ा`, `फ़ोन`, `Thị`.
- pdf.js: exact, except for a space it inserts by glyph position inside a few words with a half form or a conjunct
  (`स्टेट` as `स् टेट`, `प्रदेश` as `प्र देश`).
- pypdf: exact up to canonical equivalence (it reads ToUnicode only, so `फ़` can come out precomposed and `ị`
  decomposed) and once the U+200D described next is dropped. A syllable drawn with more glyphs than it has letters
  (the font draws ई as इ plus a reph-like mark and ऐ as ए plus a vowel sign) gives its typed text to the first glyph
  and U+200D (zero width joiner, invisible) to each extra glyph, so a copied ई can carry a trailing or inner U+200D. A joiner the user typed
  right after ई/ऐ goes on the last glyph, so no glyph's text ends in one (pdf.js drops such a text).
- pdfminer: same U+200D as pypdf, plus spaces it inserts by glyph position (`कृष्ण` as `कृ ष्ण`, `Thị` as `Thi ̣`).
- MuPDF: a run that holds such a syllable, or a nukta letter drawn precomposed, can repeat its tail (`सड़क` as
  `सड़कक`): `ईमेल` copies as `ईमेलमेल`, `ऐप ऐसा` as `ऐप ऐसासा`.
  MuPDF matches the `/ActualText` against the glyph text from both ends and, when the two differ in the middle, keeps
  some glyph text as well. Spans that cover only the rewritten syllables avoid that in MuPDF but put spaces inside
  words in poppler and PDFium, and nested spans duplicate text in poppler, PDFium and MuPDF, so the whole-run span,
  which is exact in poppler and PDFium, is kept and this MuPDF repeat is a known limit. The same happens around a
  letter the font draws decomposed (ị ọ ụ ẹ, ṃ ṅ ṣ, ऴ: `Nguyễn Thị Minh` as `Nguyễn Th ị M Minh`), and MuPDF can
  break a line inside such a word (`ज़रू` / `री`). MuPDF also splits `क़िला` as `क़ि ला` in one of the two layouts.

Where readers disagree, exactness in poppler and PDFium wins (Chrome, Edge and most desktop viewers use PDFium or
poppler; review 6014645102): the tests assert those two code point for code point, pypdf up to canonical equivalence
and the U+200D above, and the others are measured, not asserted.
