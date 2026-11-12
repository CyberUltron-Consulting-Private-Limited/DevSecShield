# Corpus labels: authorship and review (O-9)

| Part | Author | Second agent |
|---|---|---|
| The corpus files and their item comments (`// J3 static zero IV` ...): what is planted, where, and that it is a weakness | contradiction reviewer 2 of the CBOM plan, 2026-11-12 (`round6/cbom/cx2/corpus`, `contradiction-2-hidden-failure.md` H2); not a product author | CB-07 builder: read every item against its line (this table) |
| `labels.json` id, file, line, label | transcribed by `lane.labels.corpus_cases` from those comments; checked against the corpus on every run (a moved, added or removed item stops the lane) | mechanical, no judgement |
| `labels.json` `category`, `lines` of F1, `language`, the negative item NFP1, the library list | CB-07 builder | **the PR's code/QA reviewer** records the review below (O-9: a different agent from the author) |

## Item check by the CB-07 builder (each label read against its line)

All 57 comment items name a real weakness on the commented line. Notes where the location needs a decision:

* **F1** (`iac/cfn/template.yaml`): the weakness is an *absent* `BucketEncryption`; the comment sits on line 6
  (`BucketName`), the resource starts on line 3. `lines: [3, 6]`: a finding may point at the resource or the comment.
* **J3, J12**: declared on one line, used on the next (24/25, 68/69); the line tolerance 1 covers the use.
* **G2/G3** share line 19 (3DES with a literal key): two items, two findings needed.
* **G10** (weak suites, line 28) is a field of the `tls.Config` literal whose `MinVersion` (line 27) the engine
  reports; tolerance 1 lets a suite finding on 27 count.
* **J7** `SHA1withRSA` is labelled `broken_hash`: the weakness is the SHA-1 digest; a finding that names only "RSA"
  does not fit (codemap `broken_hash` needs a hash name).
* **N12** `Rfc2898DeriveBytes(p, salt, 1000)`: 1,000 iterations of PBKDF2-HMAC-SHA1; labelled by the corpus author
  as a weakness (`weak_kdf_iterations`).
* **NFP1** (negative, line 16, `public void TrustAll()`): the engine's `java.trustall` pattern matches this C#
  method name (contradiction-2 H2). The real validation bypass is N7 on line 17. A certificate-validation finding on
  line 16 is a false positive.
* Findings the engine reports that the corpus does not label (e.g. the literal RC4 key `"secretkey"` on
  `go/main.go:23`) are **extras**: not counted against the engine, but a new extra fails `NR-CORPUS-no-new-extras`.

## Libraries
Name and version exactly as in the manifests (checked on every run). Whether a version is vulnerable is never
written here: it is OSV.dev's answer at run time (`osv.json` in the work directory, `osv_answers` in report.json).

## Second-agent review
Reviewer, date, verdict and any changed rows are recorded here by the reviewing agent.
