# Corpus labels: authorship and review (O-9)

| Part | Author | Second agent |
|---|---|---|
| The corpus files and their item comments (`// J3 static zero IV` ...): what is planted, where, and that it is a weakness | contradiction reviewer 2 of the CBOM plan, 2026-11-12 (`round6/cbom/cx2/corpus`, `contradiction-2-hidden-failure.md` H2); not a product author | CB-07 builder: read every item against its line (this table) |
| `labels.json` id, file, line, label | transcribed by `lane.labels.corpus_cases` from those comments; checked against the corpus on every run (a moved, added or removed item stops the lane) | mechanical, no judgement |
| `labels.json` `category`, `lines` of F1 and J9, `language`, the negative item NFP1, the library list | CB-07 builder | **the PR's code/QA reviewer**: accepted in review 5878689101, recorded below (O-9: a different agent from the author) |

## Item check by the CB-07 builder (each label read against its line)

All 57 comment items name a real weakness on the commented line. Notes where the location needs a decision:

* **F1** (`iac/cfn/template.yaml`): the weakness is an *absent* `BucketEncryption`; the comment sits on line 6
  (`BucketName`), the resource starts on line 3. `lines: [3, 6]`: a finding may point at the resource or the comment.
  Since 2023-01-05 S3 encrypts every new bucket with SSE-S3, so "no BucketEncryption" means a provider-managed key,
  not plaintext: the product's `PROVIDER_MANAGED_KEY` is the right reading, although the lane category is called
  `unencrypted_at_rest` (codemap: "storage without encryption at rest, or only the provider's default key").
* **J9** (trust-all TrustManager): the comment and the anonymous `X509TrustManager` are on line 57; the empty
  `checkServerTrusted(...) {}` a detector reports is on line 59 (CryptoAPI-Bench labels its trust-manager cases by
  that method: 5.1.1 `checkServerTrusted()`, 5.1.2 `checkClientTrusted(), checkServerTrusted()`). `lines: [57, 59]`
  (review 5878689101). J1 (DES/ECB) is declared on line 14 (`TRANSFORM`) and used on 17, the commented line; the
  product reports 17, so it stays `line: 17`.
* **J3, J12**: declared on one line, used on the next (24/25, 68/69); the line tolerance 1 covers the use.
* **G2/G3** share line 19 (3DES with a literal key): two items, two findings needed.
* **G10** (weak suites, line 28) is a field of the `tls.Config` literal whose `MinVersion` (line 27) the engine
  reports; tolerance 1 lets a suite finding on 27 count.
* **J7** `SHA1withRSA` is labelled `broken_hash`: the weakness is the SHA-1 digest; a finding that names only "RSA"
  does not fit (codemap `broken_hash` needs a hash name).
* **N12** `Rfc2898DeriveBytes(p, salt, 1000)`: 1,000 iterations of PBKDF2-HMAC-SHA1; labelled by the corpus author
  as a weakness (`weak_kdf_iterations`). The label rests on the OWASP Password Storage Cheat Sheet (1,300,000
  iterations for PBKDF2-HMAC-SHA1); 1,000 meets only NIST SP 800-132's minimum of 1,000.
* **NFP1** (negative, line 16, `public void TrustAll()`): the engine's `java.trustall` pattern matches this C#
  method name (contradiction-2 H2). The real validation bypass is N7 on line 17. A certificate-validation finding on
  line 16 is a false positive.
* Findings the engine reports that the corpus does not label (e.g. the literal RC4 key `"secretkey"` on
  `go/main.go:23`) are **extras**: not counted against the engine, but a new extra fails `NR-CORPUS-no-new-extras`.

## Libraries
Name and version exactly as in the manifests (checked on every run). Whether a version is vulnerable is never
written here: it is OSV.dev's answer at run time (`osv.json` in the work directory, `osv_answers` in report.json).

## Second-agent review (O-9)

Recorded from PR #97 review 5878689101 (2026-11-12, on 2d02668), "O-9 second-agent record", as the reviewer asked:

> Reviewer: PR #97 code/QA reviewer (agent), 2026-11-12, this review.
>
> I read all 57 comment items and NFP1 against their lines. They are byte-identical to `round6/cbom/cx2/corpus`.
> Categories, the F1 `lines`, the NFP1 negative and the library rows are **accepted**, with two changes requested:
> * J9 `lines` (the [minor] on labels.json);
> * REVIEW.md notes for F1 and N12.
>
> Ten items checked against sources:
> 1. **T1** `ELBSecurityPolicy-2016-08` allows TLS 1.0. The AWS ALB security-policy table reads "No | Yes | Yes | Yes"
>    for TLS 1.3 | 1.2 | 1.1 | 1.0.
> 2. **F1** Since 2023-01-05 S3 encrypts every new bucket with SSE-S3, so "no BucketEncryption" means a provider-managed
>    key, not plaintext. The product's `PROVIDER_MANAGED_KEY` is the right reading. Note this in REVIEW.md, because
>    the category is called `unencrypted_at_rest`.
> 3. **N12** 1,000 iterations meets NIST SP 800-132's minimum of 1,000. It is far below OWASP's 1,300,000 for
>    PBKDF2-HMAC-SHA1. The label stands on OWASP's guidance; cite it.
> 4. **J4** `Cipher.getInstance("AES")` is AES/ECB/PKCS5Padding on SunJCE.
> 5. **N8** `SecurityProtocolType.Tls` is TLS 1.0.
> 6. **N6** `RSAEncryptionPadding.Pkcs1` is PKCS#1 v1.5.
> 7. **G10** Probe: replacing line 28 (`CipherSuites`) removes `WEAK_CIPHER_SUITE` from the line-27 row. Today's hit is
>    real, not a code attached to TLS 1.0 (`rv-97/probe/g10`).
> 8. **NFP1** `verification_patterns.json:69` is the literal `"TrustAll"`. Line 16 is the C# method name and the bypass
>    is N7 on line 17, so the negative is right.
> 9. **C3** The product reports `WEAK_ALGORITHM` RC4 and MD5 on line 11, not `WEAK_CIPHER_SUITE`. A miss under the code
>    map, consistent with cx2 H2 and DA CB-28.
> 10. **J9** The empty `checkServerTrusted` is on line 59; see the [minor].
>
> `iac/terraform/main.tf` lines 7 and 36 put several arguments on one line. python-hcl2 parses the file, so there is
> no impact today. I did not run terraform; consider one argument per line before CB-28 adds an HCL-parsing detector.

Rows changed after the review: J9 `lines: [57, 59]`; notes added above for F1, J9 (with J1) and N12. The corpus
files are unchanged (still byte-identical to `round6/cbom/cx2/corpus`).
