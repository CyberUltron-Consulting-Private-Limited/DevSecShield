# CBOM scan score

| metric | value |
|---|---|
| ground_truth_detect_items | 165 |
| findings_total | 154 |
| matched | 151 |
| recall | 0.9152 |
| precision | 0.9805 |
| baseline_recall | 0.9222 |
| false_positives_on_traps | 3 |
| spurious_findings | 0 |
| line_tolerance | 2 |
| skip_binaries | True |
| overall_gate_pass | False |

## Gate verdicts
_Thresholds from defaults (docs/lab-design.md has no '## Gate thresholds' section)_

| gate | value | threshold | verdict |
|---|---|---|---|
| baseline_recall | 0.922 | 0.95 | **FAIL** |
| precision | 0.981 | 0.90 | PASS |
| eva:EVA-01 | 0.833 | 0.60 | PASS |
| eva:EVA-02 | 0.800 | 0.60 | PASS |
| eva:EVA-03 | 1.000 | 0.60 | PASS |
| eva:EVA-04 | 0.800 | 0.60 | PASS |
| eva:EVA-05 | 0.750 | 0.60 | PASS |
| eva:EVA-06 | 1.000 | 0.60 | PASS |
| eva:EVA-07 | 1.000 | 0.60 | PASS |
| eva:EVA-08 | 1.000 | 0.60 | PASS |
| eva:EVA-09 | 0.900 | 0.60 | PASS |
| eva:EVA-10 | 0.000 | 0.60 | **FAIL** |
| eva:EVA-11 | 1.000 | 0.60 | PASS |
| eva:EVA-12 | 0.875 | 0.60 | PASS |
| eva:EVA-13 | 1.000 | 0.60 | PASS |
| eva:EVA-15 | 1.000 | 0.60 | PASS |

## Recall by category
| key | matched | total | recall |
|---|---|---|---|
| asymmetric | 8 | 10 | 0.800 |
| custom | 3 | 3 | 1.000 |
| dependency | 6 | 6 | 1.000 |
| hash | 29 | 31 | 0.935 |
| kdf | 1 | 1 | 1.000 |
| kms | 1 | 1 | 1.000 |
| mac | 0 | 1 | 0.000 |
| platform | 1 | 1 | 1.000 |
| rng | 6 | 7 | 0.857 |
| signature | 1 | 1 | 1.000 |
| storage | 3 | 3 | 1.000 |
| symmetric | 77 | 82 | 0.939 |
| tls | 14 | 17 | 0.824 |
| vendored | 1 | 1 | 1.000 |

## Recall by language
| key | matched | total | recall |
|---|---|---|---|
| c | 9 | 10 | 0.900 |
| csharp | 8 | 8 | 1.000 |
| dockerfile | 2 | 2 | 1.000 |
| go | 13 | 14 | 0.929 |
| groovy | 1 | 1 | 1.000 |
| java | 27 | 29 | 0.931 |
| javascript | 22 | 22 | 1.000 |
| json | 2 | 2 | 1.000 |
| jupyter | 1 | 1 | 1.000 |
| kotlin | 1 | 1 | 1.000 |
| nginx | 1 | 1 | 1.000 |
| pem | 2 | 4 | 0.500 |
| perl | 1 | 1 | 1.000 |
| php | 5 | 6 | 0.833 |
| powershell | 1 | 1 | 1.000 |
| python | 34 | 39 | 0.872 |
| ruby | 1 | 1 | 1.000 |
| scala | 1 | 1 | 1.000 |
| shell | 1 | 1 | 1.000 |
| sql | 3 | 3 | 1.000 |
| swift | 1 | 1 | 1.000 |
| terraform | 4 | 4 | 1.000 |
| text | 2 | 2 | 1.000 |
| typescript | 2 | 3 | 0.667 |
| vbnet | 1 | 1 | 1.000 |
| xml | 1 | 1 | 1.000 |
| yaml | 3 | 4 | 0.750 |
| zip | 1 | 1 | 1.000 |

## Recall by technique
| key | matched | total | recall |
|---|---|---|---|
| EVA-01 | 5 | 6 | 0.833 |
| EVA-02 | 4 | 5 | 0.800 |
| EVA-03 | 3 | 3 | 1.000 |
| EVA-04 | 4 | 5 | 0.800 |
| EVA-05 | 3 | 4 | 0.750 |
| EVA-06 | 5 | 5 | 1.000 |
| EVA-07 | 3 | 3 | 1.000 |
| EVA-08 | 5 | 5 | 1.000 |
| EVA-09 | 9 | 10 | 0.900 |
| EVA-10 | 0 | 1 | 0.000 |
| EVA-11 | 5 | 5 | 1.000 |
| EVA-12 | 7 | 8 | 0.875 |
| EVA-13 | 13 | 13 | 1.000 |
| EVA-15 | 2 | 2 | 1.000 |
| baseline | 83 | 90 | 0.922 |

## Evasion scores (variant recall / base recall)
| technique | variant recall | base recall | evasion score |
|---|---|---|---|
| EVA-01 | 0.833 | 1.000 | 0.833 |
| EVA-02 | 0.800 | 0.667 | 1.000 |
| EVA-03 | 1.000 | 1.000 | 1.000 |
| EVA-04 | 0.800 | 1.000 | 0.800 |
| EVA-05 | 0.750 | 1.000 | 0.750 |
| EVA-06 | 1.000 | 0.800 | 1.000 |
| EVA-07 | 1.000 | 1.000 | 1.000 |
| EVA-08 | 1.000 | 1.000 | 1.000 |
| EVA-09 | 0.900 | 1.000 | 0.900 |
| EVA-10 | 0.000 | 1.000 | 0.000 |
| EVA-11 | 1.000 | 1.000 | 1.000 |
| EVA-12 | 0.875 | 0.800 | 1.000 |
| EVA-13 | 1.000 | 0.875 | 1.000 |
| EVA-15 | 1.000 | 1.000 | 1.000 |

## Attribute agreement
| attribute | agreement | n |
|---|---|---|
| mode | 1.000 | 53 |
| key_bits | 1.000 | 35 |

## False positives on traps
| finding location | trap item | note |
|---|---|---|
| services/cache/key.py | COD-089 |  |
| docs/security-notes.md | COD-090 |  |
| web/src/crypto/history.js | COD-091 |  |

## Unmatched ground truth (missed detections)
| id | location | family | technique | kind |
|---|---|---|---|---|
| COD-001 | src/main/java/com/acme/pay/LegacyDes.java:5 | DES | baseline | alg-usage |
| COD-014 | src/main/java/com/acme/pay/TrustAll.java:6 | None | baseline | cert-validation-bypass |
| COD-027 | services/crypto_svc/unverified_ctx.py:3 | None | baseline | cert-validation-bypass |
| COD-040 | web/src/crypto/jwt_hs256.ts:3 | HMAC | baseline | alg-usage |
| COD-053 | native/src/rng.c:3 | None | baseline | weak-rng |
| COD-066 | deploy/tls/app.key:1 | EC | baseline | private-key |
| COD-079 | deploy/ansible/site.yml:6 | None | baseline | iac |
| COD-103 | services/crypto_svc/eva/concat1.py:4 | AES | EVA-01 | alg-usage |
| COD-116 | services/crypto_svc/eva/chain5/layer4.py:2 | AES | EVA-05 | alg-usage |
| COD-129 | services/crypto_svc/eva/key_env9.py:4 | FERNET | EVA-09 | hardcoded-key |
| COD-142 | vendored_libs/weak.py:3 | DES | EVA-12 | alg-usage |
| COD-155 | php/src/eva/reflect4.php:4 | MD5 | EVA-04 | alg-usage |
| COD-168 | go/pkg/cryptosvc/eva/prop2.go:5 | MD5 | EVA-02 | alg-usage |
| COD-191 | config/old_deploy.key:1 | RSA | EVA-10 | private-key |
