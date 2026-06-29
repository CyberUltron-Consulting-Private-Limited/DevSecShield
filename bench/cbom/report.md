# CBOM benchmark — diff matrix (ours vs IBM cbomkit-theia)

Canonical key = (normalized_name, asset_class). Misses = CBOMkit \ Ours; triaged against `fp-exclusions.json`. The oracle is a FILESYSTEM scanner (certs/keys/secrets); ours adds source-code algorithm usage, TLS protocols, PQC grading and tri-state compliance — hence the large our-unique column.

| repo | CBOMkit | Ours | overlap | raw-miss | **true-miss** | our-unique |
|------|--------:|-----:|--------:|---------:|--------------:|-----------:|
| 00-synthetic | 6 | 12 | 3 | 3 | **0** | 9 |
| 01-pyjwt | 9 | 13 | 2 | 7 | **0** | 11 |
| 02-pyopenssl | 0 | 10 | 0 | 0 | **0** | 10 |
| **TOTAL** | | | | | **0** | 30 |

### TRUE MISSES — none across all repos ✅

## GATE: PASS ✅ — true-misses=0 (must be 0), our-unique=30 (must be >0)
