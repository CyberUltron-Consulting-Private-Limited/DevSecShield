# CBOM benchmark — multi-oracle diff matrix

Canonical key = (normalized_name, asset_class). Each oracle is diffed in its own LANE, triaged against `fp-exclusions.json`:

* **cbomkit** — IBM cbomkit-theia, a FILESYSTEM scanner (certs/keys/secrets) → crypto-asset lane. Ours adds source-code algorithm usage, TLS protocols, PQC grading and tri-state compliance it structurally can't see.

* **cdxgen** — @cyclonedx/cdxgen, a DEPENDENCY-graph SBOM tool → crypto-library lane (known crypto libs only). Ours adds the stdlib crypto modules (hashlib/ssl) and source-imported libs its manifest resolution can't see.

| repo | oracle | Oracle | Ours | overlap | raw-miss | **true-miss** | our-unique |
|------|--------|-------:|-----:|--------:|---------:|--------------:|-----------:|
| 00-synthetic | cbomkit | 6 | 13 | 3 | 3 | **0** | 10 |
| 00-synthetic | cdxgen | 2 | 4 | 2 | 0 | **0** | 2 |
| 01-pyjwt | cbomkit | 9 | 13 | 2 | 7 | **0** | 11 |
| 02-pyopenssl | cbomkit | 0 | 10 | 0 | 0 | **0** | 10 |
| 02-pyopenssl | cdxgen | 1 | 4 | 1 | 0 | **0** | 3 |
| **TOTAL** | | | | | | **0** | 36 |

### TRUE MISSES — none across all repos × oracles ✅

## GATE: PASS ✅ — true-misses=0 (must be 0), our-unique=36 (must be >0)
