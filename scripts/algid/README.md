# algid: generated algorithm-identity tables

`algid.py` answers "which algorithm is this identifier, and is it quantum-safe?" for every lane: the scan node
(`scan_node/zs_scan_node/algid.py`), the backend (`backend/utilities/cbom_sources/algid.py`) and the code lane
(`aibom/src/aibom/cbom/algid.py`). The three copies are byte-identical (`backend/tests/test_algid.py`), because
those packages cannot import each other.

The tables between the `BEGIN/END GENERATED` markers come from `build_algid.py` and the files in `sources/`.
Never edit a table by hand: change or re-capture a source, then

    python3 scripts/algid/build_algid.py            # rewrite all three copies
    python3 scripts/algid/build_algid.py --check    # what the backend test runs

`build_algid.py` refuses a source that has no `sources/SOURCES.json` entry or whose sha256 differs from it.
After re-capturing a file, update its `sha256` and `retrieved_utc` in `SOURCES.json`.

| Source | How it is captured |
|---|---|
| `iana-*.csv` | `curl -sS -L -o <file> <url>` (URLs in `SOURCES.json`); the registry CSV as published |
| `nist-csor-oids.json`, `aws-elb-pq-policies.json`, `aws-apigw-pq-policies.json` | `curl` the raw pages (URLs inside each file) into a folder outside the repo, then `extract_html.py <that folder>`. Only the normalised extract is committed; it records each raw page's sha256. `ALGID_RAW_DIR=<folder> pytest backend/tests/test_algid.py -k raw` proves an extract was made from those bytes |
| `botocore-enums.json` | `capture_botocore_enums.py`, run with the backend's pinned botocore (command in its docstring) |
| `openssl-3.5-text.json`, `openssl-3.0-text.json` | `make_capture_certs.sh` (inside `python:3.12-slim`, OpenSSL 3.5) writes one throwaway certificate per algorithm, `make_oid_only_certs.py` adds composite/HashML-DSA/GOST ones, then `capture_openssl_text.py <dir>` with each OpenSSL version on PATH (the certificate goes to OpenSSL on stdin). Keys never leave the temporary directory |
| `openssh-kex-aliases.txt` | `ssh -V; ssh -Q kex` with OpenSSH 10.0 |
| `curated.json` | by hand; every section cites its document. Changes get a second-agent review recorded in the PR |

Registry churn (a new IANA row in a watched range, a new botocore enum value) is caught by a nightly diff
of the live registries against `sources/` (owner: CB-35).
