"""CB-07 D1 benchmark lane: the judge.

Everything in this package is standard-library Python and imports nothing from the product (backend/, aibom/,
scan_node/, frontend/, RabbitMQ/): expected values come only from the benchmarks' own published labels, the
independently written corpus labels and OSV answers at test time (round6 DEVILS-ADVOCATE.md §3, O-1/O-2).
`bench/cbom/d1/run_product.py` is the only file of the lane that runs the product.
"""

SCHEMA_OBSERVED = "zs-cbom-d1-observed/1"
SCHEMA_CASES = "zs-cbom-d1-cases/1"
SCHEMA_REPORT = "zs-cbom-d1-report/1"
SCHEMA_FLOORS = "zs-cbom-d1-floors/1"
SCHEMA_CODEMAP = "zs-cbom-d1-codemap/1"
SCHEMA_SOURCES = "zs-cbom-d1-sources/1"
SCHEMA_CORPUS = "zs-cbom-d1-corpus-labels/1"
SCHEMA_OSV = "zs-cbom-d1-osv/1"

BENCHES = ("cryptoapi-bench", "owasp-benchmark", "corpus")
