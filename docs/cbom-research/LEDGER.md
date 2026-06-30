# CBOM Clean-Room Provenance Ledger

Every shipped CBOM capability MUST trace to a row here. The "evidence" column is a public
spec/behavioral source (docs, papers, CycloneDX schema, tool OUTPUT) — **never copied source code**.
The "our re-implementation" column is our ORIGINAL design. This ledger is the audit trail proving the
product is clean-room: it studies OSS tools' behavior and re-implements techniques, and ships no OSS
BOM tool. OSS tools appear only as benchmark oracles in `bench/cbom/`.

| capability | source tool (studied as behavior/oracle) | public-spec / behavioral evidence (URL) | how WE re-implement (original) | gap vs current lane | story | status |
|---|---|---|---|---|---|---|
| _seed row — replace as R-stories land_ | — | — | — | — | — | pending |

## Rules
- No reading-and-pasting OSS source. Learn from docs, papers, schema, and observed output only.
- OSS tools run ONLY in `bench/cbom/` as oracles; never on the product import path.
- Each BUILD story updates its row to `implemented` with the product file path + bench oracle delta.
