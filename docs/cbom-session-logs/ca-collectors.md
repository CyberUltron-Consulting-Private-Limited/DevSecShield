# CBOM certificate collectors: Venafi, Keyfactor, DigiCert, Sectigo

Date: 2026-11-16

Checked against commit `e1b30ea9` (the gap note) and built on `origin/dev` at `fbf79f7e`.

## What shipped

PR: https://github.com/CyberUltron-Consulting-Private-Limited/DevSecShield/pull/427

Head: `708e316790a62fa4eecaff3e175ba381b5122a7c`

All four are collected by the scan node. They share the `ca_connector` registry (`kinds.CA_NODE_PROVIDERS` and `collectors/ca.py`), so this is one pull request. "Other" is still not collectable: the form saves the name and API address and does not ask for a key. No cloud-worker CA collector was added. AWS Private CA is unchanged.

No secrets are in this note.

## What each collector calls

Paths are the current public docs (Trust Protection Platform Web SDK 25.1/25.3, Keyfactor Command current GET Certificates, DigiCert CertCentral Services API, Sectigo Certificate Manager REST API 25.8). The saved API address is the base in `certDomain.ts`. A suffix is added only when that address does not already end with it.

### Venafi — shipped

- Authorize: `POST {origin}/vedauth/authorize/oauth` with JSON `client_id`, `username`, `password`, and `scope` `certificate` (read). The returned `access_token` is sent as `Authorization: Bearer`.
- List: `GET {vedsdk}/certificates/` with `Limit`, `Offset`, and `OptionalFields=KeyAlgorithm,KeySize,Subject,Issuer`.
- `POST /vedsdk/certificates/Retrieve` is not called. That method requires Private Key Read and the Certificate:Manage scope, and it can return a private key.
- A listed object with X.509 fields becomes a `certificate` asset (`subject`, `issuer`, `not_before`, `not_after`, `key_alg`, `key_size`, `serial`, `self_signed` when both names are present). An object with no X.509 values is skipped and recorded as a coverage gap.

Form: API address, scan node, API integration client id, user name, password. The password is the only stored secret. Optional CA of the server certificate.

### Keyfactor — shipped

- `GET {KeyfactorAPI}/Certificates` with `QueryString`, `PageReturned`, `ReturnLimit`, `includeExpired=true`, `includeRevoked=true`, `includeMetadata=false`, `includeLocations=false`, `includeHasPrivateKey=false`.
- Headers: `Authorization: Bearer` and `x-keyfactor-requested-with: APIClient`.
- `ContentBytes` is parsed as the public certificate (`cert_facts`). A body that contains a private key is dropped and not stored.

Form: API address, scan node, API token. That token is the only stored secret.

### DigiCert — shipped

- List: `GET {services/v2}/order/certificate` with `filters[status]=issued`, `limit`, `offset`. Header `X-DC-DEVKEY`.
- Download: `GET {services/v2}/certificate/{id}/download/format/pem_nointermediate` (glossary: end-entity PEM only). The bytes are parsed with `cert_facts`.

Form: API address, scan node, CertCentral API key. That key is the only stored secret.

### Sectigo — shipped

- Search: `GET {api}/ssl/v1` with `size`, `position`, and `status` of Issued, then Expired, then Revoked (List SSL certificates: "match the requested filter").
- Download: `GET {api}/ssl/v1/collect/{sslId}?format=pemco` (certificate only, PEM). The keystore download is not called.
- Headers on every request: `login`, `password`, `customerUri`.

Form: API address, scan node, customer URI, user name, password. The password is the only stored secret.

## Honesty

A 401 or 403 fails that target (`auth_failed`) and does not fail the process. A timeout is `timeout`, including when the body never arrives, so it is not reported as "not JSON". A 2xx body that is not JSON is reported as not JSON. Empty estates stay empty. Nothing here calls an LLM.

## Tests

Local, no vendor network.

- `scan_node`: `pytest tests/test_ca_clm_collectors.py` — 10 passed (one success and one auth failure per collector, plus a non-JSON 200 and a timeout). `test_every_collector_connection_passes_the_gate` passed. `ruff check` on the new collector files passed.
- `backend`: `pytest backend/tests/test_cbom_ca_connectors_b3.py` plus `test_ca_connector_providers` and `test_aws_private_ca_connector_is_read_by_its_aws_account` — 11 passed. The wider node-keys, promises, and AWS Private CA modules were 56 passed. One export test in that run failed in this environment with `ModuleNotFoundError` inside `cdx_xml.py` while writing a run BOM; it does not touch these collectors.
- `frontend`: `caCardStatus.test.ts`, `certDomain.test.ts`, and `content/infotips.test.ts` passed. `tsc --noEmit` exited 0.
