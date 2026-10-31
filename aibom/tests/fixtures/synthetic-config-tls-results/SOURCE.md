# synthetic-config-tls-results

Hand-derived 2026-10-27 from the public testssl.sh / sslyze / nmap output shapes
exercised in `test_cbom_posture_tls_import.py`. Hosts use only `example.com`,
`example.org`, `app.example.test`, and RFC 5737 `192.0.2.0/24` addresses.

## testssl/

- `vulnerable_flat.json` — testssl flat JSON; HEARTBLEED (scored) plus BEAST
  (reported-only per `_UNSCORED`).
- `not_tested.json` — top-level `not_tested` severity → `import_not_tested`.
- `legacy_protocols.json` — TLS 1.0 and 1.2 offered with fallback SCSV severity
  LOW → `DOWNGRADE_PROTECTION_MISSING` when an old protocol is offered.
- `host_ip_split.json` — host/ip `example.com/192.0.2.10` splits primary and alt
  endpoints; TLS 1.0 offered without fallback finding on this file alone.

## sslyze/

- `scan.json` — sslyze JSON export with `server_location.hostname` `example.org`
  and port `443`.

## nmap/

- `scan.xml` — minimal nmap XML export with hostname `app.example.test`, address
  `192.0.2.10`, port `8443`.

No secrets in this tree.
