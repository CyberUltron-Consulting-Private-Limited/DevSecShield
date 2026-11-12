# Round 3 plan: CBOM with no LLM, offline knowledge base, engine features, air-gap and AWS proofs

User decisions (2026-10-31): no LLM in any CBOM path; full AWS sandbox lab; build engine features + gap report against the
architecture PDF (ZS-ARCH-DSS-CBOM-2026-01); curated signed offline crypto knowledge base (not a full NVD mirror).

## Facts from exploration
- Repo/zip CBOM code scans already run the deterministic aibom engine (RabbitMQ/worker/scan_worker.py:650-674 ->
  aibom.integrations.cbom_devsecshield.scan_crypto_to_devsecshield). No LLM there.
- LLM still in the CBOM path: (1) "Analyze CBOM file" upload -> cbom_agent/main.py analyze_cbom_file -> Bedrock map-reduce
  (CBOMSummaryManager also calls the NVD API and LangSmith); (2) dev-only run_source_scan_with_llm; (3) backend
  "remediation" endpoint for cbom (backend/utilities/ai/remediation.py, scans.py:1127); (4) scan chat (scans.py:149).
- Credits still charge an LLM constant and a x1.4 binary surcharge although binaries are not scanned on repo/zip.
- UI row contract for code-scan findings: CbomFinding fields (title, description, impact, owasp_top_10 dict,
  compliance_controls dict, suggested_fix, algorithm_*, crypto_strength, key_size, quantum_safe, location, snippet,
  remediation). Dashboards aggregate dict VALUES.
- aibom already computes PQC readiness_pct for code scans; no Mosca/HNDL anywhere; scan-node runs (cbom_sources) have
  impact + finding_codes only.
- Backend image does not include aibom; worker image does.

## Design
1. Knowledge base `crypto_kb.json` (canonical: aibom/src/aibom/cbom/data/; byte-identical copy:
   backend/utilities/cbom_sources/data/) + loader `crypto_kb.py` (identical in both; equality test).
   Per finding code: title, description, attack scenario, CWE, OWASP 2021 + 2025, CVEs (only NVD-verified ids, with
   CVSS and source URL), evidence-conditioned CVE rules (e.g. RC4 -> CVE-2013-2566/CVE-2015-2808), PQC class,
   compliance refs (NIST SP 800-131A / IR 8547, CNSA 2.0, CERT-In, RBI, SEBI CSCRF) only where the research agent
   produced a source, remediation steps per platform, safe proof-of-exposure commands (read-only verification:
   openssl s_client, ssh -Q/-vv, nmap ssl-enum-ciphers, psql/mysql status), references.
   Library rules: OpenSSL/OpenSSH/GnuTLS/libgcrypt version -> CVE ranges + EOL; distro packages get VEX in_triage
   (backports), upstream builds get "affected".
   Built-in KB trusted as shipped code; update bundles (`CBOM_KB_BUNDLE`) need an Ed25519 signature checked against
   `CBOM_KB_PUBKEYS`; tool scripts/cbom_kb_sign.py. No network access, ever.
2. "Exploit demo" = proof of exposure: safe, read-only reproduction commands + attacker narrative. No weaponised
   exploit code.
3. Scan-node runs: per asset pqc_class; run posture = PQC-readiness score, class counts, Mosca X+Y>Z (settings:
   data shelf-life X, migration time Y, CRQC horizon Z with sourced default), HNDL flag on assets whose quantum-broken
   key exchange protects data in transit/at rest; business criticality per source -> risk score; per-asset finding
   detail endpoint (KB rendered with the asset's host/port/path); CycloneDX export with vulnerabilities[] + VEX
   analysis state; compliance summary per framework.
4. Code scans: aibom _enrich adds `kb` (cwe, cves, owasp_2025, remediation steps, proof) without changing legacy keys.
   Analyze CBOM file: CycloneDX components -> detections (parse_theia_components) -> deterministic KB enrichment ->
   CryptographicAssetVulnerability (same schema). Remove CBOMSummaryManager/NVD/LangSmith/Bedrock from the path.
   Backend CBOM remediation endpoint -> KB; CBOM chat off unless CBOM_ALLOW_LLM=1.
   Credits: remove the LLM constant and the binary surcharge (binaries are not scanned).
5. Frontend: finding detail panel (RunResults), posture card (readiness, Mosca, compliance), Mosca settings, KB
   detail in CbomResults.
6. Proofs: static no-LLM test over the CBOM path; air-gapped run (internal Docker network, tcpdump of the bridge,
   no DNS out) of code scan (zip via MinIO), CBOM-file analysis, scan node collection; AWS lab (Linux, Windows WinRM
   HTTPS, RDS, cloud read-only with CloudTrail proof, flow-log zero-egress proof in air-gap subnets).
7. Docs: user guide (SaaS + air-gapped), gap report vs the PDF, proofs.

## Risks
- KB facts wrong -> customer-visible errors. Mitigation: CVEs only from the NVD fetch; compliance clauses only with
  research sources; review agent checks the KB.
- Changing finding payloads can break the code-scan UI and PDF export: keep legacy keys, add new ones.
- Distro OpenSSL versions are patched by backports: never claim "affected" from a distro version alone.
- Air-gap proof must include the code-scan worker, which needs Mongo/RabbitMQ/MinIO containers.
