# CERT-In Compliance Ledger

## Scope

Source: **Indian Computer Emergency Response Team (CERT-In) — Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM, Version 2.0 dated 09.07.2025** (`docs/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf`).

This ledger is the human-readable twin of `aibom/src/aibom/compliance/cert_in/ledger.yaml`. Requirement **id** sets must match exactly (enforced by `test_certin_ledger_sync`).

**Out of product scope for Phase 0+:**
- Table 8 (QBOM) — no QBOM scan type; do not invent product "QBOM" labels.
- Table 11 (HBOM) — deferred.

**Advisory only:** alignment to the guidelines does **not** constitute CERT-In certification.

## Frameworks (labels; registration is Phase 1+)

| key | label | lane |
|-----|-------|------|
| `cert_in_cbom` | CERT-In CBOM (Guidelines v2.0) | cbom |
| `cert_in_aibom` | CERT-In AIBOM (Guidelines v2.0) | aibom |
| `cert_in_sbom` | CERT-In SBOM (Guidelines v2.0) | sbom |

## Requirements

| id | pdf_anchor | title | lane | mode | missing | evidence_hint |
|----|------------|-------|------|------|---------|---------------|
| `T5-Component-Name` | Table 5 / §4.2 #1 | Component Name | sbom | auto | fail | component.name |
| `T5-Component-Version` | Table 5 / §4.2 #2 | Component Version | sbom | auto | fail | component.version |
| `T5-Component-Description` | Table 5 / §4.2 #3 | Component Description | sbom | auto | nbe | description property |
| `T5-Component-Supplier` | Table 5 / §4.2 #4 | Component Supplier | sbom | auto | fail | supplier / purl |
| `T5-Component-License` | Table 5 / §4.2 #5 | Component License | sbom | auto | fail | license field |
| `T5-Component-Origin` | Table 5 / §4.2 #6 | Component Origin | sbom | auto | nbe | origin classification |
| `T5-Component-Dependencies` | Table 5 / §4.2 #7 | Component Dependencies | sbom | auto | fail | dependency graph |
| `T5-Vulnerabilities` | Table 5 / §4.2 #8 | Vulnerabilities | sbom | auto | fail | CVE / advisory linkage |
| `T5-Patch-Status` | Table 5 / §4.2 #9 | Patch Status | sbom | auto | nbe | fix/upgrade metadata |
| `T5-Release-Date` | Table 5 / §4.2 #10 | Release Date | sbom | auto | nbe | published date |
| `T5-EOL-Date` | Table 5 / §4.2 #11 | End-of-Life (EOL) Date | sbom | auto | nbe | EOL metadata |
| `T5-Criticality` | Table 5 / §4.2 #12 | Criticality | sbom | auto | nbe | org criticality judgment |
| `T5-Usage-Restrictions` | Table 5 / §4.2 #13 | Usage Restrictions | sbom | auto | nbe | export/IP restrictions |
| `T5-Checksums-or-Hashes` | Table 5 / §4.2 #14 | Checksums or Hashes | sbom | auto | nbe | component hash |
| `T5-Comments-or-Notes` | Table 5 / §4.2 #15 | Comments or Notes | sbom | auto | nbe | annotations |
| `T5-Author-of-SBOM-Data` | Table 5 / §4.2 #16 | Author of SBOM Data | sbom | auto | fail | BOM metadata author |
| `T5-Timestamp` | Table 5 / §4.2 #17 | Timestamp | sbom | auto | fail | BOM timestamp |
| `T5-Executable-Property` | Table 5 / §4.2 #18 | Executable Property | sbom | auto | nbe | CycloneDX executable prop |
| `T5-Archive-Property` | Table 5 / §4.2 #19 | Archive Property | sbom | auto | nbe | CycloneDX archive prop |
| `T5-Structured-Property` | Table 5 / §4.2 #20 | Structured Property | sbom | auto | nbe | structured data descriptors |
| `T5-Unique-Identifier` | Table 5 / §4.2 #21 | Unique Identifier (PURL-style) | sbom | auto | fail | purl / bom-ref |
| `T5-Automation-SPDX` | Table 5 / Automation Support | SBOM emit in SPDX | sbom | auto | fail | SPDX reporter available |
| `T5-Automation-CycloneDX` | Table 5 / Automation Support | SBOM emit in CycloneDX | sbom | auto | fail | CycloneDX reporter available |
| `T5-Inventory-Tools` | Table 5 / multi-tool provenance | Inventory tooling provenance | sbom | auto | nbe | Syft and/or cdxgen ran (BOM props) |
| `T5-Vuln-Scanner` | Table 5 / multi-tool provenance | Vulnerability scanner provenance | sbom | auto | nbe | Grype ran (BOM props) |
| `T5-Multi-Format-Emit` | Table 5 / multi-tool provenance | Machine-readable SBOM artifact | sbom | auto | nbe | CycloneDX/SPDX emit evidence |
| `7.1.1` | §7.1.1 | Require SBOM in procurements | process | manual | nbe | organizational process attestation |
| `7.1.2` | §7.1.2 | Supplier must provide complete SBOM | process | manual | nbe | organizational process attestation |
| `7.1.3` | §7.1.3 | Maintain SBOM for in-use software | process | manual | nbe | organizational process attestation |
| `7.1.4` | §7.1.4 | Include §4.2 minimum data fields | process | manual | nbe | organizational process attestation |
| `7.1.5` | §7.1.5 | Emit SBOM in SPDX or CycloneDX | process | manual | nbe | organizational process attestation |
| `7.1.6` | §7.1.6 | Issue VEX on vulnerability discovery | process | manual | nbe | organizational process attestation |
| `7.1.7` | §7.1.7 | Integrate SBOM with vuln intel feeds | process | manual | nbe | organizational process attestation |
| `7.1.8` | §7.1.8 | Update SBOM for patches/mitigations | process | manual | nbe | organizational process attestation |
| `7.1.9` | §7.1.9 | Maintain per-version SBOM | process | manual | nbe | organizational process attestation |
| `7.1.10` | §7.1.10 | Map supplier SBOM to internal inventory | process | manual | nbe | organizational process attestation |
| `7.1.11` | §7.1.11 | Include SBOM in vuln management workflow | process | manual | nbe | organizational process attestation |
| `7.1.12` | §7.1.12 | Audit SBOM process accuracy | process | manual | nbe | organizational process attestation |
| `7.1.13` | §7.1.13 | Correlate SBOM with VEX status | process | manual | nbe | organizational process attestation |
| `7.1.14` | §7.1.14 | Protect SBOM data in storage/transit | process | manual | nbe | organizational process attestation |
| `7.1.15` | §7.1.15 | Keep SBOM current as components change | process | manual | nbe | organizational process attestation |
| `T9-Algorithms-Name` | Table 9 / Algorithms / Name | Algorithm Name | cbom | auto | fail | crypto asset name |
| `T9-Algorithms-AssetType` | Table 9 / Algorithms / Asset Type | Algorithm Asset Type | cbom | auto | fail | crypto:assetType=algorithm |
| `T9-Algorithms-Primitive` | Table 9 / Algorithms / Primitive | Algorithm Primitive | cbom | auto | fail | crypto:primitive |
| `T9-Algorithms-Mode` | Table 9 / Algorithms / Mode | Algorithm Mode | cbom | auto | nbe | crypto:mode |
| `T9-Algorithms-Crypto-Functions` | Table 9 / Algorithms / Crypto Functions | Algorithm Crypto Functions | cbom | auto | nbe | supported crypto functions |
| `T9-Algorithms-Classical-Security-Level` | Table 9 / Algorithms / Classical security level | Algorithm Classical security level | cbom | auto | fail | crypto:securityStrengthBits |
| `T9-Algorithms-OID` | Table 9 / Algorithms / OID | Algorithm OID | cbom | auto | nbe | algorithm OID if known else NBE |
| `T9-Algorithms-List` | Table 9 / Algorithms / List | Algorithm List | cbom | auto | nbe | algorithm list on quantum/device context |
| `T9-Keys-Name` | Table 9 / Keys / Name | Key Name | cbom | auto | fail | key material name |
| `T9-Keys-AssetType` | Table 9 / Keys / Asset Type | Key Asset Type | cbom | auto | fail | crypto:assetType related-crypto-material |
| `T9-Keys-Id` | Table 9 / Keys / id | Key id | cbom | auto | nbe | key id |
| `T9-Keys-State` | Table 9 / Keys / state | Key state | cbom | auto | nbe | active/revoked/expired |
| `T9-Keys-Size` | Table 9 / Keys / size | Key size | cbom | auto | fail | key size bits |
| `T9-Keys-Creation-Date` | Table 9 / Keys / Creation Date | Key Creation Date | cbom | auto | nbe | key creation date |
| `T9-Keys-Activation-Date` | Table 9 / Keys / Activation Date | Key Activation Date | cbom | auto | nbe | key activation date |
| `T9-Protocols-Name` | Table 9 / Protocols / Name | Protocol Name | cbom | auto | fail | protocol name |
| `T9-Protocols-AssetType` | Table 9 / Protocols / Asset Type | Protocol Asset Type | cbom | auto | fail | crypto:assetType=protocol |
| `T9-Protocols-Version` | Table 9 / Protocols / Version | Protocol Version | cbom | auto | nbe | crypto:protocolVersion |
| `T9-Protocols-Cipher-Suites` | Table 9 / Protocols / Cipher Suites | Protocol Cipher Suites | cbom | auto | nbe | crypto:cipherSuite |
| `T9-Protocols-OID` | Table 9 / Protocols / OID | Protocol OID | cbom | auto | nbe | protocol OID |
| `T9-Certificates-Name` | Table 9 / Certificates / Name | Certificate Name | cbom | auto | fail | certificate name/subject |
| `T9-Certificates-AssetType` | Table 9 / Certificates / Asset Type | Certificate Asset Type | cbom | auto | fail | crypto:assetType=certificate |
| `T9-Certificates-Subject-Name` | Table 9 / Certificates / Subject Name | Certificate Subject Name | cbom | auto | fail | crypto:subjectName |
| `T9-Certificates-Issuer-Name` | Table 9 / Certificates / Issuer Name | Certificate Issuer Name | cbom | auto | fail | crypto:issuerName |
| `T9-Certificates-Not-Valid-Before` | Table 9 / Certificates / Not Valid Before | Certificate Not Valid Before | cbom | auto | fail | crypto:notValidBefore |
| `T9-Certificates-Not-Valid-After` | Table 9 / Certificates / Not Valid After | Certificate Not Valid After | cbom | auto | fail | crypto:notValidAfter |
| `T9-Certificates-Signature-Algorithm-Reference` | Table 9 / Certificates / Signature Algorithm Reference | Certificate Signature Algorithm Reference | cbom | auto | nbe | signatureAlgorithmRef |
| `T9-Certificates-Subject-Public-Key-Reference` | Table 9 / Certificates / Subject Public Key Reference | Certificate Subject Public Key Reference | cbom | auto | nbe | subjectPublicKeyRef |
| `T9-Certificates-Certificate-Format` | Table 9 / Certificates / Certificate Format | Certificate Certificate Format | cbom | auto | nbe | X.509 format |
| `T9-Certificates-Certificate-Extension` | Table 9 / Certificates / Certificate Extension | Certificate Certificate Extension | cbom | auto | nbe | file extension |
| `8.4.1.1` | §8.4.1.1 | Require CBOM in procurements | process | manual | nbe | organizational process attestation |
| `8.4.1.2` | §8.4.1.2 | Supplier must provide complete CBOM | process | manual | nbe | organizational process attestation |
| `8.4.1.3` | §8.4.1.3 | Maintain CBOM for crypto systems | process | manual | nbe | organizational process attestation |
| `8.4.1.4` | §8.4.1.4 | Disclose crypto implementation detail | process | manual | nbe | organizational process attestation |
| `8.4.1.5` | §8.4.1.5 | Emit CBOM in SPDX or CycloneDX | process | manual | nbe | organizational process attestation |
| `8.4.1.6` | §8.4.1.6 | Issue VEX for crypto vulnerabilities | process | manual | nbe | organizational process attestation |
| `8.4.1.7` | §8.4.1.7 | Integrate CBOM with vuln intel feeds | process | manual | nbe | organizational process attestation |
| `8.4.1.8` | §8.4.1.8 | Align internal CBOM with supplier data | process | manual | nbe | organizational process attestation |
| `8.4.1.9` | §8.4.1.9 | Include CBOM in vuln management | process | manual | nbe | organizational process attestation |
| `8.4.1.10` | §8.4.1.10 | Audit CBOM completeness | process | manual | nbe | organizational process attestation |
| `8.4.1.11` | §8.4.1.11 | Cross-reference CBOM with VEX | process | manual | nbe | organizational process attestation |
| `8.4.1.12` | §8.4.1.12 | Protect CBOM data in storage/transit | process | manual | nbe | organizational process attestation |
| `8.4.1.13` | §8.4.1.13 | Update CBOM as crypto components change | process | manual | nbe | organizational process attestation |
| `T10-Model-Name` | Table 10 / Model Name | Model Name | aibom | auto | fail | ModelComponent.name |
| `T10-Model-Version` | Table 10 / Model Version | Model Version | aibom | auto | fail | ModelComponent.version |
| `T10-Model-Type` | Table 10 / Model Type | Model Type | aibom | auto | nbe | model type/task |
| `T10-Model-Developer` | Table 10 / Model Developer | Model Developer | aibom | auto | nbe | developer/org |
| `T10-Model-Licensing-Information` | Table 10 / Model Licensing Information | Model Licensing Information | aibom | auto | fail | license |
| `T10-Software-Dependencies` | Table 10 / Software Dependencies | Software Dependencies | aibom | auto | fail | framework depends_on edges |
| `T10-ML-Models-and-Algorithms` | Table 10 / ML Models and Algorithms | ML Models and Algorithms | aibom | auto | nbe | algorithm inventory |
| `T10-Model-Performance-Metrics` | Table 10 / Model Performance Metrics | Model Performance Metrics | aibom | auto | nbe | metrics properties |
| `T10-Data-Source` | Table 10 / Data Source | Data Source | aibom | auto | nbe | dataset origin |
| `T10-Data-Sets` | Table 10 / Data Sets | Data Sets | aibom | auto | nbe | trained_on datasets |
| `T10-Hardware` | Table 10 / Hardware | Hardware | aibom | auto | nbe | infra/hardware props |
| `T10-Security-Requirements` | Table 10 / Security Requirements | Security Requirements | aibom | auto | nbe | encryption/access controls |
| `T10-Input` | Table 10 / Input | Input | aibom | auto | nbe | model input modality |
| `T10-Output` | Table 10 / Output | Output | aibom | auto | nbe | model output modality |
| `T10-Intended-Usage` | Table 10 / Intended Usage | Intended Usage | aibom | auto | nbe | intended use |
| `T10-Out-of-Scope-Usage` | Table 10 / Out of Scope Usage | Out of Scope Usage | aibom | auto | nbe | prohibited uses |
| `T10-Environmental-Impact` | Table 10 / Environmental Impact | Environmental Impact | aibom | auto | nbe | energy/carbon |
| `T10-Vulnerabilities` | Table 10 / Vulnerabilities | Vulnerabilities | aibom | auto | nbe | AI component vulns |
| `T10-Attestations` | Table 10 / Attestations | Attestations | aibom | auto | nbe | digital signature / attestation |
| `9.4.1.1` | §9.4.1.1 | Require AIBOM in AI procurements | process | manual | nbe | organizational process attestation |
| `9.4.1.2` | §9.4.1.2 | Supplier must provide complete AIBOM | process | manual | nbe | organizational process attestation |
| `9.4.1.3` | §9.4.1.3 | Maintain AIBOM for AI systems | process | manual | nbe | organizational process attestation |
| `9.4.1.4` | §9.4.1.4 | Include required AIBOM elements | process | manual | nbe | organizational process attestation |
| `9.4.1.5` | §9.4.1.5 | Emit AIBOM in SPDX or CycloneDX | process | manual | nbe | organizational process attestation |
| `9.4.1.6` | §9.4.1.6 | Issue VEX for AI model vulnerabilities | process | manual | nbe | organizational process attestation |
| `9.4.1.7` | §9.4.1.7 | Integrate AIBOM with vuln intel feeds | process | manual | nbe | organizational process attestation |
| `9.4.1.8` | §9.4.1.8 | Align internal AIBOM with supplier data | process | manual | nbe | organizational process attestation |
| `9.4.1.9` | §9.4.1.9 | Include AIBOM in vuln management | process | manual | nbe | organizational process attestation |
| `9.4.1.10` | §9.4.1.10 | Audit AIBOM process accuracy | process | manual | nbe | organizational process attestation |
| `9.4.1.11` | §9.4.1.11 | Correlate AIBOM with VEX status | process | manual | nbe | organizational process attestation |
| `9.4.1.12` | §9.4.1.12 | Protect AIBOM data in storage/transit | process | manual | nbe | organizational process attestation |
| `9.4.1.13` | §9.4.1.13 | Keep AIBOM current as AI components change | process | manual | nbe | organizational process attestation |
