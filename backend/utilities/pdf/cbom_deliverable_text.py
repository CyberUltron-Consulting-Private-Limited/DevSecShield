"""Authored text for the six team-wide CBOM regulatory deliverables (WP2).

Everything a regulator might read that is *words rather than data* lives here, so it can be
reviewed and pinned in one place: tool identity, disclaimers, banners, framework labels,
finding-code labels and actions, the post-quantum timeline, the grade formula, the scanner
table, the manual-discovery checklist and the per-document guidance paragraphs.

Provenance rule (plan 5.7).  Every standards or regulatory claim carries a one-line comment of
the form ``# Source: <what it supports>: <public URL>`` directly above it.  Statements about
the product's own behaviour carry ``# Product text:`` and name the code they describe.  Only
public specifications, papers and vendor-neutral references are cited; nothing is copied from
open-source scanner code.  ``test_cbom_deliverable_common.py`` allow-lists every URL below, so
adding a source is a deliberate act.

Conventions for renderers.

* All strings here are RAW text (no markup).  Pass them through ``pdf_text`` (Paragraph cells)
  or ``pdf_plain`` (helpers that escape for themselves) like any other string.
* Typed for Helvetica/WinAnsi: no characters outside WinAnsi (``\\u00b7`` and ``\\u2014`` are
  fine).  A test fails if a sentence here would turn into ``?`` in the PDF.
* Tool identity is "DevSecShield CBOM engine"; the internal engine package name must never
  appear in a document.
* IR 8547 is an *initial public draft*: every printable mention says so (decision D-06).
* Templates use ``str.format`` named fields; the renderer supplies the numbers.

Which document uses what: ``#1`` scope register: ``SCOPE_*``, ``MANUAL_DISCOVERY_ITEMS``;
``#3`` methodology: ``METHOD_*``, ``CBOM_SCANNERS``, ``MANUAL_DISCOVERY_ITEMS``, ``RACI_*``;
``#7`` certificate register: ``CERT_*``, ``EXPIRY_BAND_*``; ``#10`` assurance register:
``ASSURANCE_*``, ``VERDICT_LABELS``; ``#15`` PQC roadmap: ``PQC_*``, ``CNSA_*``;
``#16`` board report: ``GRADE_*``, ``GOVERNANCE_ACTIONS``, ``FRAMEWORK_LABELS``,
``RBI_MAPPING_NOTE``, ``finding_label`` / ``finding_action``.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------------------------
# Public source URLs (each one is repeated in a "# Source:" comment where it is relied on)
# ---------------------------------------------------------------------------------------------
# Source: NIST IR 8547 initial public draft (Nov 2024), transition tables: https://csrc.nist.gov/pubs/ir/8547/ipd
URL_NIST_IR_8547 = "https://csrc.nist.gov/pubs/ir/8547/ipd"
# Source: NIST PQC project, FIPS 203/204/205 released Aug 2024: https://www.nist.gov/pqcrypto
URL_NIST_PQC = "https://www.nist.gov/pqcrypto"
# Source: NSA CNSA 2.0 advisory (PP-22-1338): https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF
URL_CNSA_2_0 = "https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF"
# Source: CERT-In Technical Guidelines SBOM/QBOM/CBOM/AIBOM/HBOM v2.0 (09.07.2025): https://cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf
URL_CERT_IN_TG = "https://cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf"

# ---------------------------------------------------------------------------------------------
# Identity, manual-cell conventions, banners
# ---------------------------------------------------------------------------------------------
# Product text (decision D-05): the BOM metadata carries a stale internal tool name, so every
# document names the product instead.
TOOL_NAME = "DevSecShield CBOM engine"

ASSESSOR_SUFFIX = "(assessor)"
MANUAL_CELL_NOTE = "To be completed by assessor"
MANUAL_LEGEND = (
    "Cells marked (assessor) are MANUAL: they are intentionally left blank for the assessor "
    "to complete and are never pre-filled by the platform."
)
EMPTY_TABLE_TEXT = "No entries"
PREVIOUSLY_SEEN_TITLE = "Previously seen, not in latest scan"
LEGACY_TARGET_UNAVAILABLE = "not available \u2014 legacy scan"
IDENTITY_WEAK_NOTE = "identity weak \u2014 no X.509 fields"
# Plan 4.5, failed-latest rule: the register uses the older successful scan and says so.
SOURCE_FAILED_LATEST = (
    "most recent attempt failed on {failed_date} (scan #{failed_scan_id}); "
    "figures reflect scan #{current_scan_id} of {current_date}"
)

# Plan 4.6: an empty team gets a clear banner and never a grade.
BANNER_EMPTY_TITLE = "NO COMPLETED CBOM SCANS"
BANNER_EMPTY_TEXT = (
    "This document is empty because no scan has completed; it is not evidence that no "
    "cryptographic assets exist. Every count is zero and no risk grade is assigned."
)
BANNER_REDUCED_TITLE = "REDUCED-FIDELITY DATA"
BANNER_REDUCED_TEXT = (
    "Every included scan is in legacy format (produced before the current CBOM engine). "
    "Certificate details, compliance results and post-quantum target sizing may be "
    "incomplete. Re-scan the affected sources to restore full detail."
)

# Document-control labels (plan 5.4) and the Basis box templates.
CONTROL_LABELS = {
    "document": "Document",
    "document_id": "Document ID",
    "team": "Team",
    "generated": "Generated (UTC+IST)",
    "window": "Data window",
    "basis": "Basis",
    "template": "Template version",
    "fingerprint": "Data fingerprint",
}
DATA_WINDOW_NONE = "No completed CBOM scans"
BASIS_HEADING = "Basis"
BASIS_CONTROL_SUMMARY = "Team-wide roll-up of successful CBOM scans (see the Basis box)"
BASIS_SCANS = (
    "Scans: {included} included of {eligible} eligible \u00b7 excluded: {failed} failed, "
    "{not_completed} not completed, {no_data} without data"
)
# a CBOM Sources collection counts as an included scan and a source (cbom_team_rollup.merge_collections)
BASIS_SCANS_COLLECTIONS = " \u00b7 of which {collections} are CBOM Sources collections"
BASIS_SOURCES = "Sources: {sources}"
BASIS_FIDELITY = "Fidelity: {full} full / {reduced} legacy-format"
BASIS_HISTORY = "History: {folded} scans folded"
BASIS_HISTORY_TRUNCATED = " (truncated: {truncated} older not folded)"
BASIS_RULE = (
    "Rule: current state = latest successful scan per source; first/last seen over history; "
    "certificates de-duplicated across sources"
)

# ---------------------------------------------------------------------------------------------
# Disclaimers (plan 5.4).  The first two mirror existing product constants and are pinned to
# them by a contract test; the third states the method's scope.
# ---------------------------------------------------------------------------------------------
DISCLAIMER_HEADING = "Disclaimer"
# Product text: mirror of backend/utilities/pdf/certin_compliance_pdf.py _CERTIN_DISCLAIMER.
# Source: title and issue date of the CERT-In guideline (Version 2.0, 09.07.2025): https://cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf
CERTIN_DISCLAIMER = (
    "Advisory mapping to CERT-In Technical Guidelines on SBOM, QBOM & CBOM, "
    "AIBOM and HBOM v2.0 (09.07.2025). Does not constitute CERT-In certification "
    "or regulatory approval."
)
# Product text: mirror of backend/utilities/dashboard/rbi_posture.py _ADVISORY_DISCLAIMER.
RBI_BOM_DISCLAIMER = (
    "Advisory mapping only. BOM evidence supports but does not satisfy "
    "regulatory obligations. Organizational/process controls require attestation."
)
# Product text: the scanners are static (aibom/src/aibom/cbom/scanners/); nothing probes a
# live network, a key-management system or stored data.
SCOPE_OF_METHOD = (
    "Method: static analysis of repositories and uploaded artefacts, including declared "
    "infrastructure and server configuration (documents #5, #6 and #9) and offline import "
    "of TLS result files. It does not include live-network discovery, inspection of HSM "
    "or KMS custody, or inspection of stored data."
)
DISCLAIMER_PARAGRAPHS = (CERTIN_DISCLAIMER, RBI_BOM_DISCLAIMER, SCOPE_OF_METHOD)

# CBOM Sources collections in scope (M1x): the method statements may only deny what did not happen.
_CLOUD_KINDS = frozenset({"aws_account", "azure_subscription", "gcp_project"})
_KEY_CUSTODY_KINDS = _CLOUD_KINDS | {"key_manager"}


def collections_in_scope(view: object) -> tuple:
    """The view's CBOM Sources collections (``TeamCbomView.collections``), () for a hand-made view."""
    found = getattr(view, "collections", ()) or ()
    return tuple(found) if isinstance(found, (tuple, list)) else ()


def endpoints_probed(view: object) -> int:
    return sum(int(getattr(c, "endpoints_probed", 0) or 0) for c in collections_in_scope(view))


def sources_sentence(view: object) -> str:
    """One sentence on what the CBOM Sources collections in scope did ("" when there are none)."""
    found = collections_in_scope(view)
    if not found:
        return ""
    names = ", ".join(str(getattr(c, "label", "")) for c in found[:5])
    more = f" and {len(found) - 5} more" if len(found) > 5 else ""
    cloud = any(getattr(c, "source_kind", "") in _CLOUD_KINDS for c in found)
    probed = endpoints_probed(view)
    noun = "collection" if len(found) == 1 else "collections"
    reader = "the team's scan nodes and the ZeroShield cloud worker" if cloud else "the team's scan nodes"
    probes = (f" {probed} endpoint{'' if probed == 1 else 's'} {'was' if probed == 1 else 'were'} probed with live "
              "TLS or SSH handshakes." if probed else " No endpoint was probed.")
    return f"CBOM Sources: {len(found)} {noun} ({names}{more}) read by {reader}.{probes}"


def _join_negatives(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " or " + items[-1]


def scope_of_method(view: object) -> str:
    """``SCOPE_OF_METHOD``, or its CBOM Sources variant: it never says live discovery is excluded when a Sources
    collection probed an endpoint."""
    found = collections_in_scope(view)
    if not found:
        return SCOPE_OF_METHOD
    kinds = {getattr(c, "source_kind", "") for c in found}
    negatives = []
    if not endpoints_probed(view):
        negatives.append("live-network discovery")
    if not kinds & _KEY_CUSTODY_KINDS:
        negatives.append("inspection of HSM or KMS custody")
    negatives.append("inspection of stored data")
    return (
        "Method: static analysis of repositories and uploaded artefacts, including declared infrastructure and "
        "server configuration (documents #5, #6 and #9), offline import of TLS result files, and collection from the "
        f"team's own systems. {sources_sentence(view)} It does not include {_join_negatives(negatives)}."
    )


def disclaimer_paragraphs(view: object) -> tuple[str, ...]:
    return (CERTIN_DISCLAIMER, RBI_BOM_DISCLAIMER, scope_of_method(view))

# ---------------------------------------------------------------------------------------------
# Compliance framework labels (#16 regulatory exposure, #10 ledger)
# ---------------------------------------------------------------------------------------------
# Product text: mirrors frontend/components/compliance/frameworkLabels.ts (pinned by T-CON-3);
# keys are aibom CBOM_FRAMEWORKS in engine order.
FRAMEWORK_LABELS = {
    "nist_1800_38b": "NIST SP 1800-38B",
    "nist_800_57": "NIST SP 800-57",
    "omb_m_23_02": "OMB M-23-02",
    "eu_cra": "EU CRA",
    "eu_dora": "EU DORA",
    "pci_dss_4": "PCI-DSS 4.0",
    "fips_140_3": "FIPS 140-3",
    "bsi_tr_02102": "BSI TR-02102",
    "nist_1800_38c": "NIST SP 1800-38C",
    "cnsa_2_0": "CNSA 2.0",
    "rbi_free_ai_protection": "RBI FREE-AI (Protection)",
    "cert_in_cbom": "CERT-In CBOM (Guidelines v2.0)",
    "sebi_cscrf_cbom": "SEBI CSCRF (CBOM)",
}
# Product text: the registered RBI framework is the FREE-AI protection mapping
# (aibom/src/aibom/cbom/compliance.py, _S_RBI).  Deliberately does not name other RBI
# programmes: the report must never imply coverage the engine does not assess.
RBI_MAPPING_NOTE = (
    "RBI rows show the RBI FREE-AI protection mapping only (Rec 19 and the RBI Cyber Security "
    "Framework, 2016). They are not an assessment against any other RBI directive."
)
# Product text: aibom compliance verdicts (aibom/src/aibom/compliance/base.py Verdict).
VERDICT_LABELS = {
    "fail": "Fail",
    "not_bom_evidenceable": "Not evidenceable from BOM",
    "pass_with_evidence": "Pass with evidence",
    "pass": "Pass",
    "out_of_scope": "Out of scope",
    "na": "Not applicable",
}


def framework_label(key: object) -> str:
    """Display label for a framework key; unknown keys degrade to the key with spaces."""
    text = str(key).strip() if key is not None else ""
    if not text:
        return ""
    return FRAMEWORK_LABELS.get(text) or text.replace("_", " ")


# ---------------------------------------------------------------------------------------------
# Finding codes: label + recommended action (#7, #15, #16)
# ---------------------------------------------------------------------------------------------
GENERIC_FINDING_ACTION = (
    "Review this finding and remediate it in line with your cryptographic policy."
)
# Product text: codes are raised by aibom/src/aibom/cbom/weakness.py and pqc_scan.py, plus the
# three library codes.
FINDING_LABELS = {
    "WEAK_ALGORITHM": "Weak or deprecated algorithm",
    "WEAK_CIPHER_MODE": "Weak cipher mode (ECB)",
    "WEAK_KEY_SIZE": "Undersized key",
    "WEAK_PROTOCOL": "Weak protocol version",
    "WEAK_CIPHER_SUITE": "Weak cipher suite or key exchange",
    "WEAK_RNG": "Non-cryptographic random number generator",
    "STATIC_IV": "Static or predictable IV",
    "REUSED_NONCE": "Reused nonce",
    "HARDCODED_KEY": "Hard-coded key material",
    "WEAK_PADDING": "Weak RSA encryption padding",
    "WEAK_CERTIFICATE_SIGNATURE": "Certificate signed with a weak hash",
    "WEAK_CERTIFICATE_KEY": "Certificate with an undersized key",
    "SELF_SIGNED_LEAF": "Self-signed leaf certificate",
    "CERT_SELF_SIGNED": "Self-signed certificate",
    "EXPIRED_CERTIFICATE": "Expired certificate",
    "CERT_NEAR_EXPIRY": "Certificate nearing expiry",
    "QUANTUM_VULNERABLE": "Quantum-vulnerable public-key algorithm",
    # Product text: library findings from crypto_advisory_scan.py and artifact_scan.py.
    "VULNERABLE_CRYPTO_LIBRARY": "Crypto library version with a published advisory",
    "LIBRARY_CVE_RANGE": "Crypto library version inside a published CVE range",
    "EOL_CRYPTO_LIBRARY": "End-of-life crypto library branch",
    # Product text: private algorithm constants (aibom/src/aibom/cbom/scanners/custom_crypto_scan.py).
    "CUSTOM_CRYPTO": "Home-grown or private cryptographic algorithm",
}
FINDING_ACTIONS = {
    # Source: SP 800-131A Rev 2, transitioning algorithms and key lengths: https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
    "WEAK_ALGORITHM": (
        "Replace the algorithm with an approved one (for example AES-GCM, SHA-256 or SHA-3, "
        "ECDSA or RSA-3072) and retire the weak primitive."
    ),
    # Source: SP 800-38A, ECB maps identical plaintext blocks to identical ciphertext: https://csrc.nist.gov/pubs/sp/800/38/a/final
    "WEAK_CIPHER_MODE": (
        "Use an authenticated mode such as AES-GCM. ECB encrypts identical plaintext blocks "
        "to identical ciphertext blocks and exposes patterns in the data."
    ),
    # Source: SP 800-57 Part 1 Rev 5, comparable security strengths: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
    "WEAK_KEY_SIZE": (
        "Use RSA, DSA or Diffie-Hellman keys of at least 2048 bits (3072 bits for 128-bit "
        "security) or an approved elliptic curve."
    ),
    # Source: RFC 8996, TLS 1.0 and 1.1 deprecated: https://www.rfc-editor.org/rfc/rfc8996
    # Source: RFC 7568, SSL 3.0 is not sufficiently secure: https://www.rfc-editor.org/rfc/rfc7568
    "WEAK_PROTOCOL": (
        "Disable SSL and TLS 1.0/1.1 and require TLS 1.2 or later, preferring TLS 1.3."
    ),
    # Source: RFC 7465, RC4 cipher suites must not be negotiated: https://www.rfc-editor.org/rfc/rfc7465
    # Source: SP 800-52 Rev 2, 3DES suites not allowed, prefer ephemeral keys and GCM/CCM: https://csrc.nist.gov/pubs/sp/800/52/r2/final
    "WEAK_CIPHER_SUITE": (
        "Remove suites that use RC4, 3DES, NULL encryption, anonymous key exchange or "
        "export-grade keys, and Diffie-Hellman groups with less than 112 bits of security. "
        "Prefer ephemeral key exchange (forward secrecy) with GCM or CCM modes."
    ),
    # Source: CWE-338, cryptographically weak PRNG: https://cwe.mitre.org/data/definitions/338.html
    "WEAK_RNG": (
        "Draw keys, IVs, nonces and salts from the operating system's cryptographically "
        "secure generator (for example os.urandom, secrets or SecureRandom)."
    ),
    # Source: CWE-329, predictable IV with CBC mode: https://cwe.mitre.org/data/definitions/329.html
    "STATIC_IV": (
        "Generate a fresh, unpredictable IV or nonce for every encryption; never hard-code "
        "or reuse one."
    ),
    # Source: CWE-323, reusing a nonce with the same key: https://cwe.mitre.org/data/definitions/323.html
    # Source: SP 800-38D, GCM requires a unique IV per key: https://csrc.nist.gov/pubs/sp/800/38/d/final
    "REUSED_NONCE": (
        "Never reuse a nonce with the same key. Derive a unique nonce per message; reuse "
        "voids the guarantees of modes such as AES-GCM."
    ),
    # Source: CWE-321, hard-coded cryptographic key: https://cwe.mitre.org/data/definitions/321.html
    "HARDCODED_KEY": (
        "Remove keys from source code, load them from a key-management service or secret "
        "store, and rotate any key that was committed."
    ),
    # Source: RFC 8017, RSAES-OAEP required for new applications, v1.5 for compatibility only: https://www.rfc-editor.org/rfc/rfc8017
    # Source: CWE-780, RSA without OAEP: https://cwe.mitre.org/data/definitions/780.html
    "WEAK_PADDING": (
        "Use RSA-OAEP for encryption. PKCS#1 v1.5 encryption padding is kept only for "
        "compatibility with existing applications, and RSA without padding must not be used."
    ),
    # Source: RFC 6151, MD5 collision attacks: https://www.rfc-editor.org/rfc/rfc6151
    # Source: NIST retires SHA-1, move to SHA-2/SHA-3: https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm
    "WEAK_CERTIFICATE_SIGNATURE": (
        "Reissue the certificate with a SHA-256 or stronger signature."
    ),
    # Source: SP 800-131A Rev 2, minimum key lengths: https://csrc.nist.gov/pubs/sp/800/131/a/r2/final
    "WEAK_CERTIFICATE_KEY": (
        "Reissue the certificate with an RSA key of at least 2048 bits or an approved "
        "elliptic curve."
    ),
    # Source: RFC 5280, trust comes from path validation to a trust anchor: https://www.rfc-editor.org/rfc/rfc5280
    "SELF_SIGNED_LEAF": (
        "Replace it with a certificate issued by a trusted CA; reserve self-signed "
        "certificates for local testing."
    ),
    # Product decision: a self-signed certificate is Low (scan-node CERT_SELF_SIGNED); its own SHA-1 signature is
    # never verified, so it is not a weak-signature finding
    "CERT_SELF_SIGNED": (
        "Issue it from a trusted CA before relying on it in production; if it is signed with SHA-1, re-issue it "
        "with SHA-256 so policies and scanners stop flagging it."
    ),
    # Source: RFC 5280, certificate validity period: https://www.rfc-editor.org/rfc/rfc5280
    "EXPIRED_CERTIFICATE": "Renew the certificate, or remove it if it is no longer used.",
    # Product text: the engine does not raise this code today (register computes the bands).
    "CERT_NEAR_EXPIRY": "Schedule renewal before the expiry date.",
    # Source: NIST PQC project, FIPS 203/204/205 are the migration targets: https://www.nist.gov/pqcrypto
    "QUANTUM_VULNERABLE": (
        "Inventory where it is used and plan migration to the NIST post-quantum standards "
        "(ML-KEM, ML-DSA, SLH-DSA), prioritising systems that protect long-lived data."
    ),
    # Product text: the finding names the advisories and the first release that fixes all of them.
    "VULNERABLE_CRYPTO_LIBRARY": (
        "Upgrade the library to the fixed release named in the finding (or later) and rebuild; "
        "where an advisory has no fixed release, replace the library."
    ),
    # Product text: distributions back-port fixes without changing the upstream version number.
    "LIBRARY_CVE_RANGE": (
        "Check the distribution's security tracker for a back-ported fix; if there is none, "
        "update the package to a fixed release."
    ),
    # Product text: an end-of-life branch receives no further security fixes.
    "EOL_CRYPTO_LIBRARY": (
        "Move to a supported release branch of the library; the end-of-life branch receives "
        "no security fixes."
    ),
    # Source: CWE-1240, use of a cryptographic primitive with a risky implementation: https://cwe.mitre.org/data/definitions/1240.html
    "CUSTOM_CRYPTO": (
        "Replace the home-grown algorithm with a vetted library implementation of an approved "
        "algorithm (for example AES-GCM from the platform's crypto library)."
    ),
}
# Product text: codes that describe a certificate (#7 labels them; #16 groups them).
CERT_FINDING_CODES = (
    "WEAK_CERTIFICATE_SIGNATURE",
    "WEAK_CERTIFICATE_KEY",
    "SELF_SIGNED_LEAF",
    "EXPIRED_CERTIFICATE",
    "CERT_NEAR_EXPIRY",
)


def _code(code: object) -> str:
    return str(code).strip().upper() if code is not None else ""


def _posture_text():
    # the configuration-posture codes (TLS verification off, unencrypted store, provider-managed key ...) are labelled
    # once, in cbom_posture_text; imported here on use because that module imports this one
    from backend.utilities.pdf import cbom_posture_text

    return cbom_posture_text


def finding_label(code: object) -> str:
    """Human label for a finding code; unknown codes are humanised, never dropped."""
    key = _code(code)
    if not key:
        return ""
    return FINDING_LABELS.get(key) or _posture_text().FINDING_LABELS.get(key) or key.replace("_", " ").capitalize()


def finding_action(code: object) -> str:
    """Recommended action for a finding code; unknown codes get the generic action."""
    key = _code(code)
    return FINDING_ACTIONS.get(key) or _posture_text().FINDING_ACTIONS.get(key) or GENERIC_FINDING_ACTION


# ---------------------------------------------------------------------------------------------
# Post-quantum timeline and target families (#15, #16)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class TimelineRow:
    """One printed row of the regulatory timeline (#15 section 2)."""

    when: str
    milestone: str
    status: str  # "Final" | "Draft" | "Advisory"
    source: str
    url: str


# Product text: the engine's own sentences (aibom/src/aibom/cbom/pqc.py _CNSA_TIMELINE and
# _TIMELINE).  The CNSA sentence is printed; the NIST sentence over-simplifies (it names
# RSA/ECC/DH without the 112-bit distinction) so it is NOT printed (decision D-06) and is kept
# only so a contract test notices if the engine's wording ever changes.
CNSA_2_0_SENTENCE = (
    "CNSA 2.0 NSS milestones: software/firmware signing 2025, "
    "networking 2030, all NSS by 2033-2035"
)
PINNED_ENGINE_NIST_TIMELINE = (
    "NIST deprecates RSA/ECC/DH after 2030 and disallows them from 2035 "
    "(NIST SP 1800-38 / IR 8547)"
)
# Secondary sources disagree on CNSA 2.0 details, so the engine's compressed sentence is
# printed with a verification note.
CNSA_VERIFY_NOTE = "Verify against the NSA advisory before submission."

PQC_TIMELINE_ROWS = (
    # Source: NIST PQC project, FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA), Aug 2024: https://www.nist.gov/pqcrypto
    TimelineRow(
        when="Aug 2024",
        milestone=(
            "NIST publishes the first post-quantum standards: FIPS 203 (ML-KEM), "
            "FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)."
        ),
        status="Final",
        source="NIST post-quantum cryptography project",
        url=URL_NIST_PQC,
    ),
    # Source: NIST IR 8547 initial public draft published Nov 2024: https://csrc.nist.gov/pubs/ir/8547/ipd
    TimelineRow(
        when="Nov 2024",
        milestone=(
            "NIST IR 8547 initial public draft published: proposed transition timeline for "
            "quantum-vulnerable public-key algorithms."
        ),
        status="Draft",
        source="NIST IR 8547 (initial public draft)",
        url=URL_NIST_IR_8547,
    ),
    # Source: NIST IR 8547 ipd, 112-bit-strength algorithms deprecated after 2030: https://csrc.nist.gov/pubs/ir/8547/ipd
    TimelineRow(
        when="After 2030",
        milestone=(
            "Quantum-vulnerable public-key algorithms with 112 bits of security strength "
            "(for example RSA-2048) are deprecated (NIST IR 8547 initial public draft)."
        ),
        status="Draft",
        source="NIST IR 8547 (initial public draft)",
        url=URL_NIST_IR_8547,
    ),
    # Source: NIST IR 8547 ipd, all quantum-vulnerable algorithms disallowed after 2035: https://csrc.nist.gov/pubs/ir/8547/ipd
    TimelineRow(
        when="After 2035",
        milestone=(
            "All quantum-vulnerable public-key algorithms are disallowed "
            "(NIST IR 8547 initial public draft)."
        ),
        status="Draft",
        source="NIST IR 8547 (initial public draft)",
        url=URL_NIST_IR_8547,
    ),
    # Source: NSA CNSA 2.0 advisory, national security systems transition: https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF
    TimelineRow(
        when="2025 to 2035",
        milestone=f"{CNSA_2_0_SENTENCE}. {CNSA_VERIFY_NOTE}",
        status="Advisory",
        source="NSA CNSA 2.0 advisory",
        url=URL_CNSA_2_0,
    ),
)
PQC_TIMELINE_FOOTNOTE = (
    "NIST IR 8547 remains an initial public draft and its dates may change in the final "
    "publication. FIPS 203, 204 and 205 are final."
)
PQC_ROADMAP_ORDER_NOTE = "Order = current scanner impact, not a migration sequence."
PQC_NO_VULNERABLE_TITLE = "No quantum-vulnerable assets"
PQC_NO_VULNERABLE_TEXT = (
    "No quantum-vulnerable public-key algorithms were found in the current scans."
)
# Product text: primitives and target families (aibom/src/aibom/cbom/pqc.py PQC_MIGRATION_TARGETS)
# Source: CycloneDX 1.6 cryptographic primitive enumeration: https://cyclonedx.org/docs/1.6/json/
PQC_PRIMITIVE_ORDER = ("pke", "signature", "key-agree", "kem")
PQC_PRIMITIVE_LABELS = {
    "pke": "Public-key encryption and key transport (for example RSA)",
    "signature": "Digital signatures (for example RSA, ECDSA, DSA)",
    "key-agree": "Key agreement (for example Diffie-Hellman, ECDH)",
    "kem": "Key encapsulation",
}

# ---------------------------------------------------------------------------------------------
# Board report: posture grade (#16) - pinned to report_branding.compute_risk_score
# ---------------------------------------------------------------------------------------------
GRADE_NOT_ASSESSED = "NOT ASSESSED"
# Product text: formula of backend/utilities/pdf/report_branding.py compute_risk_score; the
# constants below are checked against that function by test_grade_constants_are_pinned.
GRADE_WEIGHTS = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
GRADE_SCORE_MULTIPLIER = 4
GRADE_SCORE_CAP = 100
GRADE_BANDS = (
    (70, "F", "Critical risk"),
    (50, "D", "High risk"),
    (30, "C", "Elevated risk"),
    (15, "B", "Moderate risk"),
    (0, "A", "Low risk"),
)
GRADE_FORMULA = (
    "Weighted points = 10 x Critical + 5 x High + 2 x Medium + 1 x Low. "
    "Score = min(100, 4 x weighted points). Grade bands: F at 70 or above, D at 50, "
    "C at 30, B at 15, A below 15."
)
GRADE_INPUT = (
    "Grade input: current crypto assets that carry at least one finding, counted once per "
    "source and bucketed by impact. Inventory-only assets without findings are excluded."
)
GRADE_DISCLAIMER = (
    "The grade is a platform posture grade computed from the issue assets in this report. "
    "It is not a regulatory rating and does not replace an audit opinion."
)

# Product text: static checklist templated with live counts (#16 section 8).  Fields:
# unique_certs, attestations_outstanding, quantum_vulnerable, legacy_scans.
GOVERNANCE_ACTIONS = (
    (
        "owners",
        "Assign an accountable owner to each of the {unique_certs} unique certificates "
        "in the estate.",
    ),
    (
        "attestations",
        "Collect attestation evidence for the {attestations_outstanding} requirements "
        "that a bill of materials cannot evidence.",
    ),
    (
        "pqc",
        "Approve a post-quantum migration plan covering the {quantum_vulnerable} "
        "quantum-vulnerable asset occurrences.",
    ),
    (
        "legacy",
        "Re-scan the {legacy_scans} sources whose latest scan is in legacy format.",
    ),
)

# ---------------------------------------------------------------------------------------------
# Discovery methodology (#3) and the manual-discovery checklist (#1 section E, #3 section 3)
# ---------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ScannerSpec:
    """One registered CBOM scanner, pinned to the engine registry by a contract test."""

    name: str
    order: int
    discovers: str
    evidence: str


# Product text: aibom/src/aibom/cbom/scanners/__init__.py registers exactly these twenty, in this
# order (pinned by backend/tests/fixtures/cbom_scanner_registry.json and a contract test).  A module
# in that package that is not imported is not active and is deliberately not described.  Wording
# follows each scanner's own docstring.
CBOM_SCANNERS = (
    ScannerSpec(
        "crypto_ast",
        8,
        "Python source parsed into a syntax tree: the algorithm and its parameters are bound "
        "from call arguments, following values across statements and nested calls; literal "
        "IVs, nonces and salts bound to cipher or key-derivation calls.",
        "Algorithm with key size, mode and curve; detecting library and context; source path.",
    ),
    ScannerSpec(
        "crypto_algorithm",
        10,
        "Cryptographic algorithms and crypto libraries in source files (Python, Java and Go "
        "by call-argument rules; JavaScript/TypeScript, C/C++, Rust, C# and other recognised "
        "languages by literal patterns) and in dependency manifests.",
        "Algorithm with key size, mode and curve taken from the same call or line; strength "
        "class; quantum-vulnerability flag; library name; source path.",
    ),
    ScannerSpec(
        "crypto_advisory",
        16,
        "Direct and lockfile-transitive library versions matched against a shipped advisory "
        "file. The scan does not download package metadata.",
        "Library name, version, direct or transitive scope, advisory id, and source path.",
    ),
    ScannerSpec(
        "crypto_custom",
        17,
        "Private cipher or hash implementations recognized by well-known algorithm constants "
        "in source. Comments are ignored.",
        "Algorithm asset marked as a custom implementation; source path.",
    ),
    ScannerSpec(
        "crypto_artifacts",
        18,
        "Container images, compiled binaries and firmware in the scanned tree, read only when the "
        "scan option \"scan binaries\" is on: the base operating system of each image, OS and "
        "language packages, library versions and imported crypto functions in binaries, and "
        "private keys shipped inside an artifact.",
        "Base OS release and its end-of-life status; library name, version and package URL with "
        "advisory, CVE-range or end-of-life findings; algorithm rows for imported functions and "
        "constant signatures; key material; artifact path.",
    ),
    ScannerSpec(
        "crypto_certificate",
        20,
        "X.509 certificates (.pem, .crt, .cer, .cert, .der, .ca-bundle and inline PEM blocks) "
        "and related crypto material: private and public keys, keystore containers and "
        "narrowly matched hard-coded IV, salt and secret-key literals.",
        "Certificate subject and issuer common names, validity dates, signature algorithm, "
        "public-key algorithm and size or curve, self-signed and CA flags; material kind; "
        "source path.",
    ),
    ScannerSpec(
        "crypto_misuse",
        25,
        "Misuse of cryptographic material in source: constant or predictable IVs and nonces, "
        "nonce reuse, hard-coded symmetric keys, and keys or IVs drawn from non-cryptographic "
        "random generators.",
        "Related-crypto-material asset carrying the misuse properties, linked to the cipher "
        "it secures; source path.",
    ),
    ScannerSpec(
        "crypto_protocol",
        30,
        "TLS/SSL, SSH and IPsec/IKE usage in source and configuration: pinned protocol "
        "versions and cipher suites, one protocol asset per protocol type and file carrying "
        "the weakest pinned version.",
        "Protocol type, version and cipher suites; source path.",
    ),
    ScannerSpec(
        "posture_iac",
        31,
        "Declared encryption settings in Terraform, CloudFormation, Kubernetes, "
        "docker-compose and Dockerfile files.",
        "One encryption fact per declared resource, with a verdict for each layer "
        "and the source path.",
    ),
    ScannerSpec(
        "posture_server",
        32,
        "Declared listeners and protocol floors in web, proxy and SSH server "
        "configuration.",
        "One encryption fact per listener, with the protocol floor and the source path.",
    ),
    ScannerSpec(
        "posture_database",
        33,
        "Declared transport and at-rest settings in database, disk and SQL files.",
        "One encryption fact per declared store or disk setting, with the source path.",
    ),
    ScannerSpec(
        "posture_tls_import",
        34,
        "Offline import of TLS result files the customer's own tools produced.",
        "One endpoint fact per imported result. Importing a result does not probe the endpoint.",
    ),
    ScannerSpec(
        "crypto_policy",
        35,
        "Crypto policy files: java.security (disabled-algorithm lists and JCE policy) and "
        "openssl.cnf (minimum and maximum protocol, cipher strings).",
        "Policy-source protocol asset with the protocol floor and ceiling and the "
        "disabled-algorithm list; source path.",
    ),
    ScannerSpec(
        "posture_verification",
        36,
        "Source that disables certificate verification.",
        "One verification fact per disabled check, with the source path.",
    ),
    ScannerSpec(
        "posture_linkage",
        38,
        "Business mapping files that name an owner or a data classification for a fact.",
        "Linkage fields stamped on an existing fact. The scanner emits no new asset.",
    ),
    ScannerSpec(
        "crypto_weakness",
        40,
        "Evaluates the inventory and raises weakness findings: deprecated algorithms, "
        "undersized keys, ECB mode, weak protocol versions and cipher suites, weak RSA "
        "padding, key-material misuse, and certificates that are expired, signed with a "
        "broken hash, undersized or self-signed leaves.",
        "Finding code and severity per asset; no new asset.",
    ),
    ScannerSpec(
        "posture_findings",
        45,
        "Raises posture finding flags from the declared facts already inventoried.",
        "Finding code and severity on each fact. The scanner emits no new asset.",
    ),
    ScannerSpec(
        "crypto_pqc",
        50,
        "Grades quantum-vulnerable public-key algorithms (RSA, elliptic-curve, "
        "Diffie-Hellman, DSA) and maps each to its NIST post-quantum migration target.",
        "NIST quantum security level and migration target recorded on each graded asset; "
        "QUANTUM_VULNERABLE finding.",
    ),
    ScannerSpec(
        "crypto_strength",
        55,
        "Classical security strength of algorithm assets, using the comparable-strength table "
        "of NIST SP 800-57.",
        "Security strength in bits recorded on each gradeable algorithm asset.",
    ),
    ScannerSpec(
        "crypto_occurrence",
        60,
        "Locates every inventoried asset in its source file: the line of each use, the language "
        "and the crypto libraries the file imports.",
        "Line numbers, occurrence count, language and providing library on each asset; no new "
        "asset.",
    ),
)
CBOM_SCANNER_INTRO = (
    "The engine runs its registered scanners in a fixed order. Earlier scanners inventory "
    "assets; later scanners evaluate and enrich that inventory. Detection is deterministic."
)
POSTURE_LANES_NOTE = (
    "Configuration posture lanes: posture_iac, posture_server, posture_database, "
    "posture_tls_import, posture_verification, posture_linkage and posture_findings. "
    "They read provider_defaults_aws.json, provider_defaults_azure.json, "
    "provider_defaults_gcp.json, provider_defaults_k8s.json, "
    "provider_defaults_software.json, coverage_table.json, key_specs.json, "
    "key_policy_conditions.json, named_vulnerabilities.json, cipher_suites.json, "
    "named_groups.json, tls_policies.json, verification_patterns.json, "
    "tls_import_formats.json and datastore_images.json. A configuration file is "
    "capped at 5 MiB, a TLS result file at 20 MiB and a scan at 50,000 facts. "
    "Result files are imported offline; importing a file does not probe any endpoint."
)

METHOD_PURPOSE = (
    "This document describes how the DevSecShield CBOM engine discovers, classifies and "
    "evidences cryptographic assets in the repositories and artefacts scanned for this team, "
    "what it cannot observe, and which discovery activities remain manual."
)
# Source: CycloneDX 1.6 JSON schema used to validate every emitted BOM: https://cyclonedx.org/docs/1.6/json/
METHOD_VALIDATION = (
    "Detection is deterministic: rule tables, parsers and pattern matching. Every CycloneDX "
    "1.6 bill of materials the engine emits is validated against the bundled CycloneDX "
    "schema in continuous integration, and detection is regression-tested against "
    "ground-truth fixtures. No machine-learning or large-language-model component is used."
)
# Product text: tri-state compliance semantics (AGENTS.md; aibom/src/aibom/compliance/engine.py).
METHOD_COVERAGE = (
    "Each compliance requirement receives one of four outcomes: pass, fail, not evidenceable "
    "from a bill of materials, or out of scope. Coverage % = pass / (pass + fail), where "
    "pass includes requirements passed on attached evidence. Not-evidenceable and "
    "out-of-scope requirements are reported as separate counts and are never counted as "
    "passes. Attaching attestation evidence to a scan can move a not-evidenceable "
    "requirement to pass with evidence."
)
METHOD_CONFIDENCE_SCHEME = (
    (
        "Parsed artefact",
        "The asset was read from a file the engine parsed, such as an X.509 certificate or "
        "key file. Highest confidence.",
    ),
    (
        "Rule-bound API call",
        "A library call matched a detection rule and its parameters were bound from the "
        "call arguments.",
    ),
    (
        "Literal pattern",
        "An algorithm or protocol name matched as a literal in source or configuration. "
        "Lowest confidence: indirect usage may be missed or over-matched.",
    ),
)
METHOD_CONFIDENCE_LIMIT = (
    "Per-asset confidence is not stored by the current engine. The scheme above describes "
    "the detection method, not a recorded score."
)
# Product text: each results[] row carries a repository-relative location and each scan is
# stored with its inventory, CycloneDX BOM, compliance results, scores and distributions.
METHOD_EVIDENCE_TRACE = (
    "Each asset row records the repository-relative path where it was found and the scan "
    "that observed it; certificates also record the parsed X.509 fields. The platform keeps "
    "these records per scan, so any figure in this document can be traced to a scan and a "
    "file."
)
METHOD_RETENTION = (
    "For each scan the platform stores the inventory rows, the CycloneDX bill of materials, "
    "compliance results, scores and distribution data."
)
METHOD_RETENTION_PERIOD_LABEL = "Retention period"
METHOD_EVIDENCE_STORE_LABEL = "Evidence store location"
METHOD_LIMITS = (
    "Static analysis only: source code, configuration and certificate or key files are "
    "inspected; running systems are not.",
    "No live-network discovery: TLS endpoints, load balancers and appliances are not probed.",
    "Declared KMS and HSM settings in configuration are assessed. Live HSM firmware, "
    "custodianship, and escrow are not inspected.",
    "Data-at-rest encryption is assessed from declared configuration only (document #9); "
    "the live state of databases, object stores and disks is not inspected.",
    "Third-party and SaaS services are visible only through the libraries and configuration "
    "that scanned code references.",
    "Outside Python, Java and Go, algorithm detection relies on literal patterns and can miss "
    "indirect usage.",
    "Names that contain characters outside the Latin alphabet are printed with '?' because "
    "of the PDF font.",
)
RACI_ACTIVITIES = (
    "Run and schedule CBOM scans",
    "Review findings and assign remediation",
    "Maintain the manual discovery register",
    "Approve this methodology",
)
RACI_COLUMNS = ("Responsible", "Accountable", "Consulted", "Informed")
# Product text: what a static scan cannot see (plan 3.2 #3 / #1 section E).
MANUAL_DISCOVERY_ITEMS = (
    (
        "HSM and KMS key custody",
        "Key storage and custody sit outside source and certificate files.",
    ),
    (
        "Live TLS endpoints",
        "Negotiated versions and cipher suites need network probing.",
    ),
    (
        "Data-at-rest encryption",
        "Whether stored data is actually encrypted. Declared settings are assessed in "
        "document #9 and are not proof of operation.",
    ),
    (
        "SaaS and third-party services",
        "Vendor-side cryptography is visible only through vendor assurance.",
    ),
    (
        "OT, IoT and embedded devices",
        "Firmware and appliance cryptography is not in scanned repositories.",
    ),
    (
        "Key generation and rotation ceremonies",
        "Procedural controls cannot be evidenced from a bill of materials.",
    ),
)
MANUAL_DISCOVERY_COLUMNS = (
    "Item",
    "Why a static scan cannot see it",
    "Status",
    "Owner",
    "Evidence ref",
)

# ---------------------------------------------------------------------------------------------
# Scope baseline register (#1) and third-party assurance register (#10)
# ---------------------------------------------------------------------------------------------
SCOPE_BOUNDARY_ITEMS = (
    "In-scope applications",
    "In-scope infrastructure",
    "In-scope APIs",
    "Cloud accounts and subscriptions",
    "Third parties and service providers",
)
SCOPE_BOUNDARY_COLUMNS = ("Boundary item", "Description or identifiers", "Owner")
SCOPE_BOUNDARY_STATEMENT = "Assessment boundary statement and approver"
# Product text: the engine records a library's name and where it was found, nothing else
# (backend/utilities/dashboard/cbom_team_rollup.py LibAgg).
ASSURANCE_LIBRARY_NOTE = (
    "The engine records each library's name and where it was found. Versions, vendors and "
    "licences are not captured, so those columns are left for the assessor."
)
ASSURANCE_VENDOR_COLUMNS = (
    "Vendor",
    "Service",
    "Crypto function",
    "Evidence ref",
    "Valid until",
    "Owner",
)
ATTESTED_TEMPLATE = "Attested {attested}/{attestable}"

# ---------------------------------------------------------------------------------------------
# Certificate estate register (#7)
# ---------------------------------------------------------------------------------------------
# Product text: validity bands (cbom_team_rollup EXPIRY_BANDS).  Labels avoid characters
# outside WinAnsi, so "<=" stands in for the less-than-or-equal sign.
EXPIRY_BAND_CHIP_TEXT = {
    "EXPIRED": "EXPIRED",
    "LE_30": "<=30 DAYS",
    "LE_90": "<=90 DAYS",
    "VALID": "VALID",
    "UNKNOWN": "UNKNOWN",
}
EXPIRY_BAND_TONE = {
    "EXPIRED": "critical",
    "LE_30": "high",
    "LE_90": "medium",
    "VALID": "low",
    "UNKNOWN": "unknown",
}
CERT_CHAIN_LABELS = {
    "root_ca": "Root CA",
    "self_signed_leaf": "Self-signed leaf",
    "signed_by": "Signed by {issuer_file}",
    "issuer_not_in_estate": "Issuer not in estate",
}
CERT_SCAN_FLAG_DIFFERS = "scan-time flag differs"
# Source: RFC 5280, X.509 certificate fields and validity: https://www.rfc-editor.org/rfc/rfc5280
# Product text: fields recorded by aibom/src/aibom/cbom/x509.py (Certificate).
CERT_DISCOVERY_LIMITS = (
    "The engine records subject and issuer common names, validity dates, signature "
    "algorithm, public-key algorithm, key size or curve, and the self-signed and CA flags. "
    "It does not record serial numbers, fingerprints, subject alternative names, key usage "
    "or extended key usage, organisation fields, or OCSP and CRL locations.",
    "A certificate is identified across scans by a hash of its recorded attributes. Two "
    "different certificates that agree on every recorded attribute would be shown as one; "
    "this is not expected in practice because validity dates have one-second precision.",
    "Expiry is computed from the notAfter date as of the generation date of this document "
    "and can differ from the flag raised when the scan ran.",
    "Whether a certificate is managed, orphaned or in production use needs an authoritative "
    "PKI or CMDB inventory, so owner and business-system columns are left for the assessor.",
)
CERT_CHAIN_NOTE = (
    "Chain flags are factual: a certificate is 'Signed by' a file only when that issuer "
    "certificate is in the estate, and 'Issuer not in estate' means no certificate with the "
    "issuer's name was found."
)

__all__ = [
    "ASSESSOR_SUFFIX",
    "ASSURANCE_LIBRARY_NOTE",
    "ASSURANCE_VENDOR_COLUMNS",
    "ATTESTED_TEMPLATE",
    "BANNER_EMPTY_TEXT",
    "BANNER_EMPTY_TITLE",
    "BANNER_REDUCED_TEXT",
    "BANNER_REDUCED_TITLE",
    "BASIS_CONTROL_SUMMARY",
    "BASIS_FIDELITY",
    "BASIS_HEADING",
    "BASIS_HISTORY",
    "BASIS_HISTORY_TRUNCATED",
    "BASIS_RULE",
    "BASIS_SCANS",
    "BASIS_SCANS_COLLECTIONS",
    "BASIS_SOURCES",
    "CBOM_SCANNERS",
    "CBOM_SCANNER_INTRO",
    "POSTURE_LANES_NOTE",
    "CERTIN_DISCLAIMER",
    "CERT_CHAIN_LABELS",
    "CERT_CHAIN_NOTE",
    "CERT_DISCOVERY_LIMITS",
    "CERT_FINDING_CODES",
    "CERT_SCAN_FLAG_DIFFERS",
    "CNSA_2_0_SENTENCE",
    "CNSA_VERIFY_NOTE",
    "CONTROL_LABELS",
    "DATA_WINDOW_NONE",
    "DISCLAIMER_HEADING",
    "DISCLAIMER_PARAGRAPHS",
    "EMPTY_TABLE_TEXT",
    "EXPIRY_BAND_CHIP_TEXT",
    "EXPIRY_BAND_TONE",
    "FINDING_ACTIONS",
    "FINDING_LABELS",
    "FRAMEWORK_LABELS",
    "GENERIC_FINDING_ACTION",
    "GOVERNANCE_ACTIONS",
    "GRADE_BANDS",
    "GRADE_DISCLAIMER",
    "GRADE_FORMULA",
    "GRADE_INPUT",
    "GRADE_NOT_ASSESSED",
    "GRADE_SCORE_CAP",
    "GRADE_SCORE_MULTIPLIER",
    "GRADE_WEIGHTS",
    "IDENTITY_WEAK_NOTE",
    "LEGACY_TARGET_UNAVAILABLE",
    "MANUAL_CELL_NOTE",
    "MANUAL_DISCOVERY_COLUMNS",
    "MANUAL_DISCOVERY_ITEMS",
    "MANUAL_LEGEND",
    "METHOD_CONFIDENCE_LIMIT",
    "METHOD_CONFIDENCE_SCHEME",
    "METHOD_COVERAGE",
    "METHOD_EVIDENCE_STORE_LABEL",
    "METHOD_EVIDENCE_TRACE",
    "METHOD_LIMITS",
    "METHOD_PURPOSE",
    "METHOD_RETENTION",
    "METHOD_RETENTION_PERIOD_LABEL",
    "METHOD_VALIDATION",
    "PINNED_ENGINE_NIST_TIMELINE",
    "PQC_NO_VULNERABLE_TEXT",
    "PQC_NO_VULNERABLE_TITLE",
    "PQC_PRIMITIVE_LABELS",
    "PQC_PRIMITIVE_ORDER",
    "PQC_ROADMAP_ORDER_NOTE",
    "PQC_TIMELINE_FOOTNOTE",
    "PQC_TIMELINE_ROWS",
    "PREVIOUSLY_SEEN_TITLE",
    "RACI_ACTIVITIES",
    "RACI_COLUMNS",
    "RBI_BOM_DISCLAIMER",
    "RBI_MAPPING_NOTE",
    "SCOPE_BOUNDARY_COLUMNS",
    "SCOPE_BOUNDARY_ITEMS",
    "SCOPE_BOUNDARY_STATEMENT",
    "SCOPE_OF_METHOD",
    "SOURCE_FAILED_LATEST",
    "TOOL_NAME",
    "URL_CERT_IN_TG",
    "URL_CNSA_2_0",
    "URL_NIST_IR_8547",
    "URL_NIST_PQC",
    "VERDICT_LABELS",
    "ScannerSpec",
    "TimelineRow",
    "finding_action",
    "finding_label",
    "framework_label",
]
