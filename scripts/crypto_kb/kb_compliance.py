"""Turn research/compliance.json (sourced quotes) into the KB's OWASP table, compliance references and PQC context.

Every reference keeps the source URL and the exact clause id the research recorded; nothing here is typed from memory.
"""
from __future__ import annotations

TAG_2025 = {"access": "A01:2025", "misconfig": "A02:2025", "components": "A03:2025", "crypto": "A04:2025",
            "auth": "A07:2025", "integrity": "A08:2025"}
TAG_2021 = {"access": "A01:2021", "crypto": "A02:2021", "misconfig": "A05:2021", "components": "A06:2021",
            "auth": "A07:2021", "integrity": "A08:2021"}


def owasp_tables(r: dict) -> dict:
    out = {}
    for year in ("2021", "2025"):
        out[year] = {row["id"]: {"id": row["id"], "name": row["name"], "label": f"{row['id']} - {row['name']}",
                                 "source": row["source"], "mapped_cwes": row["mapped_cwes"]}
                     for row in r[f"owasp_{year}"]}
    return out


# Who each framework binds (SOW audit A-11): a team sees only what binds it (crypto_kb.applies). "jurisdiction": the
# country the framework is law or regulation in ("*": a technical standard the platform grades against, cited
# everywhere as a reference); "entities": the regulated-entity types it binds (team setting); "requires": a team
# attribute it needs (team setting: processes_card_data, sebi_regulated, government_entity). Product decisions from
# each framework's own scope statement.
CLAUSE_FRAMEWORKS = {
    "NIST": {"jurisdiction": "*", "basis": "reference"},
    "NSA CNSA 2.0": {"jurisdiction": "*", "basis": "reference"},
    "CERT-In": {"jurisdiction": "IN", "basis": "binding"},
    # the seven RBI-regulated entity types that have a 2026 direction; an "other" entity is bound by none (review m4)
    "RBI": {"jurisdiction": "IN", "basis": "binding",
            "entities": ["nbfc", "bank", "sfb", "payments_bank", "ucb", "aifi", "credit_info_company"]},
    "SEBI CSCRF": {"jurisdiction": "IN", "basis": "binding", "requires": "sebi_regulated"},
}
# the code-scan engine's pooled frameworks (aibom.cbom.compliance.CBOM_FRAMEWORKS keys)
POOLED_FRAMEWORKS = {
    "nist_1800_38b": {"jurisdiction": "*", "basis": "reference"},
    "nist_800_57": {"jurisdiction": "*", "basis": "reference"},
    "omb_m_23_02": {"jurisdiction": "US", "basis": "binding", "note": "US federal agencies"},
    "eu_cra": {"jurisdiction": "EU", "basis": "binding", "note": "products placed on the EU market"},
    "eu_dora": {"jurisdiction": "EU", "basis": "binding", "note": "EU financial entities"},
    "pci_dss_4": {"jurisdiction": "*", "basis": "binding", "requires": "processes_card_data",
                  "note": "entities that store, process or transmit payment-card data"},
    "fips_140_3": {"jurisdiction": "*", "basis": "reference"},
    "bsi_tr_02102": {"jurisdiction": "DE", "basis": "binding", "note": "German federal guidance"},
    "nist_1800_38c": {"jurisdiction": "*", "basis": "reference"},
    "cnsa_2_0": {"jurisdiction": "*", "basis": "reference"},
    "rbi_free_ai_protection": {"jurisdiction": "IN", "basis": "binding",
                               "entities": ["nbfc", "bank", "sfb", "payments_bank", "ucb", "aifi",
                                            "credit_info_company"]},
    "cert_in_cbom": {"jurisdiction": "IN", "basis": "binding"},
    "sebi_cscrf_cbom": {"jurisdiction": "IN", "basis": "binding", "requires": "sebi_regulated"},
}


def clause_applicability(framework: str, rid: str) -> dict:
    out = dict(CLAUSE_FRAMEWORKS[framework])
    if framework == "CERT-In" and rid.startswith("Guidelines for Government Entities"):
        # "Guidelines on Information Security Practices for Government Entities" (June 2023): ministries, departments,
        # their offices and government institutions, public sector enterprises and agencies; nobody else
        out["requires"] = "government_entity"
    return out


def applicability() -> dict:
    """The KB's ``applicability`` section: who each clause framework and each pooled framework binds."""
    return {"clause_frameworks": CLAUSE_FRAMEWORKS, "frameworks": POOLED_FRAMEWORKS}


def refs(r: dict) -> dict:
    """``_clauses``: every clause by stable key; and the compliance areas, each a list of clause keys."""
    n, c, ci, s, rb = r["nist"], r["cnsa2"], r["certin"], r["sebi_cscrf"], r["rbi"]
    a131 = n["sp800_131a_rev2"]
    bom = ci["bom_guidelines"]
    gov = ci["govt_entities_guidelines"]
    sc = s["clauses"]
    md, d26, nb = rb["md_itgrca_2023"], rb["commercial_banks_directions_2026"], rb["nbfc_directions_2026"]
    sfb, pb, ucb = rb["small_finance_banks_directions_2026"], rb["payments_banks_directions_2026"], rb["ucb_directions_2026"]
    aifi, cic = rb["aifi_directions_2026"], rb["credit_information_companies_directions_2026"]

    def ref(framework, rid, text, source, note=None, applies_to=None, superseded=False):
        out = {"framework": framework, "id": rid, "text": text, "source": source}
        if note:
            out["note"] = note
        if applies_to:
            # the regulated-entity types (team setting, ENTITY_TYPES) an RBI instrument binds; a clause without it
            # applies whatever the entity type
            out["applies_to"] = list(applies_to)
        # who the clause binds (jurisdiction, and a team attribute it needs): crypto_kb.applies reads it (A-11)
        out["applicability"] = clause_applicability(framework, rid)
        if superseded:
            out["superseded"] = True  # cited for no team (crypto_kb.applies); kept so an old clause= link resolves
        return out

    rbi_md = ref("RBI", "Master Direction on IT Governance (2023), para 16 Cryptographic controls",
                 md["para_16_cryptographic_controls"], md["source"],
                 "Superseded on 31 July 2026 for every entity type it covered by the entity-wise Cybersecurity, "
                 "Technology: Risk, Resilience and Assurance Framework Directions 2026.", superseded=True)
    rbi_26 = ref("RBI", "Commercial Banks Cybersecurity Directions 2026, para 140", d26["para_140_cryptographic_controls"],
                 d26["source"], "Commercial banks (from 31 July 2026).", applies_to=("bank",))
    rbi_26_106 = ref("RBI", "Commercial Banks Cybersecurity Directions 2026, para 106", d26["para_106"], d26["source"],
                     applies_to=("bank",))
    rbi_nbfc = ref("RBI", "NBFC Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026, "
                   "para 118", nb["para_118_cryptographic_controls"], nb["source"],
                   "Binds NBFCs of the Middle Layer and above (Chapter V; not Base Layer NBFCs, not CICs), from 31 July "
                   "2026; replaces the Master Direction on IT Governance (2023) for NBFCs (para 155).", applies_to=("nbfc",))
    rbi_sfb = ref("RBI", "Small Finance Banks Cybersecurity Directions 2026, para 139",
                  sfb["para_139_cryptographic_controls"], sfb["source"], "Small finance banks (from 31 July 2026).",
                  applies_to=("sfb",))
    rbi_pb = ref("RBI", "Payments Banks Cybersecurity Directions 2026, para 139", pb["para_139_cryptographic_controls"],
                 pb["source"], "Payments banks (from 31 July 2026).", applies_to=("payments_bank",))
    rbi_ucb = ref("RBI", "Urban Co-operative Banks Cybersecurity Directions 2026, para 25",
                  ucb["para_25_cryptographic_controls"], ucb["source"],
                  "Urban co-operative banks of every level (Chapter III), from 31 July 2026: encryption algorithms that "
                  "are not deprecated or demonstrated to be insecure.", applies_to=("ucb",))
    rbi_aifi = ref("RBI", "AIFI Cybersecurity Directions 2026, para 135", aifi["para_135_cryptographic_controls"],
                   aifi["source"], "EXIM Bank, NABARD, SIDBI, NHB and NaBFID (from 31 July 2026).", applies_to=("aifi",))
    rbi_cic = ref("RBI", "Credit Information Companies Cybersecurity Directions 2026, para 135",
                  cic["para_135_cryptographic_controls"], cic["source"], "Credit information companies (from 31 July 2026).",
                  applies_to=("credit_info_company",))
    # data at rest and in transit: each 2026 direction's counterpart of the Commercial Banks para 106 (review m3), so
    # a plaintext or unencrypted finding cites the team's own instrument whatever its entity type
    rbi_sfb_105 = ref("RBI", "Small Finance Banks Cybersecurity Directions 2026, para 105", sfb["para_105"],
                      sfb["source"], applies_to=("sfb",))
    rbi_pb_105 = ref("RBI", "Payments Banks Cybersecurity Directions 2026, para 105", pb["para_105"], pb["source"],
                     applies_to=("payments_bank",))
    rbi_aifi_105 = ref("RBI", "AIFI Cybersecurity Directions 2026, para 105", aifi["para_105"], aifi["source"],
                       applies_to=("aifi",))
    rbi_cic_105 = ref("RBI", "Credit Information Companies Cybersecurity Directions 2026, para 105", cic["para_105"],
                      cic["source"], applies_to=("credit_info_company",))
    rbi_ucb_23 = ref("RBI", "Urban Co-operative Banks Cybersecurity Directions 2026, para 23", ucb["para_23"],
                     ucb["source"], "Urban co-operative banks of every level (Chapter III).", applies_to=("ucb",))
    rbi_ucb_120 = ref("RBI", "Urban Co-operative Banks Cybersecurity Directions 2026, para 120", ucb["para_120"],
                      ucb["source"], "Urban co-operative banks of Level II and above (Chapter IV); a Level I UCB is "
                      "bound by para 23 for data in transit and by no at-rest paragraph.", applies_to=("ucb",))
    rbi_nbfc_95 = ref("RBI", "NBFC Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026, "
                      "para 95(4)", nb["para_95_4"], nb["source"],
                      "Middle Layer and above (Chapter V). No NBFC paragraph names encryption at rest; para 95(4) asks for "
                      "secure storage of data.", applies_to=("nbfc",))
    certin_tls = ref("CERT-In", "BOM Guidelines v2.0, 8.4.2.2", bom["key_recommendations"]["8.4.2.2"], bom["source"])
    certin_vex = ref("CERT-In", "BOM Guidelines v2.0, 8.4.1.6", bom["key_recommendations"]["8.4.1.6"], bom["source"])
    certin_shor = ref("CERT-In", "BOM Guidelines v2.0, 8.5.1", bom["key_recommendations"]["8.5.1"], bom["source"])
    certin_617 = ref("CERT-In", "Guidelines for Government Entities (2023), 6.1.7", gov["clauses"]["6.1.7 (pg.21)"], gov["source"])
    certin_627 = ref("CERT-In", "Guidelines for Government Entities (2023), 6.2.7", gov["clauses"]["6.2.7 (pg.22)"], gov["source"])
    certin_71 = ref("CERT-In", "Guidelines for Government Entities (2023), 7.1", gov["clauses"]["7.1 (pg.22)"], gov["source"])
    certin_457 = ref("CERT-In", "Guidelines for Government Entities (2023), 4.5.7", gov["clauses"]["4.5.7 (pg.12)"], gov["source"])
    sebi_src = s["source_for_clauses"]
    sebi_prds = ref("SEBI CSCRF", "PR.DS Standard 1", sc["PR.DS Standard 1 (Part I sec 3.3, p.63)"], sebi_src)
    sebi_prds13 = ref("SEBI CSCRF", "PR.DS.S1-S3 guideline 1.a", sc["PR.DS.S1/S2/S3 guideline 1.a (Part II, p.105)"], sebi_src)
    sebi_cert = ref("SEBI CSCRF", "PR.DS.S4 item 5", sc["PR.DS.S4 item 5 (p.108)"], sebi_src)
    sebi_h = ref("SEBI CSCRF", "Annexure-H item 5", sc["Annexure-H item 5 (p.160)"], sebi_src)
    sebi_i = ref("SEBI CSCRF", "Annexure-I Data Transport Security", sc["Annexure-I Data Transport Security (p.161)"], sebi_src)
    sebi_pqc = ref("SEBI CSCRF", "Box Item 7: Cybersecurity and Quantum Computing",
                   sc["Box Item 7: Cybersecurity and Quantum Computing (pp.59-60)"], sebi_src)
    sebi_ra = ref("SEBI CSCRF", "ID.RA Standard 2", sc["ID.RA Standard 2 (Part I sec 2.2, p.59)"], sebi_src)
    sebi_sbom = ref("SEBI CSCRF", "GV.SC.S5 SBOM contents", sc["GV.SC.S5 SBOM contents (pp.88-89)"], sebi_src)
    nist_sha1 = ref("NIST", "SP 800-131A Rev. 2, Sec. 9 Table 8 (SHA-1)",
                    f"Digital signature generation: {a131['sha1']['digital_signature_generation']}; verification: "
                    f"{a131['sha1']['digital_signature_verification']}.", a131["sha1"]["source"])
    nist_tdea = ref("NIST", "SP 800-131A Rev. 2, Sec. 2 Table 1 (TDEA)", a131["tdea_3des"]["quote"], a131["tdea_3des"]["source"])
    nist_112 = ref("NIST", "SP 800-131A Rev. 2, Tables 2, 4, 5 (below 112-bit security)",
                   "Signature generation and key agreement below 112 bits of security strength are disallowed "
                   f"({a131['below_112_bit']['digital_signatures']['generation']}).", a131["below_112_bit"]["source"])
    nist_pkcs1 = ref("NIST", "SP 800-131A Rev. 2, Sec. 6 Table 5", a131["below_112_bit"]["rsa_key_transport_agreement"]["quote"],
                     a131["below_112_bit"]["source"])
    ir = n["ir8547"]
    nist_pqc = ref("NIST", ir["citation_id"], ir["quote"], ir["pdf"])
    cnsa = ref("NSA CNSA 2.0", "CNSA 2.0 FAQ (April 2024)", c["overall_goal_quote"] + ". Algorithms: AES-256, ML-KEM-1024, "
               "ML-DSA-87, SHA-384/512, LMS/XMSS.", c["source"])
    # the clause catalog (#269): one stable key per clause; each finding code names the keys it breaks in
    # sources/compliance_clauses.json, so a code never inherits the other clauses of an area
    catalog = {
        "nist-800-131a-sha1-signatures": nist_sha1, "nist-800-131a-tdea": nist_tdea,
        "nist-800-131a-pkcs1-v1_5": nist_pkcs1, "nist-800-131a-below-112-bit": nist_112, "nist-ir-8547": nist_pqc,
        "cnsa-2.0": cnsa, "certin-bom-8.4.2.2": certin_tls, "certin-bom-8.4.1.6": certin_vex,
        "certin-bom-8.5.1": certin_shor, "certin-gov-6.1.7": certin_617, "certin-gov-6.2.7": certin_627,
        "certin-gov-7.1": certin_71, "certin-gov-4.5.7": certin_457, "rbi-md-2023-para-16": rbi_md,
        "rbi-cb-2026-para-140": rbi_26, "rbi-cb-2026-para-106": rbi_26_106, "rbi-nbfc-2026-para-118": rbi_nbfc,
        "rbi-sfb-2026-para-139": rbi_sfb, "rbi-pb-2026-para-139": rbi_pb, "rbi-ucb-2026-para-25": rbi_ucb,
        "rbi-aifi-2026-para-135": rbi_aifi, "rbi-cic-2026-para-135": rbi_cic,
        "rbi-sfb-2026-para-105": rbi_sfb_105, "rbi-pb-2026-para-105": rbi_pb_105, "rbi-aifi-2026-para-105": rbi_aifi_105,
        "rbi-cic-2026-para-105": rbi_cic_105, "rbi-ucb-2026-para-23": rbi_ucb_23, "rbi-ucb-2026-para-120": rbi_ucb_120,
        "rbi-nbfc-2026-para-95": rbi_nbfc_95,
        "sebi-pr-ds-standard-1": sebi_prds,
        "sebi-pr-ds-s1-s3-1a": sebi_prds13, "sebi-pr-ds-s4-item-5": sebi_cert, "sebi-annexure-h-5": sebi_h,
        "sebi-annexure-i": sebi_i, "sebi-box-item-7": sebi_pqc, "sebi-id-ra-standard-2": sebi_ra,
        "sebi-gv-sc-s5": sebi_sbom,
    }
    # compliance areas: groups of clause keys, kept for the NIST SP 800-53 control families (OSCAL); a finding's cited
    # clauses come from its own "clauses" / "clause_rules", never from a whole area. Keys, not copies: each clause's
    # text is stored once (the catalog).
    rbi_crypto = [rbi_26, rbi_nbfc, rbi_sfb, rbi_pb, rbi_ucb, rbi_aifi, rbi_cic]  # one per entity type
    rbi_data = [rbi_sfb_105, rbi_pb_105, rbi_aifi_105, rbi_cic_105]  # the para 106 counterparts with one paragraph
    areas = {
        "tls_min": [certin_tls, sebi_i, *rbi_crypto, certin_617],
        "algorithms": [nist_sha1, nist_tdea, nist_pkcs1, certin_tls, *rbi_crypto, sebi_h],
        "keysize": [nist_112, *rbi_crypto],
        "certificates": [sebi_cert, certin_617],
        "key_mgmt": [sebi_h],
        "at_rest": [sebi_prds, sebi_prds13, rbi_26_106, *rbi_data, rbi_ucb_120, rbi_nbfc_95, certin_71],
        "in_transit": [sebi_prds, sebi_i, rbi_26_106, *rbi_data, rbi_ucb_23, rbi_nbfc, certin_627, certin_457],
        "auth": [*rbi_crypto],
        "components": [certin_vex, sebi_sbom],
        "pqc": [nist_pqc, cnsa, sebi_pqc, sebi_ra, certin_shor],
    }
    key_of = {id(ref): key for key, ref in catalog.items()}
    return {"_clauses": catalog, **{area: [key_of[id(ref)] for ref in items] for area, items in areas.items()}}


# NIST post-quantum target per asset FUNCTION (D13 PQC Migration Roadmap, D12 register CSV). A target never names a
# post-quantum algorithm here: each one is an algid SELECTOR (backend/utilities/cbom_sources/pqc_targets.py resolves it
# against algid's rows, the single source of post-quantum names, parameter sets and NIST categories). Selector keys:
#   standard      the row's published standard (FIPS 203 / FIPS 204 / FIPS 205 / SP 800-208), status "standard" only
#   category      the FIPS NIST security category (3 = the NIST default parameter set, 5 = CNSA 2.0)
#   construction  pure (default) | hybrid
#   with          a classical component of a hybrid (X25519, P-384)
#   registry      tls_group | ssh_kex: only names that registry carries (the codepoint a server is configured with)
#   variant       the end of a FIPS 205 parameter set (SHA2-256s: the small-signature SHA-2 set)
#   all           every matching name (the stateful hash-based family, SP 800-208), joined with " / "
#   names         restrict the matches to these algid names (each must be a standard algid row of the selector's
#                 standard): CNSA 2.0 approves only the single-tree SP 800-208 schemes, read from the research file
# "text" parts are classical names, written as is. "then" is the step after a transition (hybrid first, then pure).
# Sources: research compliance.json nist.ir8547.ml_kem_default (category 3 default), cnsa2.algorithms (category 5,
# LMS / XMSS for software and firmware signing, AES-256, SHA-384/512).
_KEM3 = {"standard": "FIPS 203", "category": 3}
_KEM5 = {"standard": "FIPS 203", "category": 5}
_DSA3 = {"standard": "FIPS 204", "category": 3}
_DSA5 = {"standard": "FIPS 204", "category": 5}
_SLH5 = {"standard": "FIPS 205", "category": 5, "variant": "SHA2-256s"}
_STATEFUL = {"standard": "SP 800-208", "all": True}


def _cnsa_stateful(r: dict) -> dict:
    """The SP 800-208 schemes CNSA 2.0 approves for software and firmware signing: the research file's cnsa2.algorithms
    rows with spec "NIST SP 800-208" (the NSA CNSA 2.0 FAQ, April 2024: only LMS and XMSS; the multi-tree HSS and
    XMSS^MT are not allowed). A selector, never a typed list: the names are the research's, checked against algid."""
    names = sorted(a["algorithm"] for a in r["cnsa2"]["algorithms"] if a["spec"] == "NIST SP 800-208")
    return {**_STATEFUL, "names": names}


def _cnsa_stateful_note(r: dict) -> str:
    rows = [a for a in r["cnsa2"]["algorithms"] if a["spec"] == "NIST SP 800-208"]
    recommended = " ".join(p for a in rows for p in a["parameters"].split(". ") if "recommended" in p).strip()
    return ("CNSA 2.0 approves only the single-tree stateful hash-based schemes from SP 800-208 for software and "
            "firmware signing; the multi-tree variants are not allowed (NSA CNSA 2.0 FAQ). "
            + (recommended.rstrip(".") + ". " if recommended else "")
            + "The signer must manage the one-time key state.")


def migration_targets(r: dict) -> list[dict]:
    """MIGRATION_TARGETS with the CNSA 2.0 code-signing selector read from the research file."""
    out = []
    for row in MIGRATION_TARGETS:
        if row["usage"] == "code_signing":
            row = {**row, "cnsa": [{"select": _cnsa_stateful(r)}, {"text": " or "}, {"select": _DSA5}],
                   "note": "NIST: every SP 800-208 scheme. " + _cnsa_stateful_note(r)}
        out.append(row)
    return out


MIGRATION_TARGETS = [
    {"usage": "tls_kex", "label": "TLS key exchange",
     "target": [{"select": {**_KEM3, "construction": "hybrid", "with": "X25519", "registry": "tls_group"},
                 "suffix": " (hybrid)"}],
     "then": [{"select": _KEM3}],
     "cnsa": [{"select": _KEM5}],
     "reference": "FIPS 203", "note": "Offer the hybrid group first, keep the classical group for old clients, then "
                                      "move to the pure parameter set once clients support it."},
    {"usage": "ssh_kex", "label": "SSH key exchange",
     "target": [{"select": {**_KEM3, "construction": "hybrid", "with": "X25519", "registry": "ssh_kex"},
                 "suffix": " (hybrid)"}],
     "then": [{"select": _KEM3}],
     "cnsa": [{"select": {**_KEM5, "construction": "hybrid", "with": "P-384", "registry": "ssh_kex"}}],
     "reference": "FIPS 203", "note": "Put the hybrid key exchange first in the server's KexAlgorithms."},
    {"usage": "vpn_kex", "label": "IKEv2 / IPsec key exchange",
     "target": [{"select": _KEM3}, {"text": " as an additional key exchange (RFC 9370)"}],
     "cnsa": [{"select": _KEM5}],
     "reference": "FIPS 203", "note": "Keep the classical group as the first key exchange (hybrid)."},
    {"usage": "key_establishment", "label": "Key establishment (KEM, key transport, key agreement)",
     "target": [{"select": _KEM3}], "cnsa": [{"select": _KEM5}],
     "reference": "FIPS 203", "note": "Category 3 is NIST's default parameter set; category 5 under CNSA 2.0."},
    {"usage": "signature", "label": "Digital signatures (signing keys, tokens, host keys)",
     "target": [{"select": _DSA3}], "cnsa": [{"select": _DSA5}],
     "reference": "FIPS 204", "note": "Category 3 by default; category 5 under CNSA 2.0."},
    {"usage": "certificate", "label": "Certificates (end-entity)",
     "target": [{"select": _DSA3}], "cnsa": [{"select": _DSA5}],
     "reference": "FIPS 204", "note": "Re-issue from a CA that signs with the same family."},
    {"usage": "ca_signature", "label": "Certificate authorities and trust anchors (long-lived)",
     "target": [{"select": _DSA5}, {"text": " or "}, {"select": _SLH5}, {"text": " (stateless hash-based)"}],
     "cnsa": [{"select": _DSA5}],
     "reference": "FIPS 204 / FIPS 205", "note": "A root or long-lived CA key outlives most migrations: category 5, "
                                                 "or the stateless hash-based scheme where signatures are rare."},
    {"usage": "code_signing", "label": "Software and firmware signing",
     "target": [{"select": _STATEFUL}, {"text": " or "}, {"select": _DSA5}],
     "cnsa": [{"select": _STATEFUL}, {"text": " or "}, {"select": _DSA5}],
     "reference": "SP 800-208 / FIPS 204", "note": "CNSA 2.0 names the stateful hash-based schemes for software and "
                                                   "firmware signing (state must be managed by the signer)."},
    {"usage": "asymmetric", "label": "Public-key algorithm, usage not recorded",
     "target": [{"select": _KEM3}, {"text": " for key establishment, "}, {"select": _DSA3}, {"text": " for signatures"}],
     "cnsa": [{"select": _KEM5}, {"text": " / "}, {"select": _DSA5}],
     "reference": "FIPS 203 / FIPS 204", "note": "The collector did not record what the key is used for: confirm it "
                                                 "with the owner, then keep one of the two."},
    {"usage": "symmetric", "label": "Symmetric encryption",
     "target": [{"text": "AES-256 (GCM)"}], "cnsa": [{"text": "AES-256"}],
     "reference": "FIPS 197", "note": "Grover's algorithm halves a symmetric key's strength: 256-bit keys keep 128 bits."},
    {"usage": "hash", "label": "Hashes and MACs",
     "target": [{"text": "SHA-384 or SHA-512 (SHA-3 also approved)"}], "cnsa": [{"text": "SHA-384 or SHA-512"}],
     "reference": "FIPS 180-4 / FIPS 202", "note": "HMAC keeps the hash; move SHA-1 and MD5 first (SP 800-131A)."},
]


# The classical part of waves 1-3 (a weakness a classical attacker can use today: an algorithm or key size SP 800-131A
# disallows such as RSA-1024 or Triple DES, and others such as TLS 1.0 or an expired certificate) is dated from the day
# the asset was first found, never from a post-quantum milestone and never from the day a document is generated:
# within these many days of it. A team setting (risk_model wave1_fix_days / wave2_fix_days / wave3_fix_days) replaces
# each default. The basis never says that SP 800-131A disallows every such weakness: the documents name which assets
# are disallowed algorithms or key sizes (pqc_targets.FIX_BASIS_TEXT). The wave label carries "urgent", so the basis
# does not repeat it.
WAVE_FIX_DAYS = {1: 90, 2: 180, 3: 365}
_FIX_BASIS = {
    1: "Fix the classical weakness within {days} days of the day the asset was first found.",
    2: "Fix the classical weakness within {days} days of the day the asset was first found (the quarter after "
       "wave 1).",
    3: "Fix the classical weakness within {days} days of the day the asset was first found.",
}


def wave_milestones(r: dict) -> list[dict]:
    """Each remediation wave (backend waves.WAVE_RULES): ``fix_within_days`` and ``fix_basis``, the window for the
    CLASSICAL weaknesses of waves 1-3, counted from the day the asset was first found; ``pq_date`` and ``pq_basis``,
    the post-quantum milestone (NIST IR 8547, CNSA 2.0) for the quantum-vulnerable part, read from the research file
    so the basis quotes its years. ``cites`` names the KB entries (``pqc_context`` keys) whose status and URL every document prints; the
    URL is never copied here, so the one IR 8547 entry decides it."""
    ir, c = r["nist"]["ir8547"], r["cnsa2"]
    by_cat = {row["category"]: row for row in c["timeline"]}
    net = by_cat["Traditional networking equipment (e.g., VPNs, routers)"]
    web = by_cat["Web browsers/servers and cloud services"]
    osys = by_cat["Operating systems"]
    fw = by_cat["Software- and firmware-signing"]
    fed = ir["federal_accelerators"]
    rows = [
        {"wave": 1, "pq_date": f"{osys['support_and_prefer_by']}-12-31",
         "pq_basis": f"CNSA 2.0 'support and prefer': web and cloud {web['support_and_prefer_by']}, networking "
                     f"{net['support_and_prefer_by']}, operating systems {osys['support_and_prefer_by']}. Exposed and "
                     "harvest-now-decrypt-later key exchange cannot wait for the deprecation date.",
         "cites": ["cnsa_2"]},
        {"wave": 2, "pq_date": "2030-12-31",
         "pq_basis": f"NIST IR 8547: high value assets and high impact systems adopt post-quantum key establishment "
                     f"by 31 December 2030 ({fed['page']}). CNSA 2.0 exclusively: networking {net['exclusively_use_by']}, "
                     f"software and firmware signing {fw['exclusively_use_by']}.",
         "cites": ["nist_ir_8547", "cnsa_2"]},
        {"wave": 3, "pq_date": "2031-12-31",
         "pq_basis": f"NIST IR 8547: high value assets and high impact systems adopt post-quantum digital signatures "
                     f"by 31 December 2031 ({fed['page']}). {ir['quote']}",
         "cites": ["nist_ir_8547"]},
        {"wave": 4, "pq_date": f"{web['exclusively_use_by']}-12-31",
         "pq_basis": f"CNSA 2.0: web, cloud and operating systems exclusively by {web['exclusively_use_by']}. "
                     f"{ir['quote']}",
         "cites": ["cnsa_2", "nist_ir_8547"]},
    ]
    for row in rows:
        days = WAVE_FIX_DAYS.get(row["wave"])
        row["fix_within_days"] = days
        row["fix_basis"] = _FIX_BASIS[row["wave"]].format(days=days) if days else None
        # one date per wave as before (the post-quantum one); the classical window is counted per assessment
        row["date"] = row["pq_date"]
    return rows


def pqc_context(r: dict) -> dict:
    m, ir, c = r["mosca"], r["nist"]["ir8547"], r["cnsa2"]
    gri = m["gri_quantum_threat_timeline_2025"]
    return {
        "migration_targets": migration_targets(r),
        "wave_milestones": wave_milestones(r),
        "mosca": {"inequality": "X + Y > Z", "definitions": m["inequality"]["definitions"],
                  "source": m["inequality"]["source"], "paper": m["original_paper"]["citation"]},
        "expert_survey": {"title": gri["title"], "published": gri["published"], "source": gri["source"],
                          "quotes": gri["quotes"]},
        # the ONE citation every document prints for IR 8547 (status, date, dates of the transition): from the research
        "nist_ir_8547": {"quote": ir["quote"], "source": ir["pdf"], "federal": ir["federal_accelerators"]["quote"],
                         # the citation is the document's name only; its status and publication date are their own
                         # fields, so every printed citation is built from them and a draft never reads "final"
                         # (PR #490's pqc_targets.ir8547 and cbom_kb_text.ir8547 build it the same way)
                         "citation": "NIST " + ir["citation_id"].split(" (", 1)[0], "title": ir["title"],
                         "status": "draft" if "/ipd" in ir["source"] else "final",
                         "published": ir["published"], "landing": ir["source"],
                         "deprecated_after": ir["deprecated_after"], "disallowed_after": ir["disallowed_after"]},
        "cnsa_2": {"goal": c["overall_goal_quote"], "timeline": c["timeline"], "source": c["source"]},
        "z_default": None,
        "z_note": "There is no authoritative date for a cryptographically relevant quantum computer. Set Z (years until "
                  "one exists) for your organisation; the expert survey above is one input.",
    }
