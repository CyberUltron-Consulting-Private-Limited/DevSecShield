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


def refs(r: dict) -> dict:
    """``_clauses``: every clause by stable key; and the compliance areas, each a list of clause keys."""
    n, c, ci, s, rb = r["nist"], r["cnsa2"], r["certin"], r["sebi_cscrf"], r["rbi"]
    a131 = n["sp800_131a_rev2"]
    bom = ci["bom_guidelines"]
    gov = ci["govt_entities_guidelines"]
    sc = s["clauses"]
    md, d26, nb = rb["md_itgrca_2023"], rb["commercial_banks_directions_2026"], rb["nbfc_directions_2026"]

    def ref(framework, rid, text, source, note=None, applies_to=None):
        out = {"framework": framework, "id": rid, "text": text, "source": source}
        if note:
            out["note"] = note
        if applies_to:
            # the regulated-entity types (team setting: bank / nbfc / other) an RBI instrument binds; a clause without
            # it applies whatever the entity type
            out["applies_to"] = list(applies_to)
        return out

    rbi_md = ref("RBI", "Master Direction on IT Governance (2023), para 16 Cryptographic controls",
                 md["para_16_cryptographic_controls"], md["source"],
                 "Repealed for commercial banks and for NBFCs by their 2026 Directions; kept for other regulated "
                 "entities.", applies_to=("other",))
    rbi_26 = ref("RBI", "Commercial Banks Cybersecurity Directions 2026, para 140", d26["para_140_cryptographic_controls"],
                 d26["source"], "Commercial banks (from 31 July 2026).", applies_to=("bank",))
    rbi_26_106 = ref("RBI", "Commercial Banks Cybersecurity Directions 2026, para 106", d26["para_106"], d26["source"],
                     applies_to=("bank",))
    rbi_nbfc = ref("RBI", "NBFC Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026, "
                   "para 118", nb["para_118_cryptographic_controls"], nb["source"],
                   "NBFCs, Middle Layer and above (from 31 July 2026); replaces the Master Direction on IT Governance "
                   "(2023) for NBFCs (para 155).", applies_to=("nbfc",))
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
        "sebi-pr-ds-standard-1": sebi_prds,
        "sebi-pr-ds-s1-s3-1a": sebi_prds13, "sebi-pr-ds-s4-item-5": sebi_cert, "sebi-annexure-h-5": sebi_h,
        "sebi-annexure-i": sebi_i, "sebi-box-item-7": sebi_pqc, "sebi-id-ra-standard-2": sebi_ra,
        "sebi-gv-sc-s5": sebi_sbom,
    }
    # compliance areas: groups of clause keys, kept for the NIST SP 800-53 control families (OSCAL); a finding's cited
    # clauses come from its own "clauses" / "clause_rules", never from a whole area. Keys, not copies: each clause's
    # text is stored once (the catalog).
    areas = {
        "tls_min": [certin_tls, sebi_i, rbi_md, rbi_26, rbi_nbfc, certin_617],
        "algorithms": [nist_sha1, nist_tdea, nist_pkcs1, certin_tls, rbi_md, rbi_26, rbi_nbfc, sebi_h],
        "keysize": [nist_112, rbi_md, rbi_26, rbi_nbfc],
        "certificates": [sebi_cert, certin_617],
        "key_mgmt": [sebi_h],
        "at_rest": [sebi_prds, sebi_prds13, rbi_26_106, certin_71],
        "in_transit": [sebi_prds, sebi_i, rbi_26_106, rbi_nbfc, certin_627, certin_457],
        "auth": [rbi_md, rbi_26, rbi_nbfc],
        "components": [certin_vex, sebi_sbom],
        "pqc": [nist_pqc, cnsa, sebi_pqc, sebi_ra, certin_shor],
    }
    key_of = {id(ref): key for key, ref in catalog.items()}
    return {"_clauses": catalog, **{area: [key_of[id(ref)] for ref in items] for area, items in areas.items()}}


def pqc_context(r: dict) -> dict:
    m, ir, c = r["mosca"], r["nist"]["ir8547"], r["cnsa2"]
    gri = m["gri_quantum_threat_timeline_2025"]
    return {
        "mosca": {"inequality": "X + Y > Z", "definitions": m["inequality"]["definitions"],
                  "source": m["inequality"]["source"], "paper": m["original_paper"]["citation"]},
        "expert_survey": {"title": gri["title"], "published": gri["published"], "source": gri["source"],
                          "quotes": gri["quotes"]},
        # the ONE citation every document prints for IR 8547 (status, date, dates of the transition): from the research
        "nist_ir_8547": {"quote": ir["quote"], "source": ir["pdf"], "federal": ir["federal_accelerators"]["quote"],
                         "citation": f"NIST {ir['citation_id']}", "title": ir["title"], "status": "final",
                         "published": ir["published"], "landing": ir["source"],
                         "deprecated_after": ir["deprecated_after"], "disallowed_after": ir["disallowed_after"]},
        "cnsa_2": {"goal": c["overall_goal_quote"], "timeline": c["timeline"], "source": c["source"]},
        "z_default": None,
        "z_note": "There is no authoritative date for a cryptographically relevant quantum computer. Set Z (years until "
                  "one exists) for your organisation; the expert survey above is one input.",
    }
