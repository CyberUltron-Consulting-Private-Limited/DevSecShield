"""SOW D6, D9 and D10 read what CBOM Sources collected (FIX-B1, audit B-01 / B-07 / B-08 / B-09, 23 Nov 2026).

Staging, team 1, after Sources run #52 (AWS x2, GCP, Vault, EJBCA, HSM x2, KMIP, PostgreSQL, MySQL, SQL Server ...):
* D6 Infrastructure and Cloud Encryption Posture: "KMS key register ... No entries", "Resource encryption register
  ... No entries", "Managed TLS endpoints ... No entries"; KPI "Findings High 0" above a findings table of 25 "High"
  rows with a blank Impact column (probed TLS codes of D7);
* D9 Data-at-Rest Encryption Assessment: "Data stores 0", every register empty, although run #52 read 118 storage
  settings, SQL Server TDE and database settings;
* D10 Third-Party Cryptographic Assurance: 3 code-scan libraries, versions "not captured", 61 Sources libraries
  ignored, vendor register blank although vendor "Acme Payments Gateway" answered its questionnaire;
* the three PDFs printed Document IDs CBOM-D05 / D09 / D10 while the SOW calls the first one D6.

Root cause: ``cbom_team_rollup.merge_collections`` turned only ``tls_endpoint`` rows into posture facts and never
merged Sources libraries.  The fix is one mapper, ``cbom_sources.posture_mapper``.  The fixture
(``support/sources_every_type.py``) holds every asset type those documents read, judged by the real classifier.

Oracle: literals from the fixture (names, counts written out), never the product aggregator.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import html
import re
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest
from reportlab.platypus import Flowable, KeepTogether, Paragraph, Table

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.tests.support import sources_every_type as FX  # noqa: E402
from backend.tests.support.pdf_text import pdf_text  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import TeamCbomView, merge_collections  # noqa: E402
from backend.utilities.pdf import cbom_assurance_register_pdf as d10  # noqa: E402
from backend.utilities.pdf import cbom_data_at_rest_pdf as d9  # noqa: E402
from backend.utilities.pdf import cbom_infra_posture_pdf as d6  # noqa: E402
from backend.utilities.pdf.cbom_deliverable_common import get_deliverable_styles  # noqa: E402

NOW = dt.datetime(2026, 11, 23, 12, 0, tzinfo=dt.timezone.utc)
WIDTH = 720.0


# ------------------------------------------------------------------------------------------------ helpers
def cell_text(cell: object) -> str:
    if isinstance(cell, Paragraph):
        return html.unescape(re.sub(r"<[^>]+>", "", re.sub(r"<br\s*/?>", "\n", cell.text)))
    if isinstance(cell, (list, tuple)):
        return "\n".join(cell_text(item) for item in cell)
    if isinstance(cell, Flowable):
        return ""
    return "" if cell is None else str(cell)


def iter_tables(node: object) -> Iterator[Table]:
    if isinstance(node, Table):
        yield node
        for row in node._cellvalues:
            for cell in row:
                yield from iter_tables(cell)
    elif isinstance(node, KeepTogether):
        yield from iter_tables(node._content)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from iter_tables(item)


def rows_under(story: list[Flowable], first_header: str) -> list[dict[str, str]]:
    """Body rows of every register table whose first header is ``first_header`` (a register may be split)."""
    out = []
    for table in iter_tables(story):
        heads = [cell_text(c) for c in table._cellvalues[0]] if table._cellvalues else []
        if not heads or heads[0] != first_header or len(heads) < 3:
            continue
        for row in table._cellvalues[1:]:
            values = [cell_text(c) for c in row]
            if len(values) == len(heads) and values[0] not in ("No entries", ""):  # blank rows: manual forms
                out.append(dict(zip(heads, values, strict=True)))
    return out


def kpi_cards(story: list[Flowable]) -> dict[str, str]:
    cards = {}
    for table in iter_tables(story):
        rows = table._cellvalues
        if len(rows) == 3 and all(len(r) == 1 and isinstance(r[0], Paragraph) for r in rows) \
                and rows[0][0].style.name == "DashKpiLabel":
            cards[cell_text(rows[0][0])] = cell_text(rows[1][0])
    return cards


def _empty_view() -> TeamCbomView:
    return TeamCbomView(team_id=1, team_name="Bank One", generated_at=NOW, as_of=NOW.date(), fingerprint="b1f1x000")


@pytest.fixture(scope="module")
def view() -> TeamCbomView:
    rows, collections = FX.build()
    return merge_collections(_empty_view(), rows, collections)


def story(module, view: TeamCbomView) -> list[Flowable]:
    return module.build_story(view, get_deliverable_styles(), WIDTH)


def names(rows: list[dict[str, str]], column: str) -> set[str]:
    return {row[column] for row in rows}


# ------------------------------------------------------------------------------------------------ the mapper
MAPPED = [(source, kind, asset) for source, kind, _run, asset in FX.assets()
          if asset["type"] in FX.MAPPED_KIND or asset["type"] in ("storage_encryption", "database_config")]


@pytest.mark.parametrize("source,kind,asset", MAPPED, ids=[f"{a['type']}:{a['name']}" for _s, _k, a in MAPPED])
def test_every_mapped_asset_type_becomes_a_posture_fact(source, kind, asset):
    from backend.utilities.cbom_sources import posture_mapper as M

    fact = M.posture_fact(asset["type"], asset["facts"], fact_id="f1", name=asset["name"],
                          location=asset["location"], algorithm=asset.get("algorithm"),
                          key_size=asset.get("key_size"), impact="High", finding_codes=["X_CODE"],
                          finding="sentence", source_label=f"Sources run #52 · {source}", source_kind=kind)
    assert fact is not None
    if asset["type"] in FX.MAPPED_KIND:
        assert fact["kind"] == FX.MAPPED_KIND[asset["type"]]
    assert fact["source"] == f"Sources run #52 · {source}" and fact["location"] == asset["location"]
    assert fact["finding_codes"] == ["X_CODE"] and fact["impact"] == "High"
    assert fact["evidence"] == "collected:CBOM Sources"


@pytest.mark.parametrize("asset_type,name,expected", [
    # (kind, provider, at-rest verdict, key management)
    ("storage_encryption", "payments-ledger", ("object_store", "aws", "ENCRYPTED_DECLARED", "customer-managed")),
    ("storage_encryption", "public-assets", ("object_store", "aws", "NOT_ENCRYPTED", "")),
    ("storage_encryption", "vol-09d6979c2af92f0e5", ("block_volume", "aws", "NOT_ENCRYPTED", "")),
    ("storage_encryption", "EBS encryption by default (ap-south-1)", ("disk_encryption", "aws", "NOT_ENCRYPTED",
                                                                      "account default key")),
    ("storage_encryption", "proxy-platform-postgres", ("relational_db", "aws", "ENCRYPTED_DECLARED",
                                                       "customer-managed")),
    ("storage_encryption", "EKS payments secrets", ("k8s_secrets_etcd", "aws", "NOT_ENCRYPTED", "")),
    ("storage_encryption", "acme-exports", ("object_store", "gcp", "ENCRYPTED_PROVIDER_DEFAULT", "provider-managed")),
    ("storage_encryption", "acmelogs", ("object_store", "azure", "ENCRYPTED_PROVIDER_DEFAULT", "provider-managed")),
    ("storage_encryption", "oci-backups", ("object_store", "oci", "ENCRYPTED_PROVIDER_DEFAULT", "provider-managed")),
    ("glue_catalog", "Glue Data Catalog (ap-south-1)", ("data_warehouse", "aws", "NOT_ENCRYPTED", "none")),
    ("db_encryption", "labdb", ("relational_db", "self_hosted", "ENCRYPTED_DECLARED", "CERTIFICATE")),
    ("db_encryption", "USERS", ("relational_db", "self_hosted", "NOT_ENCRYPTED", "")),
    ("database_config", "MySQL 8.4.13", ("relational_db", "self_hosted", "NOT_ENCRYPTED", "keyring: none")),
    ("database_config", "PostgreSQL 16.15", ("relational_db", "self_hosted", "UNKNOWN", "")),
    ("database_config", "MongoDB 7.0.12", ("nosql_db", "self_hosted", "NOT_ENCRYPTED", "")),
    ("database_config", "Redis 7.2.4", ("cache", "self_hosted", "UNKNOWN", "")),
    ("disk_encryption", "data_crypt", ("disk_encryption", "self_hosted", "ENCRYPTED_DECLARED", "LUKS2")),
    ("disk_encryption", "D:", ("disk_encryption", "self_hosted", "ENCRYPTED_DECLARED", "BitLocker protection On")),
])
def test_at_rest_verdicts_are_the_declared_settings(asset_type, name, expected):
    from backend.utilities.cbom_sources import posture_mapper as M

    source, kind, asset = next((s, k, a) for s, k, _r, a in FX.assets() if a["name"] == name)
    fact = M.posture_fact(asset_type, asset["facts"], fact_id="f", name=name, location=asset["location"],
                          algorithm=asset.get("algorithm"), key_size=asset.get("key_size"),
                          source_label=source, source_kind=kind)
    management = str(fact.get("key_management") or "")
    assert (fact["kind"], fact["provider"], fact["at_rest"]) == expected[:3]
    assert management.startswith(expected[3]) if expected[3] else management in ("", "none", "keyring: none")


@pytest.mark.parametrize("name,expected", [
    # (provider, key type, algorithm, protection, state, rotation)
    ("payments-cmk", ("aws", "SYMMETRIC_DEFAULT", "AES-256", "", "Enabled", "disabled")),
    ("imported-no-material", ("aws", "SYMMETRIC_DEFAULT", "AES-256", "external key material",
                              "PendingImport", "not_applicable")),
    ("key-symmetric-unrotated", ("gcp", "SYMMETRIC_DEFAULT", "AES-256", "software", "Enabled", "disabled")),
    ("tde-protector", ("azure", "RSA-HSM 3072", "RSA-3072", "HSM", "Enabled", "enabled")),
    ("oci-master", ("oci", "SYMMETRIC_DEFAULT", "AES-256", "HSM", "Enabled", "not_applicable")),
    ("legacy-rsa", ("HashiCorp Vault", "rsa-2048", "RSA-2048", "software (Vault transit); exportable", "enabled",
                    "disabled")),
    ("aes256-data", ("HSM (PKCS#11)", "secret AES", "AES-256", "HSM (PKCS#11 token); exportable", "enabled",
                     "unknown")),
    ("lab-3des", ("KMIP", "Symmetric Key", "3DES-192", "KMIP key server; exportable", "Pre-Active", "unknown")),
])
def test_kms_keys_carry_type_size_algorithm_rotation_and_state(name, expected):
    from backend.utilities.cbom_sources import posture_mapper as M

    source, kind, asset = next((s, k, a) for s, k, _r, a in FX.assets() if a["name"] == name)
    fact = M.posture_fact(asset["type"], asset["facts"], fact_id="f", name=name, location=asset["location"],
                          algorithm=asset.get("algorithm"), key_size=asset.get("key_size"), source_label=source,
                          source_kind=kind)
    got = (fact["provider"], fact["specification"], fact["algorithm"], fact["protection"], fact["state"],
           fact["rotation"])
    assert got == expected
    assert fact["attrs"]["rotation"] == fact["rotation"]  # what the posture counts read (_rotation_of)


def test_probed_endpoints_certificates_and_host_keys_are_not_posture_facts_of_this_mapper():
    from backend.utilities.cbom_sources import posture_mapper as M

    for asset_type in ("tls_endpoint", "certificate", "ssh_host_key", "crypto_library", "coverage"):
        assert M.posture_fact(asset_type, {}, fact_id="x") is None


def test_library_components_carry_name_version_purl_and_status():
    from backend.utilities.cbom_sources import posture_mapper as M

    apk = M.library_component("crypto_library", {"name": "libcrypto1.1", "version": "1.1.1w-r1",
                                                 "package_manager": "apk", "purl": "pkg:apk/alpine/libcrypto1.1@1.1.1w-r1?arch=x86_64"},
                              finding_codes=["LIB_EOL", "LIB_KNOWN_CVE"])
    assert (apk["name"], apk["version"], apk["ecosystem"], apk["status"]) == (
        "libcrypto1.1", "1.1.1w-r1", "apk", "known CVE range; end of life")
    assert M.purl_identity(apk["purl"]) == "pkg:apk/alpine/libcrypto1.1@1.1.1w-r1"
    mapped = M.library_component("process_library", {"lib": "/usr/lib/libcrypto.so.3", "process": "sshd"}, name="sshd")
    assert (mapped["name"], mapped["version"], mapped["where"]) == ("libcrypto.so.3", "", "sshd (/usr/lib/libcrypto.so.3)")
    assert M.library_component("certificate", {}) is None


# ------------------------------------------------------------------------------------------------ D6
def test_d6_registers_list_what_the_sources_collected(view):
    body = story(d6, view)
    keys = rows_under(body, "Key")
    assert names(keys, "Key") == {"payments-cmk", "imported-no-material", "key-symmetric-unrotated", "tde-protector",
                                  "oci-master", "legacy-rsa", "aes256-data", "lab-3des", "LabTdes"}
    by_key = {row["Key"]: row for row in keys}
    assert by_key["payments-cmk"]["Rotation"] == "disabled"
    assert by_key["payments-cmk"]["Source"] == "Sources run #52 · AWS production"
    assert by_key["tde-protector"]["Algorithm and size"] == "RSA-3072"
    assert by_key["lab-3des"]["State"] == "Pre-Active"
    stores = rows_under(body, "Key store")
    assert names(stores, "Key store") == {"Vault transit transit", "lab-a", "PyKMIP 0.10.0 Software Server"}
    resources = rows_under(body, "Resource")  # the at-rest register (first) and the secrets register share "Resource"
    assert {"payments-ledger", "public-assets", "vol-09d6979c2af92f0e5", "proxy-platform-postgres",
            "EKS payments secrets", "acme-exports", "acmelogs", "oci-backups",
            "Glue Data Catalog (ap-south-1)"} <= names(resources, "Resource")
    tls = rows_under(body, "Endpoint")
    assert names(tls, "Endpoint") == {"ComplianceShield-LB:80", "ComplianceShield-LB:443",
                                      "d3lg18b01vnyjz.cloudfront.net", "api.payments.example", "web-https-proxy",
                                      "oci-lb:443"}
    assert {r["Endpoint"]: r["Minimum version"] for r in tls}["d3lg18b01vnyjz.cloudfront.net"] == "TLS 1.0"
    secrets = [r for r in resources if "Service" in r]
    assert names(secrets, "Resource") >= {"rds-db-credentials/payments", "/payments/db_password",
                                          "dummy-api-key-with-expiry", "db-conn", "acme-kv", "oci-db-password",
                                          "CN=ZeroShield-AWS-PCA-Test"}
    by_secret = {r["Resource"]: r for r in secrets}
    assert by_secret["rds-db-credentials/payments"]["Key management (KMS key)"] == (
        "provider-managed (aws/secretsmanager)")
    assert by_secret["oci-db-password"]["Rotation"] == "enabled (P30D)"
    # the probed endpoint is D7's, never a D6 row
    flat = "\n".join(v for table in (keys, stores, resources, tls) for row in table for v in row.values())
    assert "10.232.0.101:443" not in flat


def test_d6_findings_table_never_has_a_blank_impact_and_the_kpis_equal_its_rows(view):
    body = story(d6, view)
    findings = rows_under(body, "Label")
    assert findings, "the collected findings are listed"
    assert all(row["Impact"] in ("Critical", "High", "Medium", "Low") for row in findings)
    assert all(row["Remediation"] != "Review this finding against the cryptographic policy." for row in findings)
    cards = kpi_cards(body)
    for band in ("High", "Medium", "Low"):
        listed = sum(int(row["Count"]) for row in findings if row["Impact"] == band)
        assert cards[f"Findings {band}"] == str(listed), band
    keys = rows_under(body, "Key")
    assert cards["KMS keys"] == str(len(keys)) == "9"
    facts = d6.scope_facts(view)
    assert cards["Facts"] == str(len(facts))
    at_rest = [r for r in rows_under(body, "Resource") if "At rest" in r]
    assert int(cards["Not encrypted"]) == sum(1 for r in at_rest if r["At rest"] == "Not encrypted")
    # the probed endpoint's codes (STATIC_RSA ..., D7) are not counted here
    labels = {row["Label"] for row in findings}
    assert "Storage not encrypted at rest" in labels and "Key without automatic rotation" in labels
    assert not any("Static rsa" in label or "Proto tls10" in label for label in labels)


def test_d6_view_counts_are_recomputed_after_the_merge(view):
    assert view.posture.counts.facts == len(view.posture.facts)
    assert view.posture.counts.kms.keys == 9
    assert view.posture.counts.findings_by_code.get("STORAGE_UNENCRYPTED") == 3  # S3, EBS volume, EKS


# ------------------------------------------------------------------------------------------------ D9
def test_d9_counts_and_registers_come_from_the_collected_stores(view):
    body = story(d9, view)
    stores = rows_under(body, "Store")
    expected = {"payments-ledger", "public-assets", "vol-09d6979c2af92f0e5", "proxy-platform-postgres",
                "acme-exports", "acmelogs", "oci-backups", "Glue Data Catalog (ap-south-1)", "labdb", "USERS",
                "MySQL 8.4.13", "PostgreSQL 16.15", "MongoDB 7.0.12", "Redis 7.2.4"}
    assert names(stores, "Store") == expected
    cards = kpi_cards(body)
    assert cards["Data stores"] == str(len(stores)) == "14"
    # the at-rest layer is printed first; a transport layer may follow it ("; transport: ...")
    at_rest_first = [r["Layers"].split(";")[0] for r in stores]
    assert cards["Encrypted (declared)"] == str(sum(1 for v in at_rest_first if v.endswith("Encrypted (declared)")))
    assert cards["Encrypted (declared)"] == "3"  # payments-ledger, proxy-platform-postgres, labdb
    by_store = {row["Store"]: row for row in stores}
    assert by_store["labdb"]["Layers"] == "database: Encrypted (declared)"
    assert by_store["USERS"]["Layers"] == "database: Not encrypted"
    assert by_store["MySQL 8.4.13"]["Key management"] == "keyring: none"
    assert by_store["PostgreSQL 16.15"]["Layers"].startswith("database: Not evidenceable")
    assert by_store["Redis 7.2.4"]["Layers"] == "database: Not evidenceable from BOM (unknown); transport: Not encrypted"
    disks = rows_under(body, "Resource")
    disk_names = names(disks, "Resource")
    assert {"data_crypt", "D:", "EBS encryption by default (ap-south-1)", "labdb", "USERS"} <= disk_names
    k8s = rows_under(body, "First provider")
    assert [(r["First provider"], r["Verdict"]) for r in k8s] == [("identity (no envelope encryption)",
                                                                   "Not encrypted")]
    text = " ".join(cell_text(item) for item in body if isinstance(item, Paragraph))
    assert "Declared encryption settings only" in text and "Stored data was not read (SOW section 7.2)" in text


# ------------------------------------------------------------------------------------------------ D10
def test_d10_lists_sources_libraries_with_versions_deduplicated_by_purl(view):
    body = story(d10, view)
    rows = {r["Library"]: r for r in rows_under(body, "Library") if "Version" in r}
    assert set(rows) == {"libcrypto1.1", "libssl3t64", "libcrypto.so.3"}
    apk = rows["libcrypto1.1"]  # two registries, one package URL (qualifiers differ): one component, two sources
    assert (apk["Version"], apk["#Sources"]) == ("1.1.1w-r1", "2")
    assert apk["Package URL or ecosystem"] == "pkg:apk/alpine/libcrypto1.1@1.1.1w-r1"
    assert apk["Known-vulnerability / end-of-life status"] == "end of life"
    assert rows["libssl3t64"]["Version"] == "3.0.13-0ubuntu3.16"
    assert rows["libcrypto.so.3"]["Version"] == "not captured"


def test_d10_merges_a_code_scan_library_and_a_sources_package_of_the_same_name_and_version():
    from backend.utilities.dashboard.cbom_team_rollup import LibAgg

    rows, collections = FX.build()
    code = LibAgg(key="libssl3t64@3.0.13-0ubuntu3.16", name="libssl3t64@3.0.13-0ubuntu3.16",
                  source_keys=("repo:acme",), source_labels=("github.com/acme/app (main)",),
                  current_source_keys=("repo:acme",), current=True, first_seen=NOW, last_seen=NOW, scan_count=1,
                  scan_ids=(7,), latest_scan_id=7, version="3.0.13-0ubuntu3.16", status="known CVE range",
                  advisories=("CVE-2024-0001",))
    merged = merge_collections(dataclasses.replace(_empty_view(), libs=(code,)), rows, collections)
    same = [lib for lib in merged.libs if lib.name.startswith("libssl3t64")]
    assert len(same) == 1
    assert set(same[0].source_labels) == {"github.com/acme/app (main)", "Sources run #52 · Linux web server"}


def test_d10_vendor_register_is_built_from_the_evidence_tab():
    from backend.utilities.cbom_sources import evidence as E

    now = dt.datetime(2026, 11, 23, 14, 44)
    acme = SimpleNamespace(name="Acme Payments Gateway", area_key="third_party_vendors", confidence="E2",
                           answered_at=dt.datetime(2026, 11, 12, 17, 44), link_created_at=dt.datetime(2026, 11, 12, 17, 44),
                           link_expires_at=dt.datetime(2026, 11, 26, 17, 44), link_token_hash=None,
                           answers={"tls": "TLS 1.2+ only", "keys": "HSM", "pqc": "2028"},
                           evidence_url="https://acme.example/security")
    silent = SimpleNamespace(name="Beta Card Switch", area_key="third_party_vendors", confidence="E0",
                             answered_at=None, link_created_at=None, link_expires_at=None, link_token_hash=None,
                             answers={}, evidence_url=None)
    rows = E.vendor_register([silent, acme], now)
    assert [r["name"] for r in rows] == ["Acme Payments Gateway", "Beta Card Switch"]
    assert rows[0] == {"name": "Acme Payments Gateway", "area": "Third-party vendors", "status": "answered",
                       "level": "E2", "level_label": "Documented", "attested_on": "2026-11-12",
                       "renew_by": "2027-11-12",
                       "scope": "TLS versions and cipher suites, key custody, post-quantum plan (3 of 3 answered)",
                       "evidence_ref": "https://acme.example/security"}
    assert (rows[1]["status"], rows[1]["level"], rows[1]["attested_on"]) == ("not sent", "E0", None)
    body = story(d10, dataclasses.replace(_empty_view(), vendors=rows))
    vendors = [r for r in rows_under(body, "Vendor") if "Attestation date" in r]
    assert vendors[0]["Vendor"] == "Acme Payments Gateway" and vendors[0]["Attestation date"] == "2026-11-12"
    assert vendors[0]["Evidence ref"] == "https://acme.example/security"


# ------------------------------------------------------------------------------------------------ Document IDs
@pytest.mark.parametrize("module,number", [(d6, "D06"), (d9, "D09"), (d10, "D10")])
def test_document_ids_are_the_sow_numbers(view, module, number):
    text = re.sub(r"\s+", "", pdf_text(module.build_pdf(view)))
    assert f"CBOM-{number}-T1-" in text
    assert "CBOM-D05-" not in text


def test_registry_numbers_d6_to_d10_follow_the_sow():
    from backend.utilities.pdf.cbom_deliverables import DELIVERABLES

    numbers = {slug: spec.number for slug, spec in DELIVERABLES.items()}
    assert [numbers[s] for s in ("infrastructure-cloud-encryption-posture", "network-tls-protocol-assessment",
                                 "certificate-estate-register", "data-at-rest-encryption-assessment",
                                 "third-party-assurance-register")] == [6, 7, 8, 9, 10]


# ------------------------------------------------------------------------------------------------ the DB read
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, world  # noqa: E402,F401  (fixtures)
from test_cbom_sources_as_results import no_mongo, sources_run  # noqa: E402,F401  (fixtures)


def _store_assets(engine, run_id: int) -> None:
    """Every fixture asset of the AWS and SQL Server sources, stored on the fixture run's collect job."""
    from sqlmodel import Session, select

    from backend.new_models import CbomCollectedAsset, CbomCollectionJob
    from backend.utilities.cbom_sources import classify as C

    with Session(engine) as s:
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_id)).one()
        for index, (_source, _kind, _run, asset) in enumerate(
                a for a in FX.assets() if a[0] in ("AWS production", "SQL Server 2022")):
            judged = C.classify(asset["type"], asset.get("algorithm"), asset.get("key_size"), asset.get("protocol"),
                                asset["facts"])
            s.add(CbomCollectedAsset(team_id=1, run_id=run_id, job_id=job.id, source_id=job.source_id,
                                     attempt=job.attempts, asset_key=f"fx{index:04d}", asset_type=asset["type"],
                                     cdx_type=judged["cdx_type"], target="fixture", location=asset["location"],
                                     name=asset.get("name"), algorithm=asset.get("algorithm"),
                                     key_size=asset.get("key_size"), protocol=asset.get("protocol"),
                                     quantum_vulnerable=judged["quantum_vulnerable"], impact=judged["impact"],
                                     finding_codes=judged["finding_codes"], finding=judged["finding"],
                                     facts=asset["facts"]))
        s.commit()


def test_sources_posture_facts_reads_a_teams_runs_and_nothing_else(sources_run):  # noqa: F811
    from sqlmodel import Session

    from backend.utilities.cbom_sources.posture_mapper import sources_posture_facts

    engine, run_id = sources_run["engine"], sources_run["run"]["id"]
    _store_assets(engine, run_id)
    with Session(engine) as s:
        by_run = sources_posture_facts(s, 1, [run_id])
        latest = sources_posture_facts(s, 1)
        other_team = sources_posture_facts(s, 2, [run_id])
        no_runs = sources_posture_facts(s, 1, [])
    kinds = sorted(f["kind"] for f in by_run)
    assert kinds.count("kms_key") == 3  # two AWS KMS keys and the SQL Server symmetric key
    assert {f["name"] for f in by_run if f["kind"] == "object_store"} == {"payments-ledger", "public-assets"}
    assert {f["name"] for f in by_run} == {f["name"] for f in latest}  # the run is each source's latest collection
    assert other_team == [] and no_runs == []
    unencrypted = next(f for f in by_run if f["name"] == "public-assets")
    assert (unencrypted["at_rest"], unencrypted["impact"]) == ("NOT_ENCRYPTED", "High")
    assert "STORAGE_UNENCRYPTED" in unencrypted["finding_codes"]
    assert all(f["source"].startswith(f"Sources run #{run_id} · ") for f in by_run)


def test_team_view_loads_the_vendor_register_and_the_collected_posture(sources_run):  # noqa: F811
    from sqlmodel import Session

    from backend.new_models import CbomEvidenceVendor
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view

    engine, run_id = sources_run["engine"], sources_run["run"]["id"]
    _store_assets(engine, run_id)
    with Session(engine) as s:
        s.add(CbomEvidenceVendor(team_id=1, name="Acme Payments Gateway", confidence="E2",
                                 answered_at=dt.datetime(2026, 11, 12, 17, 44),
                                 link_created_at=dt.datetime(2026, 11, 12, 17, 44),
                                 answers={"tls": "TLS 1.2+", "keys": "HSM", "pqc": "2028"},
                                 evidence_url="https://acme.example/security"))
        s.add(CbomEvidenceVendor(team_id=2, name="Other team vendor"))
        s.commit()
    view = load_team_cbom_view(engine, 1)
    assert [v["name"] for v in view.vendors] == ["Acme Payments Gateway"]
    assert (view.vendors[0]["attested_on"], view.vendors[0]["evidence_ref"]) == (
        "2026-11-12", "https://acme.example/security")
    keys = [r for r in rows_under(story(d6, view), "Key")]
    assert {"payments-cmk", "imported-no-material", "LabTdes"} <= names(keys, "Key")
    stores = rows_under(story(d9, view), "Store")
    assert {"payments-ledger", "labdb"} <= names(stores, "Store")
