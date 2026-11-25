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
from backend.utilities.dashboard.cbom_team_rollup import PostureFactAgg, TeamCbomView, merge_collections  # noqa: E402
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
                          source_label=f"Sources run #52 · {source}", source_kind=kind)
    assert fact is not None
    if asset["type"] in FX.MAPPED_KIND:
        assert fact["kind"] == FX.MAPPED_KIND[asset["type"]]
    assert fact["source"] == f"Sources run #52 · {source}" and fact["location"] == asset["location"]
    assert fact["finding_codes"] == ["X_CODE"] and fact["impact"] == "High"
    assert fact["evidence"] == "collected:CBOM Sources"


@pytest.mark.parametrize("asset_type,name,expected", [
    # (kind, provider, at-rest verdict, key management)
    ("storage_encryption", "payments-ledger", ("object_store", "aws", "ENCRYPTED_DECLARED", "customer-managed")),
    # review minor: a store that is not encrypted says "none", never a blank key management cell
    ("storage_encryption", "public-assets", ("object_store", "aws", "NOT_ENCRYPTED", "none")),
    ("storage_encryption", "vol-09d6979c2af92f0e5", ("block_volume", "aws", "NOT_ENCRYPTED", "none")),
    ("storage_encryption", "EBS encryption by default (ap-south-1)", ("disk_encryption", "aws", "NOT_ENCRYPTED",
                                                                      "none")),
    ("storage_encryption", "proxy-platform-postgres", ("relational_db", "aws", "ENCRYPTED_DECLARED",
                                                       "customer-managed")),
    ("storage_encryption", "EKS payments secrets", ("k8s_secrets_etcd", "aws", "NOT_ENCRYPTED", "none")),
    ("storage_encryption", "acme-exports", ("object_store", "gcp", "ENCRYPTED_PROVIDER_DEFAULT", "provider-managed")),
    ("storage_encryption", "acmelogs", ("object_store", "azure", "ENCRYPTED_PROVIDER_DEFAULT", "provider-managed")),
    ("storage_encryption", "oci-backups", ("object_store", "oci", "ENCRYPTED_PROVIDER_DEFAULT", "provider-managed")),
    ("glue_catalog", "Glue Data Catalog (ap-south-1)", ("data_warehouse", "aws", "NOT_ENCRYPTED", "none")),
    ("db_encryption", "labdb", ("relational_db", "self_hosted", "ENCRYPTED_DECLARED", "CERTIFICATE")),
    ("db_encryption", "USERS", ("relational_db", "self_hosted", "NOT_ENCRYPTED", "none")),
    ("database_config", "MySQL 8.4.13", ("relational_db", "self_hosted", "NOT_ENCRYPTED", "keyring: none")),
    ("database_config", "PostgreSQL 16.15", ("relational_db", "self_hosted", "UNKNOWN", "")),
    ("database_config", "MongoDB 7.0.12", ("nosql_db", "self_hosted", "NOT_ENCRYPTED", "none")),
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
    assert management.startswith(expected[3]) if expected[3] else management == ""
    if fact["at_rest"] == "NOT_ENCRYPTED":
        assert management in ("none", "keyring: none")


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


def test_gcp_asymmetric_key_rotation_is_not_applicable():
    """Review minor: Cloud KMS rotates symmetric ENCRYPT_DECRYPT keys only; gcp_collect stores rotation_enabled=None
    for an ASYMMETRIC_SIGN key, which must read "not applicable", not "unknown"."""
    from backend.utilities.cbom_sources import posture_mapper as M

    fact = M.posture_fact("kms_key", {"provider": "gcp", "purpose": "ASYMMETRIC_SIGN", "key_spec": "EC_SIGN_P256_SHA256",
                                      "rotation_enabled": None, "key_state": "Enabled"},
                          fact_id="g", name="signer", location="projects/p/locations/l/keyRings/r/cryptoKeys/signer",
                          algorithm="ECDSA", key_size=256, source_label="Sources run #52 · GCP project")
    assert (fact["rotation"], fact["attrs"]["rotation"]) == ("not_applicable", "not_applicable")


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
    assert by_key["payments-cmk"]["Source"] == "AWS production"  # a source is labelled by its name (PR #485 m8)
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
    rows = {r["Component"]: r for r in rows_under(body, "Component") if "Version" in r
            and not r["Package URL or ecosystem"].startswith("crypto product")}  # Q3-11: products are rows too
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
    assert set(same[0].source_labels) == {"github.com/acme/app (main)", "Linux web server"}


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


def test_d10_prints_the_name_without_the_version_and_merges_the_unversioned_row_of_the_same_source():
    """Review major 2: ``golang.org/x/crypto`` (import rule) and ``golang.org/x/crypto@v0.24.0`` (go.mod advisory) of
    one source were two rows and the name kept "@v0.24.0".  Now: one row, name ``golang.org/x/crypto``, version
    v0.24.0.  An unversioned row from a source that does not list that version stays its own row."""
    from backend.utilities.dashboard.cbom_team_rollup import LibAgg

    def lib(name, keys, version=""):
        return LibAgg(key=name.casefold(), name=name, source_keys=keys, source_labels=keys, current_source_keys=keys,
                      current=True, first_seen=NOW, last_seen=NOW, scan_count=1, scan_ids=(1,), latest_scan_id=1,
                      version=version)

    code = (lib("golang.org/x/crypto", ("repo:a",)), lib("golang.org/x/crypto@v0.24.0", ("repo:a",), "v0.24.0"),
            lib("PyJWT", ("repo:b",)), lib("pyjwt@2.3.0", ("repo:a",), "2.3.0"))
    rows, collections = FX.build()
    merged = merge_collections(dataclasses.replace(_empty_view(), libs=code), rows, collections)
    by_name = {}
    for item in merged.libs:
        by_name.setdefault(item.name.casefold(), []).append(item)
    assert [(x.name, x.version) for x in by_name["golang.org/x/crypto"]] == [("golang.org/x/crypto", "v0.24.0")]
    # PyJWT of repo:b is not known to be 2.3.0 (only repo:a pins it): two rows, both without "@" in the name
    assert sorted((x.name, x.version) for x in by_name["pyjwt"]) == [("PyJWT", ""), ("pyjwt", "2.3.0")]
    assert not any("@" in x.name for x in merged.libs)
    table = [r for r in rows_under(story(d10, merged), "Component") if "Version" in r]
    assert [r["Version"] for r in table if r["Component"] == "golang.org/x/crypto"] == ["v0.24.0"]


# ------------------------------------------------------------------------------------------------ scale (review)
def _many(count: int):
    """``count`` Sources rows: the fixture repeated with distinct identities (the review's 50k load, smaller)."""
    rows, collections = FX.build()
    out = []
    copy = 0
    while len(out) < count:
        for item in rows:
            if len(out) == count:
                break
            row = dict(item.row, title=f"{item.row['title']}-{copy}", location=f"{item.row['location']}-{copy}")
            out.append(dataclasses.replace(item, row=row, identity=f"{item.identity}|{copy}",
                                           asset_key=f"{item.asset_key}-{copy}"))
        copy += 1
    return out, collections


@pytest.fixture(scope="module")
def big_view() -> TeamCbomView:
    rows, collections = _many(8000)
    return merge_collections(_empty_view(), rows, collections)


def _notes(body: list[Flowable]) -> list[str]:
    return [cell_text(item) for item in body if isinstance(item, Paragraph) and "further rows omitted" in cell_text(item)]


def test_above_the_cap_shown_plus_omitted_equals_the_facts_of_each_register(big_view):
    """Review blocker (Rule P): with 19,148 at-rest facts D6 said "28980 further rows omitted", and D6 / D9 said
    "127 further rows omitted: showing the first 1 of the unknown facts".  The merge drops no fact, so the only
    omitted rows are the ones a register cuts; shown + omitted must equal the facts of that register exactly."""
    from backend.utilities.pdf import cbom_posture_text as T

    assert big_view.posture.omitted == {}  # the merge kept every fact: nothing was cut before the renderer
    facts = d6.scope_facts(big_view)
    at_rest = [f for f in facts if d6._is_at_rest(f)]
    secrets = [f for f in facts if f["kind"] in ("secret_store", "certificate_policy")]
    assert len(at_rest) > 2000 and len(secrets) > T.REGISTER_ROW_CAP
    body = story(d6, big_view)
    shown = [r for r in rows_under(body, "Resource") if "At rest" in r]
    shown_secrets = [r for r in rows_under(body, "Resource") if "Service" in r]
    notes = _notes(body)
    assert len(shown) == T.REGISTER_ROW_CAP
    assert (f"{len(at_rest) - len(shown)} further rows omitted: showing the {len(shown)} highest-impact of the "
            f"{len(at_rest)} resources") in " ".join(notes)
    assert len(shown_secrets) == T.REGISTER_ROW_CAP
    assert f"{len(secrets) - len(shown_secrets)} further rows omitted: showing the first {len(shown_secrets)} of " \
           "the secrets" in " ".join(notes)
    assert all(T.FULL_LIST_POINTER in note for note in notes)
    assert not any("unknown facts" in note for note in notes)  # grouped by reason: nothing is cut
    # the worst rows are the ones kept: every High at-rest fact of the cut register is printed while it fits
    highs = sum(1 for f in at_rest if f.get("impact") == "High")
    assert sum(1 for r in shown if r["Finding codes"]) >= min(highs, T.REGISTER_ROW_CAP)
    stores = rows_under(story(d9, big_view), "Store")
    all_stores = d9._stores(big_view)
    assert len(stores) == T.REGISTER_ROW_CAP and len(all_stores) > T.REGISTER_ROW_CAP
    assert f"{len(all_stores) - len(stores)} further rows omitted" in " ".join(_notes(story(d9, big_view)))
    assert kpi_cards(story(d9, big_view))["Data stores"] == str(len(all_stores))  # the KPI counts every store


def test_d6_page_count_is_bounded_however_many_resources_were_collected(big_view):
    """Review major 1: 50k collected assets made a 1,882-page D6 (each provider / kind group was capped on its own).
    One cap per register keeps the document bounded; 8,000 assets give the same register sizes as 50,000."""
    raw = d6.build_pdf(big_view)
    pages = len(re.findall(rb"/Type\s*/Page[^s]", raw))
    assert pages < 300, pages


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


def test_d2_evidence_plan_names_each_sow_document_by_its_registry_number():
    """The merge of #486 (D2 methodology) wrote D6 / D7 / D8 as "Team CBOM deliverable #5 / #6 / #7", the numbers
    before this PR; the registry numbers them #6 / #7 / #8, and #9 / #10 already matched."""
    from backend.utilities.pdf.cbom_deliverables import DELIVERABLES
    from backend.utilities.pdf.cbom_methodology_text import EVIDENCE_PLAN

    registry = {spec.number for spec in DELIVERABLES.values()}
    produced = {sow: produced_from for sow, _title, produced_from, _evidence in EVIDENCE_PLAN}
    for sow in ("D6", "D7", "D8", "D9", "D10"):
        number = int(sow[1:])
        assert number in registry, sow
        assert produced[sow].startswith(f"Team CBOM deliverable #{number} (PDF)"), (sow, produced[sow])


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
    other = load_team_cbom_view(engine, 2)
    assert [v["name"] for v in view.vendors] == ["Acme Payments Gateway"]
    assert [v["name"] for v in other.vendors] == ["Other team vendor"]  # team-scoped
    assert not [a for a in other.posture.facts if a.source_key.startswith("sources:")]  # team 1's run stays team 1's
    unencrypted = next(f.fact for f in view.posture.facts if f.fact.get("name") == "public-assets")
    assert (unencrypted["at_rest"], unencrypted["impact"], unencrypted["key_management"]) == (
        "NOT_ENCRYPTED", "High", "none")
    assert "STORAGE_UNENCRYPTED" in unencrypted["finding_codes"]
    assert unencrypted["source"] == "x1-ssh-lab"  # the collecting source's name, never "Sources run #N" (PR #485 m8)
    assert (view.vendors[0]["attested_on"], view.vendors[0]["evidence_ref"]) == (
        "2026-11-12", "https://acme.example/security")
    keys = [r for r in rows_under(story(d6, view), "Key")]
    assert {"payments-cmk", "imported-no-material", "LabTdes"} <= names(keys, "Key")
    stores = rows_under(story(d9, view), "Store")
    assert {"payments-ledger", "labdb"} <= names(stores, "Store")


def test_d7_keeps_the_cloud_tls_listeners_the_mapper_collected_and_lists_their_source(sources_run):  # noqa: F811
    """Merge of #481 into this PR: D7 replaces the probed ``sources:`` endpoint facts with its de-duplicated
    endpoints, and that swap must not swallow the load balancer listeners the posture mapper collected from the
    cloud account (``collected:CBOM Sources``): network_estate re-adds probed ``tls_endpoint`` rows only."""
    from backend.utilities.cbom_sources.cert_estate import inputs_of
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view
    from backend.utilities.pdf import cbom_network_tls_pdf as d7

    engine, run_id = sources_run["engine"], sources_run["run"]["id"]
    _store_assets(engine, run_id)
    view = load_team_cbom_view(engine, 1)
    assert inputs_of(view).rows  # the estate is loaded: D7 takes its de-duplicating path, not the hand-built one
    scoped, _model = d7._scoped(view)
    listeners = {f.fact.get("name"): f for f in scoped.posture.facts if f.fact.get("kind") == "tls_endpoint"}
    assert {"ComplianceShield-LB:80", "ComplianceShield-LB:443"} <= set(listeners)
    owner = listeners["ComplianceShield-LB:443"].source_key
    assert owner in {s.key for s in scoped.posture.sources}  # its source is in the D7 source table
    text = re.sub(r"\s+", "", pdf_text(d7.build_pdf(view)))
    assert "ComplianceShield-LB:443" in text
    assert "DES-CBC3-SHA" in text  # its weak suite, in the weak cipher suite table (only this listener offers it)
    assert "RSAkeyexchangeaccepted" in text  # its forward-secrecy cell (static_rsa_kex)


# ------------------------------------------------------------------------------------------------ second review of #482
# One team stored the way the workers store it, then loaded with the real ``load_team_cbom_view``:
# * "Lab network" probes the fixture's one TLS endpoint;
# * "AWS prod" and "AWS prod (second role)" read the SAME AWS account (two roles, as #481's fixture does for the PCA):
#   both collect the same 4 TLS listeners / distributions (ComplianceShield-LB:80, ComplianceShield-LB:443,
#   d3lg18b01vnyjz.cloudfront.net, api.payments.example) and the same keys and stores;
# * "AWS PCA only" holds the private CA only (D8 evidence, nothing D7 prints);
# * "SQL Server 2022" holds the fixture's database settings;
# * "Gone AWS" was DELETED (job source_id 9999, no source row) and left one load balancer listener "Gone-LB:443"
#   offering TLS 1.0 and DES-CBC3-SHA.
GONE_LB = "Gone-LB"
GONE_LABEL = "Gone AWS"


@pytest.fixture(scope="module")
def seeded_view():
    import collections as _collections

    from sqlalchemy.pool import StaticPool
    from sqlmodel import Session, SQLModel, create_engine

    from backend.new_models import (
        CbomCollectedAsset,
        CbomCollectionJob,
        CbomCollectionRun,
        CbomCollectionSource,
    )
    from backend.utilities.cbom_sources import classify as C
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view

    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    SQLModel.metadata.create_all(eng)
    counter = [0]
    with Session(eng) as s:
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="rev482b", status="success")
        s.add(run)
        s.flush()

        def source(kind, name, *, deleted=False, hours_ago=2):
            src_id = None
            if not deleted:
                src = CbomCollectionSource(team_id=1, owner_user_id=1, kind=kind, name=name, name_lower=name.lower(),
                                           config={}, created_at=NOW.replace(tzinfo=None))
                s.add(src)
                s.flush()
                src_id = src.id
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src_id or 9999, kind="collect",
                                    status="success", attempts=1,
                                    finished_at=(NOW - dt.timedelta(hours=hours_ago)).replace(tzinfo=None),
                                    params={"source_uid": f"uid-{name}", "source_name": name})
            s.add(job)
            s.flush()
            return run.id, job.id, src_id

        def add(where, asset):
            counter[0] += 1
            run_id, job_id, src_id = where
            judged = C.classify(asset["type"], asset.get("algorithm"), asset.get("key_size"), asset.get("protocol"),
                                asset["facts"])
            s.add(CbomCollectedAsset(team_id=1, run_id=run_id, job_id=job_id, source_id=src_id, attempt=1,
                                     asset_key=f"r{counter[0]}", asset_type=asset["type"],
                                     cdx_type=judged["cdx_type"], target=asset.get("target") or "fixture",
                                     location=asset["location"], name=asset.get("name"),
                                     algorithm=asset.get("algorithm"), key_size=asset.get("key_size"),
                                     protocol=asset.get("protocol"), quantum_vulnerable=judged["quantum_vulnerable"],
                                     impact=judged["impact"], finding_codes=judged["finding_codes"],
                                     finding=judged["finding"], facts=asset["facts"]))

        by_source = _collections.defaultdict(list)
        for name, _kind, _run, asset in FX.assets():
            by_source[name].append(asset)
        net = source("network", "Lab network", hours_ago=6)
        for asset in by_source["Lab network"]:
            add(net, asset)
        for label, hours in (("AWS prod", 5), ("AWS prod (second role)", 4)):
            aws = source("aws_account", label, hours_ago=hours)
            for asset in by_source["AWS production"]:
                add(aws, asset)
        pca_only = source("aws_account", "AWS PCA only", hours_ago=3)
        for asset in by_source["AWS production"]:
            if asset["type"] == "cloud_ca":
                add(pca_only, asset)
        sql = source("databases", "SQL Server 2022", hours_ago=2)
        for asset in by_source["SQL Server 2022"]:
            add(sql, asset)
        gone = source("aws_account", GONE_LABEL, deleted=True, hours_ago=1)
        add(gone, {"type": "load_balancer_tls", "name": "Gone-LB:443", "protocol": "HTTPS",
                   "location": "arn:aws:elasticloadbalancing:ap-south-1:999:listener/app/Gone-LB/1/2",
                   "facts": {"ssl_policy": "ELBSecurityPolicy-2016-08", "protocols": ["TLSv1.0", "TLSv1.2"],
                             "ciphers": ["DES-CBC3-SHA"], "static_rsa_kex": True}})
        s.commit()
    yield load_team_cbom_view(eng, 1, now=NOW)
    eng.dispose()


def _squashed(pdf: bytes) -> str:
    return re.sub(r"\s+", "", pdf_text(pdf))


def _evidence_text(pdf: bytes) -> str:
    """The document without its scope-of-method sentence, which names every collection the team's scan nodes read
    ("CBOM Sources: 6 collections (...)", deleted ones included: what was read, not what is counted)."""
    return re.sub(r"CBOMSources:\d+collections\(.*?\)readbytheteam'sscannodes", "", _squashed(pdf))


def test_a_deleted_sources_collection_is_never_current_posture_evidence(seeded_view):
    """Review 6028864106 blocker: "Gone AWS | assessed", Sources 6/6 and Gone-LB:443 in D6, D7 and D9."""
    from backend.utilities.pdf import cbom_network_tls_pdf as d7

    gone = [c.key for c in seeded_view.collections if not c.source_kind]
    assert [c.label for c in seeded_view.collections if not c.source_kind] == [GONE_LABEL]
    # the posture: no source row, no fact of the deleted collection
    assert [row.label for row in seeded_view.posture.sources] == [
        "AWS PCA only", "AWS prod", "AWS prod (second role)", "Lab network", "SQL Server 2022"]
    assert not [f for f in seeded_view.posture.facts if f.source_key in gone]
    assert not [f for f in seeded_view.posture.facts if GONE_LB in str(f.fact.get("name") or "")]
    # D6 / D9: not in a register, not in the source table, and the Sources KPI counts the 5 current sources
    for module in (d6, d9):
        body = story(module, seeded_view)
        assert kpi_cards(body)["Sources"].startswith("5/5"), module.__name__
        flat = _evidence_text(module.build_pdf(seeded_view))
        assert GONE_LB not in flat and "GoneAWS" not in flat, module.__name__
        assert "5of5currentsourcesassessed" in flat, module.__name__
    # D7: not in the endpoint register, the protocol matrix, the weak-suite table or a KPI; only in "Left out"
    scoped, _model = d7._scoped(seeded_view)
    assert not [f for f in scoped.posture.facts if f.source_key in gone]
    assert GONE_LABEL not in " ".join(row.label for row in scoped.posture.sources)
    flat = _evidence_text(d7.build_pdf(seeded_view))
    assert GONE_LB not in flat
    assert flat.count("GoneAWS") == 1 and "Leftout:thelatestcollectionsof1deletedsource" in flat


@pytest.mark.parametrize("deleted", ["Lab network", "AWS production"])
def test_merge_adds_no_posture_fact_or_source_row_for_a_deleted_collection(deleted):
    """The root cause, in the pure merge: a deleted source's probed endpoints (``_probed_tls_fact``) and its mapped
    settings (``posture_mapper``) were posture facts, and so the collection became an "assessed" posture source."""
    rows, collections = FX.build()
    gone = {c.key for c in collections if c.source_name == deleted}
    collections = [dataclasses.replace(c, source_kind="") if c.key in gone else c for c in collections]
    by_key = {c.key: c for c in collections}
    for row in rows:
        row.collection = by_key[row.collection.key]
    merged = merge_collections(_empty_view(), rows, collections)
    assert gone and not [f for f in merged.posture.facts if f.source_key in gone]
    assert not [row for row in merged.posture.sources if row.key in gone]
    assert [c.key for c in merged.collections if not c.source_kind] == sorted(gone)  # still named as left out
    kept = {f.source_key for f in merged.posture.facts}
    assert kept and not kept & gone


def test_d7_prints_a_listener_two_sources_collected_once_and_names_both(seeded_view):
    """Review 6028864106 major: two roles reading one AWS account printed each listener twice (Endpoints 10)."""
    from backend.utilities.pdf import cbom_network_tls_pdf as d7

    scoped, _model = d7._scoped(seeded_view)
    labels = sorted(d7.common.endpoint_label(f) for f in d7._endpoints(scoped))
    assert labels == ["10.232.0.101:443", "ComplianceShield-LB:443", "ComplianceShield-LB:80",
                      "api.payments.example", "d3lg18b01vnyjz.cloudfront.net"]
    body = story(d7, seeded_view)
    cards = kpi_cards(body)
    assert (cards["Endpoints"], cards["Legacy protocol"], cards["Weak suites"]) == ("5", "3", "2")
    weak = rows_under(body, "Endpoint")
    # QA Q3-10: the IANA name, with the OpenSSL name the AWS policy stored beside it
    des = [r for r in weak if r.get("Suite") == "TLS_RSA_WITH_3DES_EDE_CBC_SHA (DES-CBC3-SHA)"]
    assert [r["Endpoint"] for r in des] == ["ComplianceShield-LB:443"]
    register = [r for r in weak if "Location" in r and r["Endpoint"] == "ComplianceShield-LB:443"]
    assert len(register) == 1
    where = re.sub(r"\s+", " ", register[0]["Location"])
    # the oldest source keeps the resource whichever role finished last (review 6058574998 F2: the kept row, its
    # remediation key and this cell no longer flip from run to run), and the other source is named
    assert "AWS prod (also: AWS prod (second role))" in where
    # both sources stay in the D7 source table: each holds evidence printed here
    assert [s.label for s in scoped.posture.sources] == [
        "AWS prod", "AWS prod (second role)", "Lab network"]


def test_d7_basis_box_counts_the_same_current_sources_as_the_sources_kpi(seeded_view):
    """Review 6028864106 minor: Basis box "6 of 6 current sources" against the Sources KPI "3/3"."""
    from backend.utilities.pdf import cbom_network_tls_pdf as d7

    assert kpi_cards(story(d7, seeded_view))["Sources"] == "3/3"
    flat = _squashed(d7.build_pdf(seeded_view))
    assert "3of3currentsourcesassessed" in flat
    assert "5of5currentsourcesassessed" not in flat


def test_d6_scope_cache_lives_and_dies_with_the_view():
    """Review 6028864106 minor: a module-global cache kept the last view's facts (45k at 50k assets) alive."""
    import gc
    import weakref

    class _Probe(PostureFactAgg):  # a subclass without __slots__ can be weakly referenced
        pass

    rows, collections = FX.build()
    built = merge_collections(_empty_view(), rows, collections)
    first_fact = built.posture.facts[0]
    held = _Probe(**{f.name: getattr(first_fact, f.name) for f in dataclasses.fields(first_fact)})
    built.posture = dataclasses.replace(built.posture, facts=(held, *built.posture.facts[1:]))
    probe = weakref.ref(held)  # alive while anything holds the posture's fact tuple
    del held, first_fact
    first = d6.scope_facts(built)
    assert first and d6.scope_facts(built) == first  # the second read is served from the cache
    cached_on_view = getattr(d6, "_SCOPE_ATTR", "?") in vars(built.posture)
    del built, first
    gc.collect()
    assert probe() is None  # nothing outside the view holds its facts once the request is done
    assert cached_on_view and not hasattr(d6, "_SCOPE_CACHE")
