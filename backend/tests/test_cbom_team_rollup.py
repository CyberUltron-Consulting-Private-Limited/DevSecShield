"""T-ROLL: tests for ``backend.utilities.dashboard.cbom_team_rollup`` (plan 6.3, WP1b).

ORACLE RULE (plan 8.4): every expected number in this module is a literal taken from plan
Appendix B (hand / openssl-DER-fingerprint derived) or from a stdlib-only probe that read the
committed raw fixture with plain loops.  NOTHING is recomputed with the product aggregator.  The
fixture ``cbom_team_rollup_scans.json`` is consumed as plain JSON; the view under test is built by
feeding ``ScanHead`` objects and a spying ``load_blobs`` into ``fold_scans``.

Fixture scans (Appendix B): 1 payments v1 / 2 payments v2 (current) / 3 identity-gateway /
4 crypto-misuse-lab / 5 pqc-pilot / 6 cert-lifecycle-lab (zip) / 7 vendor-sdk-manifests /
8 legacy-billing (Tier B) / 9 failed / 10 queued / 11 started / 12 sbom_sca (other type) /
13 success-but-empty / 14 other team.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import hashlib
import inspect
import json
import os
import random
import subprocess
import sys
import textwrap
import time
import typing
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard import cbom_team_rollup as roll  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import (  # noqa: E402
    ASSET_ALGORITHM,
    ASSET_CERTIFICATE,
    ASSET_MATERIAL,
    ASSET_PROTOCOL,
    EXCLUDED_FAILURE,
    EXCLUDED_NO_DATA,
    EXCLUDED_NOT_COMPLETED,
    EXPIRED,
    FIDELITY_FULL,
    FIDELITY_NONE,
    FIDELITY_REDUCED,
    LE_30,
    LE_90,
    MAX_LOCATIONS,
    MAX_SCAN_IDS,
    TIER_A,
    TIER_B,
    TIER_C,
    TIER_NONE,
    UNKNOWN,
    VALID,
    ExpiryBand,
    ScanFacts,
    ScanHead,
    TeamCbomView,
    cert_identity_key,
    classify_expiry,
    extract_scan_facts,
    fold_scans,
    load_team_cbom_view,
    sanitize_repo_url,
    source_key_for,
)

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)  # 17:58 IST; the fixture's frozen "now"
AS_OF = date(2026, 10, 19)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Appendix B source keys
PAYMENTS = "repo:github.com/e2e-demo/payments-service@main"
IDENTITY = "repo:github.com/e2e-demo/identity-gateway@main"
MISUSE = "repo:github.com/e2e-demo/crypto-misuse-lab@main"
PQC = "repo:github.com/e2e-demo/pqc-pilot@release"
ZIPLAB = "zip:cert-lifecycle-lab"
MANIFESTS = "repo:github.com/e2e-demo/vendor-sdk-manifests@main"
LEGACY = "repo:github.com/e2e-demo/legacy-billing@main"

# Canary strings that live ONLY in scan blobs / raw metadata and must never reach a view
CANARIES = (
    "NOT-A-REAL-TOKEN-CANARY",
    "x-access-token",
    "FAILED-SCAN-CANARY",
    "QUEUED-SCAN-CANARY",
    "RUNNING-SCAN-CANARY",
    "SBOM-TYPE-CANARY",
    "other-team-canary",
    "other-org",
)


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _head(scan: dict, *, naive: bool = False) -> ScanHead:
    created, updated = _ts(scan["created_at"]), _ts(scan["last_updated"])
    if naive:  # what Postgres / SQLite hand back for a DateTime column without tz
        created, updated = created.replace(tzinfo=None), updated.replace(tzinfo=None)
    return ScanHead(
        id=scan["id"],
        team_id=scan["team_id"],
        scan_type=scan["scan_type"],
        title=scan["title"],
        status=scan["status"],
        created_at=created,
        last_updated=updated,
        scan_metadata=scan["scan_metadata"],
    )


class BlobSpy:
    """A ``load_blobs`` callable that records every id it is asked for."""

    def __init__(self, blobs: dict) -> None:
        self.blobs = blobs
        self.calls: list[list[int]] = []

    def __call__(self, ids):
        self.calls.append(list(ids))
        return {i: self.blobs[i] for i in ids if i in self.blobs}

    @property
    def seen(self) -> list[int]:
        return [i for call in self.calls for i in call]


def run_fold(scans, *, team_id=1, name="E2E Demo Team", now=NOW, naive=False, **kwargs):
    """Fold ``scans`` (fixture-shaped dicts) and return ``(view, spy)``."""
    spy = BlobSpy({s["id"]: s["scan_data"] for s in scans})
    heads = [_head(s, naive=naive) for s in scans]
    view = fold_scans(heads, spy, team_id=team_id, team_name=name, now=now, **kwargs)
    return view, spy


# ---------------------------------------------------------------------------------------------
# Synthetic builders (small hand-made run-objects; the real ones come from the fixture)
# ---------------------------------------------------------------------------------------------
def only(items):
    items = list(items)
    assert len(items) == 1, items
    return items[0]


def _row(title, *, asset_type="algorithm", impact="Low", codes=(), bom_ref="auto",
         location="app.py", **extra):  # fmt: skip
    row = {
        "title": title,
        "asset_type": asset_type,
        "impact": impact,
        "finding_codes": list(codes),
        "location": location,
        "description": f"{title} finding text",
        "quantum_vulnerable": False,
        "quantum_safe": True,
        "hybrid": False,
        "key_size": None,
        # a synthetic row above Low is a finding (cbom_rows.is_finding): a clean row has no impact
        "weak": impact not in (None, "Low"),
    }
    if bom_ref == "auto":
        row["bom_ref"] = f"ref-{asset_type}-{title}-{location}"
    elif bom_ref is not None:
        row["bom_ref"] = bom_ref
    row.update(extra)
    return row


def _cert_component(name, subject, *, issuer=None, not_before="2026-01-01T00:00:00Z",
                    not_after="2030-01-01T00:00:00Z", sig="sha256WithRSAEncryption",
                    pk="rsaEncryption", size="2048", curve=None, self_signed="false",
                    ca="false", path=None):  # fmt: skip
    props = {
        "crypto:assetType": "certificate",
        "crypto:subjectName": subject,
        "crypto:issuerName": issuer or subject,
        "crypto:notValidBefore": not_before,
        "crypto:notValidAfter": not_after,
        "crypto:signatureAlgorithm": sig,
        "crypto:publicKeyAlgorithm": pk,
        "crypto:keySize": size,
        "crypto:curve": curve,
        "crypto:selfSigned": self_signed,
        "crypto:isCertificateAuthority": ca,
        "discovery:source": path or name,
    }
    return {
        "bom-ref": f"ref-cert-{name}",
        "type": "cryptographic-asset",
        "name": name,
        "cryptoProperties": {"assetType": "certificate"},
        "properties": [{"name": k, "value": v} for k, v in props.items() if v is not None],
    }


def _cert_row(name, *, impact="Low", codes=(), path=None, not_after="2030-01-01T00:00:00Z",
              expired=False, self_signed=False):  # fmt: skip
    return _row(
        name, asset_type="certificate", impact=impact, codes=codes, bom_ref=f"ref-cert-{name}",
        location=path or name, expired=expired, self_signed=self_signed,
        not_valid_after=not_after, key_size="2048",
    )  # fmt: skip


def _lib(name, path="requirements.txt"):
    return {
        "bom-ref": f"ref-lib-{name}",
        "type": "library",
        "name": name,
        "properties": [
            {"name": "crypto:role", "value": "library"},
            {"name": "discovery:source", "value": path},
        ],
    }


_STATES = ("pass", "pass_with_evidence", "fail", "out_of_scope", "not_bom_evidenceable", "na")


def _compliance(**frameworks):
    """``_compliance(nist_800_57={"KM-1": "pass"})`` -> a Tier-A ``cbom_compliance`` dict."""
    out = {}
    for framework, reqs in frameworks.items():
        tally = Counter(reqs.values())
        block = {state: tally.get(state, 0) for state in _STATES}
        block["coverage"] = None
        block["requirements"] = [
            {
                "id": rid, "title": f"Title {rid}", "source": f"Cite {rid}", "verdict": verdict,
                "attestable": verdict in ("not_bom_evidenceable", "pass_with_evidence"),
                "evidence": "e", "refs": [],
            }
            for rid, verdict in reqs.items()
        ]  # fmt: skip
        out[framework] = block
    out["disclaimer"] = "AIBOM-DISCLAIMER-MUST-NEVER-BE-PRINTED"
    return out


def _blob(rows=(), components=(), *, edges=(), compliance=None, distributions=True,
          attestations=None):  # fmt: skip
    data = {
        "results": list(rows),
        "cbom_json": {"specVersion": "1.6", "components": list(components)},
    }
    if distributions:
        data["cbom_distributions"] = {"pqc": {}}
    data["cbom_compliance"] = (
        compliance if compliance is not None else _compliance(nist_800_57={"KM-1": "pass"})
    )
    if edges:
        data["cbom_graph"] = {"nodes": [], "edges": list(edges)}
    if attestations:
        data["attestations"] = attestations
    return data


_UNSET = object()


def synth(sid, *, age=timedelta(days=1), data=_UNSET, status="success", team=1,
          scan_type="cbom", title=None, repo="https://github.com/o/r", branch="main",
          zip_title=None):  # fmt: skip
    """One fixture-shaped scan dict; ``age`` is how long before ``NOW`` it was created."""
    created = NOW - age
    if zip_title:
        meta = {"zip_file_used": True, "repo_url": None, "branch": None}
    else:
        meta = {"zip_file_used": False, "repo_url": repo, "branch": branch}
    return {
        "id": sid, "team_id": team, "scan_type": scan_type,
        "title": title or zip_title or f"scan-{sid}",
        "status": status, "created_at": _iso(created),
        "last_updated": _iso(created + timedelta(minutes=2)),
        "scan_metadata": meta, "scan_data": _blob() if data is _UNSET else data,
    }  # fmt: skip


# ---------------------------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------------------------
@pytest.fixture(scope="session")
def raw():
    return json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def registry():
    return json.loads((FIXTURES / "cbom_scanner_registry.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def run(raw):
    """Fold ALL 14 fixture scans (incl. other-team / sbom_sca / failed) for team 1."""
    return run_fold(raw["scans"])


@pytest.fixture(scope="module")
def view(run):
    return run[0]


def scan_by_id(raw, sid):
    return next(s for s in raw["scans"] if s["id"] == sid)


# =============================================================================================
# sanitize_repo_url / source_key_for  (T-ROLL 4)
# =============================================================================================
LEGACY_URL = "https://x-access-token:NOT-A-REAL-TOKEN-CANARY@github.com/e2e-demo/legacy-billing.git"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        (123, None),
        ("https://github.com/e2e-demo/pay", "https://github.com/e2e-demo/pay"),
        ("https://github.com/E2E-Demo/pay.git", "https://github.com/E2E-Demo/pay"),
        ("https://github.com/e2e-demo/pay/", "https://github.com/e2e-demo/pay"),
        ("https://github.com/e2e-demo/pay.git/", "https://github.com/e2e-demo/pay"),
        ("HTTPS://GitHub.COM/Org/Repo.GIT", "https://github.com/Org/Repo"),
        (LEGACY_URL, "https://github.com/e2e-demo/legacy-billing"),
        ("https://user@github.com/o/r", "https://github.com/o/r"),
        ("https://github.com/o/r?token=abc123#frag", "https://github.com/o/r"),
        ("  https://github.com/o/r \n", "https://github.com/o/r"),
        ("https://git.example.com:8443/o/r.git", "https://git.example.com:8443/o/r"),
        ("https://github.com:443/o/r", "https://github.com/o/r"),
        ("github.com/o/r", "https://github.com/o/r"),
        ("git@github.com:o/r.git", "ssh://github.com/o/r"),
        ("ssh://git@github.com/o/r.git", "ssh://github.com/o/r"),
        ("file:///etc/passwd", None),
        ("javascript:alert(1)", None),
        ("https://", None),
        ("not a url", None),
        ("https://exa mple.com/o/r", None),
    ],
)
def test_sanitize_repo_url_table(url, expected):
    assert sanitize_repo_url(url) == expected


def test_sanitize_repo_url_never_leaks_credentials():
    cleaned = sanitize_repo_url(LEGACY_URL)
    assert "NOT-A-REAL-TOKEN-CANARY" not in cleaned and "x-access-token" not in cleaned


_PAYMENTS_KEY = "repo:github.com/e2e-demo/payments-service@main"


@pytest.mark.parametrize(
    ("meta", "title", "scan_id", "expected"),
    [
        ({"repo_url": "https://github.com/E2E-Demo/payments-service.git", "branch": "main"},
         "t", 1, (_PAYMENTS_KEY, "github.com/E2E-Demo/payments-service (main)", "repo")),
        ({"repo_url": "https://github.com/e2e-demo/payments-service/", "branch": "main"},
         "t", 9, (_PAYMENTS_KEY, "github.com/e2e-demo/payments-service (main)", "repo")),
        ({"repo_url": LEGACY_URL, "branch": "main"}, "legacy-billing", 8,
         (LEGACY, "github.com/e2e-demo/legacy-billing (main)", "repo")),
        ({"repo_url": "https://github.com/o/r", "branch": None}, "t", 2,
         ("repo:github.com/o/r@default", "github.com/o/r (default)", "repo")),
        ({"repo_url": "https://github.com/o/r", "branch": "Release/1.0"}, "t", 2,
         ("repo:github.com/o/r@release/1.0", "github.com/o/r (Release/1.0)", "repo")),
        ({"zip_file_used": True, "repo_url": None}, "Cert Lifecycle Lab", 6,
         ("zip:cert-lifecycle-lab", "Zip upload: Cert Lifecycle Lab", "zip")),
        ({"zip_file_used": False, "repo_url": None, "cbom_file_used": True}, "My CBOM v2.json", 3,
         ("file:my-cbom-v2-json", "Uploaded CBOM: My CBOM v2.json", "file")),
        (None, "whatever", 42, ("scan:42", "Scan #42", "scan")),
        ({}, "whatever", 7, ("scan:7", "Scan #7", "scan")),
        ("not-a-dict", "x", 5, ("scan:5", "Scan #5", "scan")),
        ({"repo_url": 123, "zip_file_used": False}, "x", 6, ("scan:6", "Scan #6", "scan")),
        ({"repo_url": "file:///etc/passwd", "zip_file_used": True}, "z", 2,
         ("zip:z", "Zip upload: z", "zip")),
    ],
)  # fmt: skip
def test_source_key_for_table(meta, title, scan_id, expected):
    assert source_key_for(meta, title, scan_id) == expected


def test_source_key_never_contains_userinfo():
    key, label, _ = source_key_for({"repo_url": LEGACY_URL, "branch": "main"}, "t", 8)
    for text in (key, label):
        assert "NOT-A-REAL-TOKEN-CANARY" not in text and "x-access-token" not in text


def test_same_repo_on_two_branches_is_two_sources_and_same_zip_title_is_one():
    main = source_key_for({"repo_url": "https://github.com/o/r", "branch": "main"}, "a", 1)[0]
    dev = source_key_for({"repo_url": "https://github.com/o/r", "branch": "dev"}, "a", 2)[0]
    assert main != dev
    zip_a = source_key_for({"zip_file_used": True}, "Same Title", 1)[0]
    zip_b = source_key_for({"zip_file_used": True}, "Same Title", 2)[0]
    assert zip_a == zip_b == "zip:same-title"


def test_zip_title_without_ascii_letters_still_gets_a_stable_distinct_key():
    first = source_key_for({"zip_file_used": True}, "日本語アップロード", 1)[0]
    again = source_key_for({"zip_file_used": True}, "日本語アップロード", 2)[0]
    other = source_key_for({"zip_file_used": True}, "!!!", 3)[0]
    assert first == again and first.startswith("zip:") and first != "zip:"
    assert other.startswith("zip:") and other != first


# =============================================================================================
# cert_identity_key  (plan 4.4)
# =============================================================================================
APP_CERT = {  # cert.pem of synthetic-crypto-app (fixture scans 1, 2, 3, 8)
    "crypto:subjectName": "synthetic-crypto-app.test",
    "crypto:issuerName": "synthetic-crypto-app.test",
    "crypto:notValidBefore": "2026-06-29T09:56:21Z",
    "crypto:notValidAfter": "2027-06-29T09:56:21Z",
    "crypto:signatureAlgorithm": "sha256WithRSAEncryption",
    "crypto:publicKeyAlgorithm": "rsaEncryption",
    "crypto:keySize": "2048",
}
EC_CERT = {  # ec-p256.crt of synthetic-crypto-certs
    "crypto:subjectName": "ec-p256-ca.test",
    "crypto:issuerName": "ec-p256-ca.test",
    "crypto:notValidBefore": "2026-07-01T09:22:57Z",
    "crypto:notValidAfter": "2036-06-28T09:22:57Z",
    "crypto:signatureAlgorithm": "ecdsaWithSHA256",
    "crypto:publicKeyAlgorithm": "ecPublicKey",
    "crypto:keySize": "256",
    "crypto:curve": "P-256",
}


def test_cert_identity_key_pins_the_ten_field_tuple_formula():
    # literals: sha256("\x1f".join(parts)).hexdigest()[:16], derived outside the product
    assert cert_identity_key(APP_CERT, fallback_name="cert.pem", source_key="s") == (
        "4b38347cc848f7ee",
        True,
    )
    assert cert_identity_key(EC_CERT, fallback_name="ec.crt", source_key="s") == (
        "d5e9379e0029c818",
        True,
    )


def test_cert_identity_key_is_case_and_whitespace_insensitive_where_specified():
    noisy = dict(APP_CERT)
    noisy["crypto:subjectName"] = "  Synthetic-Crypto-App.TEST "
    noisy["crypto:issuerName"] = "SYNTHETIC-CRYPTO-APP.test"
    noisy["crypto:signatureAlgorithm"] = "SHA256WITHRSAENCRYPTION"
    noisy["crypto:keySize"] = 2048  # a non-text value must hash like its text form
    assert cert_identity_key(noisy, fallback_name="x", source_key="s")[0] == "4b38347cc848f7ee"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("crypto:notValidAfter", "2027-06-30T09:56:21Z"),
        ("crypto:notValidBefore", "2026-06-30T09:56:21Z"),
        ("crypto:keySize", "4096"),
        ("crypto:publicKeyAlgorithm", "ecPublicKey"),
        ("crypto:curve", "P-384"),
        ("crypto:issuerName", "another-issuer"),
    ],
)
def test_cert_identity_key_changes_when_any_identity_field_changes(field, value):
    changed = dict(APP_CERT)
    changed[field] = value
    assert cert_identity_key(changed, fallback_name="x", source_key="s")[0] != "4b38347cc848f7ee"


@pytest.mark.parametrize("missing", ["crypto:subjectName", "crypto:notValidAfter"])
@pytest.mark.parametrize("blank", [None, "", "   "])
def test_cert_identity_key_falls_back_to_a_weak_name_key(missing, blank):
    props = dict(APP_CERT)
    if blank is None:
        props.pop(missing)
    else:
        props[missing] = blank
    assert cert_identity_key(props, fallback_name="cert.pem", source_key="repo:h/o/r@main") == (
        "name:cert.pem|repo:h/o/r@main",
        False,
    )


# =============================================================================================
# classify_expiry  (plan F-03: the register computes its own validity bands)
# =============================================================================================
@pytest.mark.parametrize(
    ("not_after", "band", "days"),
    [
        ("2026-10-18T23:59:59Z", EXPIRED, -1),
        ("2026-09-14T00:00:00Z", EXPIRED, -35),
        ("2026-10-19T00:00:00Z", LE_30, 0),  # expires today: NOT expired ("strictly before")
        ("2026-11-08T00:00:00Z", LE_30, 20),
        ("2026-11-18T00:00:00Z", LE_30, 30),
        ("2026-11-19T00:00:00Z", LE_90, 31),
        ("2027-01-17T00:00:00Z", LE_90, 90),
        ("2027-01-18T00:00:00Z", VALID, 91),
        ("2036-06-28T09:22:57Z", VALID, (date(2036, 6, 28) - AS_OF).days),
    ],
)
def test_classify_expiry_boundaries(not_after, band, days):
    assert classify_expiry(not_after, AS_OF) == ExpiryBand(band, days)


@pytest.mark.parametrize(
    "garbage", [None, "", "garbage", 20261108, "2026-13-45T00:00:00Z", "26-10-19", [], {}]
)
def test_classify_expiry_unknown_for_missing_or_unparseable(garbage):
    assert classify_expiry(garbage, AS_OF) == ExpiryBand(UNKNOWN, None)


def test_classify_expiry_accepts_a_datetime_as_of():
    assert classify_expiry("2026-11-08T00:00:00Z", NOW) == ExpiryBand(LE_30, 20)
    assert roll.NEAR_EXPIRY_DAYS == 90


# =============================================================================================
# extract_scan_facts  (T-ROLL 9 / 11 / 19)
# =============================================================================================
def facts_of(scan, data=_UNSET, *, status=None):
    head = _head(scan)
    if status is not None:
        head = dataclasses.replace(head, status=status)
    return extract_scan_facts(head, scan["scan_data"] if data is _UNSET else data)


class Explosive(dict):
    """A blob that fails the test if the extractor so much as looks at it."""

    def __getitem__(self, key):
        raise AssertionError("blob must not be read")

    get = items = keys = values = __iter__ = __contains__ = __getitem__


def test_tier_a_scan_is_full_fidelity_and_fully_extracted(raw):
    facts = facts_of(scan_by_id(raw, 2))
    assert (facts.fidelity, facts.tier, facts.fidelity_reasons) == (FIDELITY_FULL, TIER_A, ())
    assert facts.exclusion is None and facts.included
    assert (facts.scan_id, facts.source_key, facts.source_kind) == (2, PAYMENTS, "repo")
    assert facts.repo_url == "https://github.com/e2e-demo/payments-service"
    assert facts.branch == "main" and facts.created_at == NOW - timedelta(days=7)
    assert (facts.asset_count, facts.cert_count, facts.lib_count) == (14, 2, 4)
    assert (len(facts.assets), len(facts.certs), len(facts.libs)) == (14, 2, 4)
    assert len(facts.frameworks) == 13 and "disclaimer" not in facts.frameworks
    assert len(facts.requirements) == 109 and facts.warnings == []
    assert not facts.is_current  # currentness is decided by the fold, not by extraction


def test_framework_counts_of_one_scan_are_copied_not_recomputed(raw):
    pool = facts_of(scan_by_id(raw, 2)).frameworks["cert_in_cbom"]
    assert (pool.passed, pool.failed, pool.not_bom_evidenceable, pool.out_of_scope) == (
        15,
        2,
        26,
        0,
    )
    assert (pool.passed_with_evidence, pool.na, pool.sources_pooled) == (0, 0, 1)
    assert pool.coverage == 0.882


def test_nothing_from_the_aibom_boilerplate_survives_extraction(raw):
    blob = scan_by_id(raw, 2)["scan_data"]
    facts = facts_of(scan_by_id(raw, 2))
    for leak in (blob["cbom_compliance"]["disclaimer"][:40], "clinithread", "serialNumber"):
        assert leak not in repr(facts)


def test_tier_b_scan_is_reduced_with_reasons_but_keeps_typed_rows_and_cbom_json(raw):
    facts = facts_of(scan_by_id(raw, 8))
    assert (facts.fidelity, facts.tier) == (FIDELITY_REDUCED, TIER_B)
    assert facts.fidelity_reasons == ("no_distributions", "no_compliance")
    assert facts.exclusion is None
    assert (facts.asset_count, facts.cert_count, facts.lib_count) == (12, 1, 4)
    assert facts.frameworks == {} and facts.requirements == []


def test_tier_c_rows_derive_asset_type_and_grade_from_quantum_safe():
    scan = synth(1, data={"results": [
        {"title": "cert.pem", "algorithm_type": "certificate", "impact": "Low",
         "location": "cert.pem"},
        {"title": "id_rsa", "algorithm_type": "key", "impact": "High", "location": "id_rsa"},
        {"title": "TLS 1.0", "algorithm_type": "protocol", "impact": "High", "location": "tls.py"},
        {"title": "RSA-1024", "algorithm_type": "pke", "impact": "high", "location": "a.py",
         "quantum_safe": False, "key_size": 1024},
        {"title": "AES-GCM", "algorithm_type": "block-cipher", "impact": "Low", "location": "a.py",
         "quantum_safe": True},
        {"algorithm_name": "MD5", "algorithm_type": "hash", "impact": "High", "location": "b.py"},
    ]})  # fmt: skip
    facts = facts_of(scan)
    assert (facts.fidelity, facts.tier) == (FIDELITY_REDUCED, TIER_C)
    assert facts.fidelity_reasons == (
        "no_distributions", "no_compliance", "no_asset_type", "no_cbom_json",
    )  # fmt: skip
    by_title = {a.title: a for a in facts.assets}
    assert [a.asset_type for a in facts.assets] == [
        ASSET_CERTIFICATE, ASSET_MATERIAL, ASSET_PROTOCOL,
        ASSET_ALGORITHM, ASSET_ALGORITHM, ASSET_ALGORITHM,
    ]  # fmt: skip
    rsa = by_title["RSA-1024"]
    assert (rsa.impact, rsa.key_size, rsa.primitive) == ("High", "1024", "pke")
    assert (rsa.quantum_safe, rsa.quantum_vulnerable) == (False, True)
    assert by_title["AES-GCM"].quantum_vulnerable is False
    assert by_title["MD5"].quantum_vulnerable is None  # title from algorithm_name; ungradeable
    cert = only(facts.certs)  # no cbom_json: the certificate row alone becomes a weak identity
    assert (cert.identity_strong, cert.key, cert.name) == (
        False, f"name:cert.pem|{facts.source_key}", "cert.pem",
    )  # fmt: skip
    assert facts.cert_count == 1


@pytest.mark.parametrize(
    ("status", "exclusion"),
    [
        ("failure", EXCLUDED_FAILURE),
        (" Failure ", EXCLUDED_FAILURE),
        ("pending", EXCLUDED_NOT_COMPLETED),
        ("started", EXCLUDED_NOT_COMPLETED),
        ("retry", EXCLUDED_NOT_COMPLETED),
        ("NOT_STARTED", EXCLUDED_NOT_COMPLETED),
        ("revoked", EXCLUDED_NOT_COMPLETED),
        (None, EXCLUDED_NOT_COMPLETED),
    ],
)
def test_non_success_scans_are_excluded_and_their_blob_is_never_read(raw, status, exclusion):
    head = dataclasses.replace(_head(scan_by_id(raw, 2)), status=status)
    facts = extract_scan_facts(head, Explosive(results=[1]))
    assert facts.exclusion == exclusion and not facts.included
    assert (facts.tier, facts.fidelity) == (TIER_NONE, FIDELITY_NONE)
    assert facts.assets == [] and facts.certs == [] and facts.requirements == []


@pytest.mark.parametrize("status", ["success", " Success ", "SUCCESS"])
def test_success_status_is_normalised(raw, status):
    assert facts_of(scan_by_id(raw, 2), status=status).exclusion is None


@pytest.mark.parametrize(
    "blob",
    [None, {}, [], "x", 7, {"results": "x"}, {"cbom_json": []}, {"cbom_json": "x"}, {"other": 1}],
)
def test_success_scans_without_results_list_or_cbom_json_are_no_data(raw, blob):
    facts = facts_of(scan_by_id(raw, 2), blob)
    assert facts.exclusion == EXCLUDED_NO_DATA and not facts.included
    assert (facts.tier, facts.fidelity, facts.assets) == (TIER_NONE, FIDELITY_NONE, [])


def test_valid_but_empty_scans_are_included_not_excluded(raw):
    clean = facts_of(scan_by_id(raw, 7))  # manifest-only: results == [] but 18 libraries
    assert clean.included and clean.fidelity == FIDELITY_FULL and clean.tier == TIER_A
    assert (clean.asset_count, clean.lib_count) == (0, 18)
    assert facts_of(scan_by_id(raw, 2), {"results": []}).included
    assert facts_of(scan_by_id(raw, 2), {"cbom_json": {}}).included


def _variant(raw, mutate):
    blob = copy.deepcopy(scan_by_id(raw, 2)["scan_data"])
    mutate(blob)
    return facts_of(scan_by_id(raw, 2), blob)


@pytest.mark.parametrize(
    ("mutate", "reasons", "tier"),
    [
        (lambda b: b.pop("cbom_distributions"), ("no_distributions",), TIER_B),
        (lambda b: b.pop("cbom_compliance"), ("no_compliance",), TIER_B),
        (lambda b: b.update(cbom_compliance={}), ("no_compliance",), TIER_B),
        (lambda b: b.update(cbom_compliance={"disclaimer": "x"}), ("no_compliance",), TIER_B),
        (lambda b: b["results"][0].pop("asset_type"), ("no_asset_type",), TIER_C),
        (lambda b: b.update(cbom_json=[]), ("no_cbom_json",), TIER_C),
        (lambda b: b.update(cbom_distributions={}), (), TIER_A),  # an empty dict is still a dict
    ],
)
def test_each_fidelity_reason_is_detected_on_its_own(raw, mutate, reasons, tier):
    facts = _variant(raw, mutate)
    assert facts.fidelity_reasons == reasons and facts.tier == tier
    assert facts.fidelity == (FIDELITY_FULL if not reasons else FIDELITY_REDUCED)


def test_tier_a_algorithm_row_maps_every_field_and_keeps_text_as_text(raw):
    facts = facts_of(scan_by_id(raw, 2))
    rsa = next(a for a in facts.assets if a.title == "RSA-1024")
    assert (rsa.source_key, rsa.asset_type) == (PAYMENTS, ASSET_ALGORITHM)
    assert rsa.ident == rsa.bom_ref == "crypto-algo-rsa-1024-crypto-app-py"
    assert (rsa.location, rsa.impact) == ("crypto_app.py", "High")
    assert sorted(rsa.finding_codes) == ["QUANTUM_VULNERABLE", "WEAK_ALGORITHM"]
    assert (rsa.key_size, rsa.primitive, rsa.security_strength_bits) == ("1024", "pke", 80)
    assert (rsa.quantum_vulnerable, rsa.quantum_safe, rsa.hybrid) == (True, False, False)
    assert rsa.nist_quantum_security_level == 0
    assert rsa.pqc_migration_target == "ML-KEM (FIPS 203) / ML-DSA (FIPS 204)"
    assert rsa.pqc_migration_roadmap == "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)"
    assert isinstance(rsa.risk_score, float) and rsa.description.startswith("Quantum-vulnerable")
    assert (rsa.tier, rsa.current, rsa.scan_count) == (TIER_A, False, 1)
    assert (rsa.first_seen, rsa.last_seen) == (facts.created_at, facts.created_at)
    assert (rsa.scan_ids, rsa.latest_scan_id) == ((2,), 2)


def test_tier_b_rows_have_no_bom_ref_so_identity_falls_back_to_slug_and_location(raw):
    rsa = next(a for a in facts_of(scan_by_id(raw, 8)).assets if a.title == "RSA-1024")
    assert (rsa.bom_ref, rsa.ident, rsa.tier) == (None, "rsa-1024#crypto_app.py", TIER_B)
    assert (rsa.risk_score, rsa.security_strength_bits, rsa.pqc_migration_roadmap) == (None,) * 3
    assert (rsa.quantum_vulnerable, rsa.nist_quantum_security_level) == (True, 0)


def test_certificate_rows_carry_validity_and_finding_codes(raw):
    facts = facts_of(scan_by_id(raw, 6))
    expired = next(a for a in facts.assets if a.title == "expired.crt")
    assert expired.asset_type == ASSET_CERTIFICATE and expired.impact == "High"
    assert expired.not_valid_after == "2026-09-14T00:00:00Z"
    assert sorted(expired.finding_codes) == ["EXPIRED_CERTIFICATE", "SELF_SIGNED_LEAF"]


def test_pqc_rows_expose_nist_level_parameter_set_and_hybrid(raw):
    rows = {a.title: a for a in facts_of(scan_by_id(raw, 5)).assets}
    kem = rows["ML-KEM-768"]
    assert (kem.primitive, kem.parameter_set, kem.nist_quantum_security_level) == ("kem", "768", 3)
    assert (kem.security_strength_bits, kem.quantum_vulnerable, kem.hybrid) == (192, False, False)
    assert rows["Hybrid ML-KEM-768"].hybrid is True


def test_certificate_components_join_their_result_row_and_graph_edges():
    comps = [
        _cert_component("leaf.crt", "leaf.test", issuer="Root CA", ca="false", path="tls/leaf.crt"),
        _cert_component("root.crt", "Root CA", self_signed="true", ca="true"),
        _cert_component("orphan.crt", "orphan.test", ca=None),  # CA flag absent => unknown
    ]
    rows = [
        _cert_row("leaf.crt", impact="High", codes=("WEAK_CERTIFICATE_KEY",), path="tls/leaf.crt",
                  expired=True, self_signed=False),
        _cert_row("root.crt", self_signed=True),
        _cert_row("orphan.crt"),
    ]  # fmt: skip
    edge = {"rel": "signed_by", "source": "ref-cert-leaf.crt", "target": "ref-cert-root.crt"}
    noise = {"rel": "signatureAlgorithm", "source": "ref-cert-leaf.crt", "target": "x"}
    facts = facts_of(synth(1), _blob(rows, comps, edges=[edge, noise]))
    leaf, root, orphan = facts.certs
    assert (leaf.subject_cn, leaf.issuer_cn, leaf.signed_by) == (
        "leaf.test",
        "Root CA",
        ("root.crt",),
    )
    assert (leaf.is_ca, leaf.self_signed, leaf.scan_time_expired) == (False, False, True)
    assert (leaf.impact, leaf.finding_codes) == ("High", ("WEAK_CERTIFICATE_KEY",))
    assert leaf.locations == ((facts.source_label, "tls/leaf.crt"),) and leaf.locations_total == 1
    assert leaf.public_key_algorithm == "rsaEncryption" and leaf.key_size == "2048"
    assert leaf.signature_algorithm == "sha256WithRSAEncryption" and leaf.curve is None
    assert (root.is_ca, root.self_signed, root.signed_by) == (True, True, ())
    assert (orphan.is_ca, orphan.signed_by) == (None, ())
    assert all(c.identity_strong and len(c.key) == 16 for c in facts.certs)
    assert facts.cert_count == 3 and facts.asset_count == 3


def test_certificate_component_falls_back_to_certificate_properties_for_names():
    comp = _cert_component("c.crt", "ignored")
    comp["properties"] = [
        p
        for p in comp["properties"]
        if p["name"]
        not in (
            "crypto:subjectName",
            "crypto:issuerName",
            "crypto:notValidAfter",
            "crypto:notValidBefore",
        )
    ]
    comp["cryptoProperties"]["certificateProperties"] = {
        "subjectName": "cp.test", "issuerName": "cp-ca.test",
        "notValidBefore": "2026-01-01T00:00:00Z", "notValidAfter": "2031-01-01T00:00:00Z",
    }  # fmt: skip
    cert = only(facts_of(synth(1), _blob([], [comp])).certs)
    assert (cert.subject_cn, cert.issuer_cn, cert.not_after) == (
        "cp.test",
        "cp-ca.test",
        "2031-01-01T00:00:00Z",
    )
    assert cert.identity_strong


def test_libraries_are_merged_by_casefolded_name_within_one_scan():
    libs = [
        _lib("pyOpenSSL", "requirements.txt"),
        _lib("PYOPENSSL", "app/tls.py"),
        _lib("ssl (stdlib)"),
    ]
    facts = facts_of(synth(1), _blob([], libs))
    assert facts.lib_count == 2
    openssl = next(lib for lib in facts.libs if lib.key == "pyopenssl")
    assert openssl.name == "pyOpenSSL" and openssl.discovered_in == (
        "requirements.txt",
        "app/tls.py",
    )
    assert (openssl.discovered_in_total, openssl.source_keys) == (2, (facts.source_key,))
    assert openssl.source_labels == (facts.source_label,)


def test_requirements_and_attestations_of_one_scan():
    compliance = _compliance(nist_800_57={
        "KM-1": "pass_with_evidence", "KM-2": "not_bom_evidenceable", "KM-3": "fail"})  # fmt: skip
    note = {"filename": "hsm-policy.pdf", "note": "n", "uploaded_at": "2026-10-18T09:00:00Z"}
    facts = facts_of(
        synth(1), _blob(compliance=compliance, attestations={"nist_800_57": {"KM-1": note}})
    )
    reqs = {r.req_id: r for r in facts.requirements}
    assert (reqs["KM-1"].attestable_sources, reqs["KM-1"].attested_sources) == (1, 1)
    assert (reqs["KM-2"].attestable_sources, reqs["KM-2"].attested_sources) == (1, 0)
    assert (reqs["KM-3"].attestable_sources, reqs["KM-3"].attested_sources) == (0, 0)
    assert reqs["KM-1"].verdicts == {facts.source_key: "pass_with_evidence"}
    assert (reqs["KM-1"].title, reqs["KM-1"].citation) == ("Title KM-1", "Cite KM-1")
    assert reqs["KM-1"].latest_attestation_file == "hsm-policy.pdf"
    assert reqs["KM-1"].latest_attestation_at == "2026-10-18T09:00:00Z"
    assert reqs["KM-2"].latest_attestation_file is None
    pool = facts.frameworks["nist_800_57"]
    assert (pool.passed, pool.passed_with_evidence, pool.failed, pool.coverage) == (0, 1, 1, 0.5)


def test_a_duplicate_asset_identity_in_one_scan_keeps_the_first_row_and_warns():
    rows = [_row("RSA-2048", impact="High"), _row("RSA-2048", impact="Low")]
    facts = facts_of(synth(1), _blob(rows))
    assert [a.impact for a in facts.assets] == ["High"] and facts.asset_count == 1
    assert len(facts.warnings) == 1 and "duplicate" in facts.warnings[0]


# ---------------------------------------------------------------------------------------------
# T-ROLL 19: garbage in -> never raises, bad rows counted in warnings
# ---------------------------------------------------------------------------------------------
GARBAGE = [
    None, [], "x", 123, 4.5, True, {}, {"results": "x"}, {"results": None, "cbom_json": []},
    {"results": [1, "a", None, [], {"title": "ok", "asset_type": "algorithm", "impact": "High"}]},
    {"cbom_json": {"components": "x"}},
    {"cbom_json": {"components": [1, None, "x", {"type": 5}, {"properties": "x"}, {"name": 7}]}},
    {"results": [], "cbom_compliance": {"fw": "x"}},
    {"results": [], "cbom_compliance": {"fw": {"requirements": "x"}}},
    {"results": [], "cbom_compliance": {"fw": {"pass": "NaN", "requirements": [1, {"id": None}]}}},
    {"results": [], "cbom_json": {}, "attestations": []},
    {"results": [], "cbom_json": {}, "attestations": {"fw": "x", "g": {"r": 5}}},
    {"results": [{"asset_type": ["x"], "impact": 5, "finding_codes": "WEAK", "key_size": {"a": 1},
                  "title": {"x": 1}, "location": 9, "quantum_vulnerable": "maybe",
                  "security_strength_bits": "lots", "risk_score": "high", "bom_ref": []}]},
    {"results": [], "cbom_json": {"components": [
        {"type": "cryptographic-asset", "cryptoProperties": 5,
         "properties": [1, {"name": 2}, {"value": 3}]}]},
     "cbom_graph": {"edges": [
         1, {"rel": "signed_by"}, {"rel": "signed_by", "source": [], "target": {}}]}},
]  # fmt: skip


@pytest.mark.parametrize("garbage", GARBAGE, ids=[str(i) for i in range(len(GARBAGE))])
def test_extract_scan_facts_is_total_for_garbage_blobs(raw, garbage):
    facts = facts_of(scan_by_id(raw, 2), garbage)
    assert isinstance(facts, ScanFacts)
    assert facts.exclusion in (None, EXCLUDED_NO_DATA)
    if facts.exclusion:
        assert facts.assets == [] and facts.certs == [] and facts.libs == []


def test_skipped_rows_are_counted_in_warnings():
    rows = [1, "a", None, [], _row("ok")]
    facts = facts_of(synth(1), {"results": rows, "cbom_json": {"components": [1, None]}})
    assert facts.asset_count == 1 and facts.included
    assert len(facts.warnings) == 6
    assert sum(w.startswith("results[") for w in facts.warnings) == 4
    assert sum(w.startswith("cbom_json.components[") for w in facts.warnings) == 2


def test_fold_scans_survives_garbage_in_heads_and_blobs(raw):
    scans = []
    for index, blob in enumerate(GARBAGE):
        scan = synth(100 + index, age=timedelta(hours=index + 1), data=blob)
        scan["scan_metadata"] = None if index % 2 else "not-a-mapping"
        scans.append(scan)
    odd = synth(500)
    odd["status"] = None
    scans.append(odd)
    view, _ = run_fold(scans)
    assert isinstance(view, TeamCbomView)
    assert view.scans_total == len(GARBAGE) + 1
    assert view.excluded[EXCLUDED_NOT_COMPLETED] == 1
    assert view.eligible == view.included + view.excluded[EXCLUDED_NO_DATA] + view.history_truncated


# =============================================================================================
# fold_scans: empty team, exclusions, selection  (T-ROLL 1 / 2 / 3)
# =============================================================================================
def test_empty_team_folds_to_an_empty_view_without_loading_anything():
    view, spy = run_fold([], team_id=3, name="Empty Team")
    assert (view.team_id, view.team_name) == (3, "Empty Team")
    assert (view.generated_at, view.as_of) == (NOW, AS_OF)
    assert (view.scans_total, view.eligible, view.included, view.history_truncated) == (0, 0, 0, 0)
    assert view.excluded == {EXCLUDED_FAILURE: 0, EXCLUDED_NOT_COMPLETED: 0, EXCLUDED_NO_DATA: 0}
    assert view.is_empty and view.fidelity_summary == "none"
    assert (view.sources, view.assets, view.certs, view.libs) == ((), (), (), ())
    assert (view.frameworks, view.requirements, view.scans, view.warnings) == ((), (), (), ())
    assert (view.window_start, view.window_end, view.readiness_pct) == (None, None, None)
    assert (view.asset_occurrences, view.pqc_vulnerable, view.pqc_safe) == (0, 0, 0)
    assert view.fingerprint == "6e3aaf5a99cc"  # sha256("cbom-team-rollup|")[:12]
    assert spy.calls == []


def test_a_team_with_no_scans_of_its_own_is_empty_even_if_others_have_many(raw):
    view, spy = run_fold(raw["scans"], team_id=3, name="Empty Team")
    assert view.scans_total == 0 and view.is_empty and spy.calls == []
    assert "other-team-canary" not in repr(view)


def test_only_failed_queued_and_started_scans_fold_nothing(raw):
    scans = [scan_by_id(raw, i) for i in (9, 10, 11)]
    view, spy = run_fold(scans)
    assert (view.scans_total, view.eligible, view.included) == (3, 0, 0)
    assert view.excluded == {EXCLUDED_FAILURE: 1, EXCLUDED_NOT_COMPLETED: 2, EXCLUDED_NO_DATA: 0}
    assert view.is_empty and view.sources == () and view.assets == ()
    assert spy.calls == []  # their blobs (which carry canaries) were never requested
    assert {s.exclusion for s in view.scans} == {EXCLUDED_FAILURE, EXCLUDED_NOT_COMPLETED}
    assert "CANARY" not in repr(view)


def test_only_eligible_cbom_success_scans_of_the_team_are_ever_loaded(run):
    _, spy = run
    assert sorted(spy.seen) == [1, 2, 3, 4, 5, 6, 7, 8, 13]  # each exactly once
    assert not {9, 10, 11, 12, 14} & set(spy.seen)  # failed, queued, started, sbom_sca, team 2


@pytest.mark.parametrize("batch_size", [1, 3, 4, 20])
def test_load_blobs_is_never_called_with_more_than_batch_size_ids(raw, batch_size):
    view, spy = run_fold(raw["scans"], batch_size=batch_size)
    assert max(len(call) for call in spy.calls) <= batch_size
    assert sorted(spy.seen) == [1, 2, 3, 4, 5, 6, 7, 8, 13] and view.included == 8


# =============================================================================================
# Basis counts and sources (Appendix B)
# =============================================================================================
def test_basis_counts_match_appendix_b(view):
    assert (view.team_id, view.team_name) == (1, "E2E Demo Team")
    assert (view.generated_at, view.as_of) == (NOW, AS_OF)
    assert (view.scans_total, view.eligible, view.included) == (12, 9, 8)
    assert view.excluded == {EXCLUDED_FAILURE: 1, EXCLUDED_NOT_COMPLETED: 2, EXCLUDED_NO_DATA: 1}
    assert view.history_truncated == 0
    assert view.eligible == view.included + view.excluded[EXCLUDED_NO_DATA] + view.history_truncated
    assert (view.fidelity_full, view.fidelity_reduced) == (7, 1)
    assert view.fidelity_summary == "mixed" and not view.is_empty
    assert view.window_start == NOW - timedelta(days=60)  # legacy-billing, scan 8
    assert view.window_end == NOW - timedelta(days=2)  # vendor-sdk-manifests, scan 7
    assert view.warnings == ()


def test_scan_facts_are_slim_ordered_newest_first_and_flag_the_current_ones(view):
    assert [s.scan_id for s in view.scans] == [11, 10, 9, 7, 6, 13, 5, 2, 4, 3, 1, 8]
    assert {s.scan_id for s in view.scans if s.is_current} == {2, 3, 4, 5, 6, 7, 8}
    exclusion = {s.scan_id: s.exclusion for s in view.scans}
    assert exclusion == {
        1: None, 2: None, 3: None, 4: None, 5: None, 6: None, 7: None, 8: None,
        9: EXCLUDED_FAILURE, 10: EXCLUDED_NOT_COMPLETED, 11: EXCLUDED_NOT_COMPLETED,
        13: EXCLUDED_NO_DATA,
    }  # fmt: skip
    for s in view.scans:  # no payload survives folding
        assert (s.assets, s.certs, s.libs, s.requirements, s.warnings) == ([], [], [], [], [])
        assert s.frameworks == {}
    assert {s.scan_id: s.tier for s in view.scans if s.included} == {
        1: TIER_A, 2: TIER_A, 3: TIER_A, 4: TIER_A, 5: TIER_A, 6: TIER_A, 7: TIER_A, 8: TIER_B,
    }  # fmt: skip
    counts = {
        s.scan_id: (s.asset_count, s.cert_count, s.lib_count) for s in view.scans if s.included
    }
    assert counts == {
        1: (13, 1, 4), 2: (14, 2, 4), 3: (12, 12, 0), 4: (17, 0, 2),
        5: (11, 0, 0), 6: (2, 2, 0), 7: (0, 0, 18), 8: (12, 1, 4),
    }  # fmt: skip
    assert sum(c[1] for c in counts.values()) == 18  # raw certificate occurrences (Appendix B)
    legacy = next(s for s in view.scans if s.scan_id == 8)
    assert legacy.fidelity_reasons == ("no_distributions", "no_compliance")
    first = next(s for s in view.scans if s.scan_id == 1)  # hostile spelling of the same source
    assert (
        first.source_key == PAYMENTS
        and first.source_label == "github.com/E2E-Demo/payments-service (main)"
    )


EXPECTED_SOURCES = {
    # key: (label, kind, scan_ids, tier, fidelity, last_attempt, asset_counts, impact_counts, libs)
    PAYMENTS: ("github.com/e2e-demo/payments-service (main)", "repo", (2, 1), TIER_A, "full",
               (9, "failure"), {"algorithm": 9, "certificate": 2, "protocol": 1,
                                "related-crypto-material": 2},
               {"High": 6, "Medium": 1, "Info": 7}, 4),
    IDENTITY: ("github.com/e2e-demo/identity-gateway (main)", "repo", (3,), TIER_A, "full",
               (3, "success"), {"certificate": 12},
               {"Critical": 1, "High": 4, "Medium": 1, "Info": 6}, 0),
    MISUSE: ("github.com/e2e-demo/crypto-misuse-lab (main)", "repo", (4,), TIER_A, "full",
             (4, "success"), {"algorithm": 8, "related-crypto-material": 9},
             {"High": 6, "Info": 11}, 2),
    PQC: ("github.com/e2e-demo/pqc-pilot (release)", "repo", (5,), TIER_A, "full",
          (5, "success"), {"algorithm": 11}, {"Medium": 1, "Info": 10}, 0),
    ZIPLAB: ("Zip upload: cert-lifecycle-lab", "zip", (6,), TIER_A, "full",
             (6, "success"), {"certificate": 2}, {"High": 1, "Medium": 1}, 0),
    MANIFESTS: ("github.com/e2e-demo/vendor-sdk-manifests (main)", "repo", (7,), TIER_A, "full",
                (7, "success"), {}, {}, 18),
    LEGACY: ("github.com/e2e-demo/legacy-billing (main)", "repo", (8,), TIER_B, "reduced",
             (8, "success"), {"algorithm": 9, "certificate": 1, "protocol": 1,
                              "related-crypto-material": 1},
             {"High": 6, "Medium": 1, "Info": 5}, 4),
}  # fmt: skip
SOURCE_AGES = {
    PAYMENTS: (21, 7),
    IDENTITY: (14, 14),
    MISUSE: (10, 10),
    PQC: (5, 5),
    ZIPLAB: (3, 3),
    MANIFESTS: (2, 2),
    LEGACY: (60, 60),
}  # (first, last) days before NOW


def test_seven_sources_sorted_by_label(view):
    assert [s.key for s in view.sources] == [
        MISUSE,
        IDENTITY,
        LEGACY,
        PAYMENTS,
        PQC,
        MANIFESTS,
        ZIPLAB,
    ]


@pytest.mark.parametrize("key", list(EXPECTED_SOURCES))
def test_source_rollup_matches_appendix_b(view, key):
    label, kind, scan_ids, tier, fidelity, attempt, assets, impacts, libs = EXPECTED_SOURCES[key]
    src = only(s for s in view.sources if s.key == key)
    assert (src.label, src.kind, src.scan_ids, src.scan_count) == (
        label,
        kind,
        scan_ids,
        len(scan_ids),
    )
    assert (src.current_scan_id, src.current_tier, src.current_fidelity) == (
        scan_ids[0],
        tier,
        fidelity,
    )
    assert (src.last_attempt_scan_id, src.last_attempt_status) == attempt
    assert (src.asset_counts, src.impact_counts, src.library_count) == (assets, impacts, libs)
    first_days, last_days = SOURCE_AGES[key]
    assert src.first_scanned == NOW - timedelta(days=first_days)
    assert src.last_scanned == NOW - timedelta(days=last_days)
    if key != PAYMENTS:  # payments' newest attempt is the failed scan 9
        assert src.last_attempt_at == src.last_scanned


def test_payments_shows_the_failed_latest_attempt_but_reports_the_older_success(view):
    src = only(s for s in view.sources if s.key == PAYMENTS)
    assert (src.last_attempt_scan_id, src.last_attempt_status) == (9, "failure")
    assert src.last_attempt_at == NOW - timedelta(days=1)
    assert (src.current_scan_id, src.last_scanned) == (2, NOW - timedelta(days=7))
    assert src.repo_url == "https://github.com/e2e-demo/payments-service" and src.branch == "main"
    zip_src = only(s for s in view.sources if s.key == ZIPLAB)
    assert (zip_src.repo_url, zip_src.branch) == (None, None)
    assert only(s for s in view.sources if s.key == PQC).branch == "release"


def test_excluded_only_sources_do_not_appear_and_no_canary_reaches_the_view(view):
    keys = {s.key for s in view.sources}
    assert not any(token in key for key in keys for token in ("queued", "running", "empty"))
    text = repr(view)
    for canary in CANARIES:
        assert canary not in text, canary


# =============================================================================================
# Certificates: 18 raw occurrences -> 14 unique  (T-ROLL 5, Appendix B)
# =============================================================================================
def cert_by_subject(view, cn):
    return only(c for c in view.certs if c.subject_cn == cn)


def test_certificates_dedupe_eighteen_raw_occurrences_into_fourteen_unique(view):
    assert len(view.certs) == 14
    assert all(c.identity_strong and c.current for c in view.certs)
    assert [c.key for c in view.certs] == sorted(c.key for c in view.certs)
    assert Counter(c.scan_count for c in view.certs) == {4: 1, 2: 1, 1: 12}  # no false merges


def test_the_app_certificate_collapses_four_occurrences_across_three_sources(view):
    cert = cert_by_subject(view, "synthetic-crypto-app.test")
    assert cert.key == "4b38347cc848f7ee"
    assert (cert.scan_count, cert.latest_scan_id, cert.scan_ids) == (4, 2, (2, 3, 1, 8))
    assert cert.first_seen == NOW - timedelta(days=60)  # legacy-billing, scan 8
    assert cert.last_seen == NOW - timedelta(days=7)  # payments #2
    assert set(cert.source_keys) == {PAYMENTS, IDENTITY, LEGACY} and len(cert.source_keys) == 3
    assert set(cert.current_source_keys) == {PAYMENTS, IDENTITY, LEGACY}
    pay, ident, leg = (
        "github.com/e2e-demo/payments-service (main)",
        "github.com/e2e-demo/identity-gateway (main)",
        "github.com/e2e-demo/legacy-billing (main)",
    )
    assert cert.locations == (
        (pay, "cert.pem"), (ident, "certs/imported/payments-ca.pem"), (leg, "cert.pem"),
    )  # fmt: skip
    assert cert.locations_total == 3
    assert (cert.name, cert.file_names) == ("cert.pem", ("cert.pem", "payments-ca.pem"))
    assert (cert.is_ca, cert.self_signed, cert.signed_by) == (True, True, ())
    assert (cert.impact, cert.finding_codes, cert.tier) == ("Info", (), TIER_A)  # clean: no finding
    assert cert.expiry == ExpiryBand(VALID, (date(2027, 6, 29) - AS_OF).days)


def test_the_chain_leaf_collapses_two_occurrences_and_knows_its_signer(view):
    leaf = cert_by_subject(view, "chain.leaf.test")
    assert (leaf.scan_count, leaf.scan_ids, leaf.locations_total) == (2, (2, 3), 2)
    assert set(leaf.source_keys) == {PAYMENTS, IDENTITY}
    assert (leaf.name, leaf.file_names) == ("server.crt", ("server.crt", "chain-leaf.crt"))
    assert leaf.issuer_cn == "DevSecShield Test Root CA"
    assert (leaf.is_ca, leaf.self_signed) == (False, False)
    assert leaf.signed_by == ("chain-root.crt",)  # edge seen only in identity-gateway's scan
    root = cert_by_subject(view, "DevSecShield Test Root CA")
    assert (root.signed_by, root.is_ca, root.self_signed) == ((), True, True)


def test_ec_certificate_keeps_curve_and_key_algorithm(view):
    ec = cert_by_subject(view, "ec-p256-ca.test")
    assert ec.key == "d5e9379e0029c818"
    assert (ec.public_key_algorithm, ec.curve, ec.key_size) == ("ecPublicKey", "P-256", "256")
    assert ec.signature_algorithm == "ecdsaWithSHA256"


def test_validity_bands_are_computed_against_the_injected_date(view):
    assert Counter(c.expiry.band for c in view.certs) == {VALID: 12, EXPIRED: 1, LE_30: 1}
    expired = cert_by_subject(view, "expired-api.e2e.test")
    assert expired.expiry == ExpiryBand(EXPIRED, -35) and expired.scan_time_expired is True
    soon = cert_by_subject(view, "expiring-soon.e2e.test")
    assert soon.expiry == ExpiryBand(LE_30, 20) and soon.scan_time_expired is False
    assert expired.source_keys == (ZIPLAB,) and expired.not_after == "2026-09-14T00:00:00Z"


def test_certificate_findings_and_top_impact_match_appendix_b(view):
    codes = Counter(code for c in view.certs for code in c.finding_codes)
    assert codes == {
        "WEAK_CERTIFICATE_KEY": 3, "WEAK_CERTIFICATE_SIGNATURE": 3,
        "SELF_SIGNED_LEAF": 3, "EXPIRED_CERTIFICATE": 1,
    }  # fmt: skip
    assert [c.name for c in view.certs if c.impact == "Critical"] == ["rsa1024_sha1.pem"]
    assert cert_by_subject(view, "selfsigned-leaf.test").impact == "Medium"


# =============================================================================================
# Assets, libraries, headline counts  (T-ROLL 7, Appendix B)
# =============================================================================================
APPENDIX_CODES = {
    "EXPIRED_CERTIFICATE": 1,
    "HARDCODED_KEY": 1,
    "QUANTUM_VULNERABLE": 5,
    "REUSED_NONCE": 1,
    "SELF_SIGNED_LEAF": 3,
    "STATIC_IV": 1,
    "WEAK_ALGORITHM": 8,
    "WEAK_CERTIFICATE_KEY": 3,
    "WEAK_CERTIFICATE_SIGNATURE": 3,
    "WEAK_CIPHER_MODE": 2,
    "WEAK_PROTOCOL": 2,
    "WEAK_RNG": 3,
}


def test_current_asset_occurrences_and_impact_buckets_match_appendix_b(view):
    assert len(view.assets) == view.asset_occurrences == 68
    assert all(a.current for a in view.assets)  # nothing was resolved in this seed
    assert view.assets_by_type == {
        "algorithm": 37, "certificate": 17, "protocol": 2, "related-crypto-material": 12,
    }  # fmt: skip
    assert view.assets_by_impact == {"Critical": 1, "High": 23, "Medium": 5, "Info": 39}  # clean rows: no impact
    assert view.issue_by_impact == {"Critical": 1, "High": 23, "Medium": 5}  # grade input (D-03)
    assert sum(view.issue_by_impact.values()) == 29
    assert view.finding_counts == APPENDIX_CODES
    assert [a.title for a in view.assets if a.impact == "Critical"] == ["rsa1024_sha1.pem"]


def test_assets_are_sorted_by_source_type_and_identity(view):
    order = [(a.source_key, a.asset_type, a.ident) for a in view.assets]
    assert order == sorted(order)


def test_assets_are_never_merged_across_sources_but_are_across_a_sources_scans(view):
    rsa2048 = [a for a in view.assets if a.title == "RSA-2048" and a.asset_type == "algorithm"]
    assert sorted(a.source_key for a in rsa2048) == sorted([PAYMENTS, PQC, LEGACY])
    rsa1024 = only(a for a in view.assets if a.source_key == PAYMENTS and a.title == "RSA-1024")
    assert (rsa1024.scan_count, rsa1024.scan_ids, rsa1024.latest_scan_id) == (2, (2, 1), 2)
    assert rsa1024.first_seen == NOW - timedelta(days=21) and rsa1024.last_seen == NOW - timedelta(
        days=7
    )
    assert rsa1024.source_label == "github.com/e2e-demo/payments-service (main)"
    server = only(a for a in view.assets if a.title == "server.crt")  # new in payments #2
    assert (server.scan_count, server.scan_ids, server.first_seen) == (
        1,
        (2,),
        NOW - timedelta(days=7),
    )


def test_libraries_dedupe_by_casefolded_name_across_sources(view):
    assert len(view.libs) == 23 and all(lib.current for lib in view.libs)
    shared = sorted(lib.key for lib in view.libs if len(lib.source_keys) > 1)
    assert shared == ["hashlib (stdlib)", "pyca/cryptography", "pyopenssl", "ssl (stdlib)"]
    crypto = only(lib for lib in view.libs if lib.key == "pyca/cryptography")
    assert sorted(crypto.source_keys) == sorted([PAYMENTS, MISUSE, LEGACY])
    assert crypto.scan_count == 4 and crypto.name == "pyca/cryptography"
    assert len(crypto.source_labels) == 3 and set(crypto.current_source_keys) == set(
        crypto.source_keys
    )
    assert only(lib for lib in view.libs if lib.key == "pyopenssl").name == "pyOpenSSL"
    manifests = [lib for lib in view.libs if MANIFESTS in lib.source_keys]
    assert len(manifests) == 18 and all(lib.source_keys == (MANIFESTS,) for lib in manifests)
    assert [lib.key for lib in view.libs] == sorted(lib.key for lib in view.libs)


def test_pqc_headline_counts_and_readiness_match_appendix_b(view):
    assert (view.pqc_vulnerable, view.pqc_safe, view.pqc_hybrid, view.pqc_ungraded) == (5, 32, 2, 0)
    assert view.readiness_pct == 86.5
    vulnerable = {
        (a.source_key, a.title)
        for a in view.assets
        if a.asset_type == ASSET_ALGORITHM and a.quantum_vulnerable
    }
    assert vulnerable == {
        (PAYMENTS, "RSA-1024"), (PAYMENTS, "RSA-2048"), (PQC, "RSA-2048"),
        (LEGACY, "RSA-1024"), (LEGACY, "RSA-2048"),
    }  # fmt: skip
    sized = {a.source_key: a.pqc_migration_roadmap for a in view.assets
             if a.title == "RSA-2048" and a.asset_type == ASSET_ALGORITHM}  # fmt: skip
    assert sized == {PAYMENTS: "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)",
                     PQC: "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204)", LEGACY: None}  # fmt: skip


# =============================================================================================
# Compliance pooling and requirement roll-up  (T-ROLL 12 / 13, Appendix B)
# =============================================================================================
APPENDIX_COMPLIANCE = {  # framework: (pass, fail, not_bom_evidenceable, out_of_scope, coverage)
    "bsi_tr_02102": (10, 5, 5, 4, 0.667),
    "cert_in_cbom": (114, 4, 97, 43, 0.966),
    "cnsa_2_0": (13, 2, 5, 4, 0.867),
    "eu_cra": (7, 3, 5, 3, 0.700),
    "eu_dora": (8, 2, 5, 3, 0.800),
    "fips_140_3": (11, 4, 5, 4, 0.733),
    "nist_1800_38b": (13, 2, 5, 4, 0.867),
    "nist_1800_38c": (12, 3, 5, 4, 0.800),
    "nist_800_57": (22, 8, 5, 7, 0.733),
    "omb_m_23_02": (8, 2, 5, 3, 0.800),
    "pci_dss_4": (11, 4, 5, 4, 0.733),
    "rbi_free_ai_protection": (24, 6, 10, 8, 0.800),
    "sebi_cscrf_cbom": (36, 4, 50, 18, 0.900),
}


def test_compliance_is_pooled_over_the_six_current_full_fidelity_scans(view, registry):
    assert [p.framework for p in view.frameworks] == registry["frameworks"]  # CBOM_FRAMEWORKS order
    assert set(registry["frameworks"]) == set(APPENDIX_COMPLIANCE)
    for pool in view.frameworks:
        got = (
            pool.passed,
            pool.failed,
            pool.not_bom_evidenceable,
            pool.out_of_scope,
            pool.coverage,
        )
        assert got == APPENDIX_COMPLIANCE[pool.framework], pool.framework
        assert (pool.passed_with_evidence, pool.na) == (0, 0)
        assert (pool.sources_pooled, pool.legacy_excluded) == (6, 1)
    assert (view.compliance_sources_pooled, view.compliance_legacy_excluded) == (6, 1)


def test_coverage_is_none_when_nothing_could_pass_or_fail(raw):
    manifests_only = [scan_by_id(raw, 7)]  # every framework is out_of_scope for a no-crypto repo
    view, _ = run_fold(manifests_only)
    assert len(view.frameworks) == 13
    for pool in view.frameworks:
        assert pool.coverage is None and (pool.passed, pool.failed) == (0, 0)
        assert pool.out_of_scope > 0 and pool.sources_pooled == 1


def test_a_legacy_only_team_pools_nothing_but_counts_the_exclusion(raw):
    view, _ = run_fold([scan_by_id(raw, 8)])
    assert view.frameworks == () and view.requirements == ()
    assert (view.compliance_sources_pooled, view.compliance_legacy_excluded) == (0, 1)
    assert view.fidelity_summary == "reduced"


def test_requirements_roll_up_with_fail_over_nbe_over_pass(view):
    assert len(view.requirements) == 109
    assert Counter(r.verdict for r in view.requirements) == {
        "fail": 35, "not_bom_evidenceable": 48, "pass": 26,
    }  # fmt: skip
    assert [(r.framework, r.req_id) for r in view.requirements] == sorted(
        (r.framework, r.req_id) for r in view.requirements
    )
    assert sum(r.attestable_sources for r in view.requirements) == 207
    assert sum(r.attested_sources for r in view.requirements) == 0
    assert all(r.latest_attestation_file is None for r in view.requirements)


def test_a_requirement_row_carries_title_citation_and_per_source_verdicts(view):
    req = only(
        r for r in view.requirements if (r.framework, r.req_id) == ("cert_in_cbom", "8.4.1.1")
    )
    assert (req.title, req.citation) == ("Require CBOM in procurements", "§8.4.1.1")
    assert (req.verdict, req.attestable_sources, req.attested_sources) == (
        "not_bom_evidenceable",
        5,
        0,
    )
    assert req.verdicts == {
        PAYMENTS: "not_bom_evidenceable", IDENTITY: "not_bom_evidenceable",
        MISUSE: "not_bom_evidenceable", PQC: "not_bom_evidenceable",
        ZIPLAB: "not_bom_evidenceable", MANIFESTS: "out_of_scope",
    }  # fmt: skip
    assert LEGACY not in req.verdicts  # the legacy scan is never pooled
    km1 = only(r for r in view.requirements if (r.framework, r.req_id) == ("nist_800_57", "KM-1"))
    assert km1.verdict == "fail"


# =============================================================================================
# Synthetic fold scenarios: latest wins, resolved, failed-latest, no-data fallback (T-ROLL 6-9)
# =============================================================================================
DAYS = timedelta(days=1)


@pytest.mark.parametrize("reverse", [False, True])
def test_latest_scan_wins_the_attributes_whatever_the_arrival_order(reverse):
    old = synth(1, age=10 * DAYS, data=_blob([
        _row("RSA-2048", bom_ref="ref-rsa", impact="Low", description="old text")]))  # fmt: skip
    new = synth(2, age=1 * DAYS, data=_blob([
        _row("RSA-2048", bom_ref="ref-rsa", impact="High", codes=("WEAK_KEY_SIZE",),
             description="new text", key_size="4096")]))  # fmt: skip
    view, _ = run_fold([new, old] if reverse else [old, new])
    asset = only(view.assets)
    assert (asset.impact, asset.finding_codes) == ("High", ("WEAK_KEY_SIZE",))
    assert (asset.description, asset.key_size) == ("new text", "4096")
    assert (asset.latest_scan_id, asset.scan_count, asset.scan_ids) == (2, 2, (2, 1))
    assert (asset.first_seen, asset.last_seen) == (NOW - 10 * DAYS, NOW - 1 * DAYS)
    assert view.assets_by_impact == {"High": 1}  # the older "Low" no longer counts


@pytest.mark.parametrize("reverse", [False, True])
def test_a_timestamp_tie_is_broken_by_the_higher_scan_id(reverse):
    low = synth(5, age=2 * DAYS, data=_blob([_row("A", bom_ref="r", impact="Low")]))
    high = synth(6, age=2 * DAYS, data=_blob([_row("A", bom_ref="r", impact="High")]))
    view, _ = run_fold([high, low] if reverse else [low, high])
    assert only(view.assets).impact == "High"
    assert only(view.sources).current_scan_id == 6


def test_certificate_attributes_come_from_the_newest_scan_across_sources():
    comp = _cert_component("a.crt", "shared.test")
    older = synth(1, age=10 * DAYS, repo="https://github.com/o/a", data=_blob(
        [_cert_row("a.crt", impact="Low")], [comp]))  # fmt: skip
    newer = synth(2, age=1 * DAYS, repo="https://github.com/o/b", data=_blob(
        [_cert_row("a.crt", impact="High", codes=("WEAK_CERTIFICATE_KEY",))], [comp]))  # fmt: skip
    view, _ = run_fold([older, newer])
    cert = only(view.certs)
    assert (cert.impact, cert.finding_codes, cert.latest_scan_id) == (
        "High",
        ("WEAK_CERTIFICATE_KEY",),
        2,
    )
    assert (cert.scan_count, len(cert.source_keys), cert.first_seen) == (2, 2, NOW - 10 * DAYS)
    assert [loc[0] for loc in cert.locations] == ["github.com/o/b (main)", "github.com/o/a (main)"]


def test_tri_state_certificate_facts_are_gap_filled_from_older_scans():
    old = _cert_component("c.crt", "gap.test", ca="true", self_signed="true")
    new = _cert_component("c.crt", "gap.test", ca=None, self_signed=None)
    scans = [
        synth(1, age=9 * DAYS, data=_blob([_cert_row("c.crt", self_signed=True)], [old])),
        synth(2, age=1 * DAYS, data=_blob([_cert_row("c.crt", self_signed=None)], [new])),
    ]
    cert = only(run_fold(scans)[0].certs)
    assert (cert.is_ca, cert.self_signed) == (True, True)  # unknown in the newest, known before


def test_assets_missing_from_the_latest_scan_are_resolved_not_current():
    gone_cert = _cert_component("gone.crt", "gone.test")
    v1 = synth(1, age=10 * DAYS, data=_blob(
        [_row("A", bom_ref="a"),
         _row("B", bom_ref="b", impact="High", codes=("WEAK_ALGORITHM",),
              quantum_vulnerable=True, quantum_safe=False),
         _cert_row("gone.crt", impact="High", codes=("EXPIRED_CERTIFICATE",))],
        [gone_cert, _lib("old-lib")]))  # fmt: skip
    v2 = synth(2, age=1 * DAYS, data=_blob([_row("A", bom_ref="a")], [_lib("new-lib")]))
    view, _ = run_fold([v1, v2])
    by_title = {a.title: a for a in view.assets}
    assert (by_title["A"].current, by_title["A"].scan_count) == (True, 2)
    gone = by_title["B"]
    assert (gone.current, gone.scan_count, gone.latest_scan_id, gone.scan_ids) == (
        False,
        1,
        1,
        (1,),
    )
    assert view.asset_occurrences == 1 and view.assets_by_type == {"algorithm": 1}
    assert view.assets_by_impact == {"Info": 1} and view.issue_by_impact == {}
    assert view.finding_counts == {} and (view.pqc_vulnerable, view.pqc_safe) == (0, 1)
    assert view.readiness_pct == 100.0
    src = only(view.sources)
    assert (src.scan_ids, src.asset_counts, src.library_count) == ((2, 1), {"algorithm": 1}, 1)
    cert = only(view.certs)
    assert (cert.current, cert.current_source_keys, cert.source_keys) == (False, (), (src.key,))
    assert cert.expiry.band == VALID and cert.scan_count == 1
    libs = {lib.key: lib.current for lib in view.libs}
    assert libs == {"old-lib": False, "new-lib": True}


def test_the_newest_attempt_is_reported_even_when_it_is_not_a_success():
    scans = [
        synth(1, age=5 * DAYS),
        synth(
            2, age=3 * DAYS, status="failure", data={"results": [{"title": "FAILED-SCAN-CANARY"}]}
        ),
        synth(3, age=1 * DAYS, status="started", data={}),
    ]
    view, spy = run_fold(scans)
    src = only(view.sources)
    assert (src.current_scan_id, src.last_attempt_scan_id, src.last_attempt_status) == (
        1,
        3,
        "started",
    )
    assert src.last_attempt_at == NOW - 1 * DAYS and src.scan_ids == (1,)
    assert spy.seen == [1] and "CANARY" not in repr(view)


def test_a_newest_success_without_data_falls_back_to_the_older_scan():
    scans = [
        synth(1, age=5 * DAYS, data=_blob([_row("A", bom_ref="a")])),
        synth(2, age=1 * DAYS, data={}),
    ]
    view, _ = run_fold(scans)
    src = only(view.sources)
    assert (src.current_scan_id, src.scan_ids) == (1, (1,))
    assert (view.included, view.excluded[EXCLUDED_NO_DATA]) == (1, 1)
    assert only(view.assets).current is True


def test_the_manifest_only_source_is_in_scope_with_zero_assets_and_its_libraries(view):
    src = only(s for s in view.sources if s.key == MANIFESTS)
    assert (src.asset_counts, src.impact_counts, src.library_count) == ({}, {}, 18)
    assert (src.current_tier, src.current_fidelity) == (TIER_A, FIDELITY_FULL)
    assert not [a for a in view.assets if a.source_key == MANIFESTS]
    assert view.included == 8  # the empty scan is counted, not excluded


def test_a_tier_c_scan_is_folded_at_reduced_fidelity():
    rows = [
        {"title": "cert.pem", "algorithm_type": "certificate", "impact": "Low",
         "location": "cert.pem"},
        {"title": "id_rsa", "algorithm_type": "key", "impact": "High", "location": "id_rsa"},
        {"title": "TLS 1.0", "algorithm_type": "protocol", "impact": "High", "location": "t.py"},
        {"title": "RSA-1024", "algorithm_type": "pke", "impact": "High", "location": "a.py",
         "quantum_safe": False},
        {"title": "AES-GCM", "algorithm_type": "block-cipher", "impact": "Low", "location": "a.py",
         "quantum_safe": True},
        {"title": "MD5", "algorithm_type": "hash", "impact": "High", "location": "b.py"},
    ]  # fmt: skip
    view, _ = run_fold([synth(1, data={"results": rows})])
    assert (view.fidelity_full, view.fidelity_reduced, view.fidelity_summary) == (0, 1, "reduced")
    assert view.assets_by_type == {
        "algorithm": 3, "certificate": 1, "protocol": 1, "related-crypto-material": 1,
    }  # fmt: skip
    assert (view.pqc_vulnerable, view.pqc_safe, view.pqc_ungraded) == (1, 1, 1)
    assert view.readiness_pct == 50.0
    assert view.frameworks == () and view.compliance_legacy_excluded == 1
    assert only(view.sources).current_tier == TIER_C


def test_weak_certificate_identity_merges_by_basename_within_one_source_only():
    rows = [{"title": "cert.pem", "algorithm_type": "certificate", "impact": "Low",
             "location": "cert.pem"}]  # fmt: skip
    scans = [
        synth(1, age=5 * DAYS, repo="https://github.com/o/x", data={"results": rows}),
        synth(2, age=1 * DAYS, repo="https://github.com/o/x", data={"results": rows}),
        synth(3, age=1 * DAYS, repo="https://github.com/o/y", data={"results": rows}),
    ]
    view, _ = run_fold(scans)
    assert sorted((c.identity_strong, c.scan_count) for c in view.certs) == [(False, 1), (False, 2)]
    assert len({c.key for c in view.certs}) == 2


def test_status_and_type_filters_are_applied_even_if_the_caller_passes_foreign_heads(raw):
    scans = [scan_by_id(raw, i) for i in (2, 12, 14)]  # cbom team 1, sbom_sca, cbom team 2
    view, spy = run_fold(scans)
    assert (view.scans_total, view.included) == (1, 1) and spy.seen == [2]
    other, spy2 = run_fold(scans, team_id=2, name="Other Team")
    assert (other.scans_total, other.included, spy2.seen) == (1, 1, [14])
    assert cert_by_subject(other, "other-team-canary.test").scan_ids == (14,)


# =============================================================================================
# Requirement roll-up precedence, pooling arithmetic, attestations  (T-ROLL 12 / 13)
# =============================================================================================
PRECEDENCE_CASES = {  # requirement -> (source0, source1, source2) verdicts
    "R-fail": ("pass", "fail", "na"),
    "R-nbe": ("pass", "not_bom_evidenceable", "pass_with_evidence"),
    "R-pwe": ("pass", "pass_with_evidence", "out_of_scope"),
    "R-pass": ("pass", "out_of_scope", "na"),
    "R-oos": ("out_of_scope", "na", "na"),
    "R-na": ("na", "na", "na"),
    "R-att": ("not_bom_evidenceable", "pass_with_evidence", "pass_with_evidence"),
}


def precedence_scans(attestations=None, extra=()):
    scans = []
    for index in range(3):
        reqs = {rid: verdicts[index] for rid, verdicts in PRECEDENCE_CASES.items()}
        scans.append(synth(
            10 + index, age=(3 - index) * DAYS, repo=f"https://github.com/o/s{index}",
            data=_blob(compliance=_compliance(nist_800_57=reqs),
                       attestations=(attestations or {}).get(index)),
        ))  # fmt: skip
    return scans + list(extra)


@pytest.mark.parametrize(
    ("req_id", "verdict", "attestable", "attested"),
    [
        ("R-fail", "fail", 0, 0),
        ("R-nbe", "not_bom_evidenceable", 2, 1),
        ("R-pwe", "pass_with_evidence", 1, 1),
        ("R-pass", "pass", 0, 0),
        ("R-oos", "out_of_scope", 0, 0),
        ("R-na", "na", 0, 0),
        ("R-att", "not_bom_evidenceable", 3, 2),
    ],
)
def test_rollup_precedence_is_fail_nbe_pwe_pass_oos_na(req_id, verdict, attestable, attested):
    view, _ = run_fold(precedence_scans())
    req = only(r for r in view.requirements if r.req_id == req_id)
    assert (req.verdict, req.attestable_sources, req.attested_sources) == (
        verdict,
        attestable,
        attested,
    )
    assert set(req.verdicts) == {f"repo:github.com/o/s{i}@main" for i in range(3)}
    assert (req.title, req.citation) == (f"Title {req_id}", f"Cite {req_id}")


def test_pooled_counts_and_coverage_are_hand_computed_sums():
    legacy = synth(99, age=1 * DAYS, repo="https://github.com/o/legacy", data={"results": []})
    view, _ = run_fold(precedence_scans(extra=[legacy]))
    pool = only(view.frameworks)
    assert pool.framework == "nist_800_57"
    assert (pool.passed, pool.passed_with_evidence, pool.failed) == (4, 4, 1)
    assert (pool.out_of_scope, pool.not_bom_evidenceable, pool.na) == (3, 2, 7)
    assert pool.coverage == 0.889  # (4 + 4) / (4 + 4 + 1)
    assert (pool.sources_pooled, pool.legacy_excluded) == (3, 1)
    assert (view.compliance_sources_pooled, view.compliance_legacy_excluded) == (3, 1)
    assert all("legacy" not in key for r in view.requirements for key in r.verdicts)


def test_latest_attestation_is_the_most_recent_upload_across_sources():
    first = {"filename": "a.pdf", "note": "first", "uploaded_at": "2026-10-10T08:00:00Z"}
    second = {"filename": "b.pdf", "note": "second", "uploaded_at": "2026-10-12T08:00:00Z"}
    orphan = {"filename": "x.pdf", "uploaded_at": "2026-10-13T08:00:00Z"}
    att = {
        1: {"nist_800_57": {"R-att": first}},
        2: {"nist_800_57": {"R-att": second, "R-gone": orphan}},
    }
    view, _ = run_fold(precedence_scans(att))
    req = only(r for r in view.requirements if r.req_id == "R-att")
    assert (req.latest_attestation_file, req.latest_attestation_note) == ("b.pdf", "second")
    assert req.latest_attestation_at == "2026-10-12T08:00:00Z"
    assert (req.attestable_sources, req.attested_sources) == (3, 2)
    assert not any(r.req_id == "R-gone" for r in view.requirements)  # orphan attestations ignored


def test_an_attestation_in_one_fixture_scan_shows_as_one_of_five(raw):
    scans = copy.deepcopy(raw["scans"])
    blob = next(s for s in scans if s["id"] == 2)["scan_data"]  # payments #2
    block = blob["cbom_compliance"]["cert_in_cbom"]
    next(r for r in block["requirements"] if r["id"] == "8.4.1.1")["verdict"] = "pass_with_evidence"
    block["not_bom_evidenceable"] -= 1  # what the attestation upload route would persist
    block["pass_with_evidence"] += 1
    blob["attestations"] = {"cert_in_cbom": {"8.4.1.1": {
        "filename": "supplier-cbom.pdf", "note": "Supplier CBOM received",
        "uploaded_at": "2026-10-18T09:00:00Z"}}}  # fmt: skip
    view, _ = run_fold(scans)
    req = only(
        r for r in view.requirements if (r.framework, r.req_id) == ("cert_in_cbom", "8.4.1.1")
    )
    assert (req.attestable_sources, req.attested_sources) == (5, 1)  # "Attested 1/5"
    assert req.verdict == "not_bom_evidenceable"  # 4 sources still unattested
    assert req.latest_attestation_file == "supplier-cbom.pdf"
    assert req.latest_attestation_note == "Supplier CBOM received"
    assert req.latest_attestation_at == "2026-10-18T09:00:00Z"
    pool = only(p for p in view.frameworks if p.framework == "cert_in_cbom")
    assert (pool.passed, pool.passed_with_evidence, pool.failed) == (114, 1, 4)
    assert pool.not_bom_evidenceable == 96 and pool.coverage == 0.966  # 115 / 119


def test_a_fully_attested_requirement_rolls_up_to_pass_with_evidence(raw):
    scans = copy.deepcopy(raw["scans"])
    for scan in scans:
        if scan["id"] in (2, 3, 4, 5, 6):
            block = scan["scan_data"]["cbom_compliance"]["cert_in_cbom"]
            next(r for r in block["requirements"] if r["id"] == "8.4.1.1")["verdict"] = (
                "pass_with_evidence"
            )
    view, _ = run_fold(scans)
    req = only(
        r for r in view.requirements if (r.framework, r.req_id) == ("cert_in_cbom", "8.4.1.1")
    )
    assert (req.verdict, req.attestable_sources, req.attested_sources) == (
        "pass_with_evidence",
        5,
        5,
    )


# =============================================================================================
# Caps, history window, hard max, batching  (T-ROLL 14 / 15)
# =============================================================================================
def hourly(sid, hours, repo="https://github.com/o/a", data=_UNSET):
    return synth(sid, age=timedelta(hours=hours), repo=repo, data=data)


def tiny():
    return _blob([_row("A", bom_ref="a")])


def test_history_window_truncates_deep_history_and_reports_the_exact_count():
    scans = [hourly(i, 26 - i, data=tiny()) for i in range(1, 26)]  # 25 scans, id 25 newest
    view, spy = run_fold(scans, history_window=10, batch_size=4)
    assert (view.eligible, view.included, view.history_truncated) == (25, 10, 15)
    assert view.eligible == view.included + view.excluded[EXCLUDED_NO_DATA] + view.history_truncated
    src = only(view.sources)
    assert (src.scan_count, src.current_scan_id, src.first_scanned) == (
        10,
        25,
        NOW - timedelta(hours=10),
    )
    asset = only(view.assets)
    assert asset.scan_count == 10 and asset.first_seen == NOW - timedelta(hours=10)
    assert sorted(spy.seen) == list(range(16, 26)) and max(map(len, spy.calls)) <= 4
    assert len(src.scan_ids) == 10 and len(asset.scan_ids) == 10  # below the 12-id cap


def test_per_entity_id_and_location_lists_are_capped_but_counts_stay_true():
    scans = [hourly(i, 40 - i, data=_blob([_row("A", bom_ref="a", location=f"f{i}.py")]))
             for i in range(1, 31)]  # fmt: skip
    cert_scans = [
        synth(100 + i, age=timedelta(hours=40 - i), repo=f"https://github.com/o/r{i}",
              data=_blob([_cert_row("c.crt", path=f"p{i}/c.crt")],
                         [_cert_component("c.crt", "cap.test", path=f"p{i}/c.crt")]))
        for i in range(15)
    ]  # fmt: skip
    view, _ = run_fold(scans + cert_scans)
    asset = only(a for a in view.assets if a.title == "A")
    assert asset.scan_count == 30 and len(asset.scan_ids) == MAX_SCAN_IDS == 12
    assert asset.scan_ids == tuple(range(30, 18, -1)) and asset.latest_scan_id == 30
    cert = only(view.certs)
    assert cert.scan_count == 15 and len(cert.scan_ids) == MAX_SCAN_IDS
    assert cert.locations_total == 15 and len(cert.locations) == MAX_LOCATIONS == 12
    assert len(cert.source_keys) == 15  # sources are never capped, only displayed lists


def test_the_latest_scan_of_every_source_is_kept_even_beyond_the_history_window():
    busy = [hourly(i, 21 - i, data=tiny()) for i in range(1, 21)]  # source "a": ids 1..20
    rare = hourly(100, 24 * 30, repo="https://github.com/o/rare", data=tiny())  # 30 days old
    view, spy = run_fold(busy + [rare], history_window=5, batch_size=3)
    keys = {s.key for s in view.sources}
    assert keys == {"repo:github.com/o/a@main", "repo:github.com/o/rare@main"}
    assert (view.eligible, view.included, view.history_truncated) == (21, 6, 15)
    assert 100 in spy.seen and max(map(len, spy.calls)) <= 3
    rare_src = only(s for s in view.sources if "rare" in s.key)
    assert rare_src.current_scan_id == 100


def test_a_source_whose_newest_scans_are_all_empty_is_chased_past_the_window():
    busy = [hourly(i, 30 - i, data=tiny()) for i in range(1, 21)]
    empties = [hourly(200 + i, 1 + i, repo="https://github.com/o/c", data={}) for i in range(3)]
    good = hourly(300, 24 * 40, repo="https://github.com/o/c", data=tiny())
    view, spy = run_fold(busy + empties + [good], history_window=4, batch_size=2)
    src = only(s for s in view.sources if s.key.endswith("/c@main"))
    assert (src.current_scan_id, src.scan_ids) == (300, (300,))
    assert view.excluded[EXCLUDED_NO_DATA] == 3
    assert view.eligible == view.included + view.excluded[EXCLUDED_NO_DATA] + view.history_truncated
    assert max(map(len, spy.calls)) <= 2


def test_hard_max_bounds_the_scans_loaded_even_while_chasing_sources():
    scans = [hourly(i, i, repo=f"https://github.com/o/r{i}", data=tiny()) for i in range(1, 31)]
    view, spy = run_fold(scans, history_window=5, hard_max=12, batch_size=4)
    assert (view.eligible, view.included, view.history_truncated) == (30, 12, 18)
    assert len(spy.seen) == len(set(spy.seen)) == 12 and len(view.sources) == 12
    capped, spy2 = run_fold(scans, history_window=100, hard_max=7)
    assert (capped.included, capped.history_truncated, len(spy2.seen)) == (7, 23, 7)


@pytest.mark.parametrize("window", [0, -5])
def test_a_zero_window_still_finds_the_latest_scan_of_every_source(window):
    scans = [hourly(i, 20 - i, repo=f"https://github.com/o/r{i % 3}", data=tiny())
             for i in range(1, 13)]  # fmt: skip
    view, spy = run_fold(scans, history_window=window, batch_size=5)
    assert len(view.sources) == 3 and view.included == 3
    assert all(s.scan_count == 1 for s in view.sources) and len(spy.seen) == 3


def test_the_view_does_not_depend_on_head_order_batch_size_or_timezone_flavour(raw):
    base, _ = run_fold(raw["scans"])
    shuffled = list(raw["scans"])
    random.Random(7).shuffle(shuffled)
    for batch in (1, 2, 20):
        assert run_fold(shuffled, batch_size=batch)[0] == base
    assert run_fold(raw["scans"], naive=True)[0] == base  # Postgres hands back naive UTC
    assert run_fold(raw["scans"], now=NOW.replace(tzinfo=None))[0] == base
    ist = timezone(timedelta(hours=5, minutes=30))
    shifted = run_fold(raw["scans"], now=datetime(2026, 10, 20, 0, 30, tzinfo=ist))[0]
    assert shifted.generated_at == datetime(2026, 10, 19, 19, 0, tzinfo=UTC)
    assert shifted.as_of == AS_OF  # the UTC date, not the IST date


def test_folding_never_mutates_its_inputs_and_the_view_holds_no_raw_blob(raw):
    before = hashlib.sha256(json.dumps(raw["scans"], sort_keys=True).encode()).hexdigest()
    view, _ = run_fold(raw["scans"])
    after = hashlib.sha256(json.dumps(raw["scans"], sort_keys=True).encode()).hexdigest()
    assert before == after
    dump = json.dumps(dataclasses.asdict(view), default=str)
    for marker in (
        "serialNumber",
        "specVersion",
        "bomFormat",
        "clinithread",
        "AI BOM",
        "HIPAA",
        "urn:uuid",
        "cbom_json",
        "cbom_compliance",
    ):
        assert marker not in dump, marker
    assert len(dump) < 600_000  # the fixture itself is ~590 KB of blobs


# =============================================================================================
# Fingerprint (T-ROLL 17) and performance (T-ROLL 18)
# =============================================================================================
def test_fingerprint_is_pinned_deterministic_and_matches_the_documented_formula(view, raw):
    included = [scan_by_id(raw, i) for i in range(1, 9)]  # scans 1..8, ascending id
    text = "cbom-team-rollup|" + ",".join(
        f"{s['id']}:{_ts(s['last_updated']).isoformat()}" for s in included
    )
    assert view.fingerprint == hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
    assert view.fingerprint == "6a1e31ae946c"
    assert run_fold(list(reversed(raw["scans"])), batch_size=2)[0].fingerprint == view.fingerprint


def test_fingerprint_moves_with_included_scans_only(view, raw):
    scans = copy.deepcopy(raw["scans"])
    next(s for s in scans if s["id"] == 9)["last_updated"] = "2026-10-19T00:00:00Z"  # failed
    next(s for s in scans if s["id"] == 13)["last_updated"] = "2026-10-19T00:00:00Z"  # no data
    assert run_fold(scans)[0].fingerprint == view.fingerprint
    next(s for s in scans if s["id"] == 4)["last_updated"] = "2026-10-09T12:31:00Z"  # a re-scan
    moved = run_fold(scans)[0].fingerprint
    assert moved != view.fingerprint and len(moved) == 12 and int(moved, 16) >= 0


# ---------------------------------------------------------------------------------------------
# Fingerprint and attestation uploads (addendum A-2)
# ---------------------------------------------------------------------------------------------
# The upload route stores scan_data["attestations"][framework][req_id] = {filename, note,
# uploaded_at} and never touches Scan.last_updated, so (scan id, last_updated) alone cannot see an
# upload.  Rule: the attestation records of the INCLUDED scans are appended to the hashed text as
# "|attestations|" + ",".join(compact JSON [scan_id, framework, req_id, uploaded_at], sorted), and
# ONLY when at least one record exists, so every attestation-free scan set keeps its old value.
PRE_A2_FINGERPRINT = "6a1e31ae946c"  # fixture scans 1..8 as pinned before A-2 (no attestations)
STAMP = "2026-10-18T09:00:00Z"


def a2_fingerprint(scans, included_ids, records=()):
    """The A-2 rule spelled out by hand with plain string handling (not a product helper)."""
    stamped = ",".join(
        f"{s['id']}:{_ts(s['last_updated']).isoformat()}"
        for s in sorted(scans, key=lambda s: s["id"])
        if s["id"] in included_ids
    )
    text = "cbom-team-rollup|" + stamped
    if records:
        text += "|attestations|" + ",".join(
            json.dumps(list(record), separators=(",", ":")) for record in sorted(records)
        )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def upload_record(at=STAMP, filename="supplier-cbom.pdf", note="Supplier CBOM received"):
    """One attestation entry exactly as ``upsert_attestation`` stores it."""
    return {"filename": filename, "note": note, "uploaded_at": at}


def attested_fixture(raw, uploads):
    """Deep copy of the fixture scans with ``scan_data["attestations"]`` set per scan id."""
    scans = copy.deepcopy(raw["scans"])
    for scan_id, attestations in uploads.items():
        next(s for s in scans if s["id"] == scan_id)["scan_data"]["attestations"] = attestations
    return scans


def attested_fingerprint(raw, uploads, **kwargs):
    return run_fold(attested_fixture(raw, uploads), **kwargs)[0].fingerprint


def test_an_attestation_upload_moves_the_fingerprint_by_the_documented_rule(view, raw):
    assert view.fingerprint == PRE_A2_FINGERPRINT == a2_fingerprint(raw["scans"], range(1, 9))
    moved = attested_fingerprint(raw, {2: {"cert_in_cbom": {"8.4.1.1": upload_record()}}})
    assert moved != view.fingerprint and len(moved) == 12 and int(moved, 16) >= 0
    records = [(2, "cert_in_cbom", "8.4.1.1", STAMP)]
    assert moved == a2_fingerprint(raw["scans"], range(1, 9), records)


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({}, id="no-key"),
        pytest.param({"attestations": None}, id="none"),
        pytest.param({"attestations": {}}, id="empty"),
        pytest.param({"attestations": {"cert_in_cbom": {}, "nist_800_57": {}}}, id="empty-buckets"),
    ],
)
def test_attestation_free_scan_sets_keep_the_pre_a2_value(raw, extra):
    scans = copy.deepcopy(raw["scans"])
    blob = next(s for s in scans if s["id"] == 2)["scan_data"]
    blob.pop("attestations", None)
    blob.update(extra)
    assert run_fold(scans)[0].fingerprint == PRE_A2_FINGERPRINT


def test_the_attested_fingerprint_ignores_scan_order_batching_and_dict_order(raw):
    uploads = {
        1: {"cert_in_cbom": {"8.4.1.1": upload_record("2026-09-29T09:00:00Z")}},  # history scan
        2: {
            "cert_in_cbom": {
                "8.4.1.1": upload_record("2026-10-18T09:00:00Z"),
                "8.4.1.2": upload_record("2026-10-18T09:05:00Z"),
            },
            "bsi_tr_02102": {"BSI-4": upload_record("2026-10-17T08:00:00Z")},
        },
        4: {"nist_800_57": {"KM-1": upload_record("2026-10-16T07:00:00Z")}},
    }
    records = [
        (1, "cert_in_cbom", "8.4.1.1", "2026-09-29T09:00:00Z"),
        (2, "bsi_tr_02102", "BSI-4", "2026-10-17T08:00:00Z"),
        (2, "cert_in_cbom", "8.4.1.1", "2026-10-18T09:00:00Z"),
        (2, "cert_in_cbom", "8.4.1.2", "2026-10-18T09:05:00Z"),
        (4, "nist_800_57", "KM-1", "2026-10-16T07:00:00Z"),
    ]
    expected = a2_fingerprint(raw["scans"], range(1, 9), records)
    scans = attested_fixture(raw, uploads)
    assert run_fold(scans)[0].fingerprint == expected != PRE_A2_FINGERPRINT
    shuffled = scans[:]
    random.Random(2026).shuffle(shuffled)
    for order, size in ((list(reversed(scans)), 2), (shuffled, 3), (scans, 1)):
        assert run_fold(order, batch_size=size)[0].fingerprint == expected
    flipped = {  # same records, every dict built in the opposite insertion order
        sid: {fw: dict(reversed(list(reqs.items()))) for fw, reqs in reversed(list(att.items()))}
        for sid, att in reversed(list(uploads.items()))
    }
    assert attested_fingerprint(raw, flipped) == expected


MALFORMED_ATTESTATIONS = {
    "container-list": [],
    "container-text": "attested",
    "container-number": 7,
    "container-bool": True,
    "container-none": None,
    "bucket-text": {"cert_in_cbom": "x"},
    "bucket-list": {"cert_in_cbom": [{"uploaded_at": STAMP}]},
    "bucket-none": {"cert_in_cbom": None},
    "bucket-number": {"cert_in_cbom": 5},
    "record-text": {"cert_in_cbom": {"8.4.1.1": STAMP}},
    "record-number": {"cert_in_cbom": {"8.4.1.1": 5}},
    "record-none": {"cert_in_cbom": {"8.4.1.1": None}},
    "record-list": {"cert_in_cbom": {"8.4.1.1": [{"uploaded_at": STAMP}]}},
    "record-bool": {"cert_in_cbom": {"8.4.1.1": True}},
}


@pytest.mark.parametrize(
    "junk", list(MALFORMED_ATTESTATIONS.values()), ids=list(MALFORMED_ATTESTATIONS)
)
def test_a_malformed_attestation_entry_is_ignored_without_raising(raw, junk):
    assert attested_fingerprint(raw, {2: junk}) == PRE_A2_FINGERPRINT
    valid = {"cert_in_cbom": {"8.4.1.2": upload_record()}}
    expected = a2_fingerprint(raw["scans"], range(1, 9), [(3, "cert_in_cbom", "8.4.1.2", STAMP)])
    assert attested_fingerprint(raw, {2: junk, 3: valid}) == expected  # junk beside a good scan


def test_malformed_entries_beside_a_valid_record_in_the_same_scan_are_skipped(raw):
    mixed = {
        "cert_in_cbom": {"8.4.1.1": "junk", "8.4.1.2": upload_record(), "8.4.1.3": None},
        "nist_800_57": "junk",
        "eu_dora": [],
    }
    expected = a2_fingerprint(raw["scans"], range(1, 9), [(2, "cert_in_cbom", "8.4.1.2", STAMP)])
    assert attested_fingerprint(raw, {2: mixed}) == expected


@pytest.mark.parametrize(
    "record",
    [
        pytest.param({"filename": "a.pdf"}, id="no-timestamp"),
        pytest.param({"filename": "a.pdf", "uploaded_at": None}, id="none"),
        pytest.param({"filename": "a.pdf", "uploaded_at": ""}, id="empty"),
        pytest.param({"filename": "a.pdf", "uploaded_at": "   "}, id="blank"),
    ],
)
def test_a_record_without_a_usable_timestamp_still_counts_as_a_record(raw, record):
    # the ledger prints such a record (file and note, no date), so the Document ID must see it
    moved = attested_fingerprint(raw, {2: {"cert_in_cbom": {"8.4.1.1": record}}})
    expected = a2_fingerprint(raw["scans"], range(1, 9), [(2, "cert_in_cbom", "8.4.1.1", "")])
    assert moved == expected != PRE_A2_FINGERPRINT


def test_attestations_on_scans_that_are_not_included_do_not_move_the_fingerprint(raw):
    held = {"cert_in_cbom": {"8.4.1.1": upload_record()}}
    scans = copy.deepcopy(raw["scans"])
    for scan in scans:
        if scan["id"] >= 9:  # 9 failed, 10 queued, 11 started, 12 sbom_sca, 13 no data, 14 team 2
            scan["scan_data"] = {**(scan["scan_data"] or {}), "attestations": held}
    moved, spy = run_fold(scans)
    assert moved.fingerprint == PRE_A2_FINGERPRINT
    assert set(spy.seen) == {1, 2, 3, 4, 5, 6, 7, 8, 13}  # 13 is read, then dropped as no_data
    assert moved.included == 8 and moved.excluded[EXCLUDED_NO_DATA] == 1


def test_an_attestation_on_any_one_included_scan_moves_the_fingerprint(raw):
    seen = set()
    for scan_id in range(1, 9):  # history scan 1 and the legacy scan 8 are included too
        moved = attested_fingerprint(raw, {scan_id: {"cert_in_cbom": {"8.4.1.1": upload_record()}}})
        records = [(scan_id, "cert_in_cbom", "8.4.1.1", STAMP)]
        assert moved == a2_fingerprint(raw["scans"], range(1, 9), records)
        seen.add(moved)
    assert len(seen) == 8 and PRE_A2_FINGERPRINT not in seen


def test_an_identical_rebuild_is_stable_and_every_change_of_the_record_set_moves_it(raw):
    first = {2: {"cert_in_cbom": {"8.4.1.1": upload_record("2026-10-18T09:00:00Z")}}}
    uploaded = attested_fingerprint(raw, first)
    assert attested_fingerprint(raw, copy.deepcopy(first)) == uploaded != PRE_A2_FINGERPRINT
    changed = {
        "re-upload, same slot, later": {2: {"cert_in_cbom": {
            "8.4.1.1": upload_record("2026-10-19T10:00:00Z")}}},
        "second requirement": {2: {"cert_in_cbom": {
            "8.4.1.1": upload_record("2026-10-18T09:00:00Z"),
            "8.4.1.2": upload_record("2026-10-18T09:05:00Z")}}},
        "same record, other scan": {3: {"cert_in_cbom": {
            "8.4.1.1": upload_record("2026-10-18T09:00:00Z")}}},
        "other framework": {2: {"bsi_tr_02102": {
            "8.4.1.1": upload_record("2026-10-18T09:00:00Z")}}},
    }  # fmt: skip
    variants = {name: attested_fingerprint(raw, uploads) for name, uploads in changed.items()}
    everything = [PRE_A2_FINGERPRINT, uploaded, *variants.values()]
    assert len(set(everything)) == len(everything), variants  # each change is its own value
    # the DELETE route drops the record again: the fingerprint returns to the attestation-free value
    assert attested_fingerprint(raw, {2: {}}) == PRE_A2_FINGERPRINT


def test_record_fields_cannot_blur_into_each_other_or_break_the_hash_input(raw):
    one = attested_fingerprint(raw, {2: {"a:b": {"c": upload_record("t")}}})
    two = attested_fingerprint(raw, {2: {"a": {"b:c": upload_record("t")}}})
    three = attested_fingerprint(raw, {2: {"a": {"b": upload_record("c:t")}}})
    assert len({one, two, three}) == 3  # a naive "id:framework:req:at" join would merge them
    hostile = {2: {'fw",["x': {"r|attestations|9\n": upload_record('2026"\u2028\ud800\U0001f512')}}}
    moved = attested_fingerprint(raw, hostile)
    assert len(moved) == 12 and moved != PRE_A2_FINGERPRINT


def test_two_hundred_twenty_scan_fold_stays_fast(raw):
    template = scan_by_id(raw, 2)["scan_data"]  # a real ~110 KB run-object, shared read-only
    scans = [
        synth(i, age=timedelta(hours=i), repo=f"https://github.com/o/r{i % 11}", data=template)
        for i in range(1, 221)
    ]
    started = time.perf_counter()
    view, spy = run_fold(scans)
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"fold of 220 scans took {elapsed:.2f}s"
    assert (view.eligible, view.included, view.history_truncated) == (220, 200, 20)
    assert len(view.sources) == 11 and max(map(len, spy.calls)) <= 20


# =============================================================================================
# load_team_cbom_view against hermetic SQLite  (T-ROLL 16)
# =============================================================================================
@pytest.fixture()
def sqlite_engine(raw):
    from sqlalchemy.pool import StaticPool
    from sqlmodel import Session, SQLModel, create_engine

    from backend.new_models import Scan, Team, User

    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        for team_id, name in ((1, "E2E Demo Team"), (2, "Other Team"), (3, "Empty Team")):
            session.add(Team(id=team_id, name=name))
        session.add(User(id=1, email="seed@example.com", password="x", first_name="s",
                         last_name="e", default_team_id=1))  # fmt: skip
        session.commit()
        for s in raw["scans"]:
            session.add(Scan(
                id=s["id"], team_id=s["team_id"], owner_user_id=1, scan_type=s["scan_type"],
                title=s["title"], scan_status=s["status"], scan_metadata=s["scan_metadata"],
                created_at=_ts(s["created_at"]).replace(tzinfo=None),  # naive, like Postgres
                last_updated=_ts(s["last_updated"]).replace(tzinfo=None),
                scan_data=s["scan_data"],
            ))  # fmt: skip
        session.commit()
    return engine


def test_db_view_equals_the_in_memory_fold_and_normalises_naive_datetimes(sqlite_engine, view):
    db_view = load_team_cbom_view(sqlite_engine, 1, now=NOW)
    assert db_view == view  # same Appendix-B numbers through the real SQL path
    assert db_view.window_start == NOW - timedelta(days=60) and db_view.window_start.tzinfo
    assert all(s.created_at.tzinfo is not None for s in db_view.scans)
    assert (
        len(db_view.certs) == 14
        and len(db_view.sources) == 7
        and db_view.team_name == "E2E Demo Team"
    )


def test_db_tenant_isolation_between_teams(sqlite_engine):
    other = load_team_cbom_view(sqlite_engine, 2, now=NOW)
    assert (other.team_name, other.scans_total, other.included) == ("Other Team", 1, 1)
    assert [c.subject_cn for c in other.certs] == ["other-team-canary.test"]
    for token in ("payments", "identity-gateway", "FAILED-SCAN", "legacy-billing"):
        assert token not in repr(other)
    mine = load_team_cbom_view(sqlite_engine, 1, now=NOW)
    assert "other-team-canary" not in repr(mine) and "other-org" not in repr(mine)
    empty = load_team_cbom_view(sqlite_engine, 3, now=NOW)
    assert empty.is_empty and empty.team_name == "Empty Team" and empty.scans_total == 0
    ghost = load_team_cbom_view(sqlite_engine, 99, now=NOW)
    assert ghost.is_empty and ghost.team_name == "Team 99"


def test_db_pass_one_selects_no_blobs_and_pass_two_only_eligible_ids(sqlite_engine):
    from sqlalchemy import event

    statements = []
    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append((statement, parameters))

    event.listen(sqlite_engine, "before_cursor_execute", record)
    load_team_cbom_view(sqlite_engine, 1, now=NOW)
    blob_reads = [(s, p) for s, p in statements if "scan_data" in s]
    head_reads = [(s, p) for s, p in statements if "FROM scan" in s and "scan_data" not in s]
    assert head_reads and blob_reads
    for stmt, params in blob_reads:
        assert "IN (" in stmt
        assert len(params) <= 20 + 3  # <= batch_size ids + team + type (+ slack for dialect)
        assert not {9, 10, 11, 12, 14} & {p for p in params if isinstance(p, int) and p != 1}
    first_head = head_reads[0][0]
    assert "scan_data" not in first_head and "scan_metadata" in first_head


def test_db_accepts_an_open_session_and_defaults_now_to_the_current_time(sqlite_engine):
    from sqlmodel import Session

    with Session(sqlite_engine) as session:
        live = load_team_cbom_view(session, 1)
        assert session.in_transaction()  # a session we do not own is left open
    assert abs((datetime.now(UTC) - live.generated_at).total_seconds()) < 60
    assert live.generated_at.tzinfo is not None and live.included == 8


# =============================================================================================
# Loader contract: missing / failing / odd blobs, duplicate heads, hostile text kept verbatim
# =============================================================================================
@pytest.mark.parametrize("returned", [{}, None, [], "nope"], ids=["empty", "none", "list", "str"])
def test_ids_the_loader_does_not_return_become_no_data(raw, returned):
    scans = [scan_by_id(raw, i) for i in (2, 3, 9)]
    heads = [_head(s) for s in scans]
    view = fold_scans(heads, lambda ids: returned, team_id=1, team_name="t", now=NOW)
    assert (view.eligible, view.included, view.excluded[EXCLUDED_NO_DATA]) == (2, 0, 2)
    assert view.is_empty and view.sources == () and view.excluded[EXCLUDED_FAILURE] == 1


def test_a_failing_loader_is_not_swallowed_into_an_empty_document(raw):
    def broken(ids):
        raise RuntimeError("database went away")

    with pytest.raises(RuntimeError, match="database went away"):
        fold_scans([_head(scan_by_id(raw, 2))], broken, team_id=1, team_name="t", now=NOW)


def test_a_head_listed_twice_is_counted_once(raw):
    head = _head(scan_by_id(raw, 2))
    spy = BlobSpy({2: scan_by_id(raw, 2)["scan_data"]})
    view = fold_scans([head, head], spy, team_id=1, team_name="t", now=NOW)
    assert (view.scans_total, view.included) == (1, 1) and spy.seen == [2]


def test_hostile_text_is_kept_verbatim_for_the_renderers_to_escape():
    markup = '<img src="file:///etc/hostname"><font color="red">&lt;x&gt;\x00</font>'
    odd = {markup: {"requirements": "not-a-list"}, "ok_fw": {"requirements": [1]}}
    comp = _cert_component("c.crt", markup, issuer=markup)
    blob = _blob([_row(markup, bom_ref="r1"), _cert_row("c.crt")], [comp], compliance=odd)
    scan = synth(1, data=blob, title=markup, repo="https://github.com/o/" + "r" * 5000)
    view, _ = run_fold([scan])
    assert only(a for a in view.assets if a.asset_type == ASSET_ALGORITHM).title == markup
    assert only(view.certs).subject_cn == markup
    assert only(view.scans).title == markup
    assert len(view.warnings) == 2  # the odd compliance blocks were noticed ...
    assert all("<" not in w and "\x00" not in w for w in view.warnings)  # ... but never echoed
    assert any("cbom_compliance.?.requirements is not a list" in w for w in view.warnings)
    assert any("cbom_compliance.ok_fw.requirements[0] is not an object" in w for w in view.warnings)


# =============================================================================================
# Hygiene: stdlib-only, lazy DB import, one clock read, clean import closure
# (the WP1b share of T-NOLLM-1 / T-NOLLM-2a; WP4 owns the router-wide guards)
# =============================================================================================
LLM_AND_NETWORK_ROOTS = {
    "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "langchain_openai",
    "openai", "anthropic", "instructor", "litellm", "requests", "httpx", "urllib3", "aiohttp",
    "msal", "celery", "kombu", "pymongo",
}  # fmt: skip
STDLIB_NETWORK_ROOTS = {"socket", "ssl", "http", "smtplib", "ftplib", "subprocess", "asyncio"}


def _module_source() -> str:
    return Path(roll.__file__).read_text(encoding="utf-8")


def _import_sites() -> list[tuple[str, str]]:
    """``(imported module, enclosing function or '<module>')`` for every import statement."""
    sites: list[tuple[str, str]] = []

    def visit(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child.name)
            elif isinstance(child, ast.Import):
                sites.extend((alias.name, scope) for alias in child.names)
            elif isinstance(child, ast.ImportFrom):
                sites.append(("." * child.level + (child.module or ""), scope))
            else:
                visit(child, scope)

    visit(ast.parse(_module_source()), "<module>")
    return sites


def test_the_worktree_copy_of_the_module_is_the_one_under_test():
    assert Path(roll.__file__).resolve().is_relative_to(_REPO_ROOT)


def test_module_level_imports_are_standard_library_only():
    top = [name for name, scope in _import_sites() if scope == "<module>"]
    assert top and all(name.split(".")[0] in sys.stdlib_module_names for name in top), top


# The one finding rule and the one quantum-readiness definition every CBOM view shares: pure modules whose own
# imports are stdlib only (the isolated import test below proves the closure stays clean).
SHARED_PURE_RULES = {"backend.utilities.cbom_sources.cbom_rows", "backend.utilities.cbom_sources.cbom_metrics"}


def test_only_the_db_loader_imports_non_stdlib_modules_and_only_lazily():
    outside = [(n, s) for n, s in _import_sites() if n.split(".")[0] not in sys.stdlib_module_names]
    assert outside, "load_team_cbom_view must import sqlmodel / backend.new_models lazily"
    db = [(n, s) for n, s in outside if n not in SHARED_PURE_RULES]
    assert {scope for _, scope in db} == {"load_team_cbom_view"}
    assert {name.split(".")[0] for name, _ in db} <= {"sqlmodel", "backend"}
    assert all(scope != "<module>" for name, scope in outside if name in SHARED_PURE_RULES)


def test_no_llm_network_or_process_imports_and_no_llm_tokens_in_the_source():
    names = {name for name, _ in _import_sites()}
    roots = {name.split(".")[0] for name in names}
    assert not roots & (LLM_AND_NETWORK_ROOTS | STDLIB_NETWORK_ROOTS | {"time", "os"}), roots
    assert "urllib.request" not in names and "backend.routers" not in " ".join(names)
    assert not any(name.startswith("backend.utilities.ai") for name in names)
    source = _module_source().lower()
    for token in ("get_llm", "chatbedrock", "bedrock", "anthropic", "openai"):
        assert token not in source, token


def test_the_only_clock_read_is_in_the_db_loader():
    tree = ast.parse(_module_source())
    clock = {"now", "today", "utcnow", "time", "monotonic", "perf_counter", "gmtime", "localtime"}
    readers = {
        fn.name
        for fn in ast.walk(tree)
        if isinstance(fn, ast.FunctionDef)
        for call in ast.walk(fn)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Attribute)
        and call.func.attr in clock
    }
    assert readers == {"load_team_cbom_view"}


@pytest.mark.parametrize("isolated", [True, False], ids=["python-S-stdlib-only", "full-venv"])
def test_importing_the_module_loads_no_forbidden_or_database_module(isolated):
    forbidden = sorted(LLM_AND_NETWORK_ROOTS | (STDLIB_NETWORK_ROOTS if isolated else set()))
    code = textwrap.dedent(f"""
        import json, sys
        sys.path.insert(0, {str(_REPO_ROOT)!r})
        import backend.utilities.dashboard.cbom_team_rollup  # noqa: F401
        roots = {{name.split(".")[0] for name in sys.modules}}
        heavy = ("backend.utilities.ai", "backend.routers", "backend.new_models", "backend.get_db")
        print(json.dumps({{
            "forbidden": sorted(roots & set({forbidden!r})),
            "database": sorted(roots & {{"sqlmodel", "sqlalchemy"}}),
            "ours": sorted(m for m in sys.modules if m.startswith(heavy)),
        }}))
    """)
    flags = ["-S", "-E"] if isolated else []
    proc = subprocess.run(
        [sys.executable, *flags, "-c", code], capture_output=True, text=True, timeout=120,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    loaded = json.loads(proc.stdout.strip().splitlines()[-1])
    assert loaded == {"forbidden": [], "database": [], "ours": []}


# =============================================================================================
# The WP1a interface freeze: names, fields and signatures must not drift
# =============================================================================================
FROZEN_FIELDS = {
    "ScanHead": "id team_id scan_type title status created_at last_updated scan_metadata",
    "ExpiryBand": "band days_left",
    "ScanFacts": (
        "scan_id title status created_at last_updated source_key source_label source_kind "
        "repo_url branch exclusion is_current tier fidelity fidelity_reasons asset_count "
        "cert_count lib_count assets certs libs frameworks requirements warnings posture"
    ),
    "SourceAgg": (
        "key label kind repo_url branch scan_ids scan_count first_scanned last_scanned "
        "current_scan_id current_tier current_fidelity last_attempt_scan_id "
        "last_attempt_status last_attempt_at asset_counts impact_counts library_count"
    ),
    "AssetAgg": (
        "source_key source_label asset_type ident title location impact finding_codes bom_ref "
        "description primitive key_size curve mode protocol_version material_kind parameter_set "
        "not_valid_after security_strength_bits risk_score quantum_vulnerable quantum_safe hybrid "
        "nist_quantum_security_level pqc_migration_target pqc_migration_roadmap tier current "
        "first_seen last_seen scan_count scan_ids latest_scan_id"
    ),
    "CertAgg": (
        "key identity_strong name file_names subject_cn issuer_cn not_before not_after "
        "public_key_algorithm key_size curve signature_algorithm self_signed is_ca signed_by "
        "expiry scan_time_expired impact finding_codes tier source_keys current_source_keys "
        "locations locations_total current first_seen last_seen scan_count scan_ids latest_scan_id"
    ),
    "LibAgg": (
        "key name source_keys source_labels current_source_keys discovered_in "
        "discovered_in_total current first_seen last_seen scan_count scan_ids latest_scan_id"
    ),
    "RequirementAgg": (
        "framework req_id title citation verdict verdicts attestable_sources attested_sources "
        "latest_attestation_file latest_attestation_note latest_attestation_at"
    ),
    "FrameworkPool": (
        "framework passed passed_with_evidence failed out_of_scope not_bom_evidenceable na "
        "coverage sources_pooled legacy_excluded"
    ),
    "TeamCbomView": (
        "team_id team_name generated_at as_of scans_total eligible included excluded "
        "history_truncated fidelity_full fidelity_reduced window_start window_end fingerprint "
        "scans sources assets certs libs frameworks requirements asset_occurrences "
        "assets_by_type assets_by_impact issue_by_impact finding_counts pqc_vulnerable pqc_safe "
        "pqc_hybrid pqc_ungraded readiness_pct compliance_sources_pooled "
        "compliance_legacy_excluded warnings posture remediation"  # remediation: WP10 (loader only, not compared)
    ),
}


@pytest.mark.parametrize("name", list(FROZEN_FIELDS))
def test_dataclass_fields_match_the_wp1a_freeze_and_resolve_on_py310(name):
    cls = getattr(roll, name)
    assert tuple(f.name for f in dataclasses.fields(cls)) == tuple(FROZEN_FIELDS[name].split())
    assert typing.get_type_hints(cls)  # every annotation resolves on this interpreter


def test_function_signatures_match_the_wp1a_freeze():
    def shape(fn):
        return [(p.name, p.kind.name, p.default) for p in inspect.signature(fn).parameters.values()]

    empty = inspect.Parameter.empty
    pos, kwo = "POSITIONAL_OR_KEYWORD", "KEYWORD_ONLY"
    assert shape(roll.sanitize_repo_url) == [("url", pos, empty)]
    assert shape(roll.source_key_for) == [("meta", pos, empty), ("title", pos, empty),
                                          ("scan_id", pos, empty)]  # fmt: skip
    assert shape(roll.cert_identity_key) == [("props", pos, empty), ("fallback_name", kwo, empty),
                                             ("source_key", kwo, empty)]  # fmt: skip
    assert shape(roll.classify_expiry) == [("not_after_iso", pos, empty), ("as_of", pos, empty)]
    assert shape(roll.extract_scan_facts) == [("head", pos, empty), ("scan_data", pos, empty)]
    assert shape(roll.fold_scans) == [
        ("heads", pos, empty), ("load_blobs", pos, empty), ("team_id", kwo, empty),
        ("team_name", kwo, empty), ("now", kwo, empty),
        ("history_window", kwo, roll.HISTORY_WINDOW),
        ("hard_max", kwo, roll.HARD_MAX_SCANS), ("batch_size", kwo, roll.BATCH_SIZE),
    ]  # fmt: skip
    assert shape(roll.load_team_cbom_view) == [("engine", pos, empty), ("team_id", pos, empty),
                                               ("now", kwo, None)]  # fmt: skip
    assert (roll.HISTORY_WINDOW, roll.HARD_MAX_SCANS, roll.BATCH_SIZE) == (200, 1000, 20)
    for name in roll.__all__:
        assert hasattr(roll, name), name
