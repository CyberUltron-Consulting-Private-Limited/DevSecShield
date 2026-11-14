"""CB-33 PR-A: KMS keys and ACM certificates are read one by one; what cannot be read is a scoped gap, never a fix.

Before this change (dev c75aec146):
* one DescribeKey / DescribeCertificate failure aborted the whole service in the region (B4, B8): every key or
  certificate there dropped out and the job was not compared;
* a throttled or failed GetKeyRotationStatus left ``rotation_enabled`` None with no coverage row, so drift read every
  ``KMS_NO_ROTATION`` in the region as resolved (B5);
* only Enabled keys were asked for rotation, so disabling a key resolved its finding and re-enabling opened it (B6);
* imported-material, custom-store, multi-Region and ACM export facts were not collected (B2, B3, B7).

Now each per-item read is isolated (``aws_collect._Items``): failed items become exact-ARN coverage rows (at most
``ITEM_ROWS`` single rows per operation, the rest in exact-ARN chunks, never a prefix), a per-operation breaker stops
after ``BREAKER_THROTTLES`` throttles in a row, a role that may not read anything is one row after
``ROLE_WIDE_DENIALS`` denials, and the worker's ``tick`` and a per-service time budget bound a region.  The change is
verdict-neutral under the classifier on dev (T19): only Disabled customer keys with rotation off now carry
``KMS_NO_ROTATION`` (a true finding that was hidden).

Recorded responses go through botocore's Stubber (it validates shapes, not enum values: every enum value used here goes
through ``_enum``, which checks it against the botocore 1.41.5 model, HF-12).  No network, no AWS.

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_aws_cb33.py
"""
from __future__ import annotations

import datetime as dt
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import botocore.session  # noqa: E402
from botocore.exceptions import ClientError, ReadTimeoutError  # noqa: E402
from botocore.stub import Stubber  # noqa: E402

from backend.utilities.cbom_sources import aws_collect  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import jobs as J  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_drift_last_known import Chain, emitted, engine  # noqa: E402,F401  (fixtures)

REGION, ACCOUNT = "ap-south-1", "123456789012"
LABEL = f"aws:{ACCOUNT}"
PREFIX = f"arn:aws:kms:{REGION}:{ACCOUNT}:"
ACM_PREFIX = f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/"
_BS = botocore.session.get_session()
_KMS_MODEL = _BS.get_service_model("kms")
_ACM_MODEL = _BS.get_service_model("acm")
T0 = dt.datetime(2026, 11, 14, 6, 0, 0)


def _enum(model, shape: str, value: str) -> str:
    """Every enum value a fixture uses exists in the botocore 1.41.5 model (the Stubber does not check enums)."""
    assert value in model.shape_for(shape).enum, f"{value!r} is not a {shape} in botocore's model"
    return value


def _err(code: str, op: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "recorded"}}, op)


# ----------------------------------------------------------------------------- recorded KMS / ACM answers
def kid(n: int) -> str:
    return f"1234abcd-0000-0000-0000-{n:012d}"


def arn(n: int) -> str:
    return f"{PREFIX}key/{kid(n)}"


def meta(n: int, *, origin="AWS_KMS", state="Enabled", spec="SYMMETRIC_DEFAULT", manager="CUSTOMER", **extra):
    out = {"KeyId": kid(n), "Arn": arn(n), "AWSAccountId": ACCOUNT, "Description": f"key {n}",
           "KeyManager": _enum(_KMS_MODEL, "KeyManagerType", manager),
           "KeyState": _enum(_KMS_MODEL, "KeyState", state), "Origin": _enum(_KMS_MODEL, "OriginType", origin),
           "KeySpec": _enum(_KMS_MODEL, "KeySpec", spec), "Enabled": state == "Enabled", "MultiRegion": False,
           "KeyUsage": "ENCRYPT_DECRYPT" if spec == "SYMMETRIC_DEFAULT" else "SIGN_VERIFY",
           "CreationDate": dt.datetime(2025, 1, 1)}
    if origin == "EXTERNAL":
        out["ExpirationModel"] = _enum(_KMS_MODEL, "ExpirationModelType", extra.pop("expiration_model",
                                                                                     "KEY_MATERIAL_EXPIRES"))
        out["ValidTo"] = extra.pop("valid_to", dt.datetime(2027, 1, 1))
    out.update(extra)
    return out


def rotation(enabled: bool, **extra) -> dict[str, Any]:
    return {"KeyRotationEnabled": enabled, **extra}


class Plan:
    """The calls ``kms()`` must make, in order, with each answer; anything else fails the test."""

    def __init__(self) -> None:
        self.kms: list[tuple[str, Any, dict | None]] = []
        self.acm: list[tuple[str, Any, dict | None]] = []

    def keys(self, *ns: int, pages: int = 1) -> "Plan":
        entries = [{"KeyId": kid(n), "KeyArn": arn(n)} for n in ns]
        size = -(-len(entries) // pages) if entries else 0
        for p in range(pages):
            chunk = entries[p * size:(p + 1) * size]
            last = p == pages - 1
            page = {"Keys": chunk, "Truncated": not last, **({} if last else {"NextMarker": f"m{p + 1}"})}
            self.kms.append(("list_keys", page, None))
        return self

    def describe(self, n: int, answer: dict | str) -> "Plan":
        self.kms.append(("describe_key", answer if isinstance(answer, str) else {"KeyMetadata": answer},
                         {"KeyId": kid(n)}))
        return self

    def rotation(self, n: int, answer: dict | str) -> "Plan":
        self.kms.append(("get_key_rotation_status", answer, {"KeyId": kid(n)}))
        return self

    def materials(self, n: int, answer: list | str) -> "Plan":
        self.kms.append(("list_key_rotations", answer if isinstance(answer, str) else {"Rotations": answer,
                                                                                       "Truncated": False},
                         {"KeyId": kid(n), "IncludeKeyMaterial": "ALL_KEY_MATERIAL"}))
        return self

    def raw(self, method: str, answer: Any, params: dict | None = None) -> "Plan":
        self.kms.append((method, answer, params))
        return self


class _Denied:
    """Every service a test does not record answers AccessDenied (those service rows are dropped by ``run``)."""

    def __getattr__(self, method):
        def denied(*_a, **_k):
            raise _err("AccessDenied", method)
        if method == "get_paginator":
            return lambda *_a, **_k: type("P", (), {"paginate": denied})()
        return denied


class _Acct:
    account = ACCOUNT

    def __init__(self, plan: Plan, wrap=None):
        self.clients, self.stubs = {}, []
        for service, calls in (("kms", plan.kms), ("acm", plan.acm)):
            if not calls:
                continue
            client = _BS.create_client(service, region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y")
            stub = Stubber(client)
            for method, answer, params in calls:
                if isinstance(answer, str):
                    stub.add_client_error(method, service_error_code=answer, http_status_code=400,
                                          expected_params=params)
                else:
                    stub.add_response(method, answer, params)
            stub.activate()
            self.clients[service] = wrap(service, client) if wrap else client
            self.stubs.append(stub)

    def client(self, service, _region):
        return self.clients.get(service) or _Denied()


def run(plan: Plan, *, tick=None, wrap=None) -> tuple[dict[str, str], list[dict], list[tuple]]:
    acct = _Acct(plan, wrap)
    found: list[dict] = []
    rows = aws_collect._region_services(acct, REGION, LABEL, found.append, {}, **({"tick": tick} if tick else {}))
    for stub in acct.stubs:
        stub.assert_no_pending_responses()  # every recorded call was made, in order, with the pinned parameters
    services = {svc: status for svc, status, _d in rows}
    unstubbed = {f"{svc} in {REGION}" for svc, status in services.items() if status == "denied"}
    kept = [a for a in found if not (a["type"] == "coverage" and a["facts"]["check"] in unstubbed)]
    # a call the plan did not record would surface as a "not read" row with a Stubber error: never in a passing test
    assert not [a for a in kept if a["type"] == "coverage" and "Stub" in str(a["facts"].get("code"))], kept
    return services, kept, rows


def keys_of(found):
    return {a["location"]: a for a in found if a["type"] == "kms_key"}


def gaps_of(found):
    return [a for a in found if a["type"] == "coverage"]


# ----------------------------------------------------------------------------- drift through the real functions
def stored(found: list[dict], at: dt.datetime = T0) -> list[SimpleNamespace]:
    """Collected assets as ``add_assets`` stores them (verdict by the classifier, asset key)."""
    rows = []
    for i, a in enumerate(found):
        facts = a.get("facts") or {}
        verdict = classify(a["type"], a.get("algorithm"), a.get("key_size"), a.get("protocol"), facts, at)
        rows.append(SimpleNamespace(
            id=i, asset_type=a["type"], finding_codes=verdict["finding_codes"], impact=verdict["impact"],
            quantum_vulnerable=verdict["quantum_vulnerable"], facts=facts, created_at=at, target=a["target"],
            location=a["location"], name=a.get("name"), algorithm=a.get("algorithm"), key_size=a.get("key_size"),
            protocol=a.get("protocol"), cdx_type=verdict["cdx_type"],
            asset_key=J._asset_key(a["type"], a["target"], a["location"], facts, a.get("name"))))
    return rows


def diff(before: list[dict], after: list[dict]) -> dict[str, list]:
    b, a = stored(before), stored(after)
    return D.compare(D.node_views(b, "src", reclassify=False), D.node_views(a, "src", reclassify=False),
                     D.job_gaps(a))


def events(d: dict[str, list]) -> list[tuple[str, str, str | None]]:
    out = [("new_asset", x["location"], None) for x in d["added"]] + [
        ("removed_asset", x["location"], None) for x in d["removed"]]
    out += [("opened", x["location"], x["code"]) for x in d["opened"]]
    out += [("resolved", x["location"], x["code"]) for x in d["resolved"]]
    return sorted(out)


def comparable(services: dict[str, str], found: list[dict]) -> tuple[bool, str | None]:
    """The job outcome as the server computes it for a one-region AWS job whose services are those of ``run``."""
    status = "partial" if any(s == "partial" for s in services.values() if s != "denied") else "ok"
    result = {"counts": {"total": 1, "ok": 1 if status == "ok" else 0, "partial": 1 if status == "partial" else 0,
                         "failed": 0, "skipped": 0}, "asset_count": len(found)}
    outcome, extra = J._outcome(SimpleNamespace(kind="collect"), "success", result, len(found))
    return D.job_comparable(SimpleNamespace(kind="collect", status="success", result={**result, **extra},
                                            outcome=outcome))


# ============================================================================ T-PC positive control
def test_t_pc_a_clean_mixed_region_is_ok_with_no_rows():
    plan = (Plan().keys(1, 2, 3, 4, 5)
            .describe(1, meta(1)).rotation(1, rotation(True, RotationPeriodInDays=365,
                                                        NextRotationDate=dt.datetime(2027, 1, 1)))
            .describe(2, meta(2)).rotation(2, rotation(False))
            .describe(3, meta(3, spec="RSA_2048"))
            .describe(4, meta(4, manager="AWS"))
            .describe(5, meta(5, spec="HMAC_256")))
    services, found, _rows = run(plan)
    assert services["kms"] == "ok" and gaps_of(found) == []
    keys = keys_of(found)
    assert keys[arn(1)]["facts"]["rotation_status"] == "on" and keys[arn(1)]["facts"]["rotation_period_days"] == 365
    assert keys[arn(1)]["facts"]["next_rotation"] == "2027-01-01T00:00:00Z"
    assert keys[arn(2)]["facts"]["rotation_status"] == "off" and keys[arn(2)]["facts"]["rotation_enabled"] is False
    assert {keys[arn(n)]["facts"]["rotation_status"] for n in (3, 4, 5)} == {"not applicable"}
    assert all(a["facts"]["rotation_status"] for a in keys.values())  # never null (F2)


# ============================================================================ T2' call set per origin x state
@pytest.mark.parametrize("origin,state,asked", [
    ("AWS_KMS", "Enabled", True), ("AWS_KMS", "Disabled", True), ("AWS_KMS", "Creating", True),
    ("AWS_KMS", "Updating", True), ("AWS_KMS", "PendingDeletion", False), ("AWS_KMS", "PendingReplicaDeletion", False),
    ("EXTERNAL", "Enabled", True),  # kept as on dev until PR-B changes the rule that reads it (verdict-neutral)
    ("EXTERNAL", "Disabled", False), ("EXTERNAL", "PendingImport", False),
    ("AWS_CLOUDHSM", "Enabled", False), ("EXTERNAL_KEY_STORE", "Enabled", False),
])
def test_t2_rotation_is_asked_exactly_where_aws_can_answer(origin, state, asked):
    """dev: asked only for Enabled keys, so a Disabled / Creating key's finding vanished; custom-store keys raised."""
    store = {"CustomKeyStoreId": "cks-1"} if origin in ("AWS_CLOUDHSM", "EXTERNAL_KEY_STORE") else {}
    plan = Plan().keys(1).describe(1, meta(1, origin=origin, state=state, **store))
    if asked:
        plan.rotation(1, rotation(False))
    if origin == "EXTERNAL":
        plan.materials(1, [])
    if store:
        plan.raw("describe_custom_key_stores", {"CustomKeyStores": []})
    services, found, _rows = run(plan)
    facts = keys_of(found)[arn(1)]["facts"]
    if asked:
        assert facts["rotation_status"] == "off" and facts["rotation_enabled"] is False
    elif state in ("PendingDeletion", "PendingReplicaDeletion"):
        assert facts["rotation_status"] == f"not reported while {state}"
        row = gaps_of(found)[0]["facts"]
        assert row["status"] == "not_reported" and row["incomplete"] is True and row["scope"] == [arn(1)]
        assert services["kms"] == "ok"  # known and stable: the target stays ok, drift still covers the key
    else:
        assert facts["rotation_status"] == "not applicable" and facts["rotation_enabled"] is None


# ============================================================================ T6 / T7 one key's metadata
@pytest.mark.parametrize("code,status", [("ThrottlingException", "throttled"), ("AccessDeniedException", "denied"),
                                         ("KMSInternalException", "error")])
def test_t6_t7_one_unreadable_key_never_takes_the_region_down(code, status):
    """dev: the first failing DescribeKey raised out of ``kms()``: 2 of 10 keys emitted, a service-wide error row."""
    plan = Plan().keys(*range(1, 11))
    for n in range(1, 11):
        plan.describe(n, code if n in (3, 7) else meta(n, spec="RSA_2048"))
    services, found, _rows = run(plan)
    assert services["kms"] == "partial"
    assert sorted(keys_of(found)) == sorted(arn(n) for n in range(1, 11) if n not in (3, 7))
    rows = gaps_of(found)
    assert [(r["location"], r["facts"]["scope"], r["facts"]["status"], r["facts"].get("incomplete")) for r in rows] == [
        (f"{arn(3)}#metadata", [arn(3)], status, None), (f"{arn(7)}#metadata", [arn(7)], status, None)]


def test_t_nf_not_found_for_a_listed_key_is_not_read_not_deleted():
    """S7 rejected: a NotFound for a key ListKeys has just returned is not proof of deletion."""
    plan = Plan().keys(1, 2).describe(1, "NotFoundException").describe(2, meta(2)).rotation(2, rotation(True))
    _services, found, _rows = run(plan)
    before = [{"type": "kms_key", "target": LABEL, "location": arn(1), "name": "key 1", "algorithm": "SYMMETRIC_DEFAULT",
               "key_size": 256, "facts": {**keys_of(found)[arn(2)]["facts"], "identity": arn(1),
                                          "rotation_enabled": False}}] + [a for a in found if a["type"] == "kms_key"]
    d = diff(before, found)
    assert d["removed"] == [] and d["resolved"] == [] and [x["location"] for x in d["not_read"]] == [arn(1)]


def test_t_to_a_read_timeout_is_a_gap():
    class Timeouts:
        def __init__(self, client):
            self._c = client

        def describe_key(self, **kw):
            if kw["KeyId"] == kid(2):
                raise ReadTimeoutError(endpoint_url="https://kms.ap-south-1.amazonaws.com")
            return self._c.describe_key(**kw)

        def __getattr__(self, name):
            return getattr(self._c, name)

    plan = Plan().keys(1, 2).describe(1, meta(1, spec="RSA_2048"))
    services, found, _rows = run(plan, wrap=lambda svc, c: Timeouts(c) if svc == "kms" else c)
    assert services["kms"] == "partial" and list(keys_of(found)) == [arn(1)]
    assert gaps_of(found)[0]["facts"]["code"] == "ReadTimeoutError"


# ============================================================================ T8 / T9 rotation
def test_t8_a_throttled_rotation_status_is_not_read_through_job_comparable():
    """B5. dev: no row, ``rotation_enabled`` None, the job ok: drift resolved KMS_NO_ROTATION."""
    first = run(Plan().keys(1, 2).describe(1, meta(1)).rotation(1, rotation(False))
                .describe(2, meta(2)).rotation(2, rotation(False)))
    services, found, _rows = run(Plan().keys(1, 2).describe(1, meta(1)).rotation(1, "ThrottlingException")
                                 .describe(2, meta(2)).rotation(2, rotation(False)))
    facts = keys_of(found)[arn(1)]["facts"]
    assert facts["rotation_enabled"] is None and facts["rotation_status"] == "not read: ThrottlingException"
    row = gaps_of(found)[0]
    assert row["location"] == f"{arn(1)}#rotation" and row["facts"]["incomplete"] is True
    assert services["kms"] == "partial" and comparable(services, found) == (True, None)
    d = diff(first[1], found)
    assert d["resolved"] == [] and [(x["location"], x["codes"]) for x in d["not_read"]] == [
        (arn(1), ["KMS_NO_ROTATION"])]


def test_t9_disabling_a_key_with_rotation_off_changes_nothing():
    """B6 (OQ-1: keep the finding). dev: Disabled was not asked, so KMS_NO_ROTATION resolved, then opened again."""
    enabled = run(Plan().keys(1).describe(1, meta(1)).rotation(1, rotation(False)))[1]
    disabled = run(Plan().keys(1).describe(1, meta(1, state="Disabled")).rotation(1, rotation(False)))[1]
    assert "KMS_NO_ROTATION" in classify("kms_key", "SYMMETRIC_DEFAULT", 256, None, keys_of(disabled)[arn(1)]["facts"])[
        "finding_codes"]
    assert events(diff(enabled, disabled)) == [] and events(diff(disabled, enabled)) == []


def test_t9b_pending_deletion_and_its_cancellation_resolve_and_open_nothing(engine, emitted):  # noqa: F811
    """HF-5 / S9 through the real drift recording (PR-0's last-known baseline carries the finding across the
    ``not_reported`` gap).  dev: PendingDeletion resolved KMS_NO_ROTATION, the cancellation (Disabled) did not
    report it, and re-enabling opened it again."""
    ch = Chain(engine)
    ch.record(ch.run(run(Plan().keys(1).describe(1, meta(1)).rotation(1, rotation(False)))[1]))
    services, pending, _rows = run(Plan().keys(1).describe(1, meta(1, state="PendingDeletion")))
    assert services["kms"] == "ok"
    assert ch.record(ch.run(pending)) == [("opened", arn(1), "KMS_PENDING_DELETION")]
    cancelled = run(Plan().keys(1).describe(1, meta(1, state="Disabled")).rotation(1, rotation(False)))[1]
    assert ch.record(ch.run(cancelled)) == [("resolved", arn(1), "KMS_PENDING_DELETION")]
    enabled = run(Plan().keys(1).describe(1, meta(1)).rotation(1, rotation(False)))[1]
    assert ch.record(ch.run(enabled)) == []


def test_t_unsup_an_unsupported_rotation_answer_is_a_fact_not_a_gap():
    plan = (Plan().keys(1).describe(1, meta(1, origin="EXTERNAL")).rotation(1, "UnsupportedOperationException")
            .materials(1, []))
    services, found, _rows = run(plan)
    assert services["kms"] == "ok" and gaps_of(found) == []
    assert keys_of(found)[arn(1)]["facts"]["rotation_status"] == "not supported"


def test_t_rot_a_rotation_only_throttle_trips_the_rotation_breaker_and_metadata_goes_on():
    n_keys = 30
    plan = Plan().keys(*range(1, n_keys + 1))
    for n in range(1, n_keys + 1):
        plan.describe(n, meta(n))
        if n <= aws_collect.BREAKER_THROTTLES:
            plan.rotation(n, "ThrottlingException")
    services, found, _rows = run(plan)  # Stubber: no rotation call after the 10th throttle (else UnStubbed)
    assert len(keys_of(found)) == n_keys and services["kms"] == "partial"
    rows = gaps_of(found)
    assert len(rows) == n_keys and all(r["facts"]["incomplete"] for r in rows)
    assert sum(1 for r in rows if "stopped after" in r["facts"]["detail"]) == n_keys - aws_collect.BREAKER_THROTTLES


# ============================================================================ denials
def test_t_deny_denials_never_trip_the_throttle_breaker():
    plan = Plan().keys(*range(1, 16))
    for n in range(1, 16):
        plan.describe(n, "AccessDeniedException" if n <= 10 else meta(n, spec="RSA_2048"))
    _services, found, _rows = run(plan)
    assert len(keys_of(found)) == 5 and len(gaps_of(found)) == 10


def test_t_role_a_role_that_may_read_no_key_is_one_row_after_25_denials():
    """EC-4: 1,000 keys, every DescribeKey denied: 25 calls, one service-region row (never 1,000)."""
    plan = Plan().keys(*range(1, 1001))
    for n in range(1, aws_collect.ROLE_WIDE_DENIALS + 1):
        plan.describe(n, "AccessDeniedException")
    services, found, _rows = run(plan)
    rows = gaps_of(found)
    assert keys_of(found) == {} and len(rows) == 1 and services["kms"] == "partial"
    assert rows[0]["facts"]["status"] == "denied" and rows[0]["facts"]["scope"] == [PREFIX]
    assert "incomplete" not in rows[0]["facts"]


# ============================================================================ many failures: exact ARNs, chunked
def test_t10_two_hundred_unreadable_keys_are_exact_arn_chunks_never_a_prefix():
    """HF-3 / S6: a prefix row would hide every real fix in the region; chunks list exact ARNs."""
    plan = Plan().keys(*range(1, 201))
    for n in range(1, 201):
        plan.describe(n, "KMSInternalException")
    _services, found, rows = run(plan)
    gaps = gaps_of(found)
    singles = [g for g in gaps if g["location"].endswith("#metadata")]
    chunks = [g for g in gaps if "#metadata-not-read-" in g["location"]]
    assert len(singles) == aws_collect.ITEM_ROWS and len(chunks) == 2
    assert len({g["location"] for g in gaps}) == len(gaps)  # distinct locations: none collapses into another
    assert sum(g["facts"].get("not_read_count", 1) for g in gaps) == 200
    assert all(s.startswith(f"{PREFIX}key/") and s != f"{PREFIX}key/" for g in gaps for s in g["facts"]["scope"])
    assert chunks[0]["facts"]["codes"] == {"KMSInternalException": 100}
    assert dict((s, d) for s, _st, d in rows)["kms"] == "200 not read"


def test_t10b_beside_many_unreadable_keys_a_real_fix_and_a_real_deletion_still_drift():
    def region(fixed: bool, deleted: bool):
        ns = [n for n in range(1, 63) if not (deleted and n == 62)]
        plan = Plan().keys(*ns)
        for n in ns:
            if n <= 60:
                plan.describe(n, "AccessDeniedException" if n % 2 else meta(n, spec="RSA_2048"))
            else:
                plan.describe(n, meta(n)).rotation(n, rotation(fixed and n == 61))
        return run(plan)[1]

    before = region(False, False)
    # the denied keys are odd: 30 of them interleaved with readable ones, so the role-wide stop never applies
    before_ok = [a for a in before if a["type"] != "coverage"] + [
        {"type": "kms_key", "target": LABEL, "location": arn(n), "name": f"key {n}", "algorithm": "RSA_2048",
         "key_size": 2048, "facts": {"key_spec": "RSA_2048", "identity": arn(n)}} for n in range(1, 61, 2)]
    after = region(True, True)
    assert events(diff(before_ok, after)) == [("removed_asset", arn(62), None), ("resolved", arn(61), "KMS_NO_ROTATION"),
                                              ("resolved", arn(62), "KMS_NO_ROTATION")]


# ============================================================================ paging
def test_t_page_a_failed_later_page_keeps_what_was_listed():
    """EC-8. dev: the whole service failed, 0 keys."""
    plan = Plan().keys(1, 2, 3, 4, pages=2)
    plan.kms = plan.kms[:1]  # page 1 lists keys 1 and 2; page 2 is throttled
    plan.raw("describe_key", {"KeyMetadata": meta(1, spec="RSA_2048")}, {"KeyId": kid(1)})
    plan.raw("describe_key", {"KeyMetadata": meta(2, spec="RSA_2048")}, {"KeyId": kid(2)})
    plan.kms.insert(1, ("list_keys", "ThrottlingException", None))
    # the paginator asks for page 2 before the keys of page 1 are described
    services, found, _rows = run(plan)
    assert sorted(keys_of(found)) == [arn(1), arn(2)] and services["kms"] == "partial"
    row = gaps_of(found)[0]
    assert row["facts"]["scope"] == [f"{PREFIX}key/"] and "incomplete" not in row["facts"]  # plain: listed keys drift


# ============================================================================ imported material, stores, multi-Region
def test_t3_custom_key_stores_are_inventoried_and_joined():
    plan = (Plan().keys(1, 2)
            .describe(1, meta(1, origin="AWS_CLOUDHSM", CustomKeyStoreId="cks-a", CloudHsmClusterId="cluster-1234567abcdef"))
            .describe(2, meta(2, origin="EXTERNAL_KEY_STORE", CustomKeyStoreId="cks-b",
                              XksKeyConfiguration={"Id": "xks-key-9"}))
            .raw("describe_custom_key_stores", {"CustomKeyStores": [
                {"CustomKeyStoreId": "cks-a", "CustomKeyStoreName": "hsm",
                 "CustomKeyStoreType": _enum(_KMS_MODEL, "CustomKeyStoreType", "AWS_CLOUDHSM"),
                 "ConnectionState": _enum(_KMS_MODEL, "ConnectionStateType", "CONNECTED"),
                 "CloudHsmClusterId": "cluster-1234567abcdef", "TrustAnchorCertificate": "-----BEGIN CERTIFICATE-----x"},
                {"CustomKeyStoreId": "cks-b", "CustomKeyStoreName": "xks",
                 "CustomKeyStoreType": _enum(_KMS_MODEL, "CustomKeyStoreType", "EXTERNAL_KEY_STORE"),
                 "ConnectionState": _enum(_KMS_MODEL, "ConnectionStateType", "FAILED"),
                 "ConnectionErrorCode": "NETWORK_ERRORS"}]}))
    services, found, _rows = run(plan)
    assert services["kms"] == "ok"
    stores = {a["location"]: a for a in found if a["type"] == "key_store"}
    assert stores[f"{PREFIX}custom-key-store/cks-b"]["facts"]["connection_error_code"] == "NETWORK_ERRORS"
    assert "BEGIN CERTIFICATE" not in json.dumps(found)
    keys = keys_of(found)
    assert keys[arn(1)]["facts"]["key_store_connection_state"] == "CONNECTED"
    assert keys[arn(2)]["facts"]["key_store_connection_state"] == "FAILED"
    assert keys[arn(2)]["facts"]["xks_key_id"] == "xks-key-9" and keys[arn(1)]["facts"]["rotation_enabled"] is None


def test_t3b_a_failed_store_read_covers_the_stores_and_the_joined_keys():
    """HF-11."""
    plan = (Plan().keys(1, 2).describe(1, meta(1, origin="AWS_CLOUDHSM", CustomKeyStoreId="cks-a"))
            .describe(2, meta(2, spec="RSA_2048"))
            .raw("describe_custom_key_stores", "AccessDeniedException"))
    services, found, _rows = run(plan)
    row = gaps_of(found)[0]["facts"]
    assert row["scope"] == [f"{PREFIX}custom-key-store/", arn(1)] and row["incomplete"] is True
    assert services["kms"] == "partial" and len(keys_of(found)) == 2


MAT1, MAT2 = "a" * 64, "b" * 64  # KMS key material ids are 64 hex characters


def test_imported_material_and_multi_region_facts():
    """B3 / EC-7 / FP-5 facts (the rules that read them come in PR-B and PR-C)."""
    primary = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/mrk-1"
    plan = (Plan().keys(1, 2)
            .describe(1, meta(1, origin="EXTERNAL", state="Enabled", CurrentKeyMaterialId=MAT2,
                              valid_to=dt.datetime(2026, 12, 1)))
            .rotation(1, rotation(False))
            .materials(1, [{"KeyId": kid(1), "KeyMaterialId": MAT1,
                            "KeyMaterialState": _enum(_KMS_MODEL, "KeyMaterialState", "NON_CURRENT"),
                            "ImportState": _enum(_KMS_MODEL, "ImportState", "IMPORTED"),
                            "ExpirationModel": "KEY_MATERIAL_DOES_NOT_EXPIRE"},
                           {"KeyId": kid(1), "KeyMaterialId": MAT2,
                            "KeyMaterialState": _enum(_KMS_MODEL, "KeyMaterialState", "CURRENT"),
                            "ImportState": "IMPORTED", "ExpirationModel": "KEY_MATERIAL_EXPIRES",
                            "ValidTo": dt.datetime(2026, 12, 1)}])
            .describe(2, meta(2, MultiRegion=True, MultiRegionConfiguration={
                "MultiRegionKeyType": _enum(_KMS_MODEL, "MultiRegionKeyType", "REPLICA"),
                "PrimaryKey": {"Arn": primary, "Region": "us-east-1"}}))
            .rotation(2, rotation(False)))
    _services, found, _rows = run(plan)
    k1, k2 = keys_of(found)[arn(1)]["facts"], keys_of(found)[arn(2)]["facts"]
    assert k1["expiration_model"] == "KEY_MATERIAL_EXPIRES" and k1["valid_to"] == "2026-12-01T00:00:00Z"
    assert k1["current_key_material_id"] == MAT2
    assert [(m["id"], m["state"], m["valid_to"]) for m in k1["key_materials"]] == [
        (MAT1, "NON_CURRENT", None), (MAT2, "CURRENT", "2026-12-01T00:00:00Z")]
    assert k2["multi_region_type"] == "REPLICA" and k2["primary_key_arn"] == primary


def test_a_failed_material_listing_is_an_incomplete_gap():
    plan = (Plan().keys(1).describe(1, meta(1, origin="EXTERNAL")).rotation(1, rotation(False))
            .materials(1, "AccessDeniedException"))
    services, found, _rows = run(plan)
    row = gaps_of(found)[0]
    assert row["location"] == f"{arn(1)}#materials" and row["facts"]["incomplete"] is True
    assert "key_materials" not in keys_of(found)[arn(1)]["facts"] and services["kms"] == "partial"


# ============================================================================ ACM
def _cert_summary(n: int, **extra) -> dict:
    return {"CertificateArn": f"{ACM_PREFIX}c{n}", "DomainName": f"c{n}.example.com",
            "Type": _enum(_ACM_MODEL, "CertificateType", extra.pop("type", "AMAZON_ISSUED")),
            "Status": _enum(_ACM_MODEL, "CertificateStatus", "ISSUED"), "InUse": False, **extra}


def _cert_detail(n: int, **extra) -> dict:
    return {"Certificate": {"CertificateArn": f"{ACM_PREFIX}c{n}", "DomainName": f"c{n}.example.com",
                            "Subject": f"CN=c{n}.example.com", "Issuer": "Amazon", "Serial": f"0{n}",
                            "KeyAlgorithm": "RSA_2048", "SignatureAlgorithm": "SHA256WITHRSA", "Status": "ISSUED",
                            "Type": "AMAZON_ISSUED", "InUseBy": [], "NotAfter": dt.datetime(2027, 6, 1), **extra}}


def test_t13_one_unreadable_certificate_never_takes_acm_down():
    """B8. dev: the first failing DescribeCertificate raised: 1 of 3 certificates, a service-wide error row."""
    plan = Plan()
    plan.acm = [("list_certificates", {"CertificateSummaryList": [
        _cert_summary(1, Exported=True, ExportOption=_enum(_ACM_MODEL, "CertificateExport", "ENABLED")),
        _cert_summary(2), _cert_summary(3)]}, None),
        ("describe_certificate", _cert_detail(1), {"CertificateArn": f"{ACM_PREFIX}c1"}),
        ("describe_certificate", "ThrottlingException", {"CertificateArn": f"{ACM_PREFIX}c2"}),
        ("describe_certificate", _cert_detail(3, Options={"Export": "DISABLED"}), {"CertificateArn": f"{ACM_PREFIX}c3"})]
    services, found, _rows = run(plan)
    certs = {a["location"]: a for a in found if a["type"] == "certificate"}
    assert sorted(certs) == [f"{ACM_PREFIX}c1", f"{ACM_PREFIX}c3"] and services["acm"] == "partial"
    assert certs[f"{ACM_PREFIX}c1"]["facts"]["exported"] is True
    assert certs[f"{ACM_PREFIX}c1"]["facts"]["export_option"] == "ENABLED"
    assert certs[f"{ACM_PREFIX}c3"]["facts"]["exported"] is None  # ACM did not say: unknown, not "no"
    assert certs[f"{ACM_PREFIX}c3"]["facts"]["export_option"] == "DISABLED"
    assert gaps_of(found)[0]["facts"]["scope"] == [f"{ACM_PREFIX}c2"]


# ============================================================================ time: tick and budget
class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _slow(clock: _Clock, seconds: float):
    """Wrap the KMS client so every DescribeKey takes ``seconds`` of virtual time."""
    class Slow:
        def __init__(self, client):
            self._c = client

        def describe_key(self, **kw):
            clock.now += seconds
            return self._c.describe_key(**kw)

        def __getattr__(self, name):
            return getattr(self._c, name)

    return lambda svc, c: Slow(c) if svc == "kms" else c


def test_t_time_tick_runs_inside_the_loop_and_the_budget_stops_the_region(monkeypatch):
    """EC-1. dev: ``should_stop`` ran once per region, so a slow region outlived its 15-minute lease."""
    clock = _Clock()
    monkeypatch.setattr(aws_collect, "_clock", clock)
    ticks: list[float] = []
    budget = aws_collect.SERVICE_BUDGET_S
    n_keys = budget + 100  # one virtual second per DescribeKey
    plan = Plan().keys(*range(1, n_keys + 1))
    for n in range(1, budget + 1):
        plan.describe(n, meta(n, spec="RSA_2048"))
    _services, found, _rows = run(plan, tick=lambda: ticks.append(clock.now) or None, wrap=_slow(clock, 1.0))
    assert max(b - a for a, b in zip(ticks, ticks[1:])) <= 60  # the lease is renewed throughout
    assert len(keys_of(found)) == budget
    left = sum(g["facts"].get("not_read_count", 1) for g in gaps_of(found))
    assert left == n_keys - budget and all(g["facts"]["status"] == "stopped" for g in gaps_of(found))
    assert "time budget" in gaps_of(found)[0]["facts"]["detail"]


def test_t_time_a_cancel_is_honoured_within_one_tick(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(aws_collect, "_clock", clock)
    plan = Plan().keys(*range(1, 101))
    for n in range(1, 41):
        plan.describe(n, meta(n, spec="RSA_2048"))
    calls = []

    def tick():
        calls.append(1)
        return "Cancelled by the user" if len(calls) > 40 else None

    _services, found, _rows = run(plan, tick=tick, wrap=_slow(clock, 1.0))
    assert len(keys_of(found)) == 40
    assert "Cancelled by the user" in gaps_of(found)[0]["facts"]["detail"]


# ============================================================================ T19 migration
def _dev_facts(m: dict, rotation_answer: bool | None) -> dict:
    """What dev c75aec146 stored for a key (``aws_collect.kms`` before CB-33): rotation asked only while Enabled."""
    spec = m.get("KeySpec")
    asked = m["KeyManager"] == "CUSTOMER" and spec == "SYMMETRIC_DEFAULT" and m["KeyState"] == "Enabled"
    return {"key_spec": spec, "key_usage": m.get("KeyUsage"), "key_manager": m["KeyManager"], "key_state": m["KeyState"],
            "origin": m["Origin"], "multi_region": m.get("MultiRegion"),
            "rotation_enabled": rotation_answer if asked else None, "signing_algorithms": None, "identity": m["Arn"]}


def test_t19_migration_is_verdict_neutral_except_disabled_keys_with_rotation_off():
    """The first PR-A run against rows stored by dev, under dev's classifier: nothing resolves; only Disabled AWS_KMS
    keys with rotation off open KMS_NO_ROTATION (a true finding dev hid; release note)."""
    estate = [  # (n, metadata, rotation answer)
        (1, meta(1), False), (2, meta(2), True), (3, meta(3, state="Disabled"), False),
        (4, meta(4, state="Disabled"), True), (5, meta(5, state="PendingDeletion"), None),
        (6, meta(6, origin="EXTERNAL"), False), (7, meta(7, origin="EXTERNAL", state="PendingImport"), None),
        (8, meta(8, origin="AWS_CLOUDHSM", CustomKeyStoreId="cks-a"), None), (9, meta(9, spec="RSA_2048"), None),
        (10, meta(10, manager="AWS"), True), (11, meta(11, state="Creating"), False)]
    plan = Plan().keys(*[n for n, _m, _r in estate])
    for n, m, answer in estate:
        plan.describe(n, m)
        asked = m["KeyManager"] == "CUSTOMER" and m["KeySpec"] == "SYMMETRIC_DEFAULT" and (
            (m["Origin"] == "AWS_KMS" and m["KeyState"] in ("Enabled", "Disabled", "Creating", "Updating"))
            or (m["Origin"] == "EXTERNAL" and m["KeyState"] == "Enabled"))
        if asked:
            plan.rotation(n, rotation(bool(answer)))
        if m["Origin"] == "EXTERNAL":
            plan.materials(n, [])
    plan.raw("describe_custom_key_stores", {"CustomKeyStores": []})
    _services, found, _rows = run(plan)
    dev_rows = [{"type": "kms_key", "target": LABEL, "location": m["Arn"], "name": m["Description"],
                 "algorithm": m["KeySpec"], "key_size": 256 if m["KeySpec"] == "SYMMETRIC_DEFAULT" else 2048,
                 "facts": _dev_facts(m, answer)} for _n, m, answer in estate]
    d = diff(dev_rows, found)
    assert d["resolved"] == [] and d["removed"] == [] and d["added"] == []
    assert sorted((x["location"], x["code"]) for x in d["opened"]) == [(arn(3), "KMS_NO_ROTATION"),
                                                                         (arn(11), "KMS_NO_ROTATION")]


# ============================================================================ logs
def test_t_log_aws_collected_names_the_gaps_by_service_and_code(monkeypatch, capsys):
    plan = (Plan().keys(1, 2, 3).describe(1, "ThrottlingException").describe(2, meta(2)).rotation(2, "AccessDenied")
            .describe(3, meta(3, spec="RSA_2048")))
    acct = _Acct(plan)
    real = aws_collect._region_services

    def region(_acct, region_name, label, emit, opts=None, tick=None):
        return real(acct, region_name, label, emit, opts, tick=tick)

    monkeypatch.setattr(aws_collect, "_region_services", region)
    monkeypatch.setattr(aws_collect, "_global_services", lambda *_a, **_k: [])

    class _Sts:
        def assume_role(self, **kw):
            if "ExternalId" not in kw:
                raise _err("AccessDenied", "AssumeRole")
            return {"Credentials": {"AccessKeyId": "a", "SecretAccessKey": "b", "SessionToken": "c"}}

    monkeypatch.setattr(aws_collect, "_boto", lambda **kw: (SimpleNamespace(client=lambda *a, **k: _Sts()), None))
    monkeypatch.setattr(aws_collect._Account, "assume", lambda self, region: None)
    found: list[dict] = []
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    result = aws_collect.collect_aws(1, {"role_arn": f"arn:aws:iam::{ACCOUNT}:role/R", "regions": [REGION]}, "ext",
                            found.append, lambda: None)
    line = next((ln for ln in out.getvalue().splitlines() if "aws collected" in ln), str(result))
    # every service this test did not record answers AccessDenied: their rows are counted too
    assert " gaps=" in line and "kms:AccessDenied:1," in line and "kms:ThrottlingException:1," in line, line
    acme = [a for a in found if a["location"].endswith("#acme")]
    assert acme and acme[0]["facts"]["status"] == "not_supported" and acme[0]["facts"]["by_choice"] is True


# ============================================================================ T16 the real retry handler
class _Raw:
    def __init__(self, body: bytes):
        self.body = body

    def stream(self, **_kw):
        yield self.body


def test_t16_a_throttled_describe_key_is_tried_six_times_then_becomes_a_row(monkeypatch):
    """FP-3 / F5: the collector's ``retries=5`` is 6 attempts (botocore counts retries after the first).  Real
    client, real retry handler (standard mode: adaptive adds a client-side rate limiter that cannot run on a fake
    clock); only the HTTP exchange is replaced."""
    from botocore.awsrequest import AWSResponse
    from botocore.config import Config

    monkeypatch.setattr("time.sleep", lambda _s: None)  # the retry back-off, not the behaviour
    client = _BS.create_client("kms", region_name=REGION, aws_access_key_id="x", aws_secret_access_key="y",
                               config=Config(retries={"max_attempts": 5, "mode": "standard"}))
    attempts: dict[str, int] = {}

    def send(request, **_kw):
        op = request.headers.get("X-Amz-Target", b"")
        op = (op.decode() if isinstance(op, bytes) else op).rsplit(".", 1)[-1]
        attempts[op] = attempts.get(op, 0) + 1
        if op == "ListKeys":
            body = {"Keys": [{"KeyId": kid(1), "KeyArn": arn(1)}, {"KeyId": kid(2), "KeyArn": arn(2)}],
                    "Truncated": False}
            return AWSResponse(request.url, 200, {}, _Raw(json.dumps(body).encode()))
        key = json.loads(request.body)["KeyId"]
        if key == kid(1):
            body = {"__type": "ThrottlingException", "message": "Rate exceeded"}
            return AWSResponse(request.url, 400, {"x-amzn-ErrorType": "ThrottlingException"},
                               _Raw(json.dumps(body).encode()))
        body = {"KeyMetadata": {**{k: v for k, v in meta(2, spec="RSA_2048").items() if k != "CreationDate"},
                                "CreationDate": 1735689600}}
        return AWSResponse(request.url, 200, {}, _Raw(json.dumps(body).encode()))

    client.meta.events.register("before-send.kms", send)
    acct = SimpleNamespace(account=ACCOUNT, client=lambda svc, _r: client if svc == "kms" else _Denied())
    found: list[dict] = []
    aws_collect._region_services(acct, REGION, LABEL, found.append, {})
    assert attempts["DescribeKey"] == 6 + 1  # key 1: six attempts; key 2: one
    assert list(keys_of(found)) == [arn(2)]
    row = next(g for g in gaps_of(found) if g["location"] == f"{arn(1)}#metadata")
    assert row["facts"]["status"] == "throttled" and row["facts"]["code"] == "ThrottlingException"
