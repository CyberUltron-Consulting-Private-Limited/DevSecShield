"""CB-32 PR-B: the per-process key index of the estate store is bounded in memory and never built on a user's request.

* Rows that can never correlate (``estate._linkless``: ``asset_keys._analyse`` answers ``_NOTHING``) are keyed per
  source and kept nowhere; the rule is pinned to ``_analyse`` over many row shapes.
* A large run recorded inside an HTTP request by a process with no warm index for the team is deferred to the
  scheduler (store marked stale), whose ``repair_due`` writes it with hooks; the store ends equal. A warm index or a
  small run is written in the request. A repair never clears a write missed while it ran.
* A team over the memory budget is keyed in full every run and keeps nothing; teams are evicted oldest first.
"""
from __future__ import annotations

import contextvars
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.build_info import _request_id  # noqa: E402
from backend.utilities.cbom_sources import estate as E  # noqa: E402
from test_cbom_cb20_estate import NOT_AFTER, SERIAL, SHA256, World, _sqlite, cert, endpoint  # noqa: E402


@pytest.fixture(autouse=True)
def _clean():
    E._INDEXES.clear()
    yield
    E._INDEXES.clear()


def _in_request(fn, *args, **kwargs):
    ctx = contextvars.copy_context()
    ctx.run(_request_id.set, "req-cb32")
    return ctx.run(fn, *args, **kwargs)


def _rows(n: int) -> list:
    out = []
    for i in range(n):
        host = f"10.0.{i // 250}.{i % 250}"
        b = i % 5
        if b < 2:
            r = SimpleNamespace(asset_type="certificate", cdx_type="certificate", target=host,
                                location=f"{host}:443#chain[0]",
                                facts={"serial": f"9f00000000000000000{i:05x}", "not_after": NOT_AFTER,
                                       "subject": f"CN=h{i % 7}", "issuer": "CN=CA,O=X",
                                       **({"fingerprint_sha256": SHA256} if i % 11 == 0 else {})})
        elif b < 3:
            r = SimpleNamespace(asset_type="tls_endpoint", cdx_type="x", target=host, location=f"{host}:443",
                                facts={"port": 443})
        elif b < 4:
            r = SimpleNamespace(asset_type="kms_key", cdx_type="x", target="aws", location=f"kms/{i}",
                                facts={"identity": f"arn:aws:kms:eu-west-1:1:key/{i % 9}"})
        else:
            r = SimpleNamespace(asset_type="crypto_library", cdx_type="x", target=host, location=f"/usr/lib/l{i}",
                                facts={"name": "openssl"})
        r.asset_key, r.name, r.algorithm = hashlib.sha256(str(i).encode()).hexdigest(), None, None
        out.append((r, f"src{i % 3}"))
    return out


def test_linkless_is_exactly_what_asset_keys_cannot_correlate():
    kinds = sorted(E.AK.CERT_TYPES | E.AK.ENDPOINT_TYPES | {
        "crypto_library", "process_library", "private_key", "public_key", "ssh_host_key", "kms_key", "secret",
        "database_config", "ssh_server_config", "key_vault", "cloud_kms_key", "coverage", "algorithm"})
    identities = [None, "", "plain-name", "arn:aws:kms:eu-west-1:1:key/a", "/subscriptions/s/resourceGroups/g/x",
                  "https://v.vault.azure.net/keys/k/1", "projects/p/locations/l/keyRings/r/cryptoKeys/k",
                  "//cloudkms.googleapis.com/projects/p", "  ARN:aws:iam::1:role/x"]
    locations = ["", "/etc/ssl/a.pem", "10.0.0.1:443", "arn:aws:acm:eu-west-1:1:certificate/x",
                 "https://v.vault.azure.net/secrets/s", "projects/p/global/x", "host:22"]
    checked = 0
    for kind in kinds:
        for cdx in ("cryptographic-asset", "certificate"):
            for ident in identities:
                for loc in locations:
                    row = SimpleNamespace(asset_type=kind, cdx_type=cdx, location=loc, target="10.0.0.1",
                                          facts={"identity": ident} if ident is not None else {}, asset_key="k" * 64)
                    analysed = E.AK._analyse(E._observation(row, "src"))
                    assert E._linkless(row) == (analysed is E.AK._NOTHING), (kind, cdx, ident, loc)
                    checked += 1
    assert checked > 1000


def test_a_team_over_the_budget_is_keyed_in_full_and_keeps_nothing(monkeypatch):
    rows = _rows(300)
    reference = E._keys_for_run(9, rows)
    E._INDEXES.clear()
    monkeypatch.setattr(E, "INDEX_BUDGET_MB", 0)
    for _ in range(2):
        out = E._keys_for_run(1, rows)
        assert out.mode == "full" and (out.keys, out.okeys) == (reference.keys, reference.okeys)
    assert E.index_stats()["observations"] == 0


def test_teams_are_evicted_oldest_first_within_the_budget(monkeypatch):
    rows = _rows(200)
    linked = sum(1 for r, _ref in rows if not E._linkless(r))
    monkeypatch.setattr(E, "index_capacity", lambda: int(linked * 2.5))
    for team in (1, 2, 3):
        E._keys_for_run(team, rows)
    assert list(E._INDEXES) == [2, 3] and E.index_stats()["observations"] == 2 * linked
    E._keys_for_run(2, rows)  # used again: now the newest
    E._keys_for_run(4, rows)
    assert list(E._INDEXES) == [2, 4]


def test_libraries_and_keys_are_never_indexed():
    rows = _rows(100)
    E._keys_for_run(1, rows)
    linkless = [r for r, _ref in rows if E._linkless(r)]
    assert linkless and E.index_stats()["observations"] == len(rows) - len(linkless)


def _three_runs(w, in_request: bool, repair=None):
    p, lin = w.source("network", "prober"), w.source("linux_servers", "linux")
    facts = {"serial": SERIAL, "not_after": NOT_AFTER, "fingerprint_sha256": SHA256}
    for r in range(3):
        run = w.run({p: {"rows": [cert("10.0.0.5", "10.0.0.5:443#chain[0]", **facts), endpoint("10.0.0.5"),
                                  endpoint(f"10.0.1.{r}")]},
                     lin: {"rows": [cert("app", "/etc/ssl/pay.pem", **facts),
                                    {"type": "crypto_library", "target": "app", "location": f"/usr/lib/l{r}",
                                     "facts": {"name": "openssl"}}]}})
        if in_request:
            _in_request(w.finalise, run)
            if repair:
                repair(w)
        else:
            w.finalise(run)


def _stale(w):
    from sqlmodel import Session, select

    from backend.new_models import CbomEstateTeam

    with Session(w.engine) as s:
        row = s.exec(select(CbomEstateTeam).where(CbomEstateTeam.team_id == 1)).first()
        return None if row is None else (row.stale, row.stale_reason, row.stale_marks)


def test_a_large_cold_run_in_a_request_is_deferred_to_the_scheduler_which_writes_it(tmp_path, monkeypatch):
    from test_cbom_cb20_estate import NOW

    monkeypatch.setattr(E, "DEFER_MIN_ROWS", 1)  # every run counts as large here
    reference = World(_sqlite(tmp_path / "sched.db"))
    _three_runs(reference, in_request=False)
    E._INDEXES.clear()
    hooked: list[int] = []
    E.register_hook(hook := (lambda _s, write: hooked.append(write.run_id)))
    seen: list = []

    def repair(w):
        stale = _stale(w)
        seen.append(stale)
        assert stale[0] is True and stale[1].endswith(E.DEFERRED)
        E._INDEXES.clear()  # a request's process (the API) is still cold for the next run
        assert E.repair_due(w.engine, NOW)["teams"] == 1
        E._INDEXES.clear()

    try:
        deferred = World(_sqlite(tmp_path / "req.db"))
        _three_runs(deferred, in_request=True, repair=repair)
    finally:
        E.unregister_hook(hook)
    assert len(seen) == 3 and hooked == [1, 2, 3]  # each run written once by the repair, hooks included
    assert deferred.dump() == reference.dump() and _stale(deferred)[0] is False


def test_a_warm_index_or_a_small_run_is_written_in_the_request(tmp_path, monkeypatch):
    w = World(_sqlite(tmp_path / "w.db"))
    _three_runs(w, in_request=True)  # 5 rows a run: below DEFER_MIN_ROWS
    assert _stale(w) is None and len(w.assets()) > 0
    monkeypatch.setattr(E, "DEFER_MIN_ROWS", 1)
    assert E._warm(1)  # the runs above built team 1's index in this process
    run = w.run({w.source("network", "edge"): {"rows": [endpoint("52.95.9.9")]}})
    _in_request(w.finalise, run)
    assert _stale(w) is None and any(a.label and "52.95.9.9" in a.label for a in w.assets().values())


def test_a_repair_never_clears_a_write_missed_while_it_ran(tmp_path):
    from sqlmodel import Session

    from test_cbom_cb20_estate import NOW

    w = World(_sqlite(tmp_path / "w.db"))
    net = w.source("network", "lab")
    run = w.run({net: {"rows": [endpoint("10.0.0.1")]}})
    w.finalise(run)
    with Session(w.engine) as s:
        E.mark_stale(s, 1, run, "first", NOW)
        s.commit()
    real = E.record_run

    def record_and_miss_another(session, r, now, **kw):
        with Session(w.engine) as other:  # a request defers a later run while the repair runs
            E.mark_stale(other, 1, r.id, "second", now)
            other.commit()
        return real(session, r, now, **kw)

    E.record_run = record_and_miss_another
    try:
        E.repair_due(w.engine, NOW)
    finally:
        E.record_run = real
    assert _stale(w)[0] is True and _stale(w)[2] == 2  # still stale: the next tick replays it
    E.repair_due(w.engine, NOW)
    assert _stale(w)[0] is False
