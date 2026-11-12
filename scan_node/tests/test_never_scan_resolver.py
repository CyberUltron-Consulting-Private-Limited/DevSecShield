"""Never-scan host names are looked up off the job's control threads, and the gate fails closed while a listed name
has no known address (PR #32: security re-review 5871690938, code/QA re-check 5871764976).

* One resolver per node process looks the listed names up on a few background threads: never on the claim thread
  (``Agent.start_job``) or the watcher (``Agent._watch``), and never more than a fixed number of lookups at once,
  however long they hang.  Names are taken oldest attempt first, so names that hang cannot shadow the others.
* While a listed name has no known address (its lookup is pending, hangs, fails or answers "no such name"), the node
  cannot tell which address is that host: every target is held (``skipped_never_scan``) with a reason that names
  it.  A newly listed name is waited for, on the job's own thread, for at most ``NAME_LOOKUP_S``.
* The job result says which listed names held targets (summary and ``never_scan_unresolved``).
"""
from __future__ import annotations

import socket
import threading
import time
import types

import pytest

from zs_scan_node import agent as A
from zs_scan_node import netutil
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.collectors import network as N
from zs_scan_node import tlsprobe as T
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, expand_targets
from zs_scan_node.scrub import Scrubber

UNRESOLVED = "not resolved from the scan node"


@pytest.fixture()
def slow_dns(monkeypatch):
    """netutil.resolve answers from ``table``; a name in ``hanging`` does not answer until ``release`` is set (then it
    answers from ``table`` like any other).  Every lookup is recorded in ``looked_up``."""
    dns = types.SimpleNamespace(table={}, hanging=set(), release=threading.Event(), looked_up=[])

    def resolve(name, timeout=5.0):
        dns.looked_up.append(name)
        if name in dns.hanging:
            dns.release.wait(30)
        if name not in dns.table:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        return list(dns.table[name])

    monkeypatch.setattr(netutil, "resolve", resolve)
    yield dns
    dns.release.set()  # let every hanging lookup finish


def _ctx(never: NeverScan, kind: str = "collect", source_kind: str | None = None) -> JobContext:
    return JobContext(job_id=7, attempt=1, run_id=None, kind=kind, source_kind=source_kind, scrubber=Scrubber(),
                      never_scan=never, deadline=time.monotonic() + 600)


def _lookup_threads() -> int:
    return sum(t.name.startswith("zs-never-dns") for t in threading.enumerate())


# ----------------------------------------------------------------------------- fail closed (security re-review, major)
def test_a_listed_host_behind_hanging_lookups_is_never_scanned(slow_dns, monkeypatch):
    """The re-review's probe: 16 listed names in a dead zone hang and sort before prod-db.corp.internal.  The old
    passes never looked prod-db up, so a sweep scanned 10.1.2.3, the host the customer listed.  Now nothing whose
    owner is unknown is scanned; once the lookups answer, only the listed host's address stays out."""
    monkeypatch.setattr(netutil, "NAME_LOOKUP_S", 0.5)
    stale = [f"old-{i:02d}.dead.example" for i in range(16)]
    slow_dns.hanging.update(stale)
    slow_dns.table["prod-db.corp.internal"] = ["10.1.2.3"]
    never = NeverScan(stale + ["prod-db.corp.internal"])
    deadline = time.monotonic() + 1.5
    while True:  # several looks, past the hold: 10.1.2.3 is never offered for scanning
        reasons: dict[str, str] = {}
        targets, skipped = expand_targets(["10.1.2.0/29"], never, reasons=reasons)
        assert "10.1.2.3" not in [t.ip for t in targets]
        if time.monotonic() > deadline:
            break
        time.sleep(0.2)
    assert targets == [] and skipped == [f"10.1.2.{i}" for i in range(1, 7)]  # held, each with the reason
    assert UNRESOLVED in reasons["10.1.2.4"] and "old-00.dead.example" in reasons["10.1.2.4"]

    for name in stale:  # the dead zone comes back: every name answers
        slow_dns.table[name] = ["10.9.0.1"]
    slow_dns.release.set()
    end = time.monotonic() + 5
    while time.monotonic() < end and never.match_ip("10.1.2.4") is not None:
        time.sleep(0.05)
    targets, skipped = expand_targets(["10.1.2.0/29"], never)
    assert [t.ip for t in targets] == ["10.1.2.1", "10.1.2.2", "10.1.2.4", "10.1.2.5", "10.1.2.6"]
    assert skipped == ["10.1.2.3"] and never.match_ip("10.1.2.3") == "an address of prod-db.corp.internal"


def test_a_newly_listed_name_is_waited_for_not_skipped_past(slow_dns):
    """A fast lookup must not cost a false skip: the job waits (on its own thread) for the first answer."""
    slow_dns.table["db.corp.internal"] = ["10.0.0.5"]
    never = NeverScan(["db.corp.internal"])
    assert never.match_ip("10.0.0.6") is None
    assert never.match_ip("10.0.0.5") == "an address of db.corp.internal"
    slow_dns.table["new.corp.internal"] = ["10.0.0.9"]
    never.update(["db.corp.internal", "new.corp.internal"])  # listed while the job runs
    assert never.match_ip("10.0.0.8") is None and never.match_ip("10.0.0.9") == "an address of new.corp.internal"


def test_a_name_that_never_answers_is_held_at_most_name_lookup_s(slow_dns, monkeypatch):
    monkeypatch.setattr(netutil, "NAME_LOOKUP_S", 0.3)
    slow_dns.hanging.add("slow.internal")
    started = time.monotonic()
    never = NeverScan(["slow.internal"])
    assert time.monotonic() - started < 0.2  # setting the list never waits for DNS
    entry = never.match_ip("10.0.0.5")  # the job's own thread waits for the answer, bounded
    assert 0.2 < time.monotonic() - started < 1.5
    assert entry is not None and "slow.internal" in entry and never.unresolved == ["slow.internal"]
    with pytest.raises(netutil.Blocked, match="slow.internal has not resolved from the scan node"):
        netutil.checked_ip("10.0.0.5", never)
    started = time.monotonic()
    assert never.match_ip("10.0.0.6") is not None and time.monotonic() - started < 0.1  # no second wait


def test_a_listed_name_that_does_not_exist_holds_targets_until_it_resolves(slow_dns, monkeypatch):
    """NXDOMAIN from the node's resolver cannot be told apart from split-horizon DNS: fail closed, retry, recover."""
    monkeypatch.setattr(netutil, "NAME_RETRY_S", 0.3)
    never = NeverScan(["later.internal", "10.1.0.0/16"])
    assert never.match_ip("10.0.0.8") is not None and never.unresolved == ["later.internal"]
    assert never.match_ip("10.1.0.5") == "10.1.0.0/16"  # a listed network still names itself
    slow_dns.table["later.internal"] = ["10.0.0.8"]
    end = time.monotonic() + 5
    while time.monotonic() < end and never.unresolved:
        time.sleep(0.05)
    assert never.unresolved == [] and never.match_ip("10.0.0.8") == "an address of later.internal"
    assert never.match_ip("10.0.0.9") is None


# ----------------------------------------------------------------------------- claim and watcher threads (minor, major)
def test_starting_a_job_does_not_wait_for_dns(slow_dns, monkeypatch, tmp_path):
    """The claim thread runs start_job: job N+1 must not wait for job N's never-scan lookups."""
    monkeypatch.setattr(netutil, "NAME_LOOKUP_S", 3.0)
    slow_dns.hanging.add("printer.corp.internal")
    monkeypatch.setenv("ZS_API_URL", "https://zeroshield.example")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    ag = A.Agent()
    monkeypatch.setattr(A, "run_job", lambda ctx, job, scope, source: ("success", None, None))
    monkeypatch.setattr(ag, "_post_result", lambda running, *rest: ag._done(running))
    payload = {"job": {"id": 7, "kind": "collect", "lease_id": "lease-7"},
               "scope": {"never_scan": ["printer.corp.internal", "10.0.0.0/24"]},
               "source": {"kind": "linux_servers", "config": {}, "secrets": {}}}
    started = time.monotonic()
    ag.start_job(payload)
    assert time.monotonic() - started < 1.0
    ag.shutdown.set()


def test_a_never_scan_change_reaches_a_running_job_within_one_watch_tick(slow_dns, monkeypatch):
    """The watcher only applies changes: a refresh lookup that hangs no longer delays a never-scan change or a stop."""
    monkeypatch.setattr(netutil, "NAME_LOOKUP_S", 5.0)
    monkeypatch.setattr(netutil, "NAME_REFRESH_S", 0.01)  # the listed name is due for its refresh at once
    slow_dns.table["printer.corp.internal"] = ["10.5.0.7"]
    never = NeverScan(["printer.corp.internal", "10.0.0.0/24"])
    assert never.match_ip("10.5.0.7") == "an address of printer.corp.internal"
    slow_dns.hanging.add("printer.corp.internal")  # from now on its lookups hang
    time.sleep(0.1)
    ctx = _ctx(never, kind="discovery", source_kind="network_range")
    running = A.Running(7, "lease", ctx, True, ["printer.corp.internal", "10.0.0.0/24"])
    fake = types.SimpleNamespace(running={7: running}, shutdown=threading.Event(), stop_network=threading.Event(),
                                 team_never=None, _post_result=lambda *a, **k: None)
    threading.Thread(target=A.Agent._watch, args=(fake, running), daemon=True).start()
    time.sleep(0.5)  # the watcher's first pass is over (on e93c2cd it is inside the hanging refresh now)
    fake.team_never = ["10.9.9.9"]  # the heartbeat brings a team change and a stop
    fake.stop_network.set()
    changed = time.monotonic()
    while time.monotonic() - changed < 2.5 and not (never.match_ip("10.9.9.9") == "10.9.9.9"
                                                     and ctx.stop_network.is_set()):
        time.sleep(0.05)
    try:
        assert never.match_ip("10.9.9.9") == "10.9.9.9" and ctx.stop_network.is_set()
        assert never.match_ip("10.5.0.7") == "an address of printer.corp.internal"  # a hanging refresh keeps them
        assert never.match_ip("10.9.9.8") is None
    finally:
        fake.shutdown.set()


def test_a_running_job_keeps_every_address_a_listed_name_answered(slow_dns, monkeypatch):
    """Round-robin or moving DNS: the node-wide resolver keeps only the latest answer, so the watcher takes each
    answer into the job as it comes; an address the name had during the job stays blocked for the rest of it."""
    monkeypatch.setattr(netutil, "NAME_REFRESH_S", 0.3)
    slow_dns.table["rr.corp.internal"] = ["10.6.0.1"]
    never = NeverScan(["rr.corp.internal"])
    assert never.match_ip("10.6.0.1") == "an address of rr.corp.internal"
    ctx = _ctx(never)
    running = A.Running(8, "lease", ctx, False, ["rr.corp.internal"])
    fake = types.SimpleNamespace(running={8: running}, shutdown=threading.Event(), stop_network=threading.Event(),
                                 team_never=None, _post_result=lambda *a, **k: None)
    threading.Thread(target=A.Agent._watch, args=(fake, running), daemon=True).start()
    try:
        slow_dns.table["rr.corp.internal"] = ["10.6.0.2"]  # answered for a while (longer than one watch tick) ...
        time.sleep(2.8)
        slow_dns.table["rr.corp.internal"] = ["10.6.0.1"]  # ... then gone again before the job checked anything
        time.sleep(0.8)
        assert never.match_ip("10.6.0.2") == "an address of rr.corp.internal"
        assert never.match_ip("10.6.0.1") == "an address of rr.corp.internal"
    finally:
        fake.shutdown.set()


def test_hanging_lookups_never_pile_up_threads(slow_dns, monkeypatch):
    monkeypatch.setattr(netutil, "NAME_LOOKUP_S", 0.2)
    names = [f"h{i:02d}.corp" for i in range(40)]
    slow_dns.hanging.update(names)
    never = NeverScan(names[:20])
    for step in range(1, 5):  # four list changes while every lookup hangs (e93c2cd: 16 more threads each time)
        never.update(names[:20 + 5 * step])
    other = NeverScan(names[:30])  # a second job listing the same names
    time.sleep(0.3)
    assert _lookup_threads() <= 8
    assert other.unresolved and never.unresolved


def test_concurrent_jobs_share_one_lookup_per_name(slow_dns):
    slow_dns.table["db.corp.internal"] = ["10.0.0.5"]
    first, second = NeverScan(["db.corp.internal"]), NeverScan(["db.corp.internal", "10.2.0.0/16"])
    assert first.blocks_ip("10.0.0.5") and second.blocks_ip("10.0.0.5") and not second.blocks_ip("10.0.0.6")
    assert slow_dns.looked_up.count("db.corp.internal") == 1


# ----------------------------------------------------------------------------- the customer is told (minor)
def test_a_listed_name_that_does_not_resolve_is_named_in_the_job_result(slow_dns):
    ctx = _ctx(NeverScan(["gone.corp.internal", "10.0.5.0/24"]))
    assert L._targets(ctx, {"targets": ["10.0.0.5"]}) == []
    [outcome] = ctx.outcomes
    assert outcome.status == "skipped_never_scan" and "gone.corp.internal" in outcome.error
    result = ctx.result()
    assert result["never_scan_unresolved"] == ["gone.corp.internal"]
    assert "gone.corp.internal" in result["summary"] and "did not resolve from the scan node" in result["summary"]


def test_a_connection_test_says_why_every_address_was_held(slow_dns, monkeypatch):
    def tcp(ip, port, never, timeout):
        raise T.ProbeError("refused", "refused")

    monkeypatch.setattr(N, "_tcp", tcp)
    ctx = _ctx(NeverScan(["gone.corp.internal"]), kind="test_connection", source_kind="network_range")
    N.test_range(ctx, {"ranges": [{"cidr": "10.0.0.0/30", "mode": "full"}], "ports": [{"port": 443, "protocol": "tls"}]})
    assert [s["status"] for s in ctx.samples] == ["skipped_never_scan"]
    assert "gone.corp.internal" in ctx.samples[0]["note"] and UNRESOLVED in ctx.samples[0]["note"]
    assert "gone.corp.internal" in ctx.result()["summary"]


# ----------------------------------------------------------------------------- round 2 (re-review 5873185024)
@pytest.mark.parametrize("answer", [["0.0.0.0"], ["0.1.2.3"], ["::"], ["::ffff:0.0.0.0"], ["64:ff9b::"],
                                    ["0.0.0.0", "::"], ["224.0.0.1"], ["255.255.255.255"], ["ff02::1"]])
def test_a_listed_name_answering_only_a_sinkhole_address_holds_every_target(slow_dns, answer):
    """A DNS sinkhole (or RPZ local data) answering 0.0.0.0 or :: is not an address of the host: the node still has
    no address for the listed name, so the real host may be any target and every target is held, with the reason."""
    slow_dns.table["prod-db.corp.internal"] = answer
    never = NeverScan(["prod-db.corp.internal"])
    reasons: dict[str, str] = {}
    targets, skipped = expand_targets(["10.1.2.0/29"], never, reasons=reasons)
    assert targets == [] and "10.1.2.3" in skipped
    assert never.unresolved == ["prod-db.corp.internal"]
    assert f"answers only {answer[0]}" in reasons["10.1.2.4"] and "a DNS sinkhole answer" in reasons["10.1.2.4"]
    assert UNRESOLVED in reasons["10.1.2.4"]


def test_a_mixed_answer_keeps_its_real_addresses(slow_dns):
    slow_dns.table["prod-db.corp.internal"] = ["0.0.0.0", "10.1.2.3", "::"]
    never = NeverScan(["prod-db.corp.internal"])
    targets, skipped = expand_targets(["10.1.2.0/29"], never)
    assert skipped == ["10.1.2.3"] and [t.ip for t in targets] == ["10.1.2.1", "10.1.2.2", "10.1.2.4", "10.1.2.5",
                                                                   "10.1.2.6"]
    assert never.match_ip("10.1.2.3") == "an address of prod-db.corp.internal" and never.unresolved == []


def test_a_sinkhole_answer_on_refresh_keeps_the_addresses_learned_before(slow_dns, monkeypatch):
    monkeypatch.setattr(netutil, "NAME_REFRESH_S", 0.1)
    slow_dns.table["prod-db.corp.internal"] = ["10.1.2.3"]
    never = NeverScan(["prod-db.corp.internal"])
    assert never.match_ip("10.1.2.3") == "an address of prod-db.corp.internal"
    slow_dns.table["prod-db.corp.internal"] = ["0.0.0.0"]  # the scan VLAN's resolver starts blackholing the zone
    time.sleep(0.5)
    fresh = NeverScan(["prod-db.corp.internal"])  # a job starting now looks the name up again
    for job in (never, fresh):
        assert job.match_ip("10.1.2.3") == "an address of prod-db.corp.internal"
        assert job.match_ip("10.1.2.4") is None and job.unresolved == []


def test_a_new_job_looks_listed_names_up_again_before_its_first_target(slow_dns, monkeypatch):
    """Another running job already lists the name: the new job still gets a lookup made after it started (not an
    answer up to NAME_REFRESH_S old) before it checks its first target."""
    monkeypatch.setattr(netutil, "FRESH_S", 0.05, raising=False)  # jobs starting this close share one lookup
    slow_dns.table["prod-db.corp.internal"] = ["10.1.2.3"]
    job_a = NeverScan(["prod-db.corp.internal"])
    assert job_a.match_ip("10.1.2.3") == "an address of prod-db.corp.internal"
    time.sleep(0.1)
    slow_dns.table["prod-db.corp.internal"] = ["10.1.2.9"]  # re-pointed while job A runs
    time.sleep(0.2)
    job_b = NeverScan(["prod-db.corp.internal", "10.5.0.0/16"])
    targets, _skipped = expand_targets(["10.1.2.8/29"], job_b)
    assert "10.1.2.9" not in [t.ip for t in targets]
    assert job_b.match_ip("10.1.2.9") == "an address of prod-db.corp.internal"
    assert slow_dns.looked_up.count("prod-db.corp.internal") == 2


def test_a_closed_job_whose_list_changes_does_not_drop_another_jobs_names(slow_dns, monkeypatch):
    """The watcher can apply a team change just after the job ended (_done closed its list): that must not release
    the job's names a second time and take them from another job, or look up names for a job that has ended."""
    monkeypatch.setattr(netutil, "NAME_REFRESH_S", 0.2)
    slow_dns.table.update({"shared.corp": ["10.1.2.3"], "other.corp": ["10.1.2.7"]})
    job_a, job_b = NeverScan(["shared.corp"]), NeverScan(["shared.corp"])
    assert job_a.match_ip("10.1.2.3") == job_b.match_ip("10.1.2.3") == "an address of shared.corp"
    job_b.close()  # _done
    job_b.update(["other.corp"])  # the watcher's update, a moment too late
    slow_dns.table["shared.corp"] = ["10.1.2.9"]  # re-pointed: job A must still learn it at the next refresh
    end = time.monotonic() + 3
    while time.monotonic() < end and job_a.match_ip("10.1.2.9") is None:
        job_a.sync()
        time.sleep(0.05)
    assert job_a.match_ip("10.1.2.9") == "an address of shared.corp"
    assert "other.corp" not in slow_dns.looked_up  # nothing is looked up for the ended job
