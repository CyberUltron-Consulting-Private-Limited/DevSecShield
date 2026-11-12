"""F1.3 transports on the scan node: AWX/AAP and salt-api adapters against API fakes (httpx.MockTransport), the
fleet glue (never-scan before dispatch, relabelling, outcomes) and the generated wrappers."""
from __future__ import annotations

import copy
import json
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml

from zs_scan_node.collectors import fleet, run_job
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber
from zs_scan_node.transports import awx as AWX
from zs_scan_node.transports import control, wrappers, zsdoc
from zs_scan_node.transports import salt as SALT
from zs_scan_node.transports.base import CollectOptions, CollectTarget, TransportCredential, TransportError

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "zs-collect" / "lab-target.json").read_text())
NONCE = "zs-7-1-0123456789abcdef"
VERSION = FIXTURE["collector_version"]


def doc_for(label: str, nonce: str = NONCE, **changes) -> dict:
    doc = copy.deepcopy(FIXTURE)
    own = doc["target_label"]
    doc.update(run_nonce=nonce, target_label=label)
    for a in doc["assets"]:
        a["target"] = label
        if a["type"] == "coverage":
            a["location"] = label + a["location"][len(own):]
    doc["result"]["targets"][0]["target"] = label
    doc.update(changes)
    return doc


def options(nonce: str = NONCE, deadline_s: float = 60, stop=None) -> CollectOptions:
    return CollectOptions(tier=2, run_nonce=nonce, deadline=time.monotonic() + deadline_s, timeout_per_target_s=60,
                          max_concurrency="", zs_collect_sha256={"amd64": "a" * 64}, should_stop=stop or (lambda: None),
                          collector_version=VERSION)


def targets(n: int, prefix: str = "10.0.0.") -> list[CollectTarget]:
    return [CollectTarget(label=f"{prefix}{i + 1}", handle=f"host-{i + 1}") for i in range(n)]


@pytest.fixture
def mock_http(monkeypatch):
    """Route control.client() to a MockTransport handler; returns a setter."""
    holder = {}

    def fake_client(config, never, headers=None, timeout=30.0, what="control plane"):
        if not str(config.get("base_url", "")).startswith("https://"):
            raise TransportError("error", f"the {what} URL must be https://")
        return httpx.Client(base_url=config["base_url"], headers=dict(headers or {}),
                            transport=httpx.MockTransport(holder["handler"]))

    monkeypatch.setattr(control, "client", fake_client)
    return lambda handler: holder.__setitem__("handler", handler)


# ----------------------------------------------------------------------------- an AWX fake
class FakeAwx:
    """The AWX REST endpoints the adapter uses.  ``hosts`` maps an AWX host name to what the playbook produced."""

    def __init__(self, hosts: dict[str, dict], ask=(True, True), ignored=None, token="tok", page_size=3,
                 finish_after=1):
        self.hosts, self.ask, self.ignored, self.token = hosts, ask, ignored or {}, token
        self.page_size, self.finish_after = page_size, finish_after
        self.launches: list[dict] = []
        self.cancelled: list[int] = []
        self.polls = 0

    def events_for(self, job: dict) -> list[dict]:
        out, counter = [], 0
        if job["id"] in self.cancelled:  # stopped before any host finished
            return out
        limit = job["limit"].split(",")
        for host in limit:
            spec = self.hosts.get(host)
            if spec is None:
                continue
            counter += 1
            if spec.get("unreachable"):
                out.append({"counter": counter, "event": "runner_on_unreachable", "host_name": host,
                            "event_data": {"res": {"msg": "Failed to connect to the host via ssh", "unreachable": True}}})
                continue
            out.append({"counter": counter, "event": "runner_on_ok", "host_name": host,
                        "event_data": {"res": {"msg": f"ZSRC {spec.get('rc', 0)} {spec.get('stderr', '')}"}}})
            for i, line in enumerate(spec.get("lines") or []):
                counter += 1
                out.append({"counter": counter, "event": "runner_item_on_ok", "host_name": host,
                            "event_data": {"res": {"msg": line, "item": i, "ansible_loop_var": "item"}}})
        return out

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") != f"Bearer {self.token}":
            return httpx.Response(401, json={"detail": "Authentication credentials were not provided."})
        path, q = request.url.path, parse_qs(request.url.query.decode())
        if path == "/api/v2/me/":
            return httpx.Response(200, json={"results": [{"username": "zs"}]})
        m = re.fullmatch(r"/api/v2/job_templates/(\d+)/launch/", path)
        if m and request.method == "GET":
            if m.group(1) != "42":
                return httpx.Response(404, json={"detail": "Not found."})
            return httpx.Response(200, json={"ask_limit_on_launch": self.ask[0], "ask_variables_on_launch": self.ask[1]})
        if m and request.method == "POST":
            body = json.loads(request.content)
            job_id = 100 + len(self.launches)
            self.launches.append({"id": job_id, **body})
            return httpx.Response(201, json={"job": job_id, "id": job_id, "ignored_fields": self.ignored})
        m = re.fullmatch(r"/api/v2/jobs/(\d+)/", path)
        if m:
            self.polls += 1
            done = self.polls >= self.finish_after
            return httpx.Response(200, json={"id": int(m.group(1)), "status": "successful" if done else "running"})
        m = re.fullmatch(r"/api/v2/jobs/(\d+)/cancel/", path)
        if m:
            self.cancelled.append(int(m.group(1)))
            return httpx.Response(202)
        m = re.fullmatch(r"/api/v2/jobs/(\d+)/job_events/", path)
        if m:
            job = next(j for j in self.launches if j["id"] == int(m.group(1)))
            events = self.events_for(job)
            page = int((q.get("page") or ["1"])[0])
            size = self.page_size
            chunk = events[(page - 1) * size: page * size]
            nxt = f"/api/v2/jobs/{job['id']}/job_events/?page={page + 1}&page_size={size}" \
                if page * size < len(events) else None
            return httpx.Response(200, json={"count": len(events), "next": nxt, "results": chunk})
        return httpx.Response(404, json={"detail": "Not found."})


AWX_CRED = TransportCredential("awx_token", {"base_url": "https://awx.example", "job_template_id": 42,
                                             "max_hosts_per_launch": 200}, {"token": "tok"})


def awx() -> AWX.AwxTransport:
    return AWX.AwxTransport(NeverScan([]), poll_s=0)


def chunked(label: str, nonce: str = NONCE, size: int = 2048) -> list[str]:
    return zsdoc.encode_chunks(doc_for(label, nonce), nonce, chunk_bytes=size)


def test_awx_collects_through_one_launch_and_reassembles_chunked_events(mock_http):
    ts = targets(3)
    fake = FakeAwx({"host-1": {"lines": chunked("10.0.0.1")}, "host-2": {"lines": chunked("10.0.0.2")},
                    "host-3": {"unreachable": True}}, finish_after=2)
    mock_http(fake)
    out = list(awx().run_collect(ts, AWX_CRED, options()))
    assert [(r.target.label, r.status) for r in out] == [("10.0.0.1", "ok"), ("10.0.0.2", "ok"),
                                                         ("10.0.0.3", "unreachable")]
    assert out[0].document["run_nonce"] == NONCE and len(out[0].document["assets"]) == len(FIXTURE["assets"])
    assert len(fake.launches) == 1
    assert fake.launches[0]["limit"] == "host-1,host-2,host-3"
    # the source's per-host timeout (options: 60 s) reaches zs-collect through the playbook's --timeout-s
    assert fake.launches[0]["extra_vars"] == {"zs_nonce": NONCE, "zs_tier": 2, "zs_timeout_s": 60}
    assert len(chunked("10.0.0.1")) > 1  # really several events per host, across event pages (page_size=3)


def test_awx_refuses_a_template_that_does_not_prompt_for_limit_before_launching(mock_http):
    fake = FakeAwx({}, ask=(False, True))
    mock_http(fake)
    with pytest.raises(TransportError) as e:
        list(awx().run_collect(targets(2), AWX_CRED, options()))
    assert e.value.status == "refused" and "Limit" in e.value.detail and "whole inventory" in e.value.detail
    assert fake.launches == []


def test_awx_cancels_a_job_whose_limit_was_ignored(mock_http):
    fake = FakeAwx({"host-1": {"lines": chunked("10.0.0.1")}}, ignored={"limit": "host-1"})
    mock_http(fake)
    with pytest.raises(TransportError) as e:
        list(awx().run_collect(targets(1), AWX_CRED, options()))
    assert e.value.status == "refused" and fake.cancelled == [100]


@pytest.mark.parametrize("token,status", [("wrong", "auth_failed")])
def test_awx_login_refused_is_auth_failed(mock_http, token, status):
    mock_http(FakeAwx({}, token="tok"))
    cred = TransportCredential("awx_token", AWX_CRED.config, {"token": token})
    with pytest.raises(TransportError) as e:
        list(awx().run_collect(targets(1), cred, options()))
    assert e.value.status == status


def test_awx_tampered_foreign_or_mismatched_documents_are_refused(mock_http):
    good = chunked("10.0.0.1")
    tampered = good[:-1] + [good[-1][:-4] + ("AAAA" if not good[-1].endswith("AAAA") else "BBBB")]
    foreign = chunked("10.0.0.2", nonce="zs-9-1-ffffffffffffffff")
    old = zsdoc.encode_chunks(doc_for("10.0.0.3", collector_version="0.9.0"), NONCE, chunk_bytes=2048)
    fake = FakeAwx({"host-1": {"lines": tampered}, "host-2": {"lines": foreign}, "host-3": {"lines": old},
                    "host-4": {"lines": good[:-1]}})
    mock_http(fake)
    out = {r.target.handle: r for r in awx().run_collect(targets(4), AWX_CRED, options())}
    assert all(r.status == "error" and r.document is None for r in out.values())
    assert "checksum" in out["host-1"].error or "base64" in out["host-1"].error
    assert "another run" in out["host-2"].error
    assert "version" in out["host-3"].error
    assert "chunks" in out["host-4"].error


def test_awx_launcher_exit_codes_map_to_statuses(mock_http):
    fake = FakeAwx({"host-1": {"rc": 4, "stderr": "zs-collect: checksum mismatch"},
                    "host-2": {"rc": 3, "stderr": "zs-collect: missing"}, "host-3": {"rc": 0}})
    mock_http(fake)
    out = {r.target.handle: r for r in awx().run_collect(targets(4), AWX_CRED, options())}
    assert out["host-1"].status == "refused" and "integrity" in out["host-1"].error
    assert out["host-2"].status == "error" and "not installed" in out["host-2"].error
    assert out["host-3"].status == "error" and "no zs-collect output" in out["host-3"].error
    assert out["host-4"].status == "error" and "no event for this host" in out["host-4"].error


def test_awx_batches_launches_at_max_hosts_per_launch(mock_http):
    fake = FakeAwx({f"host-{i}": {"lines": chunked(f"10.0.{i // 250}.{i % 250}")} for i in range(1, 251)},
                   page_size=200)
    mock_http(fake)
    ts = [CollectTarget(label=f"10.0.{i // 250}.{i % 250}", handle=f"host-{i}") for i in range(1, 251)]
    out = list(awx().run_collect(ts, AWX_CRED, options()))
    assert [len(j["limit"].split(",")) for j in fake.launches] == [200, 50]
    assert sum(r.status == "ok" for r in out) == 250


def test_awx_never_puts_an_odd_host_name_in_the_limit(mock_http):
    fake = FakeAwx({"host-1": {"lines": chunked("10.0.0.1")}})
    mock_http(fake)
    ts = [CollectTarget("10.0.0.1", "host-1"), CollectTarget("10.0.0.9", "web:&all")]
    out = {r.target.label: r for r in awx().run_collect(ts, AWX_CRED, options())}
    assert out["10.0.0.9"].status == "error" and fake.launches[0]["limit"] == "host-1"


def test_awx_job_is_cancelled_when_the_run_is_stopped(mock_http):
    fake = FakeAwx({"host-1": {"lines": chunked("10.0.0.1")}}, finish_after=10**6)
    mock_http(fake)
    stop = {"v": None}
    t = AWX.AwxTransport(NeverScan([]), poll_s=0.01)
    timer = threading.Timer(0.1, lambda: stop.__setitem__("v", "skipped_cancelled"))
    timer.start()
    out = list(t.run_collect(targets(1), AWX_CRED, options(stop=lambda: stop["v"])))
    assert fake.cancelled == [100]
    assert out[0].status == "skipped_cancelled" and "cancelled" in out[0].error


def test_control_plane_must_be_https_and_is_never_scan_checked():
    with pytest.raises(TransportError, match="https"):
        control.client({"base_url": "http://awx.example"}, NeverScan([]))
    with pytest.raises(TransportError) as e:
        control.client({"base_url": "https://10.9.9.9"}, NeverScan(["10.9.9.0/24"]), what="AWX")
    assert e.value.status == "skipped_never_scan"


class FakeClock:
    """time.monotonic / time.sleep for a transport module: sleeping advances the clock instead of waiting."""

    def __init__(self):
        self.t = time.monotonic()

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.001)


# ----------------------------------------------------------------------------- a salt-api fake
class FakeSalt:
    def __init__(self, minions: dict[str, object], *, client="local_async", user="zs", password="pw", slow=()):
        self.minions, self.client, self.user, self.password = minions, client, user, password
        self.slow = set(slow)
        self.calls: list[dict] = []
        self.polls = 0           # jobs.exit_success status polls
        self.full_lookups = 0    # GET /jobs/<jid>: every minion's whole return
        self.ready_after = 1     # status polls before the non-slow minions show as returned

    def ret_for(self, low: dict, mid: str):
        spec = self.minions[mid]
        if isinstance(spec, (str, dict)) and not (isinstance(spec, dict) and "stdout" in spec):
            return spec
        script = {"pid": 4242, "retcode": spec.get("retcode", 0), "stdout": spec["stdout"], "stderr": spec.get("stderr", "")}
        if low["fun"] == "state.apply":
            return {"cmd_|-zs_collect_|-salt://zeroshield/zs-collect-run.sh_|-script": {
                "result": True, "comment": "Command ran", "changes": script}}
        return script

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/login":
            body = json.loads(request.content)
            if (body.get("username"), body.get("password")) != (self.user, self.password):
                return httpx.Response(401, text="Could not authenticate using provided credentials")
            return httpx.Response(200, json={"return": [{"token": "t0k", "eauth": body.get("eauth")}]})
        if request.headers.get("x-auth-token") != "t0k":
            return httpx.Response(401)
        if path == "/" and request.method == "POST" and json.loads(request.content)[0].get("client") == "runner":
            low = json.loads(request.content)[0]
            assert low["fun"] == "jobs.exit_success" and low["jid"] == "20261112"
            self.polls += 1
            job = self.calls[-1]
            ready = self.polls >= self.ready_after
            return httpx.Response(200, json={"return": [{m: ready and m not in self.slow for m in job["tgt"]
                                                         if m in self.minions}]})
        if path == "/" and request.method == "POST":
            low = json.loads(request.content)[0]
            self.calls.append(low)
            tgt = [m for m in low["tgt"] if m in self.minions]
            if low["client"] == "local_async":
                return httpx.Response(200, json={"return": [{"jid": "20261112", "minions": tgt}]})
            if low["client"] == "ssh":
                out = {}
                for m in tgt:
                    r = self.ret_for(low, m)
                    out[m] = r if isinstance(r, dict) and "retcode" in r and "stdout" not in r and "return" not in r \
                        else {"return": r, "retcode": 0, "id": m, "fun": low["fun"]}
                return httpx.Response(200, json={"return": [out]})
            return httpx.Response(200, json={"return": [{m: {"ret": self.ret_for(low, m), "retcode": 0} for m in tgt}]})
        if path.startswith("/jobs/"):
            self.full_lookups += 1
            low = self.calls[-1]
            ready = [m for m in low["tgt"] if m in self.minions and (m not in self.slow)]
            return httpx.Response(200, json={"return": [{m: self.ret_for(low, m) for m in ready}],
                                             "info": [{"Minions": low["tgt"]}]})
        return httpx.Response(404)


def salt_cred(client="local_async", mode="cmd", timeout=1, **secrets) -> TransportCredential:
    return TransportCredential("salt_eauth", {"base_url": "https://salt.example:8000", "eauth": "pam",
                                              "client": client, "mode": mode, "batch_size": 50, "timeout_s": timeout},
                               {"username": "zs", "password": "pw", **secrets})


def salt() -> SALT.SaltTransport:
    return SALT.SaltTransport(NeverScan([]), poll_s=0, grace_s=0.2)


def doc_line(label: str, nonce: str = NONCE) -> str:
    return json.dumps(doc_for(label, nonce))


@pytest.mark.parametrize("mode", ["cmd", "state"])
def test_salt_local_async_collects_and_a_silent_minion_is_unreachable(mock_http, monkeypatch, mode):
    ts = targets(3)
    fake = FakeSalt({"host-1": {"stdout": doc_line("10.0.0.1")}, "host-2": {"stdout": doc_line("10.0.0.2")},
                     "host-3": {"stdout": doc_line("10.0.0.3")}}, slow={"host-3"})
    mock_http(fake)
    clock = FakeClock()
    monkeypatch.setattr(SALT, "time", clock)
    started = clock.t
    out = list(SALT.SaltTransport(NeverScan([]), poll_s=3.0, grace_s=30).run_collect(ts, salt_cred(mode=mode),
                                                                                     options(deadline_s=3600)))
    # the silent minion is waited for as long as zs-collect may run there (its 60 s + 60 s of slack, + grace)
    assert 60 + 60 <= clock.t - started <= 60 + 60 + 30 + 3
    assert [(r.target.label, r.status) for r in out] == [("10.0.0.1", "ok"), ("10.0.0.2", "ok"),
                                                         ("10.0.0.3", "unreachable")]
    low = fake.calls[0]
    assert low["tgt"] == ["host-1", "host-2", "host-3"] and low["tgt_type"] == "list"
    if mode == "cmd":
        assert low["fun"] == "cmd.script" and low["arg"] == ["salt://zeroshield/zs-collect-run.sh",
                                                              f"--nonce {NONCE} --tier 2 --timeout-s 60 --output json"]
    else:
        assert low["fun"] == "state.apply" and low["kwarg"]["pillar"] == {"zs_nonce": NONCE, "zs_tier": 2,
                                                                          "zs_timeout_s": 60}
    assert fake.full_lookups == 1  # the slow minion was waited for with status polls, the returns fetched once


def test_salt_ssh_client_shapes(mock_http):
    fake = FakeSalt({"host-1": {"stdout": doc_line("10.0.0.1")},
                     "host-2": {"retcode": 255, "stderr": "ssh: connect to host 10.0.0.2 port 22: No route to host"},
                     "host-3": {"retcode": 255, "stderr": "Permission denied (publickey)."},
                     "host-4": {"stdout": "", "stderr": "zs-collect: checksum mismatch", "retcode": 4}},
                    client="ssh")
    mock_http(fake)
    out = {r.target.handle: r for r in salt().run_collect(targets(5), salt_cred(client="ssh"), options())}
    assert out["host-1"].status == "ok"
    assert out["host-2"].status == "unreachable" and "No route" in out["host-2"].error
    assert out["host-3"].status == "auth_failed"
    assert out["host-4"].status == "refused"
    assert out["host-5"].status == "unreachable"  # salt-ssh returned nothing for it


def test_salt_local_client_full_return_and_minion_did_not_return(mock_http):
    fake = FakeSalt({"host-1": {"stdout": doc_line("10.0.0.1")}, "host-2": "Minion did not return. [No response]"},
                    client="local")
    mock_http(fake)
    out = {r.target.handle: r for r in salt().run_collect(targets(2), salt_cred(client="local"), options())}
    assert out["host-1"].status == "ok" and out["host-2"].status == "unreachable"


def test_salt_login_refused_and_bad_documents(mock_http):
    mock_http(FakeSalt({}))
    with pytest.raises(TransportError) as e:
        list(salt().run_collect(targets(1), salt_cred(password="nope"), options()))
    assert e.value.status == "auth_failed"
    fake = FakeSalt({"host-1": {"stdout": doc_line("10.0.0.1", nonce="zs-1-1-ffffffffffffffff")},
                     "host-2": {"stdout": "not json"},
                     "host-3": {"retcode": 3, "stdout": "", "stderr": "zs-collect: /opt/... is missing"},
                     "host-4": "salt: 'cmd.script' is not available."}, client="local")
    mock_http(fake)
    out = {r.target.handle: r for r in salt().run_collect(targets(4), salt_cred(client="local"), options())}
    assert out["host-1"].status == "error" and "nonce" in out["host-1"].error
    assert out["host-2"].status == "error"
    assert out["host-3"].status == "error" and "not installed" in out["host-3"].error
    assert out["host-4"].status == "error"


def test_salt_state_refusal_is_reported():
    ret = {"test_|-zs_collect_|-zs-collect needs the pillar values_|-fail_without_changes": {
        "result": False, "comment": "zs-collect needs the pillar values", "changes": {}}}
    _s, problem = SALT._script_result(ret, "local", "state")
    assert problem[0] == "error" and "refused" in problem[1]


@pytest.mark.parametrize("nonce,tier", [("short", 1), ("zs-1-1-0123456789abcdef; rm -rf /", 1),
                                        ("zs-1-1-0123456789abcdef", 3)])
def test_salt_arguments_are_validated_before_they_reach_a_shell(nonce, tier):
    with pytest.raises(ValueError):
        wrappers.salt_args(nonce, tier)


# ----------------------------------------------------------------------------- the fleet glue
class FakeTransport:
    name = "fake"

    def __init__(self, results=None, exc=None):
        self.results, self.exc, self.seen = results or {}, exc, []

    def run_collect(self, targets, credential, options):
        self.seen = [t.label for t in targets]
        self.options = options
        if self.exc:
            raise self.exc
        from zs_scan_node.transports.base import TargetResult

        for t in targets:
            spec = self.results.get(t.label)
            if spec == "doc":
                d = doc_for("lab-hostname", options.run_nonce)  # zs-collect names the host by its hostname
                yield TargetResult(t, "ok", None, d)
            elif spec:
                yield TargetResult(t, spec, "tool said so", None)

    def check(self, credential, sample):
        return list(self.run_collect(sample, credential, self.options_for_check))


def ctx_for(kind="awx_hosts", never=()) -> JobContext:
    return JobContext(job_id=7, attempt=1, run_id=3, kind="collect", source_kind=kind, scrubber=Scrubber([]),
                      never_scan=NeverScan(list(never)), deadline=time.monotonic() + 120, state_dir="/tmp")


SOURCE_CFG = {"targets": ["10.0.0.1", "10.0.0.2", "db.internal", "10.0.0.4"],
              "handles": {"10.0.0.1": "web-1", "10.0.0.2": "web-2", "db.internal": "db-1", "10.0.0.4": "web-4"},
              "addresses": {"10.0.0.4": ["10.0.0.4", "192.168.50.4"]},
              "tier": 2, "timeout_s": 120, "transport": {"base_url": "https://awx.example", "job_template_id": 42},
              "zs_collect": {"version": VERSION, "sha256": {"amd64": "a" * 64}}}


def test_fleet_checks_never_scan_before_dispatch_and_relabels_assets(monkeypatch):
    fake = FakeTransport({"10.0.0.1": "doc", "db.internal": "unreachable"})
    monkeypatch.setattr(fleet, "_transport", lambda name, ctx, check_options=None: fake)
    ctx = ctx_for(never=["10.0.0.2", "192.168.50.0/24"])
    fleet.collect(ctx, SOURCE_CFG, {"token": "tok"}, {"targets": SOURCE_CFG["targets"]})
    # the tool never saw the two listed targets: 10.0.0.2 itself, and 10.0.0.4 through its second address
    assert fake.seen == ["10.0.0.1", "db.internal"]
    by = {o.target: o for o in ctx.outcomes}
    assert by["10.0.0.2"].status == by["10.0.0.4"].status == "skipped_never_scan"
    assert "192.168.50.4" in by["10.0.0.4"].error
    assert by["db.internal"].status == "unreachable"
    assert by["10.0.0.1"].status == "ok"
    assert by["10.0.0.1"].assets == FIXTURE["result"]["targets"][0]["assets"]  # zs-collect's own count, as over SSH
    assert {a["target"] for a in ctx.collected} == {"10.0.0.1"}
    cov = [a for a in ctx.collected if a["type"] == "coverage"]
    assert cov and all(a["location"].startswith("10.0.0.1#") for a in cov)
    assert re.fullmatch(zsdoc.NONCE_RE.pattern, fake.options.run_nonce) and fake.options.collector_version == VERSION


def test_fleet_asset_rows_match_what_zs_collect_wrote_except_the_target(monkeypatch):
    fake = FakeTransport({"10.0.0.1": "doc"})
    monkeypatch.setattr(fleet, "_transport", lambda name, ctx, check_options=None: fake)
    ctx = ctx_for()
    cfg = {**SOURCE_CFG, "targets": ["10.0.0.1"]}
    fleet.collect(ctx, cfg, {}, {"targets": ["10.0.0.1"]})
    want = sorted(json.dumps(a, sort_keys=True) for a in zsdoc.relabel(doc_for("x"), "10.0.0.1"))
    got = sorted(json.dumps(a, sort_keys=True) for a in ctx.collected)
    assert got == want


def test_fleet_transport_refusal_fails_every_target_with_its_status(monkeypatch):
    fake = FakeTransport(exc=TransportError("auth_failed", "AWX refused the login (401)"))
    monkeypatch.setattr(fleet, "_transport", lambda name, ctx, check_options=None: fake)
    ctx = ctx_for()
    status, error, _summary = run_job(ctx, {"kind": "collect"}, {"targets": ["10.0.0.1", "10.0.0.2"]},
                                      {"kind": "awx_hosts", "config": {**SOURCE_CFG, "targets": ["10.0.0.1", "10.0.0.2"]},
                                       "secrets": {"token": "x"}})
    assert status == "failure" and "auth_failed" in error
    assert {o.status for o in ctx.outcomes} == {"auth_failed"}


@pytest.mark.parametrize("missing", ["zs_collect", "transport"])
def test_fleet_refuses_without_a_verified_release_or_a_transport(missing):
    ctx = ctx_for(kind="salt_hosts")
    cfg = {k: v for k, v in SOURCE_CFG.items() if k != missing}
    status, error, _ = run_job(ctx, {"kind": "collect"}, {"targets": ["10.0.0.1"]},
                               {"kind": "salt_hosts", "config": cfg, "secrets": {}})
    assert status == "failure" and ("release" in error if missing == "zs_collect" else "transport" in error)


def test_fleet_test_connection_samples_at_most_five(monkeypatch):
    fake = FakeTransport({f"10.0.0.{i}": "doc" for i in range(1, 9)})
    monkeypatch.setattr(fleet, "_transport", lambda name, ctx, check_options=None:
                        setattr(fake, "options_for_check", check_options) or fake)
    ctx = ctx_for()
    ctx.kind = "test_connection"
    lines = [f"10.0.0.{i}" for i in range(1, 9)]
    status, _e, _s = run_job(ctx, {"kind": "test_connection"}, {"targets": lines},
                             {"kind": "awx_hosts", "config": {**SOURCE_CFG, "targets": lines}, "secrets": {}})
    assert status == "success" and len(ctx.samples) == 5 and {s["status"] for s in ctx.samples} == {"ready"}
    assert ctx.collected == []  # a test posts no assets


def test_node_advertises_the_transport_capabilities():
    from zs_scan_node.collectors import CAPABILITIES, SUPPORTED

    assert {"transport_awx", "transport_salt", "zs_collect"} <= set(CAPABILITIES)
    assert {("collect", "awx_hosts"), ("collect", "salt_hosts")} <= SUPPORTED


# ----------------------------------------------------------------------------- generated wrappers
LAUNCHER = "#!/bin/sh\necho launcher\n"


def test_ansible_playbook_is_valid_yaml_and_validates_its_inputs():
    files = wrappers.render_ansible("1.0.0", LAUNCHER)
    play = yaml.safe_load(files["zs-collect.yml"])[0]
    assert play["become"] is True and play["gather_facts"] is False
    tasks = {t["name"]: t for t in play["tasks"]}
    assert "zs_nonce is match('^[A-Za-z0-9_-]{16,128}$')" in tasks["zs-collect inputs"]["ansible.builtin.assert"]["that"]
    assert tasks["zs-collect"]["no_log"] is True and "--output chunks" in tasks["zs-collect"]["ansible.builtin.script"]
    assert files["files/zs-collect-run.sh"] == LAUNCHER
    with pytest.raises(ValueError):
        wrappers.render_ansible("1.0.0", "not a launcher")


def test_salt_state_and_ssm_document():
    files = wrappers.render_salt("1.0.0", LAUNCHER)
    assert "salt://zeroshield/zs-collect-run.sh" in files["zeroshield/zs_collect.sls"]
    assert "regex_match('^([A-Za-z0-9_-]{16,128})$')" in files["zeroshield/zs_collect.sls"]
    doc = wrappers.render_ssm_document("1.0.0", LAUNCHER)
    assert doc["schemaVersion"] == "2.2"
    assert doc["parameters"]["nonce"]["allowedPattern"] == "^[A-Za-z0-9_-]{16,128}$"
    assert doc["parameters"]["tier"]["allowedValues"] == ["1", "2"]
    script = "\n".join(doc["mainSteps"][0]["inputs"]["runCommand"])
    if shutil.which("sh"):
        assert subprocess.run(["sh", "-n"], input=script, capture_output=True, text=True).returncode == 0
    assert wrappers.SSM_DOCUMENT_RE.match("devsecshield-zs-collect-1-0-0")


def test_zsdoc_parse_output_takes_json_or_chunks():
    d = doc_for("10.0.0.1")
    assert zsdoc.parse_output("noise\n" + json.dumps(d) + "\n", NONCE) == d
    assert zsdoc.parse_output("\n".join(zsdoc.encode_chunks(d, NONCE, 4096)), NONCE) == d
    with pytest.raises(ValueError):
        zsdoc.parse_output("nothing here", NONCE)


def _fake_proc(root: Path, tree: dict[int, tuple[int, float]], hz: int) -> str:
    """A /proc with ``stat`` files: {pid: (parent pid, start time in seconds since boot)}."""
    for pid, (ppid, start) in tree.items():
        (root / str(pid)).mkdir(parents=True)
        rest = " ".join(["0"] * 13) + f" {int(start * hz)} 0 0"  # fields 9..21 (flags..itrealvalue), starttime (22)
        (root / str(pid) / "stat").write_text(f"{pid} (proc name) S {ppid} 1 1 0 -1 {rest}\n")
    return str(root)


HZ = os.sysconf("SC_CLK_TCK")


def test_zs_collect_ignores_the_transports_own_processes_but_keeps_services(tmp_path):
    from zs_scan_node import zscollect as Z

    # salt-minion (review 5874466030, live-local-r7): init <- 21 salt-minion <- 79, 86 long-lived minion processes
    # <- 700 the job <- 710 sh <- 720 launcher.  The SSH path reports 21, 79 and 86 (no job running): they stay.
    minion = _fake_proc(tmp_path / "minion", {21: (1, 1000), 79: (21, 1001), 86: (79, 1002), 700: (86, 1180),
                                              710: (700, 1185), 720: (710, 1186)}, HZ)
    assert Z.transient_ancestors(720, proc=minion) == [720, 710, 700]
    # sshd as PID 1 (a container): the transport's own SSH session (695 [priv], 696) is excluded too, while it hangs
    # off PID 1 directly; the SSH path does not report its own session either
    lab = _fake_proc(tmp_path / "lab", {1: (0, 5), 695: (1, 3000), 696: (695, 3000.2), 697: (696, 3001),
                                        698: (697, 3001.1), 699: (698, 3002)}, HZ)
    assert Z.transient_ancestors(699, proc=lab) == [699, 698, 697, 696, 695]
    # a systemd host: init <- 500 sshd (since boot) <- 695 session ... : sshd itself is a service and is kept
    host = _fake_proc(tmp_path / "host", {500: (1, 12), 695: (500, 90000), 696: (695, 90000), 699: (696, 90002)}, HZ)
    assert Z.transient_ancestors(699, proc=host) == [699, 696, 695]
    assert Z.transient_ancestors(699, proc=host, window_s=1) == [699]  # the window is what bounds the chain
    assert Z.transient_ancestors(500, proc=host) == [500]  # the walk always starts at the given pid
    assert Z.transient_ancestors(999, proc=minion) == []  # unknown pid: nothing
    (tmp_path / "minion" / "79" / "stat").write_text("garbage")
    assert Z.transient_ancestors(720, proc=minion) == [720, 710, 700]  # an unreadable ancestor ends the walk


@pytest.mark.skipif(not Path("/proc/self/stat").exists(), reason="needs /proc")
def test_transient_ancestors_on_real_processes(tmp_path):
    """A real tree: a "service" that has run for 2 s starts a "transport" process, which starts zs-collect's probe.
    With a 1 s window the transport process is excluded and the service (and everything above it) is kept."""
    import sys

    probe = ("import json, os, sys; sys.path.insert(0, sys.argv[1]); from zs_scan_node import zscollect as Z; "
             "print(json.dumps({'chain': Z.transient_ancestors(window_s=1.0), 'parent': os.getppid()}))")
    transport = f"import subprocess, sys; sys.stdout.write(subprocess.run([sys.executable, '-c', {probe!r}, sys.argv[1]], " \
                "capture_output=True, text=True).stdout)"
    service = f"import os, subprocess, sys, time; time.sleep(2.0); print(os.getpid()); sys.stdout.flush(); " \
              f"sys.stdout.write(subprocess.run([sys.executable, '-c', {transport!r}, sys.argv[1]], capture_output=True, " \
              "text=True).stdout)"
    p = subprocess.run([sys.executable, "-c", service, str(Path(__file__).resolve().parents[1])], capture_output=True,
                       text=True, timeout=60)
    service_pid, result = p.stdout.strip().splitlines()
    result = json.loads(result)
    assert result["chain"] == [result["parent"]]  # the transport process only
    assert int(service_pid) not in result["chain"] and os.getpid() not in result["chain"]


# ----------------------------------------------------------------------------- one host's output never fails the batch
DEEP = 100_000  # json.loads raises RecursionError far below this depth


def nested_text(depth: int = DEEP) -> str:
    return '{"format":"zs-collect/1","x":' + "[" * depth + "]" * depth + "}"


def chunk_lines_of(text: str, nonce: str = NONCE) -> list[str]:
    """``text`` (not necessarily a document) as one valid ZSC1 chunk: right nonce, right sha256, valid gzip."""
    import base64
    import gzip
    import hashlib

    blob = gzip.compress(text.encode(), mtime=0)
    return [f"ZSC1 {nonce} 1/1 {hashlib.sha256(blob).hexdigest()} {base64.b64encode(blob).decode()}"]


def test_nested_or_corrupt_output_is_a_value_error_not_a_crash():
    with pytest.raises(RecursionError):  # the hazard itself
        json.loads(nested_text())
    with pytest.raises(ValueError, match="not a JSON document"):
        zsdoc.parse_output(nested_text() + "\n", NONCE)
    with pytest.raises(zsdoc.ChunkError, match="not a JSON document"):
        zsdoc.reassemble(chunk_lines_of(nested_text()), NONCE)
    assert issubclass(zsdoc.ChunkError, ValueError)  # every caller that catches ValueError catches chunk problems
    # a corrupt deflate stream under a matching sha256 (the digest is in the header, so anyone can compute it)
    import base64
    import gzip
    import hashlib

    blob = bytearray(gzip.compress(json.dumps(doc_for("10.0.0.1")).encode(), mtime=0))
    blob[len(blob) // 2] ^= 0xFF
    blob = bytes(blob)
    line = f"ZSC1 {NONCE} 1/1 {hashlib.sha256(blob).hexdigest()} {base64.b64encode(blob).decode()}"
    with pytest.raises(zsdoc.ChunkError):
        zsdoc.reassemble([line], NONCE)


def test_awx_a_host_with_a_nested_document_is_its_own_error(mock_http):
    fake = FakeAwx({"host-1": {"lines": chunk_lines_of(nested_text())}, "host-2": {"lines": chunked("10.0.0.2")}})
    mock_http(fake)
    out = {r.target.handle: r for r in awx().run_collect(targets(2), AWX_CRED, options())}
    assert out["host-1"].status == "error" and "not a JSON document" in out["host-1"].error
    assert out["host-2"].status == "ok"


@pytest.mark.parametrize("client", ["local", "ssh"])
def test_salt_a_minion_with_a_nested_document_is_its_own_error(mock_http, client):
    fake = FakeSalt({"host-1": {"stdout": nested_text()}, "host-2": {"stdout": doc_line("10.0.0.2")}}, client=client)
    mock_http(fake)
    out = {r.target.handle: r for r in salt().run_collect(targets(2), salt_cred(client=client), options())}
    assert out["host-1"].status == "error" and "not a JSON document" in out["host-1"].error
    assert out["host-2"].status == "ok"


def test_fleet_one_hosts_failure_never_fails_the_others(monkeypatch):
    """A per-host exception (here: relabelling one document) is that host's error row; a transport that dies mid-run
    leaves error rows for the hosts it did not report, and the job itself still finishes."""
    fake = FakeTransport({"10.0.0.1": "doc", "db.internal": "doc"})
    monkeypatch.setattr(fleet, "_transport", lambda name, ctx, check_options=None: fake)
    real_relabel = zsdoc.relabel

    def relabel(doc, label):
        if label == "10.0.0.1":
            raise RecursionError("maximum recursion depth exceeded")
        return real_relabel(doc, label)

    monkeypatch.setattr(fleet.zsdoc, "relabel", relabel)
    ctx = ctx_for()
    cfg = {**SOURCE_CFG, "targets": ["10.0.0.1", "db.internal"]}
    status, error, _ = run_job(ctx, {"kind": "collect"}, {"targets": cfg["targets"]},
                               {"kind": "awx_hosts", "config": cfg, "secrets": {}})
    by = {o.target: o for o in ctx.outcomes}
    assert by["10.0.0.1"].status == "error" and "RecursionError" in by["10.0.0.1"].error
    assert by["db.internal"].status == "ok" and {a["target"] for a in ctx.collected} == {"db.internal"}
    assert status == "success", error

    class Dies(FakeTransport):
        def run_collect(self, targets, credential, options):
            from zs_scan_node.transports.base import TargetResult

            self.seen = [t.label for t in targets]
            yield TargetResult(targets[0], "unreachable", "no route", None)
            raise RuntimeError("the control plane client broke")

    monkeypatch.setattr(fleet, "_transport", lambda name, ctx, check_options=None: Dies())
    ctx = ctx_for()
    status, error, _ = run_job(ctx, {"kind": "collect"}, {"targets": cfg["targets"]},
                               {"kind": "awx_hosts", "config": cfg, "secrets": {}})
    by = {o.target: o for o in ctx.outcomes}
    assert by["10.0.0.1"].status == "unreachable"
    assert by["db.internal"].status == "error" and "RuntimeError" in by["db.internal"].error


# ----------------------------------------------------------------------------- review 5874466030 minors
def test_salt_local_async_polls_a_cheap_status_and_fetches_the_returns_once(mock_http, monkeypatch):
    fake = FakeSalt({f"host-{i}": {"stdout": doc_line(f"10.0.0.{i}")} for i in range(1, 4)})
    fake.ready_after = 5  # the minions return after five status polls
    mock_http(fake)
    monkeypatch.setattr(SALT, "time", FakeClock())
    out = list(SALT.SaltTransport(NeverScan([]), poll_s=3.0).run_collect(targets(3), salt_cred(), options()))
    assert {r.status for r in out} == {"ok"}
    assert fake.polls == 5 and fake.full_lookups == 1  # every document crossed the wire once, not once per poll


def test_salt_ssh_batches_are_at_most_100_hosts(mock_http):
    fake = FakeSalt({f"host-{i + 1}": {"stdout": doc_line(f"10.0.{i // 250}.{i % 250 + 1}")} for i in range(150)},
                    client="ssh")
    mock_http(fake)
    cred = TransportCredential("salt_eauth", {**salt_cred(client="ssh").config, "batch_size": 500},
                               {"username": "zs", "password": "pw"})
    ts = [CollectTarget(f"10.0.{i // 250}.{i % 250 + 1}", f"host-{i + 1}") for i in range(150)]
    out = list(salt().run_collect(ts, cred, options()))
    assert [len(c["tgt"]) for c in fake.calls] == [100, 50] and len(out) == 150
    local = FakeSalt({f"host-{i + 1}": {"stdout": doc_line(f"10.0.{i // 250}.{i % 250 + 1}")} for i in range(150)},
                     client="local")
    mock_http(local)
    cred = TransportCredential("salt_eauth", {**salt_cred(client="local").config, "batch_size": 500},
                               {"username": "zs", "password": "pw"})
    list(salt().run_collect(ts, cred, options()))
    assert [len(c["tgt"]) for c in local.calls] == [150]  # minions are not limited this way


@pytest.mark.parametrize("bad", [9, 3601, 0, True, "60; id", None])
def test_the_per_host_timeout_is_validated_before_it_reaches_a_shell(bad):
    with pytest.raises(ValueError):
        wrappers.salt_args(NONCE, 1, timeout_s=bad)
    with pytest.raises(ValueError):
        wrappers.timeout_arg(bad)
    pattern = re.compile(wrappers.TIMEOUT_PATTERN)
    assert not pattern.match(str(bad)) or isinstance(bad, bool)
    assert all(pattern.match(str(v)) for v in (10, 99, 300, 1000, 3599, 3600))
    assert wrappers.salt_args(NONCE, 2, timeout_s=3600) == f"--nonce {NONCE} --tier 2 --timeout-s 3600 --output json"


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs /bin/sh")
def test_the_ssm_document_hands_the_timeout_to_the_launcher(tmp_path):
    """Run the SSM document's script as SSM would (parameters substituted) with a launcher that prints its
    arguments: --timeout-s arrives, and a collected host's exit becomes 0 with ZSRC on stderr."""
    echo = "#!/bin/sh\nprintf 'ARGS %s\\n' \"$*\"\nexit 1\n"
    doc = wrappers.render_ssm_document("1.0.0", echo)
    assert doc["parameters"]["timeout"]["allowedPattern"] == wrappers.TIMEOUT_PATTERN
    assert int(doc["mainSteps"][0]["inputs"]["timeoutSeconds"]) >= 3600 + 60
    script = "\n".join(doc["mainSteps"][0]["inputs"]["runCommand"])
    for name, value in (("nonce", NONCE), ("tier", "2"), ("timeout", "1200"), ("output", "chunks")):
        script = script.replace("{{ " + name + " }}", value)
    p = subprocess.run(["sh", "-c", script], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin",
                                                                                   "TMPDIR": str(tmp_path)})
    assert p.returncode == 0, p.stderr
    assert f"ARGS --nonce {NONCE} --tier 2 --timeout-s 1200 --output chunks" in p.stdout
    assert "ZSRC 1" in p.stderr


def test_the_ansible_playbook_passes_and_checks_the_timeout():
    play = yaml.safe_load(wrappers.render_ansible("1.0.0", LAUNCHER)["zs-collect.yml"])[0]
    tasks = {t["name"]: t for t in play["tasks"]}
    assert "--timeout-s {{ zs_timeout_s | default(300) | int }}" in tasks["zs-collect"]["ansible.builtin.script"]
    that = tasks["zs-collect inputs"]["ansible.builtin.assert"]["that"]
    assert "(zs_timeout_s | default(300) | int) >= 10" in that and "(zs_timeout_s | default(300) | int) <= 3600" in that


def _raising(exc):
    def handler(request):
        raise exc
    return handler


@pytest.mark.parametrize("exc,status", [
    (httpx.ConnectTimeout("timed out"), "timeout"),
    (httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"),
     "identity_unverified"),
    (httpx.ConnectError("[Errno 111] Connection refused"), "unreachable"),
    (httpx.ReadTimeout("read timed out"), "timeout"),
])
def test_control_plane_connection_failures_map_to_target_statuses(mock_http, monkeypatch, exc, status):
    mock_http(_raising(exc))
    with pytest.raises(TransportError) as e:
        list(awx().run_collect(targets(1), AWX_CRED, options()))
    assert e.value.status == status
    # and every host of the job gets that status, through the real AWX adapter (fleet._transport is not patched)
    ctx = ctx_for()
    cfg = {**SOURCE_CFG, "targets": ["10.0.0.1", "db.internal"]}
    fleet.collect(ctx, cfg, {"token": "tok"}, {"targets": cfg["targets"]})
    assert {o.status for o in ctx.outcomes} == {status}


def test_zsdoc_guards_duplicates_oversized_output_and_facts(monkeypatch):
    d = doc_for("10.0.0.1")
    lines = zsdoc.encode_chunks(d, NONCE, chunk_bytes=1024)
    assert len(lines) >= 2
    head, data = lines[0].rsplit(" ", 1)
    altered = head + " " + ("A" if data[0] != "A" else "B") + data[1:]
    with pytest.raises(zsdoc.ChunkError, match="twice"):  # the altered copy first: last-wins would reassemble
        zsdoc.reassemble([altered] + lines, NONCE)
    # a gzip that inflates past the cap (a bomb) is refused before it is parsed
    monkeypatch.setattr(zsdoc, "MAX_DOCUMENT_BYTES", 1000)
    with pytest.raises(zsdoc.ChunkError, match="larger than"):
        zsdoc.reassemble(zsdoc.encode_chunks({"pad": "x" * 5000}, NONCE, chunk_bytes=4096), NONCE)
    with pytest.raises(ValueError, match="larger than"):
        zsdoc.parse_output(json.dumps({"pad": "x" * 5000}), NONCE)
    monkeypatch.undo()
    big = copy.deepcopy(d)
    big["assets"][0]["facts"] = {"blob": "x" * (16 * 1024)}
    assert "16 KB" in zsdoc.validate_document(big, NONCE, VERSION)
    assert zsdoc.validate_document(d, NONCE, VERSION) is None


@pytest.mark.parametrize("kind", ["awx_hosts", "salt_hosts"])
def test_fleet_dispatches_each_kind_to_its_own_adapter(mock_http, monkeypatch, kind):
    """No monkeypatching of fleet._transport: the kind alone picks the adapter and the credential kind."""
    monkeypatch.setattr(fleet, "_nonce", lambda ctx: NONCE)  # the fakes answer with documents for NONCE
    if kind == "awx_hosts":
        fake = FakeAwx({"web-1": {"lines": chunked("10.0.0.1")}})
        cfg = {**SOURCE_CFG, "targets": ["10.0.0.1"]}
        secrets = {"token": "tok"}
        assert isinstance(fleet._transport("awx", ctx_for(kind)), AWX.AwxTransport)
    else:
        fake = FakeSalt({"web-1": {"stdout": doc_line("10.0.0.1")}}, client="local")
        cfg = {**SOURCE_CFG, "targets": ["10.0.0.1"],
               "transport": {"base_url": "https://salt.example:8000", "client": "local", "mode": "cmd"}}
        secrets = {"username": "zs", "password": "pw"}
        assert isinstance(fleet._transport("salt", ctx_for(kind)), SALT.SaltTransport)
    assert fleet.KINDS[kind] == {"awx_hosts": ("awx", "awx_token"), "salt_hosts": ("salt", "salt_eauth")}[kind]
    _name, _t, _o, credential = fleet._setup(ctx_for(kind), cfg, secrets, {"targets": ["10.0.0.1"]})
    assert credential.kind == ("awx_token" if kind == "awx_hosts" else "salt_eauth")
    mock_http(fake)
    ctx = ctx_for(kind)
    status, error, _ = run_job(ctx, {"kind": "collect"}, {"targets": ["10.0.0.1"]},
                               {"kind": kind, "config": cfg, "secrets": secrets})
    assert status == "success", error
    assert [o.status for o in ctx.outcomes] == ["ok"] and {a["target"] for a in ctx.collected} == {"10.0.0.1"}
    if kind == "awx_hosts":
        assert len(fake.launches) == 1 and fake.launches[0]["limit"] == "web-1"
    else:
        assert fake.calls and fake.calls[0]["tgt"] == ["web-1"]


def test_the_parity_normaliser_reports_pid_set_differences():
    """diff() ignores process ids (they change between runs); pid_differences() reports them, so a transport's own
    process joining a group, or a service's process left out, cannot hide behind an empty diff again."""
    import importlib.util

    path = Path(__file__).resolve().parents[2] / "bench" / "f1_transports" / "normalize.py"
    spec = importlib.util.spec_from_file_location("f1_normalize", path)
    N = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(N)

    def lib(pids, name="sshd"):
        return {"type": "process_library", "target": "10.0.0.1", "location": "/usr/lib/libcrypto.so.3", "name": name,
                "facts": {"exe": "/usr/sbin/sshd", "lib": "/usr/lib/libcrypto.so.3", "pids": pids, "deleted": False,
                          "ports": [22], "process": name}}

    ssh, zs = {"assets": [lib([1])]}, {"assets": [lib([1, 695])]}
    assert N.diff(N.normalise(ssh, "10.0.0.1"), N.normalise(zs, "10.0.0.1")) == []
    assert N.pid_differences(ssh, zs, "10.0.0.1") == [
        "pids differ: sshd /usr/lib/libcrypto.so.3: only A []; only B [695]"]
    assert N.pid_differences(ssh, {"assets": [lib([1])]}) == []


def test_salt_request_timeout_covers_the_per_host_timeout(monkeypatch):
    """The local and ssh clients answer only when the batch is done: the HTTP timeout must outlast salt's own wait,
    which now covers zs-collect's per-host timeout (here 600 s, above the transport's 300 s)."""
    seen = []
    fake = FakeSalt({"host-1": {"stdout": doc_line("10.0.0.1")}}, client="local")

    def client(config, never, headers=None, timeout=30.0, what="control plane"):
        seen.append(timeout)
        return httpx.Client(base_url=config["base_url"], headers=dict(headers or {}), transport=httpx.MockTransport(fake))

    monkeypatch.setattr(control, "client", client)
    opts = CollectOptions(tier=2, run_nonce=NONCE, deadline=time.monotonic() + 3600, timeout_per_target_s=600,
                          max_concurrency="", zs_collect_sha256={"amd64": "a" * 64}, should_stop=lambda: None,
                          collector_version=VERSION)
    cred = TransportCredential("salt_eauth", {**salt_cred(client="local").config, "timeout_s": 300},
                               {"username": "zs", "password": "pw"})
    out = list(salt().run_collect(targets(1), cred, opts))
    assert out[0].status == "ok"
    assert fake.calls[0]["timeout"] == 660 and seen == [720]  # salt waits 600 + 60 s; the request 60 s more
