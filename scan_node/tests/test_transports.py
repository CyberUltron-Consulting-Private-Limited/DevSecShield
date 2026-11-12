"""F1.3 transports on the scan node: AWX/AAP and salt-api adapters against API fakes (httpx.MockTransport), the
fleet glue (never-scan before dispatch, relabelling, outcomes) and the generated wrappers."""
from __future__ import annotations

import copy
import json
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
    assert fake.launches[0]["extra_vars"] == {"zs_nonce": NONCE, "zs_tier": 2}
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


# ----------------------------------------------------------------------------- a salt-api fake
class FakeSalt:
    def __init__(self, minions: dict[str, object], *, client="local_async", user="zs", password="pw", slow=()):
        self.minions, self.client, self.user, self.password = minions, client, user, password
        self.slow = set(slow)
        self.calls: list[dict] = []
        self.polls = 0

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
            self.polls += 1
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
def test_salt_local_async_collects_and_a_silent_minion_is_unreachable(mock_http, mode):
    ts = targets(3)
    fake = FakeSalt({"host-1": {"stdout": doc_line("10.0.0.1")}, "host-2": {"stdout": doc_line("10.0.0.2")},
                     "host-3": {"stdout": doc_line("10.0.0.3")}}, slow={"host-3"})
    mock_http(fake)
    out = list(salt().run_collect(ts, salt_cred(mode=mode), options()))
    assert [(r.target.label, r.status) for r in out] == [("10.0.0.1", "ok"), ("10.0.0.2", "ok"),
                                                         ("10.0.0.3", "unreachable")]
    low = fake.calls[0]
    assert low["tgt"] == ["host-1", "host-2", "host-3"] and low["tgt_type"] == "list"
    if mode == "cmd":
        assert low["fun"] == "cmd.script" and low["arg"] == ["salt://zeroshield/zs-collect-run.sh",
                                                              f"--nonce {NONCE} --tier 2 --output json"]
    else:
        assert low["fun"] == "state.apply" and low["kwarg"]["pillar"] == {"zs_nonce": NONCE, "zs_tier": 2}


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


def test_zs_collect_ignores_the_transports_own_processes_but_keeps_services(tmp_path):
    from zs_scan_node import zscollect as Z

    # pid 1 init <- 50 salt-minion (a service) <- 700 minion job <- 710 sh <- 720 launcher sh <- (zs-collect)
    tree = {50: 1, 700: 50, 710: 700, 720: 710}
    for pid, ppid in tree.items():
        (tmp_path / str(pid)).mkdir()
        (tmp_path / str(pid) / "stat").write_text(f"{pid} (proc name) S {ppid} 1 1 0 -1\n")
    assert Z.transient_ancestors(720, proc=str(tmp_path)) == [720, 710, 700]
    assert Z.transient_ancestors(50, proc=str(tmp_path)) == []  # a service itself is never excluded
    assert Z.transient_ancestors(999, proc=str(tmp_path)) == []  # unknown pid: nothing
