"""F1.4 live proof: real OpenSSH sshd containers that trust the ZeroShield SSH CA.

Everything ZeroShield-side is the real code: the CA is created through the API, the source is saved through the API,
the scan node enrolls with its own Ed25519 key, claims its job, asks the node route for its certificate, and logs in
with the real collector (``linux_ssh``).  The server is configured only from what the API serves: the
``templates/sshd-config`` snippet (Match User zs-cbom), and its trust files (``trusted_user_ca_keys``, ``revoked.krl``,
``principals/zs-cbom``) are fetched INSIDE the container by the ``templates/trust-fetch`` script over HTTP from the
machine read path (``/cbom/ssh-ca-trust/*``) with a trust token, exactly as a customer's server does: conditional GETs
(ETag / 304), atomic writes, the KRL checked with ``ssh-keygen -Q -l``, ``sshd -t`` then a reload (SIGHUP).  The API is
the real app served by uvicorn on the docker bridge address for the duration of the proof.

Cases: a valid certificate collects; an expired certificate is refused; a principal mismatch is refused; a
source-address mismatch is refused; a revoked certificate is refused through the KRL; a rotated CA works during the
overlap (old and new certificates; promote shows the fetcher has the new key), and the retired key stops working once
it leaves trusted-keys; a revoked CA is refused through the KRL; an unchanged bundle is answered 304 and nothing is
rewritten; a revoked trust token is refused and the server keeps its files; a long job keeps logging in across several
certificate lifetimes (TTL 60 s, renewals).

Run (one small container named f1-4-sshd, removed at the end; no stack lock; check `free -m` first):

    env ZS_F14_SSHD_PROOF=1 ZS_F14_SSHD_IMAGE=<image with sshd and a zs-cbom user> \
      uv run --frozen --with paramiko==3.5.1 --with pytest==9.2.0 python -m pytest ../bench/f1_sshca/sshd_proof.py -s -q

from ``backend/``.  ``bench/f1_sshca/Dockerfile`` builds such an image (Debian, pinned openssh-server, sshd running as
the zs-cbom user itself on port 2222, no root in the container); the mounted files belong to that user (uid 1000).
The report (cases, outcomes, sshd log lines) goes to ``ZS_F14_REPORT`` (default bench/f1_sshca/out/sshd-proof.json).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "tests"))
sys.path.insert(0, str(ROOT / "scan_node"))

pytestmark = pytest.mark.skipif(os.environ.get("ZS_F14_SSHD_PROOF") != "1", reason="ZS_F14_SSHD_PROOF=1 not set")

if os.environ.get("ZS_F14_SSHD_PROOF") == "1":
    import paramiko
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    from sqlmodel import Session

    import test_cbom_sources_api as _base
    from backend.main import app
    from backend.routers import cbom_node_sshca, cbom_sshca_trust
    from backend.utilities.cbom_sources.sshca import certs as C
    from backend.utilities.cbom_sources.sshca import keywrap as KW
    from backend.utilities.cbom_sources.sshca import registry as R
    from backend.utilities.cbom_sources.sshca import trust as T
    from backend.utilities.cbom_sources.sshca.models import CbomSshCa
    from zs_scan_node import api as node_api
    from zs_scan_node.collectors import linux_ssh as L
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan, Target
    from zs_scan_node.scrub import Scrubber

    world = _base.world
    api = _base.api

IMAGE = os.environ.get("ZS_F14_SSHD_IMAGE", "f1-4-sshd:1")
REPORT = Path(os.environ.get("ZS_F14_REPORT", str(Path(__file__).parent / "out" / "sshd-proof.json")))
BASE = "/1/cbom/sources/fleet/ssh-ca"
NODE_SEEN_AS = os.environ.get("ZS_F14_NODE_ADDRESS", "172.17.0.1")  # how the containers see this host (docker0)
CONTAINER = os.environ.get("ZS_F14_CONTAINER", "f1-4-sshd")
SSHD_PORT = 2222  # the lab image's sshd runs as zs-cbom (uid 1000), not root (bench/f1_sshca/Dockerfile)
LAB_UID = 1000
FETCH_SCRIPT = "/opt/zs/zs-trust-fetch.sh"
access_log: list[tuple[str, str, int]] = []  # (method, path, status) the uvicorn server answered


class _Access(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        args = record.args if isinstance(record.args, tuple) else ()
        if len(args) >= 5:
            access_log.append((str(args[1]), str(args[2]), int(args[4])))


def _serve_api():
    """The real app on the docker bridge address (the container's view of this host), in a thread."""
    import uvicorn

    sock = socket.socket()
    sock.bind((NODE_SEEN_AS, 0))
    port = sock.getsockname()[1]
    sock.close()
    logger = logging.getLogger("uvicorn.access")
    logger.addHandler(_Access())
    logger.setLevel(logging.INFO)
    server = uvicorn.Server(uvicorn.Config(app, host=NODE_SEEN_AS, port=port, lifespan="off", log_level="info",
                                           access_log=True, log_config=None))  # keep the handler added above
    thread = threading.Thread(target=server.run, name="proof-api", daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server, f"http://{NODE_SEEN_AS}:{port}"


def _lab_owned(*paths: Path) -> None:
    """What sshd reads from the mounted directory belongs to the container's sshd user and nobody else (sshd's
    StrictModes accepts files owned by the user or root, not writable by others)."""
    for path in paths:
        os.chown(path, LAB_UID, LAB_UID)
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
results: list[dict] = []


def _docker(*args: str, check: bool = True) -> str:
    out = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)
    if check and out.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])}: {out.stderr.strip()[:300]}")
    return out.stdout + out.stderr


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


@pytest.fixture()
def lab(world, api, monkeypatch, tmp_path):
    engine, _ids = world
    paths = {getattr(r, "path", None) for r in app.router.routes}  # mounted through the fleet aggregator
    assert {"/{team_id}/cbom/sources/fleet/ssh-ca", "/cbom/node/jobs/{job_id}/ssh-cert"} <= paths
    monkeypatch.setenv("CBOM_SSH_CA", "1")
    monkeypatch.setattr(cbom_node_sshca, "get_db", lambda: engine)
    KW.forget()
    T.reset()  # per-worker trust caches keyed by team and token ids: each test has a fresh database
    etc = Path(tempfile.mkdtemp(prefix="f14-sshd-"))
    _lab_owned(etc)  # empty: the trust-fetch script fills it
    conf = tmp_path / "50-zs-cbom-ca.conf"
    conf.write_text(api("GET", BASE + "/templates/sshd-config").text)
    script_dir = Path(tempfile.mkdtemp(prefix="f14-fetch-"))
    (script_dir / "zs-trust-fetch.sh").write_text(api("GET", BASE + "/templates/trust-fetch").text)
    _lab_owned(script_dir, script_dir / "zs-trust-fetch.sh")  # read by the container's user only (run with sh)
    token = api("POST", BASE + "/trust-tokens", json={"name": "proof-server"})
    assert token.status_code == 201, token.text
    server, url = _serve_api()
    # lab only: verbose logs for the evidence, and no OpenSSH 9.8+ PerSourcePenalties (the refusals this proof makes
    # on purpose would otherwise make sshd drop this host's next connections for a while)
    (tmp_path / "10-proof-log.conf").write_text("LogLevel VERBOSE\nPerSourcePenalties no\n")
    _docker("rm", "-f", CONTAINER, check=False)
    _docker("run", "-d", "--name", CONTAINER, "--label", "zs-owner=f1-4",
            "-v", f"{etc}:/etc/ssh/zs-cbom", "-v", f"{script_dir}:/opt/zs:ro",
            "-v", f"{conf}:/etc/ssh/sshd_config.d/50-zs-cbom-ca.conf:ro",
            "-v", f"{tmp_path / '10-proof-log.conf'}:/etc/ssh/sshd_config.d/10-proof-log.conf:ro", IMAGE)
    ip = _docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", CONTAINER).strip()
    for _ in range(50):
        if "Server listening" in _docker("logs", CONTAINER, check=False):
            break
        time.sleep(0.2)
    # the CA's Match block must not leak onto the settings after the Include in Debian's sshd_config
    leak = _docker("exec", CONTAINER, "sshd", "-T", "-C", "user=alice,host=x,addr=10.0.0.9", check=False)
    zs = _docker("exec", CONTAINER, "sshd", "-T", "-C", "user=zs-cbom,host=x,addr=10.0.0.9", check=False)
    results.append({"case": "template scoping (sshd -T)",
                    "other_user_trustedusercakeys": [ln for ln in leak.splitlines() if ln.startswith("trustedusercakeys")],
                    "zs_cbom_trustedusercakeys": [ln for ln in zs.splitlines() if ln.startswith("trustedusercakeys")],
                    "other_user_x11forwarding": [ln for ln in leak.splitlines() if ln.startswith("x11forwarding")]})
    node_key = ed25519.Ed25519PrivateKey.generate()
    key_path = tmp_path / "id_ed25519"
    key_path.write_bytes(node_key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    key_path.chmod(0o600)
    line = node_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    r = api("POST", "/1/cbom/sources/nodes", json={"name": "proof-node", "segment": "lab"})
    reg = r.json()["registration_token"]
    e = api("POST", "/cbom/node/enroll", None, json={"registration_token": reg, "hostname": "proof-node",
                                                     "version": "1.2", "source_ips": [NODE_SEEN_AS],
                                                     "ssh_public_key": line,
                                                     "capabilities": {"collectors": ["linux_ssh", "ssh_ca"]}})
    client = node_api.Api("http://testserver", e.json()["node_token"])
    client.client = api.client  # the real node client talks to the real routes
    client._wait = lambda seconds: None
    lab = {"engine": engine, "etc": etc, "ip": ip, "key_path": key_path, "node_id": r.json()["node"]["id"],
           "client": client, "state": tmp_path / "state", "line": line, "url": url, "token": token.json()["token"],
           "token_id": token.json()["trust_token"]["id"]}
    lab["state"].mkdir()
    try:
        yield lab
    finally:
        server.should_exit = True
    logs = _docker("logs", CONTAINER, check=False)
    (REPORT.parent).mkdir(parents=True, exist_ok=True)
    version = _docker("exec", CONTAINER, "sh", "-c", "sshd -V 2>&1 | head -1", check=False).strip()
    REPORT.write_text(json.dumps({"image": IMAGE, "sshd_version": version, "generated": _utcnow().isoformat() + "Z",
                                  "results": results, "sshd_log_tail": logs.splitlines()[-200:]}, indent=2))
    _docker("rm", "-f", CONTAINER, check=False)


def fetch(lab, groups: str = "prod", token: str | None = None) -> dict:
    """Run the trust-fetch script INSIDE the server container, as the server would from its timer: the trust token
    and ZeroShield's address in the environment, this server's group(s), reload = SIGHUP to sshd (PID 1 here)."""
    mark = len(access_log)
    out = subprocess.run(["docker", "exec", "-u", str(LAB_UID), "-e", f"ZS_TRUST_TOKEN={token or lab['token']}",
                          "-e", f"ZS_URL={lab['url']}", "-e", f"ZS_GROUPS={groups}", "-e", "ZS_RELOAD=kill -HUP 1",
                          CONTAINER, "sh", FETCH_SCRIPT], capture_output=True, text=True, timeout=120)
    time.sleep(0.5)  # a SIGHUP re-executes sshd: let it listen again before the next login
    for _ in range(50):
        probe = subprocess.run(["docker", "exec", CONTAINER, "bash", "-c", f"exec 3<>/dev/tcp/127.0.0.1/{SSHD_PORT}"],
                               capture_output=True)
        if probe.returncode == 0:
            break
        time.sleep(0.2)
    answers = [(m, p.split("?")[0], st) for m, p, st in access_log[mark:] if p.startswith("/cbom/ssh-ca-trust/")]
    return {"rc": out.returncode, "stderr": out.stderr.strip()[-400:], "answers": answers}


def install(lab, api, principals=("zs-1-prod",)) -> dict:
    """The server's trust files, through the machine read path only (no download by a person)."""
    groups = " ".join(p.split("-", 2)[2] for p in principals)
    got = fetch(lab, groups=groups)
    assert got["rc"] == 0, got
    return got


def source(api, lab, ca_id, name, principals=("zs-1-prod",), **cfg):
    body = {"kind": "linux_servers", "name": name, "node_id": lab["node_id"], "test_after_save": True,
            "config": {"targets": [lab["ip"]], "port": SSHD_PORT, "credential_type": "ssh_ca", "ssh_ca_id": ca_id,
                       "ssh_principals": list(principals), "host_key_policy": "tofu", **cfg}}
    r = api("POST", "/1/cbom/sources/items", json=body)
    assert r.status_code == 201, r.text
    payload = lab["client"].claim({})
    assert payload["job"]["id"] == r.json()["test"]["job_id"]
    return payload


def ctx_for(lab, payload) -> "JobContext":
    job = payload["job"]
    ctx = JobContext(job_id=job["id"], attempt=job["attempt"], run_id=None, kind="collect",
                     source_kind="linux_servers", scrubber=Scrubber([]), never_scan=NeverScan(),
                     deadline=time.monotonic() + 300, state_dir=str(lab["state"]),
                     node_private_key_path=str(lab["key_path"]))
    ctx.cert_refresher = lambda: lab["client"].ssh_cert(job["id"], job["attempt"], job["lease_id"])
    return ctx


def login(lab, config, creds, ctx) -> tuple[str, str]:
    try:
        sess = L.open_session(ctx, Target(lab["ip"], lab["ip"]), config, creds)
    except L.TargetFail as fail:
        return fail.status, fail.error
    try:
        status, out, _err, _t = sess.run("id -un")
        return ("ok" if status == 0 else "error"), out.strip()
    finally:
        sess.close()


def key_with_cert(lab, cert_line: str):
    key = paramiko.Ed25519Key.from_private_key_file(str(lab["key_path"]))
    key.load_certificate(cert_line.strip())
    return key


def log_mark() -> int:
    return len(_docker("logs", CONTAINER, check=False).splitlines())


def sshd_lines(mark: int, *needles: str) -> list[str]:
    """sshd's log lines written since ``mark`` that mention one of ``needles``."""
    new = _docker("logs", CONTAINER, check=False).splitlines()[mark:]
    return [ln for ln in new if any(n.lower() in ln.lower() for n in needles)][-6:]


def record(case: str, expected: str, actual: tuple[str, str], evidence: list[str], **extra) -> None:
    results.append({"case": case, "expected": expected, "status": actual[0], "detail": actual[1][:200],
                    "sshd": evidence, **extra})
    print(f"[{case}] expected={expected} got={actual[0]} {actual[1][:80]}")
    for line in evidence:
        print("    sshd:", line[:200])


def ca_key(lab, ca_id):
    with Session(lab["engine"]) as session:
        row = session.get(CbomSshCa, ca_id)
        return KW.cached_private_key(row.id, row.team_id, row.fingerprint, row.private_key_encrypted)


def test_sshd_trusts_the_ca(api, lab):
    ca = api("POST", BASE, json={"name": "proof-ca"}).json()["ca"]
    first = install(lab, api)
    record("trust files fetched by the server (machine read path)", "3 x 200", ("rc=%d" % first["rc"],
           ", ".join(f"{p}={st}" for _m, p, st in first["answers"])), [],
           files=sorted(str(p.relative_to(lab["etc"])) for p in lab["etc"].rglob("*") if p.is_file()
                        and ".etag" not in p.parts))
    assert [st for _m, _p, st in first["answers"]] == [200, 200, 200]
    scoping = results[0]
    assert scoping["zs_cbom_trustedusercakeys"] and scoping["other_user_trustedusercakeys"] in (
        [], ["trustedusercakeys none"])

    # 1. a valid certificate collects (claim -> node route -> login -> real collection)
    payload = source(api, lab, ca["id"], "valid")
    ctx = ctx_for(lab, payload)
    cfg, secrets = payload["source"]["config"], payload["source"]["secrets"]
    t0 = log_mark()
    L.collect(ctx, cfg, secrets, payload["scope"])
    ctx.flush()
    outcome = ctx.outcomes[0]
    record("valid certificate collects", "ok", (outcome.status, outcome.error or ""),
           sshd_lines(t0, "Accepted publickey", "Accepted certificate"),
           assets=len(ctx.collected), asset_types=sorted({a["type"] for a in ctx.collected}))
    assert outcome.status == "ok" and len(ctx.collected) > 0

    # 2. an expired certificate is refused (signed by the real CA key, validity already over)
    now = _utcnow()
    expired = C.sign_user_cert(ca_key(lab, ca["id"]), lab["line"], serial=900001, key_id="proof-expired",
                               principals=["zs-1-prod"], valid_after=now - dt.timedelta(minutes=10),
                               valid_before=now - dt.timedelta(minutes=1), source_addresses=[NODE_SEEN_AS])
    t0 = log_mark()
    got = login(lab, cfg, {"key": key_with_cert(lab, expired)}, ctx)
    record("expired certificate refused", "auth_failed", got, sshd_lines(t0, "expired", "certificate", "refused"))
    assert got[0] == "auth_failed"

    # 3. principal mismatch: the source asks for zs-1-dev, the server's principals file lists zs-1-prod
    payload = source(api, lab, ca["id"], "wrong-principal", principals=("zs-1-dev",))
    ctx = ctx_for(lab, payload)
    creds = L._credentials(ctx, payload["source"]["config"], payload["source"]["secrets"])
    t0 = log_mark()
    got = login(lab, payload["source"]["config"], creds, ctx)
    record("principal mismatch refused", "auth_failed", got, sshd_lines(t0, "principal", "certificate"))
    assert got[0] == "auth_failed"

    # 4. source-address mismatch: the certificate is bound to an address this node does not connect from
    payload = source(api, lab, ca["id"], "wrong-address", ssh_source_addresses=["10.99.99.99"])
    ctx = ctx_for(lab, payload)
    creds = L._credentials(ctx, payload["source"]["config"], payload["source"]["secrets"])
    t0 = log_mark()
    got = login(lab, payload["source"]["config"], creds, ctx)
    record("source-address mismatch refused", "auth_failed", got, sshd_lines(t0, "source-address", "source address",
                                                                             "not permitted", "certificate"))
    assert got[0] == "auth_failed"

    # 5. a revoked certificate is refused through the KRL (and the other certificates still work)
    payload = source(api, lab, ca["id"], "to-revoke")
    ctx_r = ctx_for(lab, payload)
    creds_r = L._credentials(ctx_r, payload["source"]["config"], payload["source"]["secrets"])
    assert login(lab, payload["source"]["config"], creds_r, ctx_r)[0] == "ok"
    cert_id = api("GET", f"{BASE}/certificates?job_id={payload['job']['id']}").json()["certificates"][0]["id"]
    assert api("POST", f"{BASE}/certificates/{cert_id}/revoke", json={"reason": "proof"}).status_code == 200
    install(lab, api)
    t0 = log_mark()
    got = login(lab, payload["source"]["config"], creds_r, ctx_r)
    record("revoked certificate refused (KRL)", "auth_failed", got, sshd_lines(t0, "revoked", "krl"))
    assert got[0] == "auth_failed"
    payload = source(api, lab, ca["id"], "still-valid")
    ctx_s = ctx_for(lab, payload)
    still = login(lab, payload["source"]["config"],
                  L._credentials(ctx_s, payload["source"]["config"], payload["source"]["secrets"]), ctx_s)
    record("another certificate still accepted after the KRL update", "ok", still, [])
    assert still[0] == "ok"

    # 6. rotation: old and new CA trusted during the overlap, the retired key dropped afterwards
    payload = source(api, lab, ca["id"], "rotation")
    ctx_o = ctx_for(lab, payload)
    rcfg = payload["source"]["config"]
    old_creds = L._credentials(ctx_o, rcfg, payload["source"]["secrets"])
    old_key = old_creds["cert_source"].key()
    nxt = api("POST", f"{BASE}/{ca['id']}/rotate").json()["ca"]
    before = api("GET", f"{BASE}/{nxt['id']}").json()["ca"]["readiness"]
    install(lab, api)
    after = api("GET", f"{BASE}/{nxt['id']}").json()["ca"]["readiness"]
    early = api("POST", f"{BASE}/{nxt['id']}/promote", json={})
    record("promote readiness: the server fetched the rotated key", "0 -> 1 of 1, early promote refused",
           (f"{before['fetchers_ready']}/{before['fetchers_total']} -> {after['fetchers_ready']}/"
            f"{after['fetchers_total']}", f"promote without force: {early.status_code}"), [],
           refusal=early.json().get("detail", "")[:200])
    assert (after["fetchers_ready"], after["fetchers_total"]) == (1, 1) and early.status_code == 400
    assert login(lab, rcfg, {"key": old_key}, ctx_o)[0] == "ok"
    assert api("POST", f"{BASE}/{nxt['id']}/promote", json={"force": True}).status_code == 200
    install(lab, api)
    payload = source(api, lab, ca["id"], "rotation-new")
    ctx_n = ctx_for(lab, payload)
    new_creds = L._credentials(ctx_n, payload["source"]["config"], payload["source"]["secrets"])
    new_cert = api("GET", f"{BASE}/certificates?job_id={payload['job']['id']}").json()["certificates"][0]
    t0 = log_mark()
    got_new = login(lab, rcfg, new_creds, ctx_n)
    got_old = login(lab, rcfg, {"key": old_key}, ctx_o)
    record("rotated CA: new CA's certificate during the overlap", "ok", got_new, [], ca_id=new_cert["ca_id"])
    record("rotated CA: old CA's certificate during the overlap", "ok", got_old, [])
    assert got_new[0] == "ok" and got_old[0] == "ok" and new_cert["ca_id"] == nxt["id"]
    # the overlap ends: the trust routes' clock moves past it (retired_at is written once, by promote, which moved the
    # trust generation; the trusted-keys text is cached per generation until that moment)
    with Session(lab["engine"]) as session:
        ends = session.get(CbomSshCa, ca["id"]).retired_at + R.OVERLAP
    real_now = cbom_sshca_trust.utcnow
    cbom_sshca_trust.utcnow = lambda: ends + dt.timedelta(seconds=1)
    try:
        install(lab, api)
    finally:
        cbom_sshca_trust.utcnow = real_now
    t0 = log_mark()
    got_old = login(lab, rcfg, {"key": old_key}, ctx_o)
    got_new = login(lab, rcfg, new_creds, ctx_n)
    record("rotated CA: retired key after the overlap", "auth_failed", got_old,
           sshd_lines(t0, "not trusted", "certificate", "CA"))
    record("rotated CA: new key after the overlap", "ok", got_new, [])
    assert got_old[0] == "auth_failed" and got_new[0] == "ok"

    # 7. a revoked CA is refused through the KRL even while trusted-keys still lists it (the lab puts the old
    #    trusted-keys file back after the fetch, to show the KRL alone refuses it)
    trusted_before = (lab["etc"] / "trusted_user_ca_keys").read_text()
    api("POST", f"{BASE}/{nxt['id']}/revoke", json={"reason": "proof: compromised"})
    install(lab, api)
    (lab["etc"] / "trusted_user_ca_keys").write_text(trusted_before)
    _lab_owned(lab["etc"] / "trusted_user_ca_keys")
    t0 = log_mark()
    got = login(lab, rcfg, new_creds, ctx_n)
    record("revoked CA refused (KRL, stale trusted-keys)", "auth_failed", got, sshd_lines(t0, "revoked", "krl"))
    assert got[0] == "auth_failed"

    # 8. nothing changed: every answer is a 304 and no file is rewritten
    install(lab, api)
    stamps = {p.name: p.stat().st_mtime_ns for p in lab["etc"].rglob("*") if p.is_file() and ".etag" not in p.parts}
    again = install(lab, api)
    after = {p.name: p.stat().st_mtime_ns for p in lab["etc"].rglob("*") if p.is_file() and ".etag" not in p.parts}
    record("unchanged bundle: conditional GETs", "3 x 304, files untouched",
           ("rc=%d" % again["rc"], ", ".join(f"{p}={st}" for _m, p, st in again["answers"])), [],
           files_untouched=stamps == after)
    assert [st for _m, _p, st in again["answers"]] == [304, 304, 304] and stamps == after

    # 9. a revoked trust token: the server is refused (401), keeps its files and the script fails loudly
    assert api("POST", f"{BASE}/trust-tokens/{lab['token_id']}/revoke", json={}).status_code == 200
    refused = fetch(lab)
    kept = {p.name: p.stat().st_mtime_ns for p in lab["etc"].rglob("*") if p.is_file() and ".etag" not in p.parts}
    record("revoked trust token", "401, files kept, non-zero exit",
           ("rc=%d" % refused["rc"], ", ".join(f"{p}={st}" for _m, p, st in refused["answers"])), [],
           stderr=refused["stderr"][-200:], files_kept=kept == after)
    assert refused["rc"] != 0 and {st for _m, _p, st in refused["answers"]} == {401} and kept == after


@pytest.mark.skipif(os.environ.get("ZS_F14_LONG_JOB_S") is None, reason="ZS_F14_LONG_JOB_S not set")
def test_a_long_job_keeps_logging_in_through_renewals(api, lab):
    """TTL 60 s (renewal window 30 s): logins every 5 s for ZS_F14_LONG_JOB_S seconds, all with a live certificate."""
    ca = api("POST", BASE, json={"name": "short-ttl", "default_ttl_s": 60}).json()["ca"]
    install(lab, api)
    payload = source(api, lab, ca["id"], "long-job")
    ctx = ctx_for(lab, payload)
    cfg = payload["source"]["config"]
    creds = L._credentials(ctx, cfg, payload["source"]["secrets"])
    deadline = time.monotonic() + float(os.environ["ZS_F14_LONG_JOB_S"])
    statuses = []
    while time.monotonic() < deadline:
        statuses.append(login(lab, cfg, creds, ctx)[0])
        time.sleep(5)
    serials = [c["serial"] for c in api("GET", f"{BASE}/certificates?job_id={payload['job']['id']}").json()["certificates"]]
    record("long job through renewals", "all ok", (",".join(sorted(set(statuses))), f"{len(statuses)} logins"),
           [], certificates=len(serials), renewals=creds["cert_source"].renewals)
    assert set(statuses) == {"ok"} and len(serials) >= 3
