"""F1.4 live proof: real OpenSSH sshd containers that trust the ZeroShield SSH CA.

Everything ZeroShield-side is the real code: the CA is created through the API, the source is saved through the API,
the scan node enrolls with its own Ed25519 key, claims its job, asks the node route for its certificate, and logs in
with the real collector (``linux_ssh``).  The servers are configured only from what the API serves:
``templates/sshd-config`` (Match User zs-cbom), ``trusted-keys``, ``revoked`` (KRL) and ``templates/principals``.

Cases: a valid certificate collects; an expired certificate is refused; a principal mismatch is refused; a
source-address mismatch is refused; a revoked certificate is refused through the KRL; a rotated CA works during the
overlap (old and new certificates), and the retired key stops working once it leaves trusted-keys; a revoked CA is
refused through the KRL; a long job keeps logging in across several certificate lifetimes (TTL 60 s, renewals).

Run (one small container named f1-4-sshd, removed at the end; no stack lock; check `free -m` first):

    env ZS_F14_SSHD_PROOF=1 ZS_F14_SSHD_IMAGE=<image with sshd and a zs-cbom user> \
      uv run --frozen --with paramiko==3.5.1 --with pytest==9.2.0 python -m pytest ../bench/f1_sshca/sshd_proof.py -s -q

from ``backend/``.  ``bench/f1_sshca/Dockerfile`` builds such an image (Debian, openssh-server, user zs-cbom).
The report (cases, outcomes, sshd log lines) goes to ``ZS_F14_REPORT`` (default bench/f1_sshca/out/sshd-proof.json).
"""
from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
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
    from backend.routers import cbom_node_sshca
    from backend.utilities.cbom_sources.sshca import certs as C
    from backend.utilities.cbom_sources.sshca import keywrap as KW
    from backend.utilities.cbom_sources.sshca import registry as R
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
    etc = Path(tempfile.mkdtemp(prefix="f14-sshd-"))
    (etc / "principals").mkdir(parents=True)
    os.chmod(etc, 0o755)
    os.chmod(etc / "principals", 0o755)
    conf = tmp_path / "50-zs-cbom-ca.conf"
    conf.write_text(api("GET", BASE + "/templates/sshd-config").text)
    # lab only: verbose logs for the evidence, and no OpenSSH 9.8+ PerSourcePenalties (the refusals this proof makes
    # on purpose would otherwise make sshd drop this host's next connections for a while)
    (tmp_path / "10-proof-log.conf").write_text("LogLevel VERBOSE\nPerSourcePenalties no\n")
    _docker("rm", "-f", CONTAINER, check=False)
    _docker("run", "-d", "--name", CONTAINER, "--label", "zs-owner=f1-4",
            "-v", f"{etc}:/etc/ssh/zs-cbom:ro", "-v", f"{conf}:/etc/ssh/sshd_config.d/50-zs-cbom-ca.conf:ro",
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
           "client": client, "state": tmp_path / "state", "line": line}
    lab["state"].mkdir()
    yield lab
    logs = _docker("logs", CONTAINER, check=False)
    (REPORT.parent).mkdir(parents=True, exist_ok=True)
    version = _docker("exec", CONTAINER, "sh", "-c", "sshd -V 2>&1 | head -1", check=False).strip()
    REPORT.write_text(json.dumps({"image": IMAGE, "sshd_version": version, "generated": _utcnow().isoformat() + "Z",
                                  "results": results, "sshd_log_tail": logs.splitlines()[-200:]}, indent=2))
    _docker("rm", "-f", CONTAINER, check=False)


def install(lab, api, principals=("zs-1-prod",)) -> None:
    etc = lab["etc"]
    (etc / "trusted_user_ca_keys").write_text(api("GET", BASE + "/trusted-keys").text)
    (etc / "revoked.krl").write_bytes(api("GET", BASE + "/revoked").content)
    (etc / "principals" / "zs-cbom").write_text("\n".join(principals) + "\n")
    for p in (etc / "trusted_user_ca_keys", etc / "revoked.krl", etc / "principals" / "zs-cbom"):
        os.chmod(p, 0o644)


def source(api, lab, ca_id, name, principals=("zs-1-prod",), **cfg):
    body = {"kind": "linux_servers", "name": name, "node_id": lab["node_id"], "test_after_save": True,
            "config": {"targets": [lab["ip"]], "credential_type": "ssh_ca", "ssh_ca_id": ca_id,
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
    install(lab, api)
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
    install(lab, api)
    assert login(lab, rcfg, {"key": old_key}, ctx_o)[0] == "ok"
    api("POST", f"{BASE}/{nxt['id']}/promote")
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
    with Session(lab["engine"]) as session:
        old_row = session.get(CbomSshCa, ca["id"])
        old_row.retired_at = _utcnow() - R.OVERLAP - dt.timedelta(seconds=1)
        session.add(old_row)
        session.commit()
    install(lab, api)
    t0 = log_mark()
    got_old = login(lab, rcfg, {"key": old_key}, ctx_o)
    got_new = login(lab, rcfg, new_creds, ctx_n)
    record("rotated CA: retired key after the overlap", "auth_failed", got_old,
           sshd_lines(t0, "not trusted", "certificate", "CA"))
    record("rotated CA: new key after the overlap", "ok", got_new, [])
    assert got_old[0] == "auth_failed" and got_new[0] == "ok"

    # 7. a revoked CA is refused through the KRL even while trusted-keys still lists it (a stale file on the server)
    trusted_before = (lab["etc"] / "trusted_user_ca_keys").read_text()
    api("POST", f"{BASE}/{nxt['id']}/revoke", json={"reason": "proof: compromised"})
    (lab["etc"] / "revoked.krl").write_bytes(api("GET", BASE + "/revoked").content)
    (lab["etc"] / "trusted_user_ca_keys").write_text(trusted_before)
    t0 = log_mark()
    got = login(lab, rcfg, new_creds, ctx_n)
    record("revoked CA refused (KRL, stale trusted-keys)", "auth_failed", got, sshd_lines(t0, "revoked", "krl"))
    assert got[0] == "auth_failed"


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
