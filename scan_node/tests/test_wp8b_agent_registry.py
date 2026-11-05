"""WP8b: agent mode (the node's own host from read-only mounts), the shared package-database module, and container
images pulled from a registry (Distribution API v2) through the network gate."""
from __future__ import annotations

import base64
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import ssl
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from zs_scan_node import pkgdb
from zs_scan_node.collectors import container_images as CI
from zs_scan_node.collectors import host_agent, run_job
from zs_scan_node.hostfs import HostFS, WalkStats
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

REPO = Path(__file__).resolve().parents[2]


def _ctx(agent: bool = False, never: list[str] | None = None) -> JobContext:
    import time

    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind=None, scrubber=Scrubber(),
                      never_scan=NeverScan(never or []), deadline=time.monotonic() + 600, agent_mode=agent)


# ----------------------------------------------------------------------------- one package-DB module, two copies
def test_package_db_module_is_byte_identical_to_the_engine_copy():
    engine = REPO / "aibom" / "src" / "aibom" / "cbom" / "pkgdb.py"
    node = REPO / "scan_node" / "zs_scan_node" / "pkgdb.py"
    if not engine.exists():
        pytest.skip("engine source not in this checkout")
    assert node.read_bytes() == engine.read_bytes(), "copy aibom/src/aibom/cbom/pkgdb.py to scan_node/zs_scan_node/"


# ----------------------------------------------------------------------------- host file system
def test_hostfs_resolves_links_inside_the_host_root_only(tmp_path):
    root = tmp_path / "host"
    (root / "usr/lib").mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "usr/lib/os-release").write_text('ID=debian\nVERSION_ID="12"\n')
    os.symlink("../usr/lib/os-release", root / "etc/os-release")
    os.symlink("/usr/lib/os-release", root / "etc/abs-link")
    os.symlink("/proc/self/environ", root / "etc/escape")  # must read the HOST's /proc (absent here), not ours
    os.symlink("../../../../../../etc/hostname", root / "etc/dotdot")
    (root / "etc/hostname").write_text("host-a\n")
    os.mkfifo(root / "etc/fifo")
    (root / "etc/big").write_bytes(b"x" * 5000)
    fs = HostFS(str(root))
    assert fs.read("/etc/os-release", 4096).text().startswith("ID=debian")
    assert fs.read("/etc/abs-link", 4096).ok
    assert fs.read("/etc/escape", 4096).status == "missing"
    assert fs.resolve("/etc/dotdot") == str(root / "etc/hostname")  # '..' stops at the root
    assert fs.read("/etc/fifo", 4096).status == "not_file"  # never blocks on a FIFO
    assert fs.read("/etc/big", 100).status == "too_large"
    os.symlink("loop2", root / "etc/loop1")
    os.symlink("loop1", root / "etc/loop2")
    assert fs.read("/etc/loop1", 10).status == "missing"


def test_hostfs_walk_does_not_follow_symlinks(tmp_path):
    root = tmp_path / "host"
    (root / "etc/ssl").mkdir(parents=True)
    (root / "outside").mkdir()
    (root / "outside/secret.key").write_text("k")
    (root / "etc/ssl/a.pem").write_text("p")
    os.symlink(str(root / "outside"), root / "etc/ssl/linked")
    stats = WalkStats()
    import re

    found = list(HostFS(str(root)).walk("/etc", re.compile(r".+\.(pem|key)"), 10, 1024, stats))
    assert found == ["/etc/ssl/a.pem"] and stats.symlinks == 1


def _cert(key, cn: str, ca: bool = False, issuer=None, issuer_key=None, san: list | None = None) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
               .not_valid_after(now + dt.timedelta(days=30))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName(san), critical=False)
    return builder.sign(issuer_key or key, hashes.SHA256())


DPKG = """Package: libssl3
Status: install ok installed
Architecture: amd64
Version: 3.0.2-0ubuntu1.10
Source: openssl

Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.2-0ubuntu1.10

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.1-6ubuntu1

Package: libgnutls30
Status: deinstall ok config-files
Architecture: amd64
Version: 3.7.3-4ubuntu1
"""


def _host_root(tmp_path: Path) -> Path:
    root = tmp_path / "host"
    for d in ("etc/ssh", "etc/ssl/certs", "etc/ssl/private", "etc/crypto-policies", "var/lib/dpkg", "opt/app",
              "usr/lib", "home/u/.ssh"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "usr/lib/os-release").write_text('NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n')
    os.symlink("../usr/lib/os-release", root / "etc/os-release")
    (root / "var/lib/dpkg/status").write_text(DPKG)
    (root / "etc/crypto-policies/config").write_text("LEGACY\n")
    (root / "etc/ssh/sshd_config").write_text("Ciphers aes128-cbc,aes256-ctr\nPermitRootLogin yes\n")
    host_key = ed25519.Ed25519PrivateKey.generate()
    pub = host_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    (root / "etc/ssh/ssh_host_ed25519_key.pub").write_bytes(pub + b" root@host\n")
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    (root / "opt/app/server.key").write_bytes(weak.private_bytes(serialization.Encoding.PEM,
                                                                 serialization.PrivateFormat.PKCS8,
                                                                 serialization.NoEncryption()))
    os.chmod(root / "opt/app/server.key", 0o644)
    (root / "opt/app/server.crt").write_bytes(_cert(weak, "app.internal").public_bytes(serialization.Encoding.PEM))
    for i in range(3):  # a hashed CA directory -> one summary row
        k = ec.generate_private_key(ec.SECP256R1())
        (root / f"etc/ssl/certs/ca{i}.pem").write_bytes(_cert(k, f"CA {i}", ca=True).public_bytes(serialization.Encoding.PEM))
    (root / "home/u/.ssh/authorized_keys").write_bytes(pub + b" u@laptop\n")
    return root


def test_host_agent_collects_its_own_host_from_the_mount(tmp_path, monkeypatch):
    root = _host_root(tmp_path)
    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.setenv("ZS_NODE_NAME", "k3s-node-1")
    monkeypatch.delenv("ZS_HOST_PROC", raising=False)
    ctx = _ctx(agent=True)
    status, error, summary = run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {},
                                                                             "secrets": {}})
    ctx.flush()
    assert (status, error) == ("success", None), error
    rows = ctx.collected
    by_type: dict[str, list[dict]] = {}
    for r in rows:
        by_type.setdefault(r["type"], []).append(r)
    libs = {r["name"]: r["facts"] for r in by_type["crypto_library"]}
    assert set(libs) == {"libssl3", "openssl"}  # bash is not crypto; libgnutls30 is not installed
    assert libs["libssl3"]["purl"] == "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04"
    policy = by_type["os_crypto_policy"][0]["facts"]
    assert policy["crypto_policy"] == "LEGACY" and policy["os"]["id"] == "ubuntu" and policy["agent"] is True
    assert policy["openssl"]["version"] == "3.0.2-0ubuntu1.10"
    assert by_type["ssh_host_key"][0]["algorithm"] == "ED25519" and by_type["ssh_host_key"][0]["key_size"] == 256
    assert by_type["ssh_server_config"][0]["facts"]["ciphers"] == ["aes128-cbc", "aes256-ctr"]
    key = by_type["private_key"][0]
    assert (key["algorithm"], key["key_size"], key["facts"]["world_readable"]) == ("RSA", 1024, True)
    assert "BEGIN" not in json.dumps(rows)  # no key material ever leaves the node
    certs = {r["location"]: r for r in by_type["certificate"]}
    assert certs["/opt/app/server.crt"]["key_size"] == 1024
    assert certs["/etc/ssl/certs"]["facts"]["trust_store"] is True and certs["/etc/ssl/certs"]["facts"]["count"] == 3
    assert by_type["public_key"][0]["facts"]["authorized_key"] is True
    assert all(r["target"] == "k3s-node-1" for r in rows if r["type"] != "coverage")
    assert any(r["facts"].get("check") == "process crypto libraries" for r in by_type["coverage"])
    assert ctx.outcomes[0].status == "ok"


def test_host_agent_reads_process_libraries_with_host_pid(tmp_path, monkeypatch):
    root = _host_root(tmp_path)
    proc = tmp_path / "proc"
    (proc / "42").mkdir(parents=True)
    (proc / "42/comm").write_text("nginx\n")
    (proc / "42/maps").write_text("7f00-7f01 r-xp 0 08:01 1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1\n"
                                  "7f02-7f03 r-xp 0 08:01 2 /usr/lib/x86_64-linux-gnu/libcrypto.so.3 (deleted)\n"
                                  "7f04-7f05 r-xp 0 08:01 3 /usr/lib/x86_64-linux-gnu/libz.so.1\n")
    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.setenv("ZS_HOST_PROC", str(proc))
    ctx = _ctx(agent=True)
    run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    ctx.flush()
    libs = {r["location"]: r["facts"] for r in ctx.collected if r["type"] == "process_library"}
    assert set(libs) == {"/usr/lib/x86_64-linux-gnu/libssl.so.1.1", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"}
    assert libs["/usr/lib/x86_64-linux-gnu/libcrypto.so.3"]["deleted"] is True
    assert libs["/usr/lib/x86_64-linux-gnu/libssl.so.1.1"]["process"] == "nginx"


def test_agent_mode_runs_only_its_own_host_and_never_takes_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("ZS_HOST_ROOT", str(_host_root(tmp_path)))
    linux = {"kind": "linux_servers", "config": {"targets": ["10.0.0.1"]}, "secrets": {"password": "pw-123456"}}
    status, error, _ = run_job(_ctx(agent=True), {"id": 1, "kind": "collect"}, {}, linux)
    assert status == "failure" and "agent mode" in error
    status, error, _ = run_job(_ctx(agent=True), {"id": 1, "kind": "discovery"}, {"ranges": []}, None)
    assert status == "failure" and "agent mode" in error
    status, error, _ = run_job(_ctx(agent=True), {"id": 1, "kind": "collect"}, {},
                               {"kind": "host_agent", "config": {}, "secrets": {"password": "smuggled"}})
    assert status == "failure" and "credentials" in error
    status, error, _ = run_job(_ctx(agent=False), {"id": 1, "kind": "collect"}, {},
                               {"kind": "host_agent", "config": {}, "secrets": {}})
    assert status == "failure" and "ZS_MODE=agent" in error


def test_host_agent_connection_test_reports_a_missing_mount(tmp_path, monkeypatch):
    monkeypatch.setenv("ZS_HOST_ROOT", str(tmp_path / "nothing"))
    ctx = _ctx(agent=True)
    ctx.kind = "test_connection"
    run_job(ctx, {"id": 1, "kind": "test_connection"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    assert ctx.samples[0]["status"] == "error" and "not mounted" in ctx.samples[0]["note"]


def test_agent_enrolls_in_agent_mode_with_its_node_name(tmp_path, monkeypatch):
    from zs_scan_node import agent as A

    monkeypatch.setenv("ZS_API_URL", "https://zs.example")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ZS_MODE", "agent")
    monkeypatch.setenv("ZS_NODE_NAME", "worker-7")
    monkeypatch.setenv("ZS_REGISTRATION_TOKEN", "zsp_" + "a" * 30)
    monkeypatch.setenv("ZS_VAULT_PATH_PREFIX", "secret/zs")
    agent = A.Agent()
    assert agent.vault_prefix is None  # agent mode never uses credentials
    sent = {}

    def enroll(body):
        sent.update(body)
        return {"node_token": "zsn_" + "b" * 30, "node_id": 9, "team_id": 1, "deployment_id": "dep"}

    monkeypatch.setattr(agent.api, "enroll", enroll)
    agent.ensure_enrolled()
    assert sent["mode"] == "agent" and sent["node_name"] == "worker-7"
    assert sent["capabilities"]["collectors"] == ["host_agent"] and sent["capabilities"]["mode"] == "agent"
    monkeypatch.setenv("ZS_MODE", "bogus")
    with pytest.raises(SystemExit):
        A.Agent()


# ----------------------------------------------------------------------------- registry
def test_parse_ref_follows_docker_rules():
    assert CI.parse_ref("alpine").label == "docker.io/library/alpine:latest"
    assert CI.parse_ref("alpine").api_host == "registry-1.docker.io"
    assert CI.parse_ref("bitnami/redis:7.2").repository == "bitnami/redis"
    r = CI.parse_ref("registry.corp:5000/team/app@sha256:" + "a" * 64)
    assert (r.registry, r.repository, r.reference) == ("registry.corp:5000", "team/app", "sha256:" + "a" * 64)
    assert CI.parse_ref("localhost/app:1").registry == "localhost"
    for bad in ("", "UPPER/app", "app:bad tag", "app@md5:00", "a/../b", "x" * 600):
        with pytest.raises(Exception):
            CI.parse_ref(bad)


def _layer(files: dict[str, bytes | None]) -> bytes:
    """A gzip'd layer tar; None writes a whiteout-style empty file (the name carries the meaning)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data or b"")
            tar.addfile(info, io.BytesIO(data or b""))
    return gzip.compress(raw.getvalue())


def test_whiteouts_hide_lower_layers_only():
    merged: dict[str, bytes | None] = {}
    CI.apply_layer(merged, CI.LayerDiff(files={"var/lib/dpkg/status": b"old", "var/lib/dpkg/status.d/a": b"a"}))
    CI.apply_layer(merged, CI.LayerDiff(files={"var/lib/dpkg/status.d/b": b"b"}, opaque=["var/lib/dpkg/status.d"]))
    assert merged == {"var/lib/dpkg/status": b"old", "var/lib/dpkg/status.d/b": b"b"}  # same-layer file survives
    CI.apply_layer(merged, CI.LayerDiff(whiteouts=["var/lib/dpkg/status"]))
    assert "var/lib/dpkg/status" not in merged


def test_read_layer_finds_inventory_files_and_whiteouts():
    blob = _layer({"var/lib/dpkg/.wh.status": None, "etc/.wh..wh..opq": None, "./var/lib/dpkg/status": b"x",
                   "usr/bin/tool": b"ignored", "../../etc/os-release": b"evil",
                   "usr/share/doc/.wh.bash": None, "srv/.wh..wh..opq": None})  # cannot hide a wanted path: dropped
    diff = CI.read_layer(io.BytesIO(gzip.decompress(blob)))
    assert diff.files == {"var/lib/dpkg/status": b"x"}
    assert diff.whiteouts == ["var/lib/dpkg/status"] and diff.opaque == ["etc"]
    assert diff.notes == {"pathTraversal": 1}


def test_a_gzip_bomb_layer_is_refused():
    bomb = gzip.compress(b"\x00" * (8 * 1024 * 1024))

    class Resp:
        def iter_raw(self, n):
            yield bomb

    stream = CI._Inflate(Resp(), len(bomb), 1024 * 1024)
    with pytest.raises(CI.ImageError, match="compression bomb"):
        stream.read(-1)


# A small registry over HTTPS: anonymous or Basic, Bearer with a token service, blobs redirected to another origin.
def _tls_pair(tmp_path: Path):
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "lab CA", ca=True)
    key = ec.generate_private_key(ec.SECP256R1())
    import ipaddress

    leaf = _cert(key, "localhost", issuer=ca.subject, issuer_key=ca_key,
                 san=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                      x509.IPAddress(ipaddress.ip_address("127.0.0.2"))])
    cert_file, key_file = tmp_path / "leaf.pem", tmp_path / "leaf.key"
    cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM).decode(), str(cert_file), str(key_file)


class Lab:
    def __init__(self, tmp_path: Path, auth: str = "anonymous", realm_host: str = "127.0.0.1",
                 redirect_blobs: bool = False):
        self.ca_pem, cert, key = _tls_pair(tmp_path)
        self.auth, self.realm_host, self.redirect_blobs = auth, realm_host, redirect_blobs
        self.seen: list[tuple[str, str, str | None]] = []  # (server, path, Authorization)
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, bytes] = {}
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(cert, key)
        self.registry = self._serve("127.0.0.1", tls, "registry")
        self.other = self._serve("127.0.0.2", tls, "other")

    def _serve(self, host: str, tls: ssl.SSLContext, name: str):
        lab = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", headers=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                auth = self.headers.get("Authorization")
                lab.seen.append((name, self.path, auth))
                if self.path.startswith("/token"):
                    return self._send(200, json.dumps({"token": "tok-" + ("cred" if auth else "anon")}).encode())
                if name == "other" and self.path.startswith("/cdn/"):
                    return self._send(200, lab.blobs[self.path[5:]])
                ok = (lab.auth == "anonymous" or
                      (lab.auth == "basic" and auth == "Basic " + base64.b64encode(b"u:p").decode()) or
                      (lab.auth == "bearer" and auth and auth.startswith("Bearer tok-")))
                if not ok:
                    challenge = ('Basic realm="lab"' if lab.auth == "basic" else
                                 f'Bearer realm="https://{lab.realm_host}:{lab.port_of(lab.realm_host)}/token",'
                                 'service="lab",scope="repository:team/app:pull"')
                    return self._send(401, b"{}", {"WWW-Authenticate": challenge})
                if "/manifests/" in self.path:
                    ref = self.path.rsplit("/", 1)[-1]
                    body = lab.manifests.get(ref)
                    if body is None:
                        return self._send(404, b"{}")
                    media = json.loads(body).get("mediaType", "application/vnd.oci.image.manifest.v1+json")
                    return self._send(200, body, {"Content-Type": media})
                if "/blobs/" in self.path:
                    digest = self.path.rsplit("/", 1)[-1]
                    if lab.redirect_blobs:
                        return self._send(307, b"", {"Location": f"https://127.0.0.2:{lab.other.server_port}/cdn/{digest}"})
                    return self._send(200, lab.blobs[digest])
                return self._send(404)

        server = ThreadingHTTPServer((host, 0), H)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def port_of(self, host: str) -> int:
        return self.other.server_port if host == "127.0.0.2" else self.registry.server_port

    def push(self, tag: str, layers: list[bytes], index: bool = False, tamper: str | None = None) -> None:
        descs = []
        for blob in layers:
            digest = "sha256:" + hashlib.sha256(blob).hexdigest()
            # "append": one byte more than the descriptor says; "flip": same size, another gzip MTIME (still inflates)
            self.blobs[digest] = (blob + b"x" if tamper == "append" else
                                  blob[:4] + bytes([blob[4] ^ 1]) + blob[5:] if tamper == "flip" else blob)
            descs.append({"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": digest,
                          "size": len(blob)})
        manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                               "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                          "digest": "sha256:" + "0" * 64, "size": 2}, "layers": descs}).encode()
        mdigest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        self.manifests[mdigest] = manifest
        if index:
            idx = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "1" * 64, "size": 1,
                 "platform": {"os": "linux", "architecture": "arm64"}},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": mdigest, "size": len(manifest),
                 "platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
            self.manifests[tag] = idx
        else:
            self.manifests[tag] = manifest

    def close(self):
        for s in (self.registry, self.other):
            s.shutdown()
            s.server_close()


OLD = DPKG.replace("3.0.2-0ubuntu1.10", "1.1.1f-1ubuntu2").replace("libssl3", "libssl1.1")
RELEASE = b'ID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'


def _image_layers() -> list[bytes]:
    return [_layer({"usr/lib/os-release": RELEASE, "var/lib/dpkg/status": OLD.encode(), "etc/ssl/x": b"-"}),
            _layer({"var/lib/dpkg/.wh.status": None}),  # whiteout: the old database is gone
            _layer({"var/lib/dpkg/status": DPKG.encode()})]


def _collect(lab: Lab, image: str, creds: dict | None = None, ctx: JobContext | None = None, monkeypatch=None):
    ctx = ctx or _ctx()
    cfg = {"images": [image], "credential_type": "vault" if creds else "anonymous", "ca_pem": lab.ca_pem}
    if creds:
        cfg["vault"] = {"provider": "hashicorp", "path": "secret/zs/registry"}
        from zs_scan_node import vault

        monkeypatch.setattr(vault, "fetch", lambda provider, path, prefix, timeout=10.0: dict(creds))
    status, error, _ = run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "container_images", "config": cfg,
                                                                       "secrets": {}})
    ctx.flush()
    return status, error, ctx


@pytest.fixture()
def lab_factory(tmp_path):
    labs = []

    def make(**kw):
        lab = Lab(tmp_path, **kw)
        labs.append(lab)
        return lab

    yield make
    for lab in labs:
        lab.close()


def test_pull_applies_layers_and_whiteouts_and_emits_purls(lab_factory):
    lab = lab_factory()
    lab.push("1.0", _image_layers(), index=True)
    image = f"localhost:{lab.registry.server_port}/team/app:1.0"
    status, error, ctx = _collect(lab, image)
    assert status == "success", (error, ctx.outcomes)
    libs = {r["name"]: r["facts"] for r in ctx.collected if r["type"] == "crypto_library"}
    assert set(libs) == {"libssl3", "openssl"}  # the whited-out libssl1.1 database is not reported
    assert libs["libssl3"]["purl"] == "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-20.04"
    assert libs["libssl3"]["image"] == image and libs["libssl3"]["image_digest"].startswith("sha256:")
    assert all(r["target"] == image for r in ctx.collected)
    assert ctx.outcomes[0].status == "ok"


def test_a_layer_that_does_not_match_its_digest_is_not_used(lab_factory):
    lab = lab_factory()
    lab.push("bad", _image_layers(), tamper="flip")
    status, _error, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:bad")
    assert status == "failure" and not [r for r in ctx.collected if r["type"] == "crypto_library"]
    assert "digest" in (ctx.outcomes[0].error or "")
    lab.push("long", _image_layers(), tamper="append")  # refused as soon as the extra byte arrives
    status, _error, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:long")
    assert status == "failure" and not [r for r in ctx.collected if r["type"] == "crypto_library"]
    assert "larger than its descriptor" in (ctx.outcomes[0].error or "")


def test_credentials_go_to_a_same_origin_token_service(lab_factory, monkeypatch):
    lab = lab_factory(auth="bearer", realm_host="localhost")  # same origin as the image reference
    lab.push("1.0", _image_layers())
    status, _e, _ctx2 = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:1.0",
                                 creds={"username": "u", "password": "p"}, monkeypatch=monkeypatch)
    assert status == "success"
    token_calls = [s for s in lab.seen if s[1].startswith("/token")]
    assert token_calls and token_calls[0][2] == "Basic " + base64.b64encode(b"u:p").decode()


def test_a_token_service_on_another_host_never_receives_credentials(lab_factory, monkeypatch):
    lab = lab_factory(auth="bearer", realm_host="127.0.0.2")
    lab.push("1.0", _image_layers())
    status, _e, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:1.0",
                               creds={"username": "u", "password": "p"}, monkeypatch=monkeypatch)
    token_calls = [s for s in lab.seen if s[1].startswith("/token")]
    assert token_calls and all(auth is None for _srv, _p, auth in token_calls)  # anonymous token request
    assert status == "success"  # the lab accepts anonymous tokens
    assert all(auth is None for srv, _p, auth in lab.seen if srv == "other")
    assert any("credentials were not sent" in (o.error or "") or o.status == "ok" for o in ctx.outcomes)


def test_basic_auth_and_redirected_blobs_never_leak_the_registry_authorization(lab_factory, monkeypatch):
    lab = lab_factory(auth="basic", redirect_blobs=True)
    lab.push("1.0", _image_layers())
    status, error, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:1.0",
                                  creds={"username": "u", "password": "p"}, monkeypatch=monkeypatch)
    assert status == "success", error
    cdn = [s for s in lab.seen if s[0] == "other"]
    assert cdn and all(auth is None for _s, _p, auth in cdn)


def test_never_scan_applies_to_the_registry_and_to_redirect_targets(lab_factory):
    lab = lab_factory(redirect_blobs=True)
    lab.push("1.0", _image_layers())
    # a skipped image is not a failure of the job (the never-scan list did what it should)
    _s, _e, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:1.0", ctx=_ctx(never=["127.0.0.2"]))
    assert ctx.outcomes[0].status == "skipped_never_scan" and "127.0.0.2" in ctx.outcomes[0].error
    assert not [s for s in lab.seen if s[0] == "other"]  # the redirect target was never contacted
    _s, _e, ctx = _collect(lab, f"localhost:{lab.registry.server_port}/team/app:1.0", ctx=_ctx(never=["127.0.0.1"]))
    assert ctx.outcomes[0].status == "skipped_never_scan"
    assert not [s for s in lab.seen if s[0] == "other"]


def test_image_size_cap_is_checked_before_download(lab_factory):
    lab = lab_factory()
    lab.push("big", _image_layers())
    ctx = _ctx()
    cfg = {"images": [f"localhost:{lab.registry.server_port}/team/app:big"], "ca_pem": lab.ca_pem}
    reg = CI.Registry(ctx, CI.parse_ref(cfg["images"][0]), {}, lab.ca_pem)
    with pytest.raises(CI.ImageError, match="cap"):
        CI.pull(reg, 10)
    reg.close()
    assert not [s for s in lab.seen if "/blobs/" in s[1]]


def test_an_untrusted_registry_certificate_is_refused(lab_factory):
    lab = lab_factory()
    lab.push("1.0", _image_layers())
    ctx = _ctx()
    cfg = {"images": [f"localhost:{lab.registry.server_port}/team/app:1.0"]}  # no ca_pem: public trust only
    status, _e, _ = run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "container_images", "config": cfg,
                                                                    "secrets": {}})
    assert status == "failure" and ctx.outcomes[0].status in ("tls_unavailable", "error")


def test_an_application_ca_bundle_is_one_trust_store_row_but_a_chain_file_is_not(tmp_path, monkeypatch):
    """AWS lab, round 5: the host agent on a real Ubuntu VM reported AWS CLI v2's botocore/cacert.pem as 126
    certificate rows, 16 of them "expired" roots.  A bundle of CA roots is a trust store whatever its file name; an
    operator's chain file (leaf + intermediate + root) keeps a row per certificate."""
    root = _host_root(tmp_path)
    bundle_dir = root / "usr/local/aws-cli/v2/dist/awscli/botocore"
    bundle_dir.mkdir(parents=True)
    roots = []
    for i in range(6):
        k = ec.generate_private_key(ec.SECP256R1())
        roots.append(_cert(k, f"Public Root {i}", ca=True).public_bytes(serialization.Encoding.PEM))
    (bundle_dir / "cacert.pem").write_bytes(b"".join(roots))
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = _cert(ca_key, "Internal Root", ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(leaf_key, "svc.internal", issuer=ca.subject, issuer_key=ca_key)
    (root / "opt/app/chain.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) +
                                            ca.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("ZS_HOST_ROOT", str(root))
    monkeypatch.delenv("ZS_HOST_PROC", raising=False)
    ctx = _ctx(agent=True)
    status, error, _ = run_job(ctx, {"id": 1, "kind": "collect"}, {}, {"kind": "host_agent", "config": {}, "secrets": {}})
    ctx.flush()
    assert (status, error) == ("success", None), error
    certs = [r for r in ctx.collected if r["type"] == "certificate"]
    bundle = [r for r in certs if r["location"].startswith("/usr/local/aws-cli")]
    assert len(bundle) == 1 and bundle[0]["facts"]["trust_store"] is True and bundle[0]["facts"]["count"] == 6
    assert sorted(r["location"] for r in certs if r["location"].startswith("/opt/app/chain.pem")) == \
        ["/opt/app/chain.pem#0", "/opt/app/chain.pem#1"]


def test_is_ca_bundle_needs_five_ca_roots():
    from zs_scan_node import linux_parsers as P

    roots = [{"is_ca": True, "self_signed": True}] * 5
    assert P.is_ca_bundle(roots)
    assert not P.is_ca_bundle(roots[:4])
    assert not P.is_ca_bundle(roots + [{"is_ca": False, "self_signed": False}])  # a leaf: an operator's file
    assert not P.is_ca_bundle([{"is_ca": True, "self_signed": False}] * 6)  # intermediates only
