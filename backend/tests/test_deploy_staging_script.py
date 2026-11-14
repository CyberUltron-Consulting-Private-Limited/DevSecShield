"""scripts/deploy/staging.sh, build_images.sh and the Makefile rollback targets, with docker and curl stubbed.

The stub (FAKE_DOCKER below) is a small model of what the scripts rely on: images per tag, each backend image with its
own Alembic revisions; a Postgres whose alembic_version is a list; `compose up` that runs the migrate one-shot the way
the backend entrypoint does (`alembic upgrade head`: fails with "Can't locate revision" when the database is at a
revision the image does not know, and then nothing that waits for it starts); `compose run ... alembic downgrade`
with the current tag's image; `compose ps` / `config`; `docker run ... alembic heads|show|history` and `find`;
`docker load` of an archive (a list of the images it holds), `docker info`, `docker image ls` / `image rm`, and `df` /
`du` over a small disk model (FAKE_DISK; test_staging_deploy_disk.py uses it).
A "deploy" here is what `staging.sh push` does on the host: the release's files are put in place (each carrying a
`# release-marker: <tag>` line so the test can tell whose files are in place), then `staging.sh deploy <tag>`.

Review round 5, group B: H1 (rollback across a migration left a dead stack), M1 (deploy reported success when
`compose up` failed), L3 (the image secret check treated a failed find as "no secrets").
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(BASH is None or shutil.which("tar") is None, reason="needs bash and tar")

SERVICES = ["postgres", "mongo", "rabbitmq", "migrate", "backend", "cbom-cloud-worker", "dast-scheduler",
            "scan-worker", "cicd-worker", "dast-worker", "frontend", "nginx"]

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, re, sys
from pathlib import Path

import fakedisk

STATE = Path(os.environ["FAKE_DOCKER_STATE"])
st = json.loads(STATE.read_text())
argv = sys.argv[1:]
PREFIX = st["prefix"]
INFRA = {"postgres": "postgres:15-alpine", "mongo": "mongo:8.0.6", "rabbitmq": "rabbitmq:4.1-management-alpine",
         "nginx": "nginx:1.27-alpine"}
COMPONENT = {"migrate": "devsecshield-backend", "backend": "devsecshield-backend",
             "cbom-cloud-worker": "devsecshield-backend", "dast-scheduler": "devsecshield-backend",
             "minio-init": "devsecshield-backend", "scan-worker": "scan-worker", "cicd-worker": "scan-worker",
             "dast-worker": "dast-worker", "frontend": "devsecshield-frontend"}


def save(entry):
    entry["argv"] = argv
    st["log"].append(entry)
    STATE.write_text(json.dumps(st))


def image_tag(ref):  # tag of one of our images that exists, else None
    m = re.fullmatch(re.escape(PREFIX) + r"/(devsecshield-backend|devsecshield-frontend|scan-worker|dast-worker):(.+)", ref)
    if not m or m.group(2) not in st["tags"] or ref in st["missing"] or ref in st["gone"]:
        return None
    return m.group(2)


def image(svc, tag):
    return INFRA[svc] if svc in INFRA else f"{PREFIX}/{COMPONENT[svc]}:{tag}"


def revs(tag):
    return st["tags"][tag]["revs"]


if argv[:2] == ["image", "inspect"]:
    ok = image_tag(argv[2]) is not None or argv[2] in INFRA.values()
    save({"cmd": "inspect"})
    sys.exit(0 if ok else 1)

if argv[:1] == ["info"]:
    d = st["docker_info"]
    print(f"{d['root']}|{d['driver']}|{json.dumps(d['status'])}")
    sys.exit(0)

if argv[:2] == ["image", "ls"]:  # every image on the host, whatever the filter says: the script must pick its own
    for ref in fakedisk.present(st) + st["foreign"]:
        repo, tag = ref.rsplit(":", 1)
        print(f"{repo}\t{tag}\t{st['disk']['image_kib'] // 1000}MB")
    sys.exit(0)

if argv[:1] == ["rmi"] or argv[:2] == ["image", "rm"]:
    ref = argv[-1]
    users = [s for s, c in st["containers"].items() if c["image"] == ref]
    if users:  # docker refuses to remove an image a container (running or stopped) was created from
        save({"cmd": "rmi-refused", "ref": ref})
        print(f"Error response from daemon: conflict: unable to remove repository reference \"{ref}\" (must force)"
              f" - container {users[0]} is using its referenced image", file=sys.stderr)
        sys.exit(1)
    st["removed"].append(ref)
    if ref in st["foreign"]:
        st["foreign"].remove(ref)
    elif ref not in st["gone"]:
        st["gone"].append(ref)
    save({"cmd": "rmi", "ref": ref})
    sys.exit(0)

if argv[:1] == ["load"]:
    # The archive (Host.ship) lists the references it holds. Each image is stored, then unpacked into the image
    # store; without room, the containerd image store still tags the image, prints "Error unpacking image" and exits
    # 0 (Deploy staging run 43572299641), while the classic store fails the whole load with exit 1.
    archive = Path(argv[argv.index("-i") + 1])
    refs = json.loads(archive.read_text())
    save({"cmd": "load", "archive": archive.name})
    containerd = "io.containerd.snapshotter" in json.dumps(st["docker_info"]["status"])
    store = fakedisk.mount_of(st, st["disk"]["store"])
    for ref in refs:
        room = fakedisk.avail(st, store) >= st["disk"]["image_kib"]
        if not room and not containerd:
            STATE.write_text(json.dumps(st))
            print(f"Error processing tar file(exit status 1): write /var/lib/docker/tmp/{ref}: no space left on device",
                  file=sys.stderr)
            sys.exit(1)
        if ref in st["gone"]:
            st["gone"].remove(ref)
        if ref in st["broken"]:
            st["broken"].remove(ref)
        print(f"Loaded image: {ref}")
        if not room:
            st["broken"].append(ref)
            print(f"Error unpacking image {ref}: apply layer error for \"docker.io/{ref}\": failed to extract layer:"
                  " no space left on device")
        STATE.write_text(json.dumps(st))
    sys.exit(0)

if argv[:1] == ["buildx"]:
    save({"cmd": argv[0]})
    sys.exit(0)

if argv[:1] == ["run"]:
    i, entrypoint, user = 1, None, None
    while argv[i].startswith("-"):
        if argv[i] in ("--network", "--entrypoint", "--user"):
            if argv[i] == "--entrypoint":
                entrypoint = argv[i + 1]
            if argv[i] == "--user":
                user = argv[i + 1]
            i += 2
        else:
            i += 1
    ref, args = argv[i], argv[i + 1:]
    save({"cmd": "run", "entrypoint": entrypoint, "user": user, "image": ref})
    if entrypoint == "find":
        mode = st["find_mode"]
        if mode == "run_fail":
            print("docker: Error response from daemon: exec: \"find\": executable file not found", file=sys.stderr)
            sys.exit(127)
        if mode == "fail" and user != "0":
            print("find: '/root': Permission denied", file=sys.stderr)
            sys.exit(1)
        if mode == "fail_always":
            print("find: '/frontend': No such file or directory", file=sys.stderr)
            sys.exit(1)
        if mode == "secret" and args[0] == "/":
            print("/frontend/.env.local")
        sys.exit(0)
    if entrypoint == "test":
        sys.exit(0)
    tag = image_tag(ref)
    if tag is None:
        print(f"Unable to find image '{ref}' locally", file=sys.stderr)
        sys.exit(125)
    if ref in st["broken"]:  # tagged, but its layers were never unpacked (a load that ran out of disk)
        print("docker: Error response from daemon: failed to create prepare snapshot dir: no space left on device",
              file=sys.stderr)
        sys.exit(125)
    sub = args[args.index("--config") + 2:]
    if sub[0] == "heads":
        print(f"{revs(tag)[-1]} (head)")
        sys.exit(0)
    if sub[0] == "show":
        if sub[1] in revs(tag):
            print(f"Rev: {sub[1]}")
            sys.exit(0)
        print(f"FAILED: Can't locate revision identified by '{sub[1]}'", file=sys.stderr)
        sys.exit(255)
    if sub[0] == "history":
        print(f"history {sub[2]}")
        sys.exit(0)
    sys.exit(2)

if argv[:1] == ["compose"]:
    project = Path(argv[argv.index("--project-directory") + 1])
    compose_file = Path(argv[argv.index("-f") + 1])
    rest = argv[argv.index("-f") + 2:]
    tag = os.environ.get("DSS_TAG")
    if tag is None:  # compose reads .env when the variable is not in the environment
        found = re.findall(r"^DSS_TAG=(.*)$", (project / ".env").read_text(), re.M)
        tag = found[-1] if found else ""
    marker = re.search(r"# release-marker: (\S+)", compose_file.read_text())
    marker = marker.group(1) if marker else None
    sub, opts = rest[0], rest[1:]
    if sub == "config" and "--services" in opts:
        print("\n".join(st["services"]))
        sys.exit(0)
    if sub == "ps":
        fmt = opts[opts.index("--format") + 1]
        for svc, c in st["containers"].items():
            if "|" in fmt:
                print(f"{svc}|{c['image']}|{c['state']}|{c['health']}|{c['exit']}")
            else:
                print(f"{svc}  {c['image']}  {c['state']}")
        sys.exit(0)
    if sub == "exec":
        sys.stdin.read()
        if st.get("db_down"):
            print("service \"postgres\" is not running", file=sys.stderr)
            sys.exit(1)
        print("\n".join(st["db"]))
        sys.exit(0)
    if sub == "stop":
        for svc in opts:
            if svc in st["containers"] and st["containers"][svc]["state"] == "running":
                st["containers"][svc].update(state="exited", health="", exit=0)
        save({"cmd": "stop", "tag": tag, "services": opts})
        sys.exit(0)
    if sub == "run":
        target = opts[-1]
        save({"cmd": "downgrade", "tag": tag, "target": target, "marker": marker})
        known = revs(tag)
        if st.get("fail_downgrade") or target not in known or st["db"][0] not in known \
                or known.index(target) > known.index(st["db"][0]):
            print(f"FAILED: downgrade to {target} failed", file=sys.stderr)
            sys.exit(255)
        st["db"] = [target]
        STATE.write_text(json.dumps(st))
        sys.exit(0)
    if sub == "up":
        names, i = [], 0
        while i < len(opts):
            if opts[i] == "--wait-timeout":
                i += 2
                continue
            if not opts[i].startswith("-"):
                names.append(opts[i])
            i += 1
        if names == ["postgres"]:
            st["containers"]["postgres"] = {"image": INFRA["postgres"], "state": "running", "health": "healthy", "exit": 0}
            save({"cmd": "up-postgres", "tag": tag})
            sys.exit(0)
        entry = {"cmd": "up", "tag": tag, "marker": marker, "db_before": list(st["db"]), "services": names}
        if st.get("fail_up"):
            save(entry)
            print("dependency failed to start: container frontend is unhealthy", file=sys.stderr)
            sys.exit(1)
        if image_tag(image("backend", tag)) is None:
            save(entry)
            print(f"pull access denied for {image('backend', tag)}", file=sys.stderr)
            sys.exit(1)
        if any(r not in revs(tag) for r in st["db"]):  # migrate: alembic upgrade head
            st["containers"]["migrate"] = {"image": image("migrate", tag), "state": "exited", "health": "", "exit": 255}
            for svc in ("backend", "cbom-cloud-worker", "dast-scheduler"):
                st["containers"][svc] = {"image": image(svc, tag), "state": "created", "health": "", "exit": 0}
            save(entry)
            print(f"FAILED: Can't locate revision identified by '{st['db'][0]}'", file=sys.stderr)
            print("service \"migrate\" didn't complete successfully: exit 255", file=sys.stderr)
            sys.exit(1)
        st["db"] = [revs(tag)[-1]]
        for svc in st["services"]:
            if names and svc not in names:  # `compose up <services>` starts only those
                continue
            c = {"image": image(svc, tag), "state": "running", "health": "healthy" if svc in (
                "postgres", "mongo", "rabbitmq", "backend", "frontend", "nginx") else "", "exit": 0}
            if svc == "migrate":
                c.update(state="exited", health="")
            st["containers"][svc] = c
        save(entry)
        sys.exit(0)
    sys.exit(3)

print(f"fake docker: unhandled {argv}", file=sys.stderr)
sys.exit(4)
'''

# The disk model shared by the docker, df and du stubs: each mount has a size; the archives in deploy/staging/images use
# the mount that holds that directory (their size from file_kib, else their real size), and every image on the host
# that is unpacked (ours and foreign ones) uses image_kib on the mount that holds the image store.
FAKE_DISK = r'''import json, os
from pathlib import Path

REPOS = ("devsecshield-backend", "devsecshield-frontend", "scan-worker", "dast-worker")


def load():
    path = Path(os.environ["FAKE_DOCKER_STATE"])
    return path, json.loads(path.read_text())


def present(st):  # our images on the host (unpacked or not)
    return [f"{st['prefix']}/{r}:{t}" for t in st["tags"] for r in REPOS
            if f"{st['prefix']}/{r}:{t}" not in st["missing"] and f"{st['prefix']}/{r}:{t}" not in st["gone"]]


def mount_of(st, path):
    p = os.path.abspath(path)
    found = [m for m in st["disk"]["mounts"] if p == m or p.startswith(m.rstrip("/") + "/")]
    return max(found, key=len) if found else None


def file_kib(st, f):
    f = Path(f)
    return st["disk"]["file_kib"].get(f.name, -(-f.stat().st_size // 1024))


def avail(st, mount):
    d, used = st["disk"], 0
    images = Path(d["images_dir"])
    if mount_of(st, images) == mount and images.is_dir():
        used += sum(file_kib(st, f) for f in images.iterdir() if f.is_file())
    if mount_of(st, d["store"]) == mount:
        used += d["image_kib"] * (len([r for r in present(st) if r not in st["broken"]]) + len(st["foreign"]))
    return d["mounts"][mount] - used
'''

FAKE_DF = r'''#!/usr/bin/env python3
import sys
import fakedisk

_, st = fakedisk.load()
path = sys.argv[-1]
mount = fakedisk.mount_of(st, path)
if mount is None:
    print(f"df: {path}: No such file or directory", file=sys.stderr)
    sys.exit(1)
total = st["disk"]["mounts"][mount]
free = max(0, fakedisk.avail(st, mount))
print("Filesystem     1024-blocks      Used Available Capacity Mounted on")
print(f"/dev/fake {total} {total - free} {free} 50% {mount}")
'''

FAKE_DU = r'''#!/usr/bin/env python3
import sys
import fakedisk

_, st = fakedisk.load()
for f in [a for a in sys.argv[1:] if not a.startswith("-")]:
    print(f"{fakedisk.file_kib(st, f)}\t{f}")
'''

# Healthy API and a production login page whose chunk carries the API host.
FAKE_CURL = r'''#!/usr/bin/env bash
out=""; url=""; while (($#)); do case "$1" in -o) out=$2; shift 2;; -w|--max-time|--resolve|--noproxy) shift 2;; -*) shift;; *) url=$1; shift;; esac; done
case "$url" in
  */health) echo '{"status":"healthy"}' > "$out";;
  */login) echo '<script src="/_next/static/chunks/app-1.js"></script>' > "$out";;
  *.js) echo 'fetch("https://devsec-staging-api.zeroshield.ai")' > "$out";;
esac
printf 200
'''

MARKED = ("deploy/staging/docker-compose.yml", "scripts/deploy/staging.sh")


class Host:
    """A staging host directory (as `staging.sh push` leaves it) with docker and curl stubbed."""

    def __init__(self, root: Path, tags: dict[str, list[str]]):
        self.root = root
        for rel in ("scripts/deploy/staging.sh", "scripts/deploy/build_images.sh", "deploy/staging/docker-compose.yml"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, root / rel)
        shutil.copytree(ROOT / "deploy/staging/nginx", root / "deploy/staging/nginx")
        shutil.copytree(ROOT / "compose/aibom-config-overlay", root / "compose/aibom-config-overlay")
        (root / "deploy/staging/.env").write_text(
            "DSS_IMAGE_PREFIX=dss-staging\nFRONTEND_HOST=devsec-staging.zeroshield.ai\n"
            "API_HOST=devsec-staging-api.zeroshield.ai\n")
        (root / "deploy/staging/backend.env").write_text("JWT_SECRET_KEY=test-only-not-a-secret\n")
        (root / "prod_database_migrations").mkdir()
        (root / "prod_database_migrations/alembic.ini").write_text("[alembic]\n")
        (root / "bin").mkdir()
        for name, text in (("docker", FAKE_DOCKER), ("curl", FAKE_CURL), ("df", FAKE_DF), ("du", FAKE_DU)):
            (root / "bin" / name).write_text(text)
            (root / "bin" / name).chmod(0o755)
        (root / "bin/fakedisk.py").write_text(FAKE_DISK)
        self.images_dir = root / "deploy/staging/images"
        self.store = root / "var/lib/containerd"  # the containerd image store (STAGING_CONTAINERD_ROOT)
        self.store.mkdir(parents=True)
        self.state_file = root / "docker-state.json"
        self.state_file.write_text(json.dumps({
            "prefix": "dss-staging", "services": SERVICES, "tags": {t: {"revs": r} for t, r in tags.items()},
            "missing": [], "gone": [], "broken": [], "foreign": [], "db": [], "containers": {}, "log": [],
            "removed": [], "find_mode": "clean",
            "docker_info": {"root": str(root / "var/lib/docker"), "driver": "overlayfs",
                            "status": [["driver-type", "io.containerd.snapshotter.v1"]]},
            # one roomy filesystem by default; image_kib per unpacked image
            "disk": {"mounts": {str(root): 10**10}, "images_dir": str(self.images_dir), "store": str(self.store),
                     "image_kib": 1000, "file_kib": {}}}))

    # ---- state
    @property
    def state(self) -> dict:
        return json.loads(self.state_file.read_text())

    def update(self, **changes) -> None:
        st = self.state
        st.update(changes)
        self.state_file.write_text(json.dumps(st))

    def log_since(self, mark: int) -> list[dict]:
        return self.state["log"][mark:]

    def env_tag(self) -> str:
        lines = [ln for ln in (self.root / "deploy/staging/.env").read_text().splitlines() if ln.startswith("DSS_TAG=")]
        return lines[-1].split("=", 1)[1]

    def marker_in_place(self, rel: str) -> str | None:
        found = [ln for ln in (self.root / rel).read_text().splitlines() if ln.startswith("# release-marker: ")]
        return found[-1].split(": ", 1)[1] if found else None

    def history(self) -> list[str]:
        return (self.root / "deploy/staging/deploy-history").read_text().splitlines()

    # ---- commands
    def run(self, script: str, *args: str, env: dict | None = None, typed: str | None = None) -> subprocess.CompletedProcess:
        """Runs a script; stdin is /dev/null, or with `typed` a terminal on which that line is typed."""
        full_env = {"PATH": f"{self.root / 'bin'}:{os.environ['PATH']}", "HOME": str(self.root),
                    "TMPDIR": str(self.root), "LANG": "C", "FAKE_DOCKER_STATE": str(self.state_file),
                    "STAGING_CONTAINERD_ROOT": str(self.store)}
        full_env.update(env or {})
        cmd = [BASH, str(self.root / "scripts/deploy" / script), *args]
        if typed is None:
            return subprocess.run(cmd, cwd=self.root, env=full_env, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=120)
        primary, terminal = os.openpty()
        try:
            os.write(primary, typed.encode() + b"\n")  # buffered by the terminal until the script reads it
            return subprocess.run(cmd, cwd=self.root, env=full_env, stdin=terminal, capture_output=True, text=True,
                                  timeout=120)
        finally:
            os.close(primary)
            os.close(terminal)

    def staging(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return self.run("staging.sh", *args, **kw)

    def archive(self, tag: str) -> Path:
        """The image archive of <tag> as `staging.sh push` copies it: here a list of the images it holds (every
        image of the tag but those the test declared never shipped, `missing`), with its .sha256."""
        st = self.state
        refs = [f"dss-staging/{r}:{tag}" for r in ("devsecshield-backend", "devsecshield-frontend", "scan-worker",
                                                    "dast-worker")]
        self.images_dir.mkdir(parents=True, exist_ok=True)
        path = self.images_dir / f"dss-staging-{tag}.tar.gz"
        path.write_text(json.dumps([r for r in refs if r not in st["missing"]]))
        digest = subprocess.run(["sha256sum", path.name], cwd=self.images_dir, check=True, capture_output=True,
                                text=True).stdout
        (self.images_dir / f"{path.name}.sha256").write_text(digest)
        return path

    def ship(self, tag: str, env: dict | None = None) -> subprocess.CompletedProcess:
        """What `staging.sh push` does on the host: the release's files and archive in place, then
        `staging.sh deploy <tag>`."""
        for rel in MARKED:
            (self.root / rel).write_text((ROOT / rel).read_text() + f"\n# release-marker: {tag}\n")
        (self.root / "deploy/staging/releases/files-tag").unlink(missing_ok=True)
        self.archive(tag)
        return self.staging("deploy", tag, env=env)


def ok(proc: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    assert proc.returncode == 0, f"exit {proc.returncode}\n--- stdout\n{proc.stdout}\n--- stderr\n{proc.stderr}"
    return proc


def failed(proc: subprocess.CompletedProcess) -> subprocess.CompletedProcess:
    assert proc.returncode != 0, f"unexpected success\n--- stdout\n{proc.stdout}\n--- stderr\n{proc.stderr}"
    return proc


def running_tags(host: Host) -> set[str]:
    cs = host.state["containers"]
    return {c["image"].rsplit(":", 1)[1] for c in cs.values() if c["image"].startswith("dss-staging/")}


@pytest.fixture
def two_releases(tmp_path):
    """t1 (migrations r1, r2) deployed, then t2 (adds r3) deployed: the database is at r3."""
    host = Host(tmp_path, {"t1": ["r1", "r2"], "t2": ["r1", "r2", "r3"]})
    ok(host.ship("t1"))
    ok(host.ship("t2"))
    assert host.state["db"] == ["r3"] and host.env_tag() == "t2"
    return host


# ------------------------------------------------------------------------------------------------ H1: rollback
def test_rollback_across_a_migration_needs_consent_and_changes_nothing_without_it(two_releases):
    host = two_releases
    mark = len(host.state["log"])
    proc = failed(host.staging("rollback"))  # stdin is not a terminal: no prompt possible
    assert "--allow-downgrade" in proc.stderr and "DROPS" in proc.stderr
    assert host.env_tag() == "t2" and host.state["db"] == ["r3"]
    assert host.marker_in_place("deploy/staging/docker-compose.yml") == "t2"
    assert not [e for e in host.log_since(mark) if e["cmd"] in ("stop", "downgrade", "up")]
    assert running_tags(host) == {"t2"}


def test_rollback_across_a_migration_steps_the_database_down_with_the_newer_image(two_releases):
    host = two_releases
    mark = len(host.state["log"])
    ok(host.staging("rollback", "--allow-downgrade"))
    steps = [e for e in host.log_since(mark) if e["cmd"] in ("stop", "downgrade", "up")]
    assert [e["cmd"] for e in steps] == ["stop", "downgrade", "up"]
    stop, downgrade, up = steps
    assert "backend" in stop["services"] and "postgres" not in stop["services"]
    # The downgrade runs with t2's image and t2's compose file (they know both revisions) ...
    assert (downgrade["tag"], downgrade["marker"], downgrade["target"]) == ("t2", "t2", "r2")
    # ... then t1 starts with its own compose file on a database its migrate can upgrade.
    assert (up["tag"], up["marker"], up["db_before"]) == ("t1", "t1", ["r2"])
    assert host.state["db"] == ["r2"] and host.env_tag() == "t1"
    assert running_tags(host) == {"t1"}
    assert host.state["containers"]["backend"]["state"] == "running"
    for rel in MARKED:  # t1's compose file and staging.sh are back in place
        assert host.marker_in_place(rel) == "t1", rel
    assert host.history()[-1].split()[1:] == ["rollback", "t1", "previous", "t2", "alembic", "r2"]


@pytest.mark.parametrize("typed, consents", [("no", False), ("downgrade", True)])
def test_rollback_across_a_migration_asks_on_a_terminal(two_releases, typed, consents):
    host = two_releases
    proc = host.run("staging.sh", "rollback", typed=typed)
    assert (proc.returncode == 0) is consents, proc.stderr
    assert "Type 'downgrade' to continue" in proc.stderr and "history r2" in proc.stderr
    if consents:
        assert host.env_tag() == "t1" and host.state["db"] == ["r2"] and running_tags(host) == {"t1"}
    else:
        assert "aborted; nothing was changed" in proc.stderr
        assert host.env_tag() == "t2" and host.state["db"] == ["r3"] and running_tags(host) == {"t2"}


def test_rollback_is_refused_when_the_current_image_has_no_downgrade_path(two_releases):
    host = two_releases
    host.update(tags={"t1": {"revs": ["r1", "r2"]}, "t2": {"revs": ["s1", "r3"]}})  # t2's migrations were squashed
    (host.root / "deploy/staging/releases/t1/alembic-head").unlink()  # read from the image this time
    mark = len(host.state["log"])
    proc = failed(host.staging("rollback", "--allow-downgrade"))
    assert "no downgrade path" in proc.stderr
    assert host.env_tag() == "t2" and host.state["db"] == ["r3"] and running_tags(host) == {"t2"}
    assert not [e for e in host.log_since(mark) if e["cmd"] in ("stop", "downgrade", "up")]


def test_rollback_restarts_the_current_release_when_the_downgrade_fails(two_releases):
    host = two_releases
    host.update(fail_downgrade=True)
    mark = len(host.state["log"])
    proc = failed(host.staging("rollback", "--allow-downgrade"))
    assert "refused" in proc.stderr
    ups = [e for e in host.log_since(mark) if e["cmd"] == "up"]
    assert [(e["tag"], e["marker"]) for e in ups] == [("t2", "t2")]
    assert host.env_tag() == "t2" and host.state["db"] == ["r3"] and running_tags(host) == {"t2"}
    assert host.state["containers"]["backend"]["state"] == "running"


def test_rollback_without_a_schema_change_needs_no_downgrade(tmp_path):
    host = Host(tmp_path, {"t1": ["r1", "r2"], "t2": ["r1", "r2"]})
    ok(host.ship("t1"))
    ok(host.ship("t2"))
    mark = len(host.state["log"])
    ok(host.staging("rollback"))
    assert not [e for e in host.log_since(mark) if e["cmd"] in ("stop", "downgrade")]
    assert host.env_tag() == "t1" and running_tags(host) == {"t1"}
    assert host.marker_in_place("deploy/staging/docker-compose.yml") == "t1"


def test_rollback_is_refused_when_the_previous_images_are_gone(two_releases):
    host = two_releases
    host.update(missing=["dss-staging/devsecshield-frontend:t1"])
    proc = failed(host.staging("rollback", "--allow-downgrade"))
    assert "no longer on this host" in proc.stderr
    assert host.env_tag() == "t2" and host.state["db"] == ["r3"]


def test_deploy_refuses_a_tag_whose_migrations_do_not_know_the_database(two_releases):
    host = two_releases
    mark = len(host.state["log"])
    proc = failed(host.ship("t1"))
    assert "do not contain" in proc.stderr and "staging.sh rollback" in proc.stderr
    assert host.env_tag() == "t2" and running_tags(host) == {"t2"}
    assert not [e for e in host.log_since(mark) if e["cmd"] == "up"]


def test_deploy_after_a_rollback_puts_the_newer_files_back(tmp_path):
    host = Host(tmp_path, {"t1": ["r1", "r2"], "t2": ["r1", "r2"]})
    ok(host.ship("t1"))
    ok(host.ship("t2"))
    ok(host.staging("rollback"))
    assert host.marker_in_place("deploy/staging/docker-compose.yml") == "t1"
    mark = len(host.state["log"])
    ok(host.staging("deploy", "t2"))  # on the host, no new bundle
    up = [e for e in host.log_since(mark) if e["cmd"] == "up"]
    assert [(e["tag"], e["marker"]) for e in up] == [("t2", "t2")]
    for rel in MARKED:
        assert host.marker_in_place(rel) == "t2", rel


def test_redeploying_the_running_tag_keeps_its_rollback_target(tmp_path):
    host = Host(tmp_path, {"t1": ["r1", "r2"], "t2": ["r1", "r2"]})
    ok(host.ship("t1"))
    ok(host.ship("t2"))
    ok(host.ship("t2"))
    assert host.history()[-1].split()[1:5] == ["deploy", "t2", "previous", "t1"]
    ok(host.staging("rollback"))
    assert host.env_tag() == "t1"


# ------------------------------------------------------------------------------------------------ M1: deploy status
def test_deploy_reports_a_failed_compose_up(tmp_path):
    host = Host(tmp_path, {"t1": ["r1", "r2"], "t2": ["r1", "r2", "r3"]})
    ok(host.ship("t1"))
    host.update(fail_up=True)
    proc = failed(host.ship("t2"))
    assert "compose up failed for t2" in proc.stderr
    assert "deployed t2" not in proc.stdout
    assert host.history()[-1].endswith("FAILED") and " deploy t2 previous t1 " in host.history()[-1]


def test_rollback_after_a_failed_deploy_goes_back_to_the_running_release(tmp_path):
    host = Host(tmp_path, {"t1": ["r1", "r2"], "t2": ["r1", "r2", "r3"]})
    ok(host.ship("t1"))
    host.update(fail_up=True)
    failed(host.ship("t2"))
    host.update(fail_up=False)
    ok(host.staging("rollback"))
    assert host.env_tag() == "t1" and running_tags(host) == {"t1"}
    assert host.marker_in_place("deploy/staging/docker-compose.yml") == "t1"


@pytest.mark.parametrize("service, change, message", [
    ("backend", {"image": "dss-staging/devsecshield-backend:t0"}, "FAIL backend: runs dss-staging/devsecshield-backend:t0"),
    ("backend", {"health": "unhealthy"}, "FAIL backend: running (unhealthy)"),
    ("scan-worker", {"state": "restarting"}, "FAIL scan-worker: restarting"),
    ("migrate", {"exit": 1}, "FAIL migrate: exited (exit 1)"),
    ("dast-worker", None, "FAIL dast-worker: no container"),
])
def test_check_fails_unless_every_service_runs_the_tag_and_is_up(tmp_path, service, change, message):
    host = Host(tmp_path, {"t1": ["r1"]})
    ok(host.ship("t1"))
    ok(host.staging("check"))
    containers = host.state["containers"]
    if change is None:
        del containers[service]
    else:
        containers[service].update(change)
    host.update(containers=containers)
    proc = failed(host.staging("check"))
    assert message in proc.stdout and "not every service runs t1" in proc.stderr


# ------------------------------------------------------------------------------------------------ STAGING_SERVICES
CORE = "postgres mongo rabbitmq migrate backend frontend nginx"


def worker_images(tag: str) -> list[str]:
    return [f"dss-staging/scan-worker:{tag}", f"dss-staging/dast-worker:{tag}"]


def test_check_and_rollback_keep_the_services_a_partial_deploy_started(tmp_path):
    """Found releasing to a stand-in host (round 5, L1): `make deploy-staging` with STAGING_SERVICES started the core
    services and passed its own check, then `make check-staging` failed on the workers left out on purpose
    ("FAIL scan-worker: no container") and `make rollback-staging` refused because their images were never shipped:
    neither target passes STAGING_SERVICES over ssh. The deploy now records the set it started, per tag."""
    host = Host(tmp_path, {"t1": ["r1"], "t2": ["r1"]})
    host.update(missing=worker_images("t1") + worker_images("t2"))
    partial = {"STAGING_SERVICES": CORE}
    ok(host.ship("t1", env=partial))
    ok(host.ship("t2", env=partial))
    assert set(host.state["containers"]) == set(CORE.split())
    proc = ok(host.staging("check"))  # what `make check-staging` runs: no STAGING_SERVICES
    assert "FAIL" not in proc.stdout and "deployed with" in proc.stdout
    mark = len(host.state["log"])
    ok(host.staging("rollback"))  # what `make rollback-staging` runs
    up = [e for e in host.log_since(mark) if e["cmd"] == "up"]
    assert len(up) == 1 and sorted(up[0]["services"]) == sorted(CORE.split())
    assert host.env_tag() == "t1" and running_tags(host) == {"t1"}


def test_a_full_deploy_after_a_partial_one_checks_every_service(tmp_path):
    host = Host(tmp_path, {"t1": ["r1"], "t2": ["r1"]})
    host.update(missing=worker_images("t1"))
    ok(host.ship("t1", env={"STAGING_SERVICES": CORE.replace(" ", ",")}))
    ok(host.ship("t2"))
    ok(host.staging("check"))
    containers = host.state["containers"]
    del containers["dast-worker"]
    host.update(containers=containers)
    proc = failed(host.staging("check"))
    assert "FAIL dast-worker: no container" in proc.stdout


# ------------------------------------------------------------------------------------------------ Makefile
def make_n(*args: str) -> str:
    proc = subprocess.run(["make", "-n", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=60,
                          env={**os.environ, "SSH_OPTS": ""})
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.mark.skipif(shutil.which("make") is None, reason="needs make")
def test_make_rollback_targets_pass_the_downgrade_consent_and_a_terminal():
    staging = make_n("rollback-staging", "HOST=deploy@stage")
    assert "ssh -t" in staging and "scripts/deploy/staging.sh rollback" in staging
    assert "--allow-downgrade" not in staging
    assert "staging.sh rollback --allow-downgrade" in make_n("rollback-staging", "HOST=deploy@stage", "ALLOW_DOWNGRADE=1")
    prod = make_n("rollback-prod", "HOST=deploy@prod", "ALLOW_DOWNGRADE=1")
    assert "ssh -t" in prod and "DSS_IMAGE_PREFIX=dss-prod scripts/deploy/staging.sh rollback --allow-downgrade" in prod


# ------------------------------------------------------------------------------------------------ L3: image secrets
@pytest.mark.parametrize("mode, rc_ok, message", [
    ("clean", True, "no .env, *.pem or SSH key inside"),
    ("fail", True, "no .env, *.pem or SSH key inside"),  # unreadable as the image's USER, readable as root
    ("fail_always", False, "could not check"),
    ("run_fail", False, "could not check"),
    ("secret", False, "contains secret-bearing files"),
])
def test_build_images_secret_check_runs_as_root_and_fails_closed(tmp_path, mode, rc_ok, message):
    host = Host(tmp_path, {"t1": ["r1"]})
    host.update(find_mode=mode)
    proc = host.run("build_images.sh", "--only", "frontend",
                    env={"DSS_TAG": "t1", "NEXT_PUBLIC_BACKEND_URL": "https://devsec-staging-api.zeroshield.ai"})
    assert (proc.returncode == 0) is rc_ok, proc.stderr
    assert message in proc.stdout + proc.stderr
    finds = [e for e in host.state["log"] if e["cmd"] == "run" and e["entrypoint"] == "find"]
    assert finds and all(e["user"] == "0" for e in finds)
    removed = host.state["removed"] == ["dss-staging/devsecshield-frontend:t1"]
    assert removed is (not rc_ok)


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="needs shellcheck")
def test_deploy_scripts_pass_shellcheck():
    scripts = [ROOT / "scripts/deploy" / s for s in ("staging.sh", "build_images.sh", "check_image_contexts.sh")]
    proc = subprocess.run(["shellcheck", *map(str, scripts)], capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout
