"""Scan-node downloads (routers/cbom_node_artifacts.py): a customer with no repository access and no registry gets the
node image file, its .sha256, the Helm chart and the OVA/AMI build kits from this server, as a member of the team.

Checked against the real app and the real routes: team-scoped auth (header or short-lived link), the bytes streamed
are the file's (sha256 and Content-Length match the listing), a missing file is a 404 with the sentence the wizard
shows, and every download is an audit event."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest
from sqlmodel import Session, select

from test_cbom_sources_api import api, world  # noqa: F401  (fixtures)
from backend.new_models import CbomCollectionAuditEvent
from backend.routers import cbom_node_artifacts as NA

VERSION = "1.0.0"
REPO = Path(__file__).resolve().parents[2]


@pytest.fixture()
def artifacts(tmp_path, monkeypatch, world):  # noqa: F811
    engine, _ = world
    monkeypatch.setattr(NA, "get_db", lambda: engine)
    d = tmp_path / "node-artifacts"
    d.mkdir()
    image = d / f"scan-node-{VERSION}.tar.gz"
    image.write_bytes(os.urandom(3 * 1024 * 1024 + 17))  # several stream chunks, an odd size
    (d / f"cbom-scan-node-{VERSION}.tgz").write_bytes(b"chart" * 1000)
    (d / f"cbom-scan-node-ova-kit-{VERSION}.zip").write_bytes(b"PK-ova")
    (d / f"cbom-scan-node-ami-kit-{VERSION}.zip").write_bytes(b"PK-ami")
    (d / "manifest.json").write_text(json.dumps({
        "version": VERSION, "image_ref": f"zeroshield/cbom-scan-node:{VERSION}",
        "files": {"image": image.name, "helm-chart": f"cbom-scan-node-{VERSION}.tgz",
                  "ova-kit": f"cbom-scan-node-ova-kit-{VERSION}.zip", "ami-kit": f"cbom-scan-node-ami-kit-{VERSION}.zip"}}))
    monkeypatch.setenv("CBOM_NODE_ARTIFACT_DIR", str(d))
    monkeypatch.delenv("CBOM_NODE_IMAGE_REF", raising=False)
    return d


def _by_kind(body):
    return {a["kind"]: a for a in body["artifacts"]}


def test_listing_names_every_file_with_size_and_sha256(api, artifacts):  # noqa: F811
    r = api("GET", "/1/cbom/node-artifacts", "bob")  # a member, not an admin
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["version"] == VERSION and body["image_ref"] == f"zeroshield/cbom-scan-node:{VERSION}"
    assert body["pull_image_ref"] is None  # no registry configured: the wizard offers no docker pull
    kinds = _by_kind(body)
    assert set(kinds) == {"image", "helm-chart", "ova-kit", "ami-kit"}
    for kind in kinds.values():
        path = artifacts / kind["filename"]
        assert kind["available"] and kind["size"] == path.stat().st_size
        assert kind["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("kind", ["image", "helm-chart", "ova-kit", "ami-kit"])
def test_download_streams_the_listed_bytes(api, artifacts, kind):  # noqa: F811
    listed = _by_kind(api("GET", "/1/cbom/node-artifacts").json())[kind]
    r = api("GET", f"/1/cbom/node-artifacts/{kind}", "bob")
    assert r.status_code == 200
    assert int(r.headers["content-length"]) == listed["size"] == len(r.content)
    assert hashlib.sha256(r.content).hexdigest() == listed["sha256"]
    assert r.headers["content-disposition"] == f'attachment; filename="{listed["filename"]}"'
    assert r.headers["cache-control"] == "no-store"


def test_download_never_reads_the_file_whole(api, artifacts, monkeypatch):  # noqa: F811
    """FileResponse reads the file in chunks: no single read asks for the whole file."""
    import anyio

    sizes: list[int] = []
    real_open = anyio.open_file

    async def counting_open(*args, **kwargs):
        fh = await real_open(*args, **kwargs)
        real_read = fh.read

        async def read(n=-1):
            sizes.append(n)
            return await real_read(n)

        fh.read = read
        return fh

    monkeypatch.setattr(anyio, "open_file", counting_open)
    r = api("GET", "/1/cbom/node-artifacts/image")
    total = (artifacts / f"scan-node-{VERSION}.tar.gz").stat().st_size
    assert r.status_code == 200 and len(r.content) == total
    assert sizes and all(0 < n < total for n in sizes), sizes  # bounded chunks (Starlette's 64 KiB)
    assert len(sizes) > 10


def test_sha256_file_checks_the_downloaded_image(api, artifacts, tmp_path):  # noqa: F811
    """What the customer runs: sha256sum -c scan-node-<v>.tar.gz.sha256 next to the downloaded image."""
    image = api("GET", "/1/cbom/node-artifacts/image")
    sha = api("GET", "/1/cbom/node-artifacts/image-sha256")
    assert sha.status_code == 200
    assert sha.headers["content-disposition"] == f'attachment; filename="scan-node-{VERSION}.tar.gz.sha256"'
    out = tmp_path / "download"
    out.mkdir()
    (out / f"scan-node-{VERSION}.tar.gz").write_bytes(image.content)
    (out / f"scan-node-{VERSION}.tar.gz.sha256").write_bytes(sha.content)
    done = subprocess.run(["sha256sum", "-c", f"scan-node-{VERSION}.tar.gz.sha256"], cwd=out, capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
    (out / f"scan-node-{VERSION}.tar.gz").write_bytes(image.content[:-1] + b"x")  # a corrupted download is caught
    assert subprocess.run(["sha256sum", "-c", f"scan-node-{VERSION}.tar.gz.sha256"], cwd=out,
                          capture_output=True).returncode != 0


def test_auth_is_team_scoped(api, artifacts):  # noqa: F811
    assert api("GET", "/1/cbom/node-artifacts", None).status_code in (401, 403)
    assert api("GET", "/1/cbom/node-artifacts/image", None).status_code in (401, 403)
    assert api("GET", "/1/cbom/node-artifacts", "carol").status_code == 403  # another team's admin
    assert api("GET", "/1/cbom/node-artifacts/image", "carol").status_code == 403
    assert api("POST", "/1/cbom/node-artifacts/image/link", "carol").status_code == 403
    assert api("GET", "/1/cbom/node-artifacts/../../etc/passwd").status_code in (400, 404)
    assert api("GET", "/1/cbom/node-artifacts/manifest").status_code == 400  # not a kind


def test_download_link_works_without_a_header_and_only_for_its_team_and_kind(api, artifacts, monkeypatch):  # noqa: F811
    r = api("POST", "/1/cbom/node-artifacts/image/link", "bob")
    assert r.status_code == 200 and r.json()["expires_in"] == NA.TICKET_SECONDS
    url = r.json()["url"]
    assert url.startswith("/1/cbom/node-artifacts/image?ticket=")
    got = api("GET", url, None)  # the browser follows the link: no Authorization header
    assert got.status_code == 200 and len(got.content) == (artifacts / f"scan-node-{VERSION}.tar.gz").stat().st_size
    ticket = url.split("ticket=")[1]
    assert api("GET", f"/1/cbom/node-artifacts/helm-chart?ticket={ticket}", None).status_code == 401  # other kind
    assert api("GET", f"/2/cbom/node-artifacts/image?ticket={ticket}", None).status_code == 401  # other team
    forged = ticket.rsplit(".", 1)[0] + ".AAAA"
    refused = api("GET", f"/1/cbom/node-artifacts/image?ticket={forged}", None)
    assert refused.status_code == 401 and "expired" in refused.json()["detail"]
    # expired
    old = NA.make_ticket(1, "image", int(ticket.split(".")[0]), now=1_000_000)
    assert api("GET", f"/1/cbom/node-artifacts/image?ticket={old}", None).status_code == 401


def test_a_link_stops_working_when_the_member_leaves_the_team(api, artifacts, world):  # noqa: F811
    engine, ids = world
    url = api("POST", "/1/cbom/node-artifacts/image/link", "bob").json()["url"]
    from backend.new_models import TeamMembership

    with Session(engine) as s:
        s.delete(s.exec(select(TeamMembership).where(TeamMembership.user_id == ids["bob"])).one())
        s.commit()
    assert api("GET", url, None).status_code == 403


def test_every_download_is_audited(api, artifacts, world):  # noqa: F811
    engine, ids = world
    api("GET", "/1/cbom/node-artifacts/image", "bob")
    url = api("POST", "/1/cbom/node-artifacts/ova-kit/link", "alice").json()["url"]
    api("GET", url, None)
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.action == "node_artifact.download")
                      .order_by(CbomCollectionAuditEvent.id)).all()
    assert [(r.team_id, r.actor_type, r.actor_id, r.changed_fields) for r in rows] == [
        (1, "user", ids["bob"], ["image"]), (1, "user", ids["alice"], ["ova-kit"])]


NOT_HERE = "not available on this server yet. Contact your administrator."


def test_a_server_without_the_files_says_so(api, world, monkeypatch, tmp_path):  # noqa: F811
    monkeypatch.delenv("CBOM_NODE_ARTIFACT_DIR", raising=False)
    body = api("GET", "/1/cbom/node-artifacts").json()
    assert body["version"] is None and all(not a["available"] for a in body["artifacts"])
    assert all(a["message"].endswith(NOT_HERE) for a in body["artifacts"])
    for kind in ("image", "image-sha256", "helm-chart", "ova-kit", "ami-kit"):
        r = api("GET", f"/1/cbom/node-artifacts/{kind}")
        assert r.status_code == 404 and r.json()["detail"].endswith(NOT_HERE), r.text
        assert api("POST", f"/1/cbom/node-artifacts/{kind}/link").status_code == 404
    # a directory without a manifest, or a manifest naming a file that is not there: the same
    monkeypatch.setenv("CBOM_NODE_ARTIFACT_DIR", str(tmp_path))
    assert api("GET", "/1/cbom/node-artifacts/image").status_code == 404
    (tmp_path / "manifest.json").write_text(json.dumps({"version": "1.0.0", "files": {"image": "scan-node-1.0.0.tar.gz"}}))
    r = api("GET", "/1/cbom/node-artifacts/image")
    assert r.status_code == 404 and r.json()["detail"] == "Scan node image " + NOT_HERE.replace("not", "is not", 1)


def test_one_missing_file_leaves_the_others_available(api, artifacts):  # noqa: F811
    (artifacts / f"cbom-scan-node-ami-kit-{VERSION}.zip").unlink()
    kinds = _by_kind(api("GET", "/1/cbom/node-artifacts").json())
    assert not kinds["ami-kit"]["available"] and kinds["ami-kit"]["message"] == "AMI build kit is " + NOT_HERE
    assert kinds["image"]["available"] and kinds["ova-kit"]["available"]
    assert api("GET", "/1/cbom/node-artifacts/ova-kit").status_code == 200


@pytest.mark.parametrize("name", ["../secret.txt", "/etc/passwd", ".hidden", "sub/dir.zip", "link.zip"])
def test_manifest_names_outside_the_directory_are_refused(api, artifacts, tmp_path, name):  # noqa: F811
    outside = tmp_path / "secret.txt"
    outside.write_text("no")
    (artifacts / "link.zip").symlink_to(outside)
    manifest = json.loads((artifacts / "manifest.json").read_text())
    manifest["files"]["ami-kit"] = name
    (artifacts / "manifest.json").write_text(json.dumps(manifest))
    assert api("GET", "/1/cbom/node-artifacts/ami-kit").status_code == 404
    assert not _by_kind(api("GET", "/1/cbom/node-artifacts").json())["ami-kit"]["available"]


def test_pull_reference_only_when_configured_and_valid(api, artifacts, monkeypatch):  # noqa: F811
    monkeypatch.setenv("CBOM_NODE_IMAGE_REF", "registry.bank.example:5000/zs/cbom-scan-node:1.0.0")
    assert api("GET", "/1/cbom/node-artifacts").json()["pull_image_ref"] == "registry.bank.example:5000/zs/cbom-scan-node:1.0.0"
    for bad in ("no-tag/image", "Upper/Case:1", "x:1; rm -rf /", " "):
        monkeypatch.setenv("CBOM_NODE_IMAGE_REF", bad)
        assert api("GET", "/1/cbom/node-artifacts").json()["pull_image_ref"] is None, bad


def test_the_sha256_follows_a_replaced_file(api, artifacts):  # noqa: F811
    first = _by_kind(api("GET", "/1/cbom/node-artifacts").json())["helm-chart"]["sha256"]
    path = artifacts / f"cbom-scan-node-{VERSION}.tgz"
    path.write_bytes(b"a new chart, another size")
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000))
    second = _by_kind(api("GET", "/1/cbom/node-artifacts").json())["helm-chart"]["sha256"]
    assert second != first and second == hashlib.sha256(path.read_bytes()).hexdigest()


def test_staging_compose_mounts_the_directory_into_the_backend():
    compose = (REPO / "deploy" / "staging" / "docker-compose.yml").read_text()
    backend = compose.split("\n  backend:\n", 1)[1].split("\n  cbom-cloud-worker:", 1)[0]
    assert "CBOM_NODE_ARTIFACT_DIR: /node-artifacts" in backend
    assert ":/node-artifacts:ro" in backend
    assert "CBOM_NODE_IMAGE_REF: ${CBOM_NODE_IMAGE_REF:-}" in backend
