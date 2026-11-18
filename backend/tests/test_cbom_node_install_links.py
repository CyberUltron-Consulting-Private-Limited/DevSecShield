"""Install links (routers/cbom_node_artifacts.py install_links): a terminal-only host fetches the scan node files with
curl/wget straight from the one-paste install command the Add scan node wizard shows after "Create node and show
install command".

A link is bound to the team, the node, the file kind and the node's current registration token: it works exactly as
long as that token does (refused after the node registers, after the token is regenerated or the node reset, after
the token expires, and for another team or another kind), it carries nothing the registration token could be derived
from, and every use is an audit event with the node as actor. Checked against the real app and the real routes."""
from __future__ import annotations

import datetime as dt
import hashlib
import subprocess
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import update
from sqlmodel import Session, select

from test_cbom_sources_api import api, world  # noqa: F401  (fixtures)
from test_cbom_node_artifacts import VERSION, artifacts  # noqa: F401  (fixture)
from backend.new_models import CbomCollectionAuditEvent, CbomScanNode
from backend.routers import cbom_node_artifacts as NA


def _create(api, deployment="docker", team=1, who="alice", name="dc-01"):  # noqa: F811
    r = api("POST", f"/{team}/cbom/sources/nodes", who, json={"name": name, "segment": "DC", "deployment": deployment})
    assert r.status_code == 201, r.text
    return r.json()


def _enroll(api, token):  # noqa: F811
    e = api("POST", "/cbom/node/enroll", None, json={"registration_token": token, "hostname": "n1", "version": "1.0",
                                                     "source_ips": ["10.20.1.15"],
                                                     "clock": dt.datetime.utcnow().isoformat() + "Z"})
    assert e.status_code == 200, e.text


def _audit(engine, action="node_artifact.download"):
    with Session(engine) as s:
        return s.exec(select(CbomCollectionAuditEvent).where(CbomCollectionAuditEvent.action == action)
                      .order_by(CbomCollectionAuditEvent.id)).all()


REFUSED = "This install link no longer works"


@pytest.mark.parametrize("deployment,kinds", [("docker", ["image"]), ("helm", ["image", "helm-chart"]),
                                              ("ova", ["ova-kit", "image"]), ("ami", ["ami-kit", "image"])])
def test_create_returns_links_for_exactly_the_files_its_method_needs(api, artifacts, deployment, kinds):  # noqa: F811
    body = _create(api, deployment)
    links = body["install_links"]
    assert links["version"] == VERSION and links["expires_at"] == body["node"]["registration_expires_at"]
    assert [f["kind"] for f in links["files"]] == kinds
    for f in links["files"]:
        path = artifacts / f["filename"]
        assert f["size"] == path.stat().st_size and f["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert set(f) == {"kind", "filename", "size", "sha256", "url"}
        got = api("GET", f["url"], None)  # curl on the host: no Authorization header
        assert got.status_code == 200 and hashlib.sha256(got.content).hexdigest() == f["sha256"]


def test_a_docker_node_gets_the_image_and_its_sha256_only(api, artifacts):  # noqa: F811
    body = _create(api, "docker")
    (image,) = body["install_links"]["files"]
    assert image["kind"] == "image" and len(image["sha256"]) == 64
    ticket = parse_qs(urlsplit(image["url"]).query)["node_ticket"][0]
    for other in ("helm-chart", "ova-kit", "ami-kit", "image-sha256"):
        r = api("GET", f"/1/cbom/node-artifacts/{other}?node_ticket={ticket}", None)
        assert r.status_code == 401 and r.json()["detail"].startswith(REFUSED), other
    # the listing and the browser link route still need a signed-in member
    assert api("GET", f"/1/cbom/node-artifacts?node_ticket={ticket}", None).status_code in (401, 403)
    assert api("POST", f"/1/cbom/node-artifacts/image/link?node_ticket={ticket}", None).status_code in (401, 403)


def test_the_link_never_carries_the_registration_token(api, artifacts):  # noqa: F811
    body = _create(api, "helm")
    token = body["registration_token"]
    for f in body["install_links"]["files"]:
        assert token not in f["url"] and token[4:] not in f["url"]
        assert hashlib.sha256(token.encode()).hexdigest() not in f["url"]
        assert len(parse_qs(urlsplit(f["url"]).query)["node_ticket"][0]) <= NA.NODE_TICKET_MAX


def test_another_team_cannot_use_the_link(api, artifacts):  # noqa: F811
    url = _create(api)["install_links"]["files"][0]["url"]
    assert api("GET", url.replace("/1/", "/2/", 1), None).status_code == 401
    # nor a forged or another node's ticket
    ticket = parse_qs(urlsplit(url).query)["node_ticket"][0]
    node_id, sig = ticket.split(".", 1)
    other = _create(api, name="dc-02")["node"]["id"]
    for bad in (f"{other}.{sig}", f"{node_id}.AAAA", f"{node_id}.", "x.y", f"999999.{sig}"):
        r = api("GET", f"/1/cbom/node-artifacts/image?node_ticket={bad}", None)
        assert r.status_code == 401, bad


def test_the_link_stops_working_when_the_node_registers(api, artifacts):  # noqa: F811
    body = _create(api)
    url = body["install_links"]["files"][0]["url"]
    assert api("GET", url, None).status_code == 200
    _enroll(api, body["registration_token"])
    r = api("GET", url, None)
    assert r.status_code == 401 and r.json()["detail"].startswith(REFUSED)


def test_a_regenerated_token_revokes_the_old_links_and_brings_new_ones(api, artifacts):  # noqa: F811
    body = _create(api)
    old = body["install_links"]["files"][0]["url"]
    again = api("POST", f"/1/cbom/sources/nodes/{body['node']['id']}/registration-token")
    assert again.status_code == 200, again.text
    new = again.json()["install_links"]["files"][0]["url"]
    assert new != old
    assert api("GET", old, None).status_code == 401
    assert api("GET", new, None).status_code == 200


def test_a_reset_node_gets_new_links_and_its_old_ones_stay_dead(api, artifacts):  # noqa: F811
    body = _create(api)
    old = body["install_links"]["files"][0]["url"]
    _enroll(api, body["registration_token"])
    reset = api("POST", f"/1/cbom/sources/nodes/{body['node']['id']}/reset")
    assert reset.status_code == 200, reset.text
    new = reset.json()["install_links"]["files"][0]["url"]
    assert api("GET", old, None).status_code == 401
    assert api("GET", new, None).status_code == 200


def test_the_link_expires_with_the_registration_token(api, artifacts, world):  # noqa: F811
    engine, _ = world
    body = _create(api)
    url = body["install_links"]["files"][0]["url"]
    with Session(engine) as s:
        s.exec(update(CbomScanNode).where(CbomScanNode.id == body["node"]["id"])
               .values(registration_expires_at=dt.datetime.utcnow() - dt.timedelta(seconds=1)))
        s.commit()
    r = api("GET", url, None)
    assert r.status_code == 401 and r.json()["detail"].startswith(REFUSED)


def test_a_deleted_node_takes_its_links_with_it(api, artifacts):  # noqa: F811
    body = _create(api)
    url = body["install_links"]["files"][0]["url"]
    assert api("DELETE", f"/1/cbom/sources/nodes/{body['node']['id']}").status_code in (200, 204)
    assert api("GET", url, None).status_code == 401


def test_every_use_is_audited_with_the_node_as_actor_and_refusals_are_not(api, artifacts, world):  # noqa: F811
    engine, ids = world
    body = _create(api, "helm")
    node_id = body["node"]["id"]
    for f in body["install_links"]["files"]:
        assert api("GET", f["url"], None).status_code == 200
    api("GET", body["install_links"]["files"][0]["url"].replace("/1/", "/2/", 1), None)  # refused: not audited
    rows = _audit(engine)
    assert [(r.team_id, r.actor_type, r.actor_id, r.object_type, r.object_id, r.changed_fields) for r in rows] == [
        (1, "node", node_id, "node", node_id, ["image"]), (1, "node", node_id, "node", node_id, ["helm-chart"])]


def test_no_links_without_files_or_signing_key_and_the_create_still_works(api, world, monkeypatch):  # noqa: F811
    monkeypatch.delenv("CBOM_NODE_ARTIFACT_DIR", raising=False)
    body = _create(api)
    assert body["install_links"] is None and body["registration_token"]


def test_no_links_without_a_signing_key(api, artifacts, monkeypatch):  # noqa: F811
    monkeypatch.delenv("JWT_SECRET_KEY", raising=False)
    body = _create(api)
    assert body["install_links"] is None and body["registration_token"]


def test_a_pool_node_reset_gets_no_links(api, artifacts, world):  # noqa: F811
    engine, _ = world
    body = _create(api)
    from backend.new_models import CbomNodePool
    with Session(engine) as s:
        pool = CbomNodePool(team_id=1, owner_user_id=1, name="pool", token_hash="x" * 64,
                            expires_at=dt.datetime.utcnow() + dt.timedelta(hours=1), max_enrollments=5)
        s.add(pool)
        s.commit()
        s.exec(update(CbomScanNode).where(CbomScanNode.id == body["node"]["id"]).values(pool_id=pool.id))
        s.commit()
    reset = api("POST", f"/1/cbom/sources/nodes/{body['node']['id']}/reset")
    assert reset.status_code == 200 and reset.json()["registration_token"] is None
    assert reset.json()["install_links"] is None


def test_the_one_paste_docker_fetch_checks_the_bytes(api, artifacts, tmp_path):  # noqa: F811
    """What the wizard's command does on the host: fetch, then `echo '<sha256>  <file>' | sha256sum -c -`."""
    f = _create(api)["install_links"]["files"][0]
    (tmp_path / f["filename"]).write_bytes(api("GET", f["url"], None).content)
    check = f"echo '{f['sha256']}  {f['filename']}' | sha256sum -c -"
    assert subprocess.run(["bash", "-c", check], cwd=tmp_path, capture_output=True).returncode == 0
    (tmp_path / f["filename"]).write_bytes(b"tampered")
    assert subprocess.run(["bash", "-c", check], cwd=tmp_path, capture_output=True).returncode != 0


def test_registry_chart_reference_only_with_a_valid_image_reference(api, artifacts, monkeypatch):  # noqa: F811
    monkeypatch.setenv("CBOM_NODE_CHART_REF", "oci://ghcr.io/acme/charts/cbom-scan-node:1.0.0")
    body = api("GET", "/1/cbom/node-artifacts").json()
    assert body["pull_chart_ref"] is None and body["pull_chart_version"] is None  # no image ref: no chart either
    monkeypatch.setenv("CBOM_NODE_IMAGE_REF", "ghcr.io/acme/devsecshield-scan-node:staging-0123456789ab")
    body = api("GET", "/1/cbom/node-artifacts").json()
    assert body["pull_chart_ref"] == "oci://ghcr.io/acme/charts/cbom-scan-node"
    assert body["pull_chart_version"] == "1.0.0"
    for bad in ("ghcr.io/acme/charts/cbom-scan-node:1.0.0", "oci://ghcr.io/acme/charts/cbom-scan-node",
                "oci://x:1; rm -rf /", "https://ghcr.io/a:1"):
        monkeypatch.setenv("CBOM_NODE_CHART_REF", bad)
        assert api("GET", "/1/cbom/node-artifacts").json()["pull_chart_ref"] is None, bad
