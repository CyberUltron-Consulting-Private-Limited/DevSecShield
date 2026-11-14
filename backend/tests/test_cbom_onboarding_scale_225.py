"""Issue #225: onboarding at scale. The CMDB import maps a segment (or scan_node) column to scan nodes, imports
Windows hosts as WinRM sources with a vault reference, imports database, Kubernetes cluster and HSM rows as the existing
source kinds; and the source list has server-side search, filters (kind, segment, status) and keyset paging."""
from __future__ import annotations

import sys
import time
from pathlib import Path

from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import api, world  # noqa: E402,F401

from backend.new_models import CbomCollectionSource, CbomScanNode  # noqa: E402

PREVIEW, APPLY = "/1/cbom/sources/cmdb/preview", "/1/cbom/sources/cmdb/apply"
WIN_VAULT = {"provider": "hashicorp", "path": "secret/data/cbom/winrm"}


def node(api, name: str, segment: str, team: int = 1, who: str = "alice") -> int:  # noqa: F811 (the api fixture, passed in)
    r = api("POST", f"/{team}/cbom/sources/nodes", who, json={"name": name, "segment": segment})
    assert r.status_code == 201, r.text
    return r.json()["node"]["id"]


def sources(engine, team_id: int = 1) -> list[CbomCollectionSource]:
    with Session(engine) as s:
        return list(s.exec(select(CbomCollectionSource).where(CbomCollectionSource.team_id == team_id)
                           .order_by(CbomCollectionSource.id)).all())


def preview_apply(api, body: dict) -> tuple[dict, dict]:  # noqa: F811 (the api fixture, passed in)
    r = api("POST", PREVIEW, json=body)
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    a = api("POST", APPLY, json={**body, "digest": plan["digest"]})
    assert a.status_code == 200, a.text
    return plan, a.json()["result"]


# ----------------------------------------------------------------------------- segment -> scan node
def test_segment_column_maps_each_row_to_the_scan_node_of_its_segment(api, world):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    mumbai, chennai = node(api, "mum-01", "dc-mumbai"), node(api, "che-01", "dc-chennai")
    default = node(api, "hq-01", "hq")
    csv_text = ("fqdn,os,owner,application,environment,segment\n"
                "m1.bank.local,linux,Ops,Core,prod,dc-mumbai\n"
                "m2.bank.local,linux,Ops,Core,prod,DC-Mumbai\n"  # segment names match whatever their case
                "c1.bank.local,linux,Ops,Core,prod,dc-chennai\n"
                "h1.bank.local,linux,Ops,Core,prod,\n"  # no segment: the import's scan node
                "x1.bank.local,linux,Ops,Core,prod,dc-delhi\n")  # no node in that segment: skipped, with why
    plan, result = preview_apply(api, {"csv": csv_text, "node_id": default})
    by_node = {c["node_name"]: c for c in plan["creates"]}
    assert set(by_node) == {"mum-01", "che-01", "hq-01"}, plan["creates"]
    assert by_node["mum-01"]["targets"] == ["m1.bank.local", "m2.bank.local"] and by_node["mum-01"]["segment"] == "dc-mumbai"
    assert by_node["che-01"]["targets"] == ["c1.bank.local"]
    (skip,) = plan["skipped"]
    assert skip["line"] == 6 and "no scan node in segment 'dc-delhi'" in skip["reason"], skip
    assert result["created"] == 3
    got = {(s.node_id, tuple(s.config["targets"])) for s in sources(engine)}
    assert got == {(mumbai, ("m1.bank.local", "m2.bank.local")), (chennai, ("c1.bank.local",)),
                   (default, ("h1.bank.local",))}


def test_a_segment_with_two_nodes_needs_a_choice_and_scan_node_column_wins(api, world):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    a, b = node(api, "mum-01", "dc-mumbai"), node(api, "mum-02", "dc-mumbai")
    csv_text = "fqdn,segment,scan_node\nm1.bank.local,dc-mumbai,\nm2.bank.local,dc-mumbai,mum-02\nm3.bank.local,,nope\n"
    plan = api("POST", PREVIEW, json={"csv": csv_text}).json()["plan"]
    reasons = {s["line"]: s["reason"] for s in plan["skipped"]}
    assert "segment 'dc-mumbai' has 2 scan nodes (mum-01, mum-02)" in reasons[2], reasons
    assert "no scan node named 'nope'" in reasons[4], reasons
    assert [(c["node_id"], c["targets"]) for c in plan["creates"]] == [(b, ["m2.bank.local"])]
    plan, result = preview_apply(api, {"csv": csv_text, "segment_nodes": {"dc-mumbai": a}})
    assert result["created"] == 2
    assert {(s.node_id, s.config["targets"][0]) for s in sources(engine)} == {(a, "m1.bank.local"), (b, "m2.bank.local")}
    # a mapping to another team's node is refused
    other = node(api, "t2-node", "dc-mumbai", team=2, who="carol")
    r = api("POST", PREVIEW, json={"csv": csv_text, "segment_nodes": {"dc-mumbai": other}})
    assert r.status_code == 400 and "segment_nodes" in r.json()["detail"], r.text


# ----------------------------------------------------------------------------- Windows
def test_windows_rows_become_winrm_sources_with_the_chosen_vault_reference(api, world):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    n = node(api, "dc-01", "dc")
    csv_text = ("fqdn,os,owner,application,environment,login\n"
                "w1.bank.local,Windows Server 2022,Ops,Core,prod,CORP\\svc-cbom\n"
                "w2.bank.local,cmdb_ci_win_server,Ops,Core,prod,CORP\\svc-cbom\n"
                "l1.bank.local,Ubuntu,Ops,Core,prod,\n")
    without = api("POST", PREVIEW, json={"csv": csv_text, "node_id": n}).json()["plan"]
    assert [c["kind"] for c in without["creates"]] == ["linux_servers"]
    assert all("WinRM login" in s["reason"] and "vault" in s["reason"] for s in without["skipped"]), without["skipped"]
    plan, result = preview_apply(api, {"csv": csv_text, "node_id": n, "windows_vault": WIN_VAULT})
    assert result["created"] == 2 and plan["counts"]["skipped"] == 0
    (win,) = [s for s in sources(engine) if s.kind == "windows_servers"]
    assert win.config["targets"] == ["w1.bank.local", "w2.bank.local"] and win.config["port"] == 5986
    assert win.config["credential_type"] == "vault" and win.config["vault"] == WIN_VAULT
    assert win.config["login_user"] == "CORP\\svc-cbom" and win.secret_encrypted is None
    # a vault_path column overrides the import's choice per row
    plan = api("POST", PREVIEW, json={"csv": "fqdn,os,vault_path\nw9.bank.local,windows,secret/data/other\n",
                                      "node_id": n, "windows_vault": WIN_VAULT}).json()["plan"]
    assert plan["creates"][0]["config"]["vault"] == {"provider": "hashicorp", "path": "secret/data/other"}


# ----------------------------------------------------------------------------- databases, clusters, HSMs
DB_K8S_HSM = (
    "kind,host,engine,port,login,database_name,vault_path,api_url,context,module,token_label,owner,segment\n"
    "database,pg1.bank.local,postgres,,cbom_ro,,secret/data/db/pg1,,,,,DBA,dc-mumbai\n"
    "database,ora1.bank.local,oracle,1522,cbom_ro,ORCLPDB1,secret/data/db/ora1,,,,,DBA,dc-mumbai\n"
    "database,my1.bank.local,mysql,,cbom_ro,,secret/data/db/my1,,,,,DBA,dc-mumbai\n"
    "database,pg2.bank.local,postgres,,cbom_ro,,,,,,,DBA,dc-mumbai\n"
    "database,rd1.bank.local,redis,,,,,,,,,DBA,dc-mumbai\n"
    "kubernetes,,,,,,secret/data/k8s/prod,https://k8s-prod.bank.local:6443,prod,,,Platform,dc-mumbai\n"
    "kubernetes,,,,,,,https://k8s-dev.bank.local:6443,,,,Platform,dc-mumbai\n"
    "hsm,,,,,,secret/data/hsm/pin,,,luna,payments-01,Crypto,dc-mumbai\n"
    "kmip,kmip.bank.local,,,,,,,,,,Crypto,dc-mumbai\n"
)


def test_database_cluster_and_hsm_rows_use_the_existing_source_kinds(api, world):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    n = node(api, "mum-01", "dc-mumbai")
    plan, result = preview_apply(api, {"csv": DB_K8S_HSM, "vault_provider": "hashicorp"})
    reasons = {s["line"]: s["reason"] for s in plan["skipped"]}
    assert set(reasons) == {4, 5, 8, 10}, reasons
    assert "TLS" in reasons[4] and "CA certificate" in reasons[4]  # MySQL logins need the server CA: by hand
    assert "vault_path" in reasons[5] and "never imported" in reasons[5]
    assert "vault_path" in reasons[8] and "kubeconfig" in reasons[8]
    assert "KMIP" in reasons[10] and "client certificate" in reasons[10]
    assert result["created"] == 5
    made = {s.kind: [] for s in sources(engine)}
    for s in sources(engine):
        made[s.kind].append(s)
        assert s.node_id == n and s.secret_encrypted is None and s.config["owner"]
    ora, pg, redis = sorted(made["database"], key=lambda s: s.config["host"])
    assert (ora.config["engine"], ora.config["port"], ora.config["database_name"]) == ("oracle", 1522, "ORCLPDB1")
    assert (pg.config["port"], pg.config["vault"]) == (5432, {"provider": "hashicorp", "path": "secret/data/db/pg1"})
    assert redis.config["engine"] == "redis" and redis.config["credential_type"] == "password"
    (k8s,) = made["kubernetes"]
    assert k8s.config["api_url"] == "https://k8s-prod.bank.local:6443" and k8s.config["credential_type"] == "vault"
    assert k8s.config["context"] == "prod"
    (hsm,) = made["key_manager"]
    assert (hsm.config["provider"], hsm.config["module"], hsm.config["token_label"]) == ("pkcs11", "luna", "payments-01")
    assert hsm.config["credential_type"] == "vault"
    # importing the same file again matches every source by its identity: nothing new, metadata only
    again = api("POST", PREVIEW, json={"csv": DB_K8S_HSM.replace("DBA", "Data Team"), "vault_provider": "hashicorp"})
    again = again.json()["plan"]
    assert again["counts"]["create"] == 0 and again["counts"]["update"] == 3, again["counts"]
    assert {u["kind"] for u in again["updates"]} == {"database"}


# ----------------------------------------------------------------------------- the issue's file, timed
def test_issue_file_5000_rows_two_segments_10pct_windows_timed(api, world, capsys):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    mumbai, chennai = node(api, "mum-01", "dc-mumbai"), node(api, "che-01", "dc-chennai")
    lines = ["fqdn,ip,os,owner,application,environment,segment"]
    for i in range(5000):
        os_ = "Windows Server 2019" if i % 20 in (0, 1) else "RHEL 8"  # 10% Windows, half in each segment
        seg = "dc-mumbai" if i % 2 == 0 else "dc-chennai"
        lines.append(f"h{i}.bank.local,10.{i >> 16}.{(i >> 8) & 255}.{i & 255},{os_},Team {i % 50},App {i % 50},prod,{seg}")
    body = {"csv": "\n".join(lines) + "\n", "windows_vault": WIN_VAULT}
    t0 = time.perf_counter()
    r = api("POST", PREVIEW, json=body)
    preview_s = time.perf_counter() - t0
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    assert plan["counts"]["skipped"] == 0 and plan["counts"]["new_targets"] == 5000, plan["counts"]
    t0 = time.perf_counter()
    a = api("POST", APPLY, json={**body, "digest": plan["digest"]})
    apply_s = time.perf_counter() - t0
    assert a.status_code == 200, a.text
    made = sources(engine)
    hosts = {(s.kind, s.node_id): 0 for s in made}
    for s in made:
        hosts[(s.kind, s.node_id)] += len(s.config["targets"])
    assert hosts == {("linux_servers", mumbai): 2250, ("linux_servers", chennai): 2250,
                     ("windows_servers", mumbai): 250, ("windows_servers", chennai): 250}, hosts
    with capsys.disabled():
        print(f"\n[#225 timing] 5,000-row two-segment CMDB preview {preview_s:.2f}s, apply {apply_s:.2f}s "
              f"({len(made)} sources)")
    assert preview_s < 30 and apply_s < 60


# ----------------------------------------------------------------------------- search, filters, keyset paging
def _seed(engine, n: int, nodes: list[int]) -> None:
    with Session(engine) as s:
        for i in range(n):
            kind = "windows_servers" if i % 5 == 0 else "linux_servers"
            s.add(CbomCollectionSource(
                team_id=1, owner_user_id=1, kind=kind, name=f"src-{i:05d}", name_lower=f"src-{i:05d}",
                node_id=nodes[i % len(nodes)], enabled=i % 7 != 0,
                config={"targets": [f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"], "credential_type": "node_key",
                        "host_key_policy": "tofu", "owner": "Payments" if i % 3 == 0 else "Cards"},
                secret_fields=[], last_test_status="failed" if i % 11 == 0 else "never"))
        s.commit()


def test_source_list_search_filters_and_keyset_paging_at_6000_sources(api, world, capsys):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    mumbai, chennai = node(api, "mum-01", "dc-mumbai"), node(api, "che-01", "dc-chennai")
    _seed(engine, 6000, [mumbai, chennai])
    url = "/1/cbom/sources/items"
    seen, after, pages, t0 = [], None, 0, time.perf_counter()
    while True:
        r = api("GET", url, params={"group": "servers", "limit": 500, **({"after": after} if after else {})})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 6000
        seen += [s["id"] for s in body["sources"]]
        pages += 1
        after = body["next_after"]
        if after is None:
            break
    paging_s = time.perf_counter() - t0
    assert len(seen) == 6000 and seen == sorted(seen) and len(set(seen)) == 6000 and pages == 12

    def q(**params):
        r = api("GET", url, params={"group": "servers", "limit": 50, **params})
        assert r.status_code == 200, r.text
        return r.json()

    t0 = time.perf_counter()
    one = q(q="SRC-00042")
    search_s = time.perf_counter() - t0
    assert [s["name"] for s in one["sources"]] == ["src-00042"] and one["total"] == 1
    assert q(q="10.0.16.3")["sources"][0]["name"] == "src-04099"  # a target address (inside the config)
    assert q(q="payments")["total"] == 2000  # metadata
    assert q(q="100%")["total"] == 0 and q(q="src_0")["total"] == 0  # LIKE wildcards are literal
    assert q(kind="windows_servers")["total"] == 1200
    assert q(kind="windows_servers,linux_servers")["total"] == 6000  # several kinds (the Servers tab)
    assert api("GET", url, params={"kind": "linux_servers,nope"}).status_code == 400
    assert q(segment="DC-Chennai")["total"] == 3000 and q(segment="nowhere")["total"] == 0
    assert q(status="disabled")["total"] == 858 and q(status="enabled")["total"] == 5142
    assert q(status="failed")["total"] == 546
    combo = q(kind="windows_servers", segment="dc-mumbai", status="failed")
    assert combo["total"] == len([i for i in range(6000) if i % 5 == 0 and i % 2 == 0 and i % 11 == 0])
    assert all(s["kind"] == "windows_servers" and s["node_id"] == mumbai for s in combo["sources"])
    for bad in ({"status": "sideways"}, {"after": "x"}, {"limit": 0}, {"limit": 501}):
        assert api("GET", url, params=bad).status_code in (400, 422), bad
    # no limit: every row, as before (the tabs that compute totals keep working)
    assert len(api("GET", url, params={"group": "servers"}).json()["sources"]) == 6000
    with capsys.disabled():
        print(f"\n[#225 timing] 6,000 sources: 12 keyset pages of 500 in {paging_s:.2f}s "
              f"({paging_s / 12:.2f}s each), search {search_s:.3f}s")
    assert paging_s / 12 < 5


def test_node_segment_is_listed_with_each_source(api, world):  # noqa: F811 (pytest fixtures)
    engine, _ = world
    n = node(api, "mum-01", "dc-mumbai")
    _seed(engine, 3, [n])
    rows = api("GET", "/1/cbom/sources/items", params={"group": "servers"}).json()["sources"]
    assert {r["node_segment"] for r in rows} == {"dc-mumbai"}
    with Session(engine) as s:
        assert s.get(CbomScanNode, n).segment == "dc-mumbai"
