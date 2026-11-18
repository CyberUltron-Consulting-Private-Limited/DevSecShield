"""#364: vault-backed credentials only with a vault a scan node can read, checked before the import.

* CyberArk and Azure Key Vault are offered but no scan node version reads them (scan_node vault.py). They stay
  listed as "not available yet" and cannot be saved: on a source, a fleet credential, or a CMDB import row.
  A source stored with one before is still readable and can be edited to another vault.
* The import checks each vault row against what its scan node reports at heartbeat (vault use on or off, the
  providers it reads, its prefix in either KV v2 form, whether the provider is set up) and says what to set on
  the node. A node that has not reported (an older node, never connected) is not blocked.

dev: every one of these saved or imported, and failed only at the first test or collection.
Real routers on SQLite (the harness of test_cbom_sources_api.py).
"""
from __future__ import annotations

import pytest
from sqlmodel import Session, select

from tests import test_cbom_sources_api as H
from tests.test_cbom_sources_api import PASSWORD

from backend.new_models import CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources import vault_support as VS

api, world = H.api, H.world  # the harness's fixtures: SQLite + real routers + real JWTs
PREVIEW = "/1/cbom/sources/cmdb/preview"
READY = {"vault": True, "vault_providers": ["hashicorp", "aws_secrets_manager"], "vault_prefix": "secret/cbom",
         "vault_setup": {"hashicorp": "ready", "aws_secrets_manager": "ready"}}


def _node(api, world, name="mum-01", capabilities=None) -> int:
    r = api("POST", "/1/cbom/sources/nodes", json={"name": name, "segment": "dc-mumbai"})
    assert r.status_code == 201, r.text
    node_id = r.json()["node"]["id"]
    if capabilities is not None:
        with Session(world[0]) as s:
            node = s.get(CbomScanNode, node_id)
            node.capabilities = capabilities
            s.add(node)
            s.commit()
    return node_id


def _db(node_id: int, provider: str, path: str = "secret/data/cbom/pg1") -> dict:
    return {"kind": "database", "name": "pg-vault", "node_id": node_id,
            "config": {"engine": "postgres", "host": "pg1.bank.local", "port": 5432, "login": "cbom_ro",
                       "credential_type": "vault", "vault": {"provider": provider, "path": path}}}


# ----------------------------------------------------------------------------- not available yet: never saved
@pytest.mark.parametrize("provider, label", [("cyberark", "CyberArk"), ("azure_key_vault", "Azure Key Vault")])
def test_364_a_source_cannot_be_saved_with_a_vault_no_node_reads(api, world, provider, label):
    n = _node(api, world)
    r = api("POST", "/1/cbom/sources/items", json=_db(n, provider))
    assert r.status_code == 400, r.text  # dev: 201, then "cyberark vaults are not supported by this scan node version"
    assert r.json()["detail"] == (f"vault: {label} is not available yet: no scan node version reads it; use HashiCorp "
                                  "Vault or AWS Secrets Manager")
    ok = api("POST", "/1/cbom/sources/items", json=_db(n, "hashicorp"))
    assert ok.status_code == 201, ok.text
    sid = ok.json()["source"]["id"]
    edited = api("PATCH", f"/1/cbom/sources/items/{sid}", json={"config": _db(n, provider)["config"]})
    assert edited.status_code == 400 and "not available yet" in edited.json()["detail"]


def test_364_a_source_stored_with_one_before_can_be_edited_to_a_supported_vault(api, world):
    n = _node(api, world)
    sid = api("POST", "/1/cbom/sources/items", json=_db(n, "hashicorp")).json()["source"]["id"]
    with Session(world[0]) as s:  # stored before this change
        src = s.get(CbomCollectionSource, sid)
        src.config = {**src.config, "vault": {"provider": "cyberark", "path": "secret/data/cbom/pg1"}}
        s.add(src)
        s.commit()
    assert api("GET", f"/1/cbom/sources/items/{sid}").status_code == 200  # still readable
    edited = api("PATCH", f"/1/cbom/sources/items/{sid}", json={"config": _db(n, "aws_secrets_manager", "cbom/pg1")["config"]})
    assert edited.status_code == 200, edited.text


def test_364_a_fleet_credential_cannot_use_one_either():
    from backend.utilities.cbom_sources.fleet.credentials import check_config

    with pytest.raises(ValueError, match="CyberArk is not available yet"):
        check_config("vault", {"vault": {"provider": "cyberark", "path": "secret/cbom/linux"}})
    assert check_config("vault", {"vault": {"provider": "hashicorp", "path": "secret/cbom/linux"}})["vault"]


def test_364_the_providers_are_listed_with_their_availability():
    assert [(p["value"], p["available"]) for p in VS.provider_list()] == [
        ("hashicorp", True), ("aws_secrets_manager", True), ("cyberark", False), ("azure_key_vault", False)]


# ----------------------------------------------------------------------------- the import checks the node
CSV = ("kind,host,engine,login,vault_path,segment\n"
       "database,pg1.bank.local,postgres,cbom_ro,{path},dc-mumbai\n")


def _preview(api, path="secret/data/cbom/pg1", provider="hashicorp"):
    r = api("POST", PREVIEW, json={"csv": CSV.format(path=path), "vault_provider": provider})
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    return plan, [s["reason"] for s in plan["skipped"]]


@pytest.mark.parametrize("provider", ["cyberark", "azure_key_vault"])
def test_364_an_import_row_with_a_vault_no_node_reads_is_not_imported(api, world, provider):
    _node(api, world, capabilities=READY)
    plan, reasons = _preview(api, provider=provider)
    assert not plan["creates"] and reasons and "is not available yet" in reasons[0]  # dev: created


def test_364_a_node_with_vault_use_off_is_named_with_what_to_set(api, world):
    _node(api, world, capabilities={"vault": False, "vault_providers": ["hashicorp", "aws_secrets_manager"]})
    plan, reasons = _preview(api)
    assert not plan["creates"]  # dev: created; every test then "vault credentials are disabled on this scan node"
    assert reasons == ["vault: scan node mum-01 has vault use off: its operator sets ZS_VAULT_PATH_PREFIX (and, for "
                       "HashiCorp Vault, VAULT_ADDR and VAULT_TOKEN) on the node"]


def test_364_a_path_outside_the_nodes_prefix_is_refused_in_either_kv2_form(api, world):
    _node(api, world, capabilities=READY)
    for path in ("secret/data/cbom/pg1", "secret/cbom/pg1"):
        plan, reasons = _preview(api, path=path)
        assert len(plan["creates"]) == 1 and not reasons, (path, reasons)
    plan, reasons = _preview(api, path="secret/data/other/pg1")
    assert not plan["creates"]
    assert reasons == ["vault: the path is outside the prefix scan node mum-01 allows (secret/cbom/... or "
                       "secret/data/cbom/...)"]


def test_364_a_provider_the_node_is_not_set_up_for_is_named(api, world):
    caps = {**READY, "vault_setup": {"hashicorp": "VAULT_ADDR and VAULT_TOKEN are not set on this scan node",
                                     "aws_secrets_manager": "ready"}}
    _node(api, world, capabilities=caps)
    plan, reasons = _preview(api)
    assert not plan["creates"]
    assert reasons == ["vault: scan node mum-01 is not set up for HashiCorp Vault: VAULT_ADDR and VAULT_TOKEN are not "
                       "set on this scan node"]


def test_364_a_node_whose_version_cannot_read_the_provider_is_named(api, world):
    _node(api, world, capabilities={**READY, "vault_providers": ["hashicorp"]})
    plan, reasons = _preview(api, path="cbom/pg1", provider="aws_secrets_manager")
    assert not plan["creates"] and reasons == [
        "vault: scan node mum-01 cannot read AWS Secrets Manager (update the node to a version that does)"]


def test_364_a_node_that_has_not_reported_is_not_blocked(api, world):
    """An older node reports only vault: true (or nothing before its first heartbeat): the import goes ahead."""
    _node(api, world, capabilities={"vault": True})
    plan, reasons = _preview(api)
    assert len(plan["creates"]) == 1 and not reasons
    with Session(world[0]) as s:
        assert s.exec(select(CbomScanNode)).first().capabilities == {"vault": True}


def test_364_the_node_list_shows_each_nodes_vault_support(api, world):
    _node(api, world, capabilities=READY)
    listed = api("GET", "/1/cbom/sources/nodes").json()["nodes"][0]
    assert listed["vault"] == {"enabled": True, "providers": ["hashicorp", "aws_secrets_manager"],
                               "prefix": "secret/cbom", "setup": {"hashicorp": "ready", "aws_secrets_manager": "ready"}}
    assert PASSWORD not in str(listed)
