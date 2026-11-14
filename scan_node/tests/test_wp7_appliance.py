"""Appliance configurations (WP7): parsers on vendor-syntax fixtures, the read-only command/API allow-lists, and
collection against a SIMULATED SSH appliance (tests/sim_appliance.py; not a real device)."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from zs_scan_node import appliance_parsers as AP
from zs_scan_node.collectors import appliance as A
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

from sim_appliance import SimAppliance, load_fixture

FIX = Path(__file__).parent / "fixtures/appliance"


def _rows(vendor: str, outputs) -> dict[str, tuple]:
    return {r[1]: r for r in AP.PARSERS[vendor](outputs)}


def _no_secret(rows) -> None:
    assert "FIXTURE-NOT-A-SECRET" not in json.dumps(rows, default=str)  # shared secrets are never copied


# ----------------------------------------------------------------------------- parsers
def test_cisco_ios_parser():
    rows = _rows("cisco_ios", load_fixture(FIX / "cisco_ios.txt"))
    _no_secret(list(rows.values()))
    ssh = rows["ip ssh"][5]
    assert ssh["versions"] == [1] and "3des-cbc" in ssh["ciphers"] and "diffie-hellman-group1-sha1" in ssh["kex"]
    https = rows["ip http secure-server"][5]
    assert https["min_version"] == "TLSv1.0" and set(https["weak_ciphers"]) == {"3des-ede-cbc-sha", "rc4-128-md5"}
    legacy = rows["crypto ikev2 proposal PROP-LEGACY"][5]
    assert legacy["version"] == 2 and legacy["encryption"] == ["AES-CBC-256", "AES-CBC-128", "3DES"]
    assert legacy["integrity"] == ["SHA2-256", "SHA1", "MD5"] and legacy["groups"] == ["MODP-2048", "MODP-1536", "MODP-1024"]
    gcm = rows["crypto ikev2 proposal PROP-GCM"][5]
    assert gcm["encryption"] == ["AES-GCM-16-256"] and gcm["prf"] == ["SHA2-384"] and gcm["groups"] == ["ECP-384"]
    p10 = rows["crypto isakmp policy 10"][5]
    assert p10["version"] == 1 and p10["encryption"] == ["3DES"] and p10["integrity"] == ["MD5"]
    assert p10["aggressive"] is True  # pre-share and no 'crypto isakmp aggressive-mode disable'
    assert "aggressive" not in rows["crypto isakmp policy 20"][5]  # rsa-sig
    ts = rows["crypto ipsec transform-set TS-OLD"][5]
    assert ts["kind"] == "ipsec_policy" and ts["encryption"] == ["3DES"] and ts["integrity"] == ["MD5"]
    assert rows["crypto ipsec transform-set TS-NEW"][5]["encryption"] == ["AES-GCM-16-256"]
    keys = {r[2]: r for r in rows.values() if r[0] == "public_key"}
    assert keys["TP-self-signed-4294967295 (RSA key pair)"][4] == 1024  # read from the key data
    assert keys["VPN-KEY (RSA key pair)"][4] == 4096


def test_cisco_asa_parser():
    rows = _rows("cisco_asa", load_fixture(FIX / "cisco_asa.txt"))
    tls = rows["ssl"][5]
    assert tls["min_version"] == "TLSv1.0" and "tlsv1 low" in tls["weak_ciphers"] and "DES-CBC3-SHA" in tls["weak_ciphers"]
    ssh = rows["ssh"][5]
    assert ssh["versions"] == [1] and ssh["kex"] == ["diffie-hellman-group1-sha1"]
    v1 = rows["crypto ikev1 policy 10"][5]
    assert v1["active"] is True and v1["aggressive"] is True and v1["encryption"] == ["3DES"] and v1["groups"] == ["MODP-1024"]
    v2 = rows["crypto ikev2 policy 10"][5]
    assert v2["encryption"] == ["AES-CBC-256", "3DES"] and v2["integrity"] == ["SHA2-256", "SHA1"]
    assert v2["prf"] == ["SHA2-256", "SHA1"] and v2["groups"] == ["MODP-2048", "MODP-1536"]
    gcm = rows["crypto ikev2 policy 1"][5]
    assert gcm["encryption"] == ["AES-GCM-16-256"] and gcm["groups"] == ["ECP-521", "ECP-384"]
    sizes = {r[2]: r[4] for r in rows.values() if r[0] == "public_key"}
    assert sizes == {"<Default-RSA-Key> (RSA key pair)": 1024, "ASDM_TrustPoint0 (RSA key pair)": 2048}


def test_fortios_parser():
    rows = _rows("fortios", load_fixture(FIX / "fortios.txt"))
    _no_secret(list(rows.values()))
    tls = rows["system global"][5]
    assert tls["min_version"] == "TLSv1.1" and tls["strong_crypto"] is False
    assert tls["protocols"] == ["TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert rows["system global ssh"][5]["versions"] == [1, 2]
    legacy = rows["vpn ipsec phase1-interface to-branch-legacy"][5]
    assert legacy["version"] == 1 and legacy["aggressive"] is True
    assert legacy["encryption"] == ["DES", "3DES", "AES-CBC-128"] and legacy["integrity"] == ["MD5", "SHA1", "SHA2-256"]
    assert legacy["groups"] == ["MODP-1024", "MODP-1536"]
    dc = rows["vpn ipsec phase1-interface to-dc"][5]
    assert dc["version"] == 2 and dc["encryption"] == ["AES-GCM-16-256", "CHACHA20-POLY1305"] and dc["prf"] == ["SHA2-384", "SHA2-256"]
    p2 = rows["vpn ipsec phase2-interface to-branch-legacy-p2"][5]
    assert p2["encryption"] == ["3DES", "AES-CBC-128"] and p2["integrity"] == ["MD5", "SHA1"] and p2["pfs_groups"] == ["MODP-1024"]


def test_panos_parser():
    outputs = json.loads((FIX / "panos.json").read_text())
    rows = _rows("panos", outputs)
    _no_secret(list(rows.values()))
    legacy = rows["ike-crypto-profile legacy-ike (IKEv1)"][5]
    assert legacy["version"] == 1 and legacy["aggressive"] is True
    assert legacy["encryption"] == ["DES", "3DES"] and legacy["integrity"] == ["MD5", "SHA1"]
    assert legacy["groups"] == ["MODP-768", "MODP-1024"]
    assert rows["ike-crypto-profile default (IKEv2)"][5]["encryption"] == ["AES-CBC-128", "3DES"]
    esp = rows["ipsec-crypto-profile default"][5]
    assert esp["encryption"] == ["AES-CBC-128", "3DES"] and esp["pfs_groups"] == ["MODP-1024"]
    assert rows["ssl-tls-service-profile mgmt-legacy"][5]["min_version"] == "TLSv1.0"
    assert AP.parse_panos({"ike-crypto-profiles": '<!DOCTYPE x [<!ENTITY a "b">]><response/>'}) == []


def test_f5_parser():
    outputs = json.loads((FIX / "f5.json").read_text())
    rows = _rows("f5_bigip", outputs)
    legacy = rows["client-ssl /Common/legacy-app"][5]
    # DEFAULT holds TLS 1.2 suites (N11), the listed TLSv1 adds TLS 1.0
    assert set(legacy["weak_ciphers"]) == {"RC4-SHA", "DES-CBC3-SHA"} and legacy["protocols"] == ["TLSv1.0", "TLSv1.2"]
    modern = rows["client-ssl /Common/modern"][5]
    assert modern["weak_ciphers"] == [] and modern["protocols"] == []
    keys = {r[2]: r for r in rows.values() if r[0] == "private_key"}
    assert keys["/Common/legacy-app.key"][3:5] == ("RSA", 1024) and keys["/Common/ec.key"][3] == "EC"


# ----------------------------------------------------------------------------- allow-lists: read-only only
WRITE_VERBS = re.compile(r"\b(configure|conf t|write|copy|delete|erase|reload|commit|set|unset|request|clear|"
                         r"no|debug|test|execute|exec|crypto key generate)\b", re.I)


def test_ssh_commands_are_show_commands_only():
    for vendor, cmds in A.COMMANDS.items():
        for cmd in cmds:
            assert cmd.startswith("show ") and not WRITE_VERBS.search(cmd[5:]), (vendor, cmd)
    assert A.ALLOWED_COMMANDS - {c for cmds in A.COMMANDS.values() for c in cmds} == {"terminal pager 0"}


def test_api_calls_are_read_only_gets():
    for path in A.API_PATHS["panos"].values():
        assert path.startswith("/api/?type=config&action=show&xpath=")  # 'show' = running config, read-only
        assert not re.search(r"action=(set|edit|delete|rename|move|override|commit)|type=(op|commit|import)", path)
    for path in A.API_PATHS["f5_bigip"].values():
        assert path.startswith("/mgmt/tm/") and "/util/" not in path and "bash" not in path
    import inspect

    src = inspect.getsource(A)
    assert ".post(" not in src and ".put(" not in src and ".patch(" not in src and ".delete(" not in src


# ----------------------------------------------------------------------------- collection against the simulator
def _ctx(never=None, tmp=None):
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="appliance", scrubber=Scrubber(),
                      never_scan=NeverScan(never or []), deadline=time.monotonic() + 60, state_dir=str(tmp))


@pytest.mark.parametrize("vendor, fixture, shell", [("cisco_ios", "cisco_ios.txt", False),
                                                    ("fortios", "fortios.txt", False),
                                                    ("cisco_asa", "cisco_asa.txt", True)])
def test_collect_from_simulated_appliance(tmp_path, vendor, fixture, shell):
    sim = SimAppliance(FIX / fixture, shell=shell)
    port = sim.serve()
    config = {"vendor": vendor, "port": port, "login_user": "zs-cbom", "credential_type": "password",
              "host_key_policy": "pinned", "known_hosts": sim.known_hosts_line("127.0.0.1", port)}
    ctx = _ctx(tmp=tmp_path)
    A.collect(ctx, config, {"password": "lab-only"}, {"targets": ["127.0.0.1"]})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["ok"]
    assert sim.received and set(sim.received) <= A.ALLOWED_COMMANDS and sim.refused == []
    assert set(A.COMMANDS[vendor]) <= set(sim.received)
    kinds = {a["facts"].get("kind") for a in ctx.collected}
    assert {"tls", "ike_policy"} <= kinds
    assert "FIXTURE-NOT-A-SECRET" not in json.dumps(ctx.collected) and "lab-only" not in json.dumps(ctx.collected)


def test_password_never_goes_to_an_unpinned_or_changed_host_key(tmp_path):
    sim = SimAppliance(FIX / "cisco_ios.txt")
    port = sim.serve()
    other = SimAppliance(FIX / "cisco_ios.txt")  # someone else's host key
    ctx = _ctx(tmp=tmp_path)
    A.collect(ctx, {"vendor": "cisco_ios", "port": port, "credential_type": "password", "host_key_policy": "tofu"},
              {"password": "lab-only"}, {"targets": ["127.0.0.1"]})
    assert ctx.outcomes[0].status == "identity_unverified"
    ctx = _ctx(tmp=tmp_path)
    A.collect(ctx, {"vendor": "cisco_ios", "port": port, "credential_type": "password", "host_key_policy": "pinned",
                    "known_hosts": other.known_hosts_line("127.0.0.1", port)}, {"password": "lab-only"},
              {"targets": ["127.0.0.1"]})
    assert ctx.outcomes[0].status == "host_key_changed" and sim.received == []


def test_never_scan_appliance_is_not_contacted(tmp_path):
    sim = SimAppliance(FIX / "cisco_ios.txt")
    port = sim.serve()
    ctx = _ctx(never=["127.0.0.1/32"], tmp=tmp_path)
    A.collect(ctx, {"vendor": "cisco_ios", "port": port, "credential_type": "password", "host_key_policy": "pinned",
                    "known_hosts": sim.known_hosts_line("127.0.0.1", port)}, {"password": "lab-only"},
              {"targets": ["127.0.0.1"]})
    assert ctx.outcomes[0].status == "skipped_never_scan" and sim.received == []


def test_connection_test_reads_but_emits_nothing(tmp_path):
    sim = SimAppliance(FIX / "fortios.txt")
    port = sim.serve()
    ctx = _ctx(tmp=tmp_path)
    ctx.kind = "test_connection"
    A.test(ctx, {"vendor": "fortios", "port": port, "credential_type": "password", "host_key_policy": "pinned",
                 "known_hosts": sim.known_hosts_line("127.0.0.1", port)}, {"password": "lab-only"},
           {"targets": ["127.0.0.1"]})
    ctx.flush()
    assert ctx.samples[0]["status"] == "ready" and ctx.samples[0]["privilege"] is True and ctx.collected == []
