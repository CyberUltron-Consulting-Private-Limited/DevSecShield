"""N11 (owner bug list 14 Nov 2026), end to end on vendor-syntax fixtures: the scan node's appliance parsers
(scan_node/zs_scan_node/appliance_parsers.py) read the fixture, the API's classifier judges each row.

* F5 'DEFAULT:...' cipher strings include TLS 1.2 (F5's DEFAULT list): no NO_TLS12 ("supports neither TLS 1.2 nor
  TLS 1.3"); a listed TLSv1 is still PROTO_TLS10; a profile that really has no TLS 1.2 still gets NO_TLS12.
* Weak Diffie-Hellman sizes on appliance TLS/SSH services get the KB's DH_LT_2048 (IOS 'ip ssh dh min size 1024',
  ASA 'ssl dh-group group2', FortiOS 'set dh-params 1024'); ASA IKE policies with group 2 / group 5 get IKE_WEAK_DH.
  2048 bits and more raise nothing.  No new KB code: both codes are in crypto_kb.json.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for _p in (str(ROOT), str(ROOT / "scan_node")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from zs_scan_node import appliance_parsers as AP  # noqa: E402

FIX = ROOT / "scan_node/tests/fixtures/appliance"


def _fixture(path: Path) -> dict[str, str]:  # scan_node/tests/sim_appliance.load_fixture (that module needs paramiko)
    out: dict[str, str] = {}
    current = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            current = line[4:].strip()
            out[current] = ""
        elif current is not None:
            out[current] += line + "\n"
    return out


def _judged(vendor: str, outputs) -> dict[str, dict]:
    return {r[1]: classify(r[0], r[3], r[4], None, {**r[5], "vendor_label": AP.VENDOR_LABELS[vendor]})
            for r in AP.PARSERS[vendor](outputs)}


def test_f5_default_strings_are_not_flagged_as_missing_tls12():
    out = _judged("f5_bigip", json.loads((FIX / "n11/f5_default.json").read_text()))
    codes = {name.split("/")[-1]: set(v["finding_codes"]) for name, v in out.items()}
    assert "NO_TLS12" not in codes["default-no-rc4"]
    assert "NO_TLS12" not in codes["default-plus-tlsv1"] and "PROTO_TLS10" in codes["default-plus-tlsv1"]
    assert "NO_TLS12" not in codes["default-tlsv1-off"] and "PROTO_TLS10" not in codes["default-tlsv1-off"]
    # a profile that really has no TLS 1.2 is still flagged
    assert {"NO_TLS12", "PROTO_TLS10"} <= codes["default-no-12"]
    assert {"NO_TLS12", "PROTO_TLS10"} <= codes["default-option-off"]
    assert {"NO_TLS12", "PROTO_TLS10"} <= codes["tlsv1-only"]
    legacy = _judged("f5_bigip", json.loads((FIX / "f5.json").read_text()))["client-ssl /Common/legacy-app"]
    assert "NO_TLS12" not in legacy["finding_codes"] and {"PROTO_TLS10", "WEAK_CIPHER"} <= set(legacy["finding_codes"])


def test_ios_ssh_dh_min_size_1024_is_weak_dh():
    ssh = _judged("cisco_ios", _fixture(FIX / "n11/cisco_ios_dh.txt"))["ip ssh"]
    assert "DH_LT_2048" in ssh["finding_codes"] and ssh["impacts"]["DH_LT_2048"] == "Medium"
    assert "1024 bits" in ssh["texts"]["DH_LT_2048"] and "Cisco IOS" in ssh["texts"]["DH_LT_2048"]
    ok = _judged("cisco_ios", _fixture(FIX / "n11/cisco_ios_dh_ok.txt"))["ip ssh"]
    assert "DH_LT_2048" not in ok["finding_codes"]
    policies = _judged("cisco_ios", _fixture(FIX / "n11/cisco_ios_dh.txt"))
    assert "IKE_WEAK_DH" in policies["crypto isakmp policy 10"]["finding_codes"]  # group 2
    assert "IKE_WEAK_DH" not in policies["crypto isakmp policy 20"]["finding_codes"]  # group 14


def test_asa_dh_group2_is_weak_dh_on_tls_and_ike():
    out = _judged("cisco_asa", _fixture(FIX / "n11/cisco_asa_dh.txt"))
    tls = out["ssl"]
    assert "DH_LT_2048" in tls["finding_codes"] and tls["impacts"]["DH_LT_2048"] == "High"
    assert "MODP-1024" in tls["texts"]["DH_LT_2048"]
    assert out["crypto ikev1 policy 10"]["impacts"]["IKE_WEAK_DH"] == "High"  # group 2 (MODP-1024)
    assert out["crypto ikev1 policy 20"]["impacts"]["IKE_WEAK_DH"] == "Medium"  # group 5 (MODP-1536)
    assert "IKE_WEAK_DH" in out["crypto ikev2 policy 10"]["finding_codes"]
    ok = _judged("cisco_asa", _fixture(FIX / "n11/cisco_asa_dh_ok.txt"))
    assert "DH_LT_2048" not in ok["ssl"]["finding_codes"]
    assert "IKE_WEAK_DH" not in ok["crypto ikev2 policy 10"]["finding_codes"]
    # the original WP7 fixture has the same 'ssl dh-group group2' line: now flagged there too
    assert "DH_LT_2048" in _judged("cisco_asa", _fixture(FIX / "cisco_asa.txt"))["ssl"]["finding_codes"]


def test_fortios_dh_params_1024_is_weak_dh():
    tls = _judged("fortios", _fixture(FIX / "n11/fortios_dh.txt"))["system global"]
    assert tls["finding_codes"] == ["DH_LT_2048"] and tls["impacts"]["DH_LT_2048"] == "High"


def test_weak_dh_codes_are_existing_kb_codes():
    assert {"DH_LT_2048", "IKE_WEAK_DH"} <= set(crypto_kb.load()["findings"]["node"])
