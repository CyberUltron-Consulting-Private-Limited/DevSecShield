"""N11 (owner bug list 14 Nov 2026): appliance parsing gaps, on vendor-syntax fixtures (tests/fixtures/appliance/n11).

* F5 BIG-IP: a client-ssl cipher string that starts with DEFAULT takes F5's DEFAULT cipher list, which holds TLS 1.2
  suites, so the profile configures TLS 1.2 (it was read as "TLS 1.0 only" when the string also listed TLSv1, and the
  server then raised "supports neither TLS 1.2 nor TLS 1.3").  '!TLSv1_2' in the string or the 'no-tlsv1.2' option
  still switch it off; a 'no-...' option switches off a listed version.
* Weak Diffie-Hellman sizes are read: IOS 'ip ssh dh min size 1024', ASA 'ssl dh-group group2' (normalised to
  MODP-1024), FortiOS 'set dh-params 1024'.  ASA 'crypto ikev1|ikev2 policy ... group 2' stays an IKE group (MODP-1024).
"""
from __future__ import annotations

import json
from pathlib import Path

from zs_scan_node import appliance_parsers as AP

from sim_appliance import load_fixture

FIX = Path(__file__).parent / "fixtures/appliance/n11"


def _rows(vendor: str, outputs) -> dict[str, tuple]:
    return {r[1]: r for r in AP.PARSERS[vendor](outputs)}


def test_f5_default_cipher_string_configures_tls12():
    rows = _rows("f5_bigip", json.loads((FIX / "f5_default.json").read_text()))
    protocols = {name.split("/")[-1]: row[5]["protocols"] for name, row in rows.items()}
    assert protocols == {
        "default-no-rc4": ["TLSv1.2"],                  # DEFAULT:!RC4
        "default-plus-tlsv1": ["TLSv1.0", "TLSv1.2"],   # the reported case: DEFAULT plus TLSv1 is not "TLS 1.0 only"
        "default-no-12": ["TLSv1.0"],                   # DEFAULT:!TLSv1_2 removes TLS 1.2
        "default-option-off": ["TLSv1.0"],              # option no-tlsv1.2 switches it off
        "tlsv1-only": ["TLSv1.0"],                      # no DEFAULT: nothing is assumed
        "default-tlsv1-off": ["TLSv1.2"],               # option no-tlsv1 switches the listed TLSv1 off
    }


def test_existing_f5_fixture_profiles_read_tls12_from_default():
    rows = _rows("f5_bigip", json.loads((FIX.parent / "f5.json").read_text()))
    assert rows["client-ssl /Common/legacy-app"][5]["protocols"] == ["TLSv1.0", "TLSv1.2"]  # DEFAULT:RC4-SHA:...:TLSv1
    assert rows["client-ssl /Common/clientssl"][5]["protocols"] == ["TLSv1.2"]  # DEFAULT, options no-tlsv1.3
    assert rows["client-ssl /Common/modern"][5]["protocols"] == []  # not DEFAULT, no protocol keyword


def test_ios_ssh_dh_min_size_is_read():
    ssh = _rows("cisco_ios", load_fixture(FIX / "cisco_ios_dh.txt"))["ip ssh"][5]
    assert ssh["dh_min_bits"] == 1024 and ssh["versions"] == [2]
    assert _rows("cisco_ios", load_fixture(FIX / "cisco_ios_dh_ok.txt"))["ip ssh"][5]["dh_min_bits"] == 4096


def test_ios_dh_min_size_alone_still_makes_an_ssh_row():
    rows = _rows("cisco_ios", {"show running-config | include ^ip ssh|^ip http": "ip ssh dh min size 1024\n"})
    assert rows["ip ssh"][5]["dh_min_bits"] == 1024


def test_asa_ssl_dh_group_is_normalised_and_ike_group2_stays_modp1024():
    rows = _rows("cisco_asa", load_fixture(FIX / "cisco_asa_dh.txt"))
    tls = rows["ssl"][5]
    assert tls["dh_group"] == "group2" and tls["dh_groups"] == ["MODP-1024"]
    assert rows["crypto ikev1 policy 10"][5]["groups"] == ["MODP-1024"]
    assert rows["crypto ikev1 policy 20"][5]["groups"] == ["MODP-1536"]
    assert rows["crypto ikev2 policy 10"][5]["groups"] == ["MODP-1024"]
    ok = _rows("cisco_asa", load_fixture(FIX / "cisco_asa_dh_ok.txt"))["ssl"][5]
    assert ok["dh_groups"] == ["MODP-2048"]


def test_fortios_dh_params_is_read():
    tls = _rows("fortios", load_fixture(FIX / "fortios_dh.txt"))["system global"][5]
    assert tls["dh_bits"] == 1024 and tls["protocols"] == ["TLSv1.2", "TLSv1.3"]
