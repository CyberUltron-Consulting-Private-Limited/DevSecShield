"""Windows host findings from the facts win01 (AWS lab) returned, and the least-privilege setup script."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources.classify import classify
from backend.utilities.cbom_sources.exploit_demo import _BY_CODE as FAMILIES
from backend.utilities.cbom_sources.templates import TEMPLATE_NAMES, template_text

WIN01 = {
    "os": {"Caption": "Windows Server 2022 Datacenter", "Version": "10.0.20348.5773"},
    "schannel_protocols": {"TLS 1.0": {"server": {"enabled": True, "disabled_by_default": False},
                                       "client": {"enabled": True, "disabled_by_default": False}}},
    "schannel_algorithms": {"Ciphers/Triple DES 168": {"kind": "Ciphers", "name": "Triple DES 168", "enabled": True,
                                                       "server_min_key_bits": None}},
    "cipher_suites": ["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
    "cipher_suite_source": "local",
    "dotnet": [{"key": "HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319", "wow64": False, "framework": "v4.0.30319",
                "sch_use_strong_crypto": 0},
               {"key": "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319", "wow64": True,
                "framework": "v4.0.30319", "sch_use_strong_crypto": 0}],
    "rdp": {"security_layer": 0, "nla": False},
}


def _codes(facts):
    return classify("os_crypto_policy", None, None, None, facts)["finding_codes"]


def test_every_planted_win01_weakness_is_a_finding():
    codes = _codes(WIN01)
    for code in ("PROTO_TLS10", "WEAK_CIPHER", "STATIC_RSA_KEX", "DOTNET_WEAK_TLS", "RDP_NO_TLS", "RDP_NO_NLA"):
        assert code in codes, code


def test_registry_only_3des_and_strong_dotnet():
    only_registry = {"schannel_algorithms": WIN01["schannel_algorithms"], "cipher_suites": ["TLS_AES_256_GCM_SHA384"]}
    assert "WEAK_CIPHER" in _codes(only_registry)
    off = {"schannel_algorithms": {"Ciphers/Triple DES 168": {**WIN01["schannel_algorithms"]["Ciphers/Triple DES 168"],
                                                              "enabled": False}}}
    assert "WEAK_CIPHER" not in _codes(off)
    strong = {"dotnet": [{**d, "sch_use_strong_crypto": 1} for d in WIN01["dotnet"]]}
    assert "DOTNET_WEAK_TLS" not in _codes(strong)
    unset = {"dotnet": [{**d, "sch_use_strong_crypto": None} for d in WIN01["dotnet"]]}
    assert "DOTNET_WEAK_TLS" not in _codes(unset)  # not set = OS default, which the network probe measures


def test_new_code_is_in_the_offline_kb_with_a_demo_family():
    entry = crypto_kb.load()["findings"]["node"]["DOTNET_WEAK_TLS"]
    assert entry["cwe"] and entry["remediation"]["steps"]
    assert "DOTNET_WEAK_TLS" in FAMILIES


def test_windows_setup_script_is_least_privilege():
    assert TEMPLATE_NAMES["windows-setup"][1].endswith(".ps1")
    text = template_text("windows-setup")
    assert "S-1-5-32-580" in text and "RootSDDL" in text and "0x20000000" in text
    assert "Administrators" not in text  # never adds the account to an admin group
