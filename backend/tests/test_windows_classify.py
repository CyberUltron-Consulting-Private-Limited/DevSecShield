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


def test_eol_openssl_mapped_by_a_container_process_is_flagged():
    """AWS lab: `openssl s_server` from a Debian buster container (OpenSSL 1.1.1n) on the host network."""
    facts = {"exe": "/usr/bin/openssl", "lib": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1", "pids": [6996],
             "deleted": False, "ports": [9444], "process": "openssl"}
    assert "LIB_EOL" in classify("process_library", None, None, None, facts)["finding_codes"]
    current = {**facts, "lib": "/usr/lib/x86_64-linux-gnu/libssl.so.3"}
    assert "LIB_EOL" not in classify("process_library", None, None, None, current)["finding_codes"]


def test_world_readable_key_and_luks1_from_new_node_facts():
    key = {"path": "/opt/payments/conf/server.key", "key_alg": "RSA", "key_size": 1024, "encrypted": False,
           "readable": True, "mode": "0644", "world_readable": True}
    got = classify("private_key", "RSA", 1024, None, key)["finding_codes"]
    assert {"KEY_WORLD_READABLE", "KEY_READABLE", "RSA_LT_2048"} <= set(got)
    disk = {"name": "zs_legacy_crypt", "cipher": "aes-cbc-essiv:sha256", "key_bits": 256, "effective_key_bits": 256,
            "device": "7:4", "luks_version": 1}
    assert {"LUKS1", "DISK_CBC"} <= set(classify("disk_encryption", "aes-cbc-essiv:sha256", 256, None, disk)["finding_codes"])


def test_host_service_secrets_overrides_and_cli_uses():
    sec = {"name": "AES_KEY", "encoding": "hex", "length": 64, "key_bits": 256, "store": "systemd unit Environment=",
           "unit": "zs-payments.service", "file": "/etc/systemd/system/zs-payments.service", "world_readable": True}
    assert classify("host_secret", None, 256, None, sec)["finding_codes"] == ["SECRET_IN_CONFIG"]
    ossl = {"kind": "openssl_conf", "used_by": ["zs-payments.service"], "directives": {
        "minprotocol": {"value": "TLSv1", "line": 12}, "cipherstring": {"value": "DEFAULT@SECLEVEL=0", "line": 13}}}
    assert {"MIN_TLS10", "TLS_POLICY_OVERRIDE"} <= set(classify("crypto_config", None, None, None, ossl)["finding_codes"])
    java = {"kind": "java_security", "used_by": ["zs-legacy-java.service"],
            "directives": {"jdk.tls.disabledalgorithms": {"value": "", "line": 1}}}
    assert classify("crypto_config", None, None, None, java)["finding_codes"] == ["TLS_POLICY_OVERRIDE"]
    strict_java = {**java, "directives": {"jdk.tls.disabledalgorithms": {"value": "SSLv3, TLSv1, RC4", "line": 1}}}
    assert classify("crypto_config", None, None, None, strict_java)["finding_codes"] == []
    ng = {"kind": "nginx", "protocols": ["TLSv1", "TLSv1.1", "TLSv1.2"], "ciphers": "ALL:@SECLEVEL=0"}
    assert {"PROTO_TLS10", "PROTO_TLS11", "WEAK_CIPHER"} <= set(classify("crypto_config", None, None, None, ng)["finding_codes"])
    good = {"kind": "nginx", "protocols": ["TLSv1.2", "TLSv1.3"], "ciphers": "ECDHE+AESGCM:!aNULL:!MD5"}
    assert classify("crypto_config", None, None, None, good)["finding_codes"] == []
    cron = {"kind": "openssl_cli", "file": "/etc/cron.d/zs-payments-backup", "line": 2, "cipher": "aes-128-cbc", "md": "md5",
            "pbkdf2": False, "decrypt": False, "hardcoded_passphrase": True}
    assert set(classify("crypto_config", "aes-128-cbc", None, None, cron)["finding_codes"]) == {"OPENSSL_ENC_WEAK_KDF", "SECRET_IN_CONFIG"}
    legacy = {**cron, "cipher": "des3", "md": None}
    assert "WEAK_CIPHER" in classify("crypto_config", "des3", None, None, legacy)["finding_codes"]
    modern = {**cron, "cipher": "aes-256-cbc", "pbkdf2": True, "hardcoded_passphrase": False}
    assert classify("crypto_config", "aes-256-cbc", None, None, modern)["finding_codes"] == []
