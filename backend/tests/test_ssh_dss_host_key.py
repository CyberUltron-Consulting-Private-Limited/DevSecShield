"""#126 (review of #161, classification track): a collected DSA host key (``ssh-dss``, 1024 bits) got no finding at
all: algid did not know the SSH public-key name ``ssh-dss`` (classify logged "unknown identifier type=ssh_host_key
value=ssh-dss"), so the key was missing from the DSA / quantum counts (CERT-In 8.5.1, CNSA 2.0). algid now knows the
SSH DSA key names (RFC 4253 ``ssh-dss``; RFC 6187 ``x509v3-ssh-dss``, ``x509v3-sign-dss``) as DSA, in all three
vendored copies."""
from __future__ import annotations

import pytest

from backend.utilities.cbom_sources import algid
from backend.utilities.cbom_sources import classify as C


@pytest.mark.parametrize("name", ["ssh-dss", "x509v3-ssh-dss", "x509v3-sign-dss", "SSH-DSS"])
def test_algid_knows_the_ssh_dsa_key_names(name):
    found = algid.resolve(name)
    assert found is not None and found.family_label == "DSA" and found.quantum == "vulnerable", found
    assert C.family(name) == "DSA" and C.quantum_vulnerable(name) is True


def test_a_dsa_1024_ssh_host_key_gets_its_findings_and_no_unknown_log(capsys):
    C._unknown_seen.discard("ssh-dss")
    r = C.classify("ssh_host_key", "ssh-dss", 1024, None, {"type": "ssh-dss", "bits": 1024})
    assert "DSA" in r["finding_codes"] and "QUANTUM_VULNERABLE" in r["finding_codes"], r
    assert r["quantum_vulnerable"] is True and r["impact"] == "High"
    assert "unknown identifier" not in capsys.readouterr().out


def test_names_that_merely_contain_dss_are_not_dsa():
    for name in ("ssh-dssx", "dss", "sshdss-foo", "ML-DSA-65"):
        found = algid.resolve(name)
        assert found is None or found.family_label != "DSA", (name, found)


def test_other_ssh_host_keys_are_unchanged():
    for alg, bits, codes in (("ssh-ed25519", 256, ["QUANTUM_VULNERABLE"]), ("ssh-rsa", 1024, ["RSA_LT_2048", "QUANTUM_VULNERABLE"]),
                             ("ecdsa-sha2-nistp256", 256, ["QUANTUM_VULNERABLE"])):
        assert C.classify("ssh_host_key", alg, bits, None, {"type": alg, "bits": bits})["finding_codes"] == codes, alg
