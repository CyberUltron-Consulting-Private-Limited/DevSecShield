"""Windows certificate keys: ECC size and curve (CB36-BUG-01); private-key facts left unread (CB36-BUG-02 split).

ZSLABDC below is what the certificates script prints for the C6 lab server (ZSLABDC, Windows Server 2022, CB-36,
2026-11-14). Every value comes from the SSM oracle that ran as SYSTEM on that server
(runs/C6-windows/oracle/ssm-oracle-before.txt), except KeyParameters:
* thumbprint, subject, issuer, NotAfter, signature algorithm, key algorithm (FriendlyName and "Algorithm ObjectId")
  and "Public Key Length" from ``Get-ChildItem`` / ``certutil -store -v My``; ``GetECDsaPublicKey(c).KeySize`` = 256
  for the two ECC certificates (CB6DDE1B... ecc-valid, FE331BE6... expired). Every one has a private key (certutil
  shows its key container; run 2 stored has_private_key true).
* KeyParameters is NOT in the oracle (its certutil filter left out "Algorithm Parameters"): it is the DER of the
  P-256 OID for the ECC rows (a 256-bit ECC key from New-SelfSignedCertificate's default ECDSA_nistP256) and
  ``05-00`` (ASN.1 NULL, RFC 4055) for RSA.
Rows marked SYNTHETIC were never observed on a host; they exercise parser paths (old .NET, DSA, unknown keys).
The run that found the bug (consistency-run2.json, assets #136/#138) stored key_size null and no curve for both ECC
certificates.
"""
from __future__ import annotations

import base64
import json
import re
import time

from zs_scan_node.collectors import windows_winrm as W
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

P256 = "06-08-2A-86-48-CE-3D-03-01-07"  # DER OBJECT IDENTIFIER 1.2.840.10045.3.1.7
RSA_NULL = "05-00"
LAB_CA = "CN=ZS Lab Enterprise CA, DC=lab, DC=zs, DC=test"
EC, RSA = "1.2.840.10045.2.1", "1.2.840.113549.1.1.1"


def _row(thumb, subject, issuer, not_after, sig, oid, friendly, params, size, *, error=None, store="My", private=True):
    return {"Store": store, "Subject": subject, "Issuer": issuer, "Thumbprint": thumb, "NotAfter": not_after,
            "SignatureAlgorithm": sig, "KeyAlgorithm": friendly, "KeyAlgorithmOid": oid, "KeyParameters": params,
            "KeySize": size, "KeyError": error, "HasPrivateKey": private}


ZSLABDC = [
    _row("FE331BE6A23EF51D9020A198E9613D7754E8AC6C", "CN=expired.lab.zs.test", "CN=expired.lab.zs.test",
         "2026-11-02T17:28:34.0000000Z", "sha256ECDSA", EC, "ECC", P256, 256),
    _row("F531E55FE678496340318D73ADDC9075C1A0CD39", "CN=ZSLABDC.lab.zs.test", LAB_CA,
         "2027-11-12T17:28:31.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048),
    _row("CB6DDE1BCB02D34B3C917A9ED7C253B589789C9B", "CN=ecc-valid.lab.zs.test", "CN=ecc-valid.lab.zs.test",
         "2027-01-13T04:54:30.0000000Z", "sha256ECDSA", EC, "ECC", P256, 256),
    _row("C0DC247958648C9276899D510F55A213681FDC1F", LAB_CA, LAB_CA,
         "2031-11-12T17:27:51.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048),
    _row("8BEB4085ECD0DA5319F4D97283AABD15CC96BCB6", "CN=ZSLABDC.lab.zs.test", LAB_CA,
         "2027-11-12T17:20:13.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048),
    _row("87C8207893AEF8E86D27EBC630152548304CA5C1", "CN=expired-rsa.lab.zs.test", "CN=expired-rsa.lab.zs.test",
         "2026-10-15T04:54:30.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048),
    _row("2540244C0B5C4581C0A5EF6B4929D05D88F72016", "CN=legacy-sha1.lab.zs.test", "CN=legacy-sha1.lab.zs.test",
         "2028-11-12T17:28:33.0000000Z", "sha1RSA", RSA, "RSA", RSA_NULL, 1024),
    _row("106D2A2313CD5A910A016AF9A56AE79C60B16823", "CN=cng-nonexport.lab.zs.test", "CN=cng-nonexport.lab.zs.test",
         "2027-01-13T04:54:30.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048),
]
CERTS_JSON = json.dumps(ZSLABDC, separators=(",", ":"))


def _by_thumb(rows):
    return {r["thumbprint"]: r for r in rows}


def test_ecc_p256_certificates_get_key_size_and_curve():
    rows = _by_thumb(W.parse_certificates(CERTS_JSON))
    for thumb in ("CB6DDE1BCB02D34B3C917A9ED7C253B589789C9B", "FE331BE6A23EF51D9020A198E9613D7754E8AC6C"):
        assert (rows[thumb]["key_alg"], rows[thumb]["key_size"], rows[thumb]["curve"]) == ("EC", 256, "P-256")
    # RSA rows stay sized and carry no curve
    assert rows["2540244C0B5C4581C0A5EF6B4929D05D88F72016"]["key_size"] == 1024
    assert rows["87C8207893AEF8E86D27EBC630152548304CA5C1"]["key_size"] == 2048
    assert all(rows[t]["curve"] is None for t in rows if rows[t]["key_alg"] == "RSA")
    assert not any("key_read_error" in r for r in rows.values())


def test_ecc_curve_alone_still_sizes_the_key():
    """SYNTHETIC: .NET Framework older than 4.6.1 has no GetECDsaPublicKey; the size comes from the named curve."""
    row = _row("AA", "CN=a", "CN=a", "2027-01-01T00:00:00.0000000Z", "sha384ECDSA", EC, "ECC",
               "06-05-2B-81-04-00-22", None, private=False,  # 1.3.132.0.34
               error="RuntimeException: Unable to find type "
                     "[System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions].")
    (c,) = W.parse_certificates(json.dumps([row]))
    assert (c["key_alg"], c["key_size"], c["curve"]) == ("EC", 384, "P-384")
    assert c["key_read_error"].startswith("RuntimeException: Unable to find type")


def test_private_key_facts_are_named_and_not_read():
    """No key is opened (CB-24 plan section 5): every certificate with a private key carries the provider and
    exportability facts as not read, so CB-24's R-HW-UNREAD sees them as unread rather than missing."""
    rows = W.parse_certificates(CERTS_JSON)
    assert len(rows) == 8 and all(r["has_private_key"] for r in rows)
    for r in rows:
        assert {k: r[k] for k in ("key_provider", "key_provider_type", "key_provider_class", "key_exportable",
                                  "exportable_basis", "key_not_read_reason")} == {
            "key_provider": None, "key_provider_type": None, "key_provider_class": None, "key_exportable": None,
            "exportable_basis": "not read: needs_key_open", "key_not_read_reason": "needs_key_open"}


def test_certificate_without_private_key_has_no_key_facts():
    """SYNTHETIC row."""
    row = _row("BB", "CN=b", "CN=ca", "2027-01-01T00:00:00.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048,
               private=False)
    (c,) = W.parse_certificates(json.dumps([row]))
    assert not any(k.startswith("key_provider") or k.startswith("key_export") for k in c)
    assert "exportable_basis" not in c and "key_not_read_reason" not in c


def test_dsa_and_unknown_keys_do_not_fail_the_batch():
    """SYNTHETIC rows: DSA (PublicKey.Key), an OID FriendlyName does not name, and a malformed row."""
    dsa = _row("D1", "CN=dsa", "CN=dsa", "2027-01-01T00:00:00.0000000Z", "sha1DSA", "1.2.840.10040.4.1", "DSA",
               "30-82-01-1E", 1024)
    ed = _row("E1", "CN=ed", "CN=ed", "2027-01-01T00:00:00.0000000Z", "1.3.101.112", "1.3.101.112", "", "", None,
              private=False)
    junk = _row("F1", "CN=junk", "CN=junk", "2027-01-01T00:00:00.0000000Z", "x", "not-an-oid", None, "ZZ-TOP", "big")
    rows = _by_thumb(W.parse_certificates(json.dumps([dsa, ed, junk, ZSLABDC[2]])))
    assert (rows["D1"]["key_alg"], rows["D1"]["key_size"], rows["D1"]["curve"]) == ("DSA", 1024, None)
    assert rows["E1"]["key_alg"] == "Ed25519" and rows["E1"]["key_size"] is None
    assert rows["F1"]["key_size"] is None and rows["F1"]["curve"] is None
    assert rows["CB6DDE1BCB02D34B3C917A9ED7C253B589789C9B"]["curve"] == "P-256"  # the rest of the batch survives


def test_rows_from_an_older_script_still_parse():
    old = ('[{"Store":"My","Subject":"CN=web","Issuer":"CN=ca","Thumbprint":"AB","NotAfter":"2027-01-01T00:00:00Z",'
           '"SignatureAlgorithm":"sha256ECDSA","KeyAlgorithm":"ECC","KeySize":null,"HasPrivateKey":true}]')
    (c,) = W.parse_certificates(old)
    assert (c["key_alg"], c["key_size"], c["curve"]) == ("EC", None, None)
    assert c["key_exportable"] is None and c["key_not_read_reason"] == "needs_key_open"


def _ctx() -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="windows_servers",
                      scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + 60)


def test_collect_emits_sized_ecc_certificates(monkeypatch):
    outputs = {"certificates": (0, CERTS_JSON, "")}
    monkeypatch.setattr(W, "_run", lambda _s, name: outputs.get(name, (0, "", "")))
    monkeypatch.setattr(W, "_session", lambda *a, **k: object())
    ctx = _ctx()
    W.collect_target(ctx, Target("zslabdc.lab.zs.test", "10.0.0.5"), {}, "pw")
    ctx.flush()
    certs = {a["location"]: a for a in ctx.collected if a["type"] == "certificate"}
    ecc = certs["cert:My/CB6DDE1BCB02D34B3C917A9ED7C253B589789C9B"]
    assert (ecc["algorithm"], ecc["key_size"], ecc["facts"]["curve"]) == ("EC", 256, "P-256")
    assert ecc["facts"]["key_not_read_reason"] == "needs_key_open"


def test_certificate_script_reads_public_keys_only():
    script = W.SCRIPTS["certificates"]
    for needed in ("GetECDsaPublicKey", "GetRSAPublicKey", "EncodedParameters", "GetBaseException()"):
        assert needed in script, needed
    # CB-24 plan T9: no private key is opened, and no certutil (it runs an encryption test with the key)
    assert not re.search(r"\.PrivateKey|Get\w*PrivateKey|CngKey|CspKeyContainerInfo|certutil|\.Export|SignData|SignHash|Decrypt|Encrypt", script, re.I)
    # Windows PowerShell 5.1: none of the PowerShell 7 operators
    assert not re.search(r"\?\?|\?\.|\s\?\s|&&|\|\|", script)


CMD_EXE_LIMIT = 8191  # cmd.exe's maximum command line (Microsoft: "Command prompt line string limitation")
MARGIN = 1024


def test_every_script_fits_the_command_line_with_margin():
    """pywinrm's run_ps sends ``powershell -encodedcommand <base64 of the UTF-16LE script>`` through cmd.exe; a
    script that grows past the limit fails on Windows with "The command line is too long"."""
    for name, script in W.SCRIPTS.items():
        line = "powershell -encodedcommand " + base64.b64encode(script.encode("utf_16_le")).decode("ascii")
        assert len(line) <= CMD_EXE_LIMIT - MARGIN, (name, len(line))
