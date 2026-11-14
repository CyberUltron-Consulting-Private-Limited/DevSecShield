"""Windows certificate keys: ECC size and curve (CB36-BUG-01), key provider and exportability (CB36-BUG-02).

The rows below are what the certificates script prints for the C6 lab server (ZSLABDC, Windows Server 2022, CB-36,
2026-11-14), built from the SSM oracle that ran as SYSTEM on that server
(runs/C6-windows/oracle/ssm-oracle-before.txt):
* ``GetECDsaPublicKey(c).KeySize`` = 256 and ``certutil -store -v My`` "Public Key Length: 256 bits" for the two ECC
  certificates (CB6DDE1B... ecc-valid, FE331BE6... expired); their EncodedParameters are the P-256 named curve.
* certutil "Provider = Microsoft Software Key Storage Provider" and "Export Policy = 0" for cng-nonexport (106D2A23...),
  1 (NCRYPT_ALLOW_EXPORT_FLAG) for the other KSP keys, 3 for the CA key (C0DC2479...).
* certutil "Provider = Microsoft RSA SChannel Cryptographic Provider" (CAPI) for the DC certificate 8BEB4085...; certutil
  prints no export flag for a CAPI key, so its Exportable value here (false) is the DomainController template default,
  not an oracle reading.
* legacy-sha1 (2540244C...) RSA-1024 / sha1RSA, expired-rsa (87C82078...) RSA-2048 expired 2026-10-15.
The run that found the bugs (consistency-run2.json, assets #136/#138) stored key_size null and no curve for both ECC
certificates, and no provider or exportability for any.
"""
from __future__ import annotations

import json
import re
import time

from zs_scan_node.collectors import windows_winrm as W
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

P256 = "06-08-2A-86-48-CE-3D-03-01-07"  # DER OBJECT IDENTIFIER 1.2.840.10045.3.1.7
RSA_NULL = "05-00"
KSP = "Microsoft Software Key Storage Provider"
SCHANNEL_CSP = "Microsoft RSA SChannel Cryptographic Provider"
LAB_CA = "CN=ZS Lab Enterprise CA, DC=lab, DC=zs, DC=test"


def _row(thumb, subject, issuer, not_after, sig, oid, friendly, params, size, *, provider=None, ptype=None,
         policy=None, exportable=None, hardware=None, error=None, store="My", private=True):
    return {"Store": store, "Subject": subject, "Issuer": issuer, "Thumbprint": thumb, "NotAfter": not_after,
            "SignatureAlgorithm": sig, "KeyAlgorithm": friendly, "KeyAlgorithmOid": oid, "KeyParameters": params,
            "KeySize": size, "HasPrivateKey": private, "KeyProvider": provider, "KeyProviderType": ptype,
            "KeyExportPolicy": policy, "KeyExportable": exportable, "KeyHardware": hardware, "KeyError": error}


EC, RSA = "1.2.840.10045.2.1", "1.2.840.113549.1.1.1"
ZSLABDC = [  # the script's output as an account that may open the keys (the oracle ran as SYSTEM)
    _row("FE331BE6A23EF51D9020A198E9613D7754E8AC6C", "CN=expired.lab.zs.test", "CN=expired.lab.zs.test",
         "2026-11-02T17:28:34.0000000Z", "sha256ECDSA", EC, "ECC", P256, 256, provider=KSP, ptype="cng", policy=1),
    _row("F531E55FE678496340318D73ADDC9075C1A0CD39", "CN=ZSLABDC.lab.zs.test", LAB_CA,
         "2027-11-12T17:28:31.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048, provider=KSP, ptype="cng", policy=1),
    _row("CB6DDE1BCB02D34B3C917A9ED7C253B589789C9B", "CN=ecc-valid.lab.zs.test", "CN=ecc-valid.lab.zs.test",
         "2027-01-13T04:54:30.0000000Z", "sha256ECDSA", EC, "ECC", P256, 256, provider=KSP, ptype="cng", policy=1),
    _row("C0DC247958648C9276899D510F55A213681FDC1F", LAB_CA, LAB_CA,
         "2031-11-12T17:27:51.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048, provider=KSP, ptype="cng", policy=3),
    _row("8BEB4085ECD0DA5319F4D97283AABD15CC96BCB6", "CN=ZSLABDC.lab.zs.test", LAB_CA,
         "2027-11-12T17:20:13.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048, provider=SCHANNEL_CSP, ptype="capi",
         exportable=False, hardware=False),
    _row("87C8207893AEF8E86D27EBC630152548304CA5C1", "CN=expired-rsa.lab.zs.test", "CN=expired-rsa.lab.zs.test",
         "2026-10-15T04:54:30.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048, provider=KSP, ptype="cng", policy=1),
    _row("2540244C0B5C4581C0A5EF6B4929D05D88F72016", "CN=legacy-sha1.lab.zs.test", "CN=legacy-sha1.lab.zs.test",
         "2028-11-12T17:28:33.0000000Z", "sha1RSA", RSA, "RSA", RSA_NULL, 1024, provider=KSP, ptype="cng", policy=1),
    _row("106D2A2313CD5A910A016AF9A56AE79C60B16823", "CN=cng-nonexport.lab.zs.test", "CN=cng-nonexport.lab.zs.test",
         "2027-01-13T04:54:30.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048, provider=KSP, ptype="cng", policy=0),
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


def test_ecc_curve_alone_still_sizes_the_key():
    """.NET Framework older than 4.6.1 has no GetECDsaPublicKey: the size comes from the named curve."""
    row = _row("AA", "CN=a", "CN=a", "2027-01-01T00:00:00.0000000Z", "sha384ECDSA", EC, "ECC",
               "06-05-2B-81-04-00-22", None, private=False)  # 1.3.132.0.34
    (c,) = W.parse_certificates(json.dumps([row]))
    assert (c["key_alg"], c["key_size"], c["curve"]) == ("EC", 384, "P-384")


def test_cng_non_exportable_and_exportable_keys():
    rows = _by_thumb(W.parse_certificates(CERTS_JSON))
    nonexport = rows["106D2A2313CD5A910A016AF9A56AE79C60B16823"]
    assert {k: nonexport[k] for k in ("key_provider", "key_provider_type", "key_provider_class", "key_exportable",
                                      "key_export_policy", "key_plaintext_exportable", "exportable_basis")} == {
        "key_provider": KSP, "key_provider_type": "cng", "key_provider_class": "software", "key_exportable": False,
        "key_export_policy": 0, "key_plaintext_exportable": False, "exportable_basis": "CNG export policy"}
    legacy = rows["2540244C0B5C4581C0A5EF6B4929D05D88F72016"]  # RSA-1024, Export Policy 1 (NCRYPT_ALLOW_EXPORT_FLAG)
    assert (legacy["key_exportable"], legacy["key_plaintext_exportable"], legacy["key_export_policy"]) == (True, False, 1)
    ca = rows["C0DC247958648C9276899D510F55A213681FDC1F"]  # Export Policy 3: export and plaintext export
    assert (ca["key_exportable"], ca["key_plaintext_exportable"]) == (True, True)
    assert rows["87C8207893AEF8E86D27EBC630152548304CA5C1"]["key_exportable"] is True  # expired RSA-2048


def test_capi_key_provider_and_exportable_flag():
    capi = _by_thumb(W.parse_certificates(CERTS_JSON))["8BEB4085ECD0DA5319F4D97283AABD15CC96BCB6"]
    assert (capi["key_provider"], capi["key_provider_type"], capi["key_provider_class"]) == (
        SCHANNEL_CSP, "capi", "software")
    assert (capi["key_exportable"], capi["exportable_basis"], capi["key_hardware"]) == (
        False, "CAPI CRYPT_EXPORTABLE", False)
    assert "key_export_policy" not in capi or capi["key_export_policy"] is None


def test_provider_classes_are_a_reviewed_list_never_guessed():
    assert W.key_provider_class("Microsoft Platform Crypto Provider") == "tpm"
    assert W.key_provider_class("Microsoft Smart Card Key Storage Provider") == "smartcard"
    assert W.key_provider_class("Microsoft Base Smart Card Crypto Provider") == "smartcard"
    assert W.key_provider_class("Microsoft Enhanced RSA and AES Cryptographic Provider") == "software"
    assert W.key_provider_class("Some Vendor Key Storage Provider") == "other"
    assert W.key_provider_class(None) is None and W.key_provider_class("") is None


def test_key_that_cannot_be_opened_is_not_read_not_guessed():
    """A least-privilege account (the UI's setup script) has no access to LocalMachine private keys: the script
    records why, and the row keeps everything else."""
    row = _row("106D2A2313CD5A910A016AF9A56AE79C60B16823", "CN=cng-nonexport.lab.zs.test",
               "CN=cng-nonexport.lab.zs.test", "2027-01-13T04:54:30.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048,
               error="CryptographicException: Keyset does not exist")
    (c,) = W.parse_certificates(json.dumps([row]))
    assert c["key_size"] == 2048 and c["has_private_key"] is True
    assert c["key_provider"] is None and c["key_exportable"] is None and "key_provider_class" not in c
    assert c["exportable_basis"] == "not read: CryptographicException: Keyset does not exist"


def test_certificate_without_private_key_has_no_key_facts():
    row = _row("BB", "CN=b", "CN=ca", "2027-01-01T00:00:00.0000000Z", "sha256RSA", RSA, "RSA", RSA_NULL, 2048,
               private=False)
    (c,) = W.parse_certificates(json.dumps([row]))
    assert not any(k.startswith("key_provider") or k.startswith("key_export") for k in c)
    assert "exportable_basis" not in c


def test_dsa_and_unknown_keys_do_not_fail_the_batch():
    dsa = _row("D1", "CN=dsa", "CN=dsa", "2027-01-01T00:00:00.0000000Z", "sha1DSA", "1.2.840.10040.4.1", "DSA",
               "30-82-01-1E", 1024, error="no private key handle for this key type")
    ed = _row("E1", "CN=ed", "CN=ed", "2027-01-01T00:00:00.0000000Z", "1.3.101.112", "1.3.101.112", "", "", None,
              private=False)
    junk = _row("F1", "CN=junk", "CN=junk", "2027-01-01T00:00:00.0000000Z", "x", "not-an-oid", None, "ZZ-TOP", "big")
    rows = _by_thumb(W.parse_certificates(json.dumps([dsa, ed, junk, ZSLABDC[2]])))
    assert (rows["D1"]["key_alg"], rows["D1"]["key_size"], rows["D1"]["curve"]) == ("DSA", 1024, None)
    assert rows["D1"]["key_exportable"] is None
    assert rows["E1"]["key_alg"] == "Ed25519" and rows["E1"]["key_size"] is None
    assert rows["F1"]["key_size"] is None and rows["F1"]["curve"] is None
    assert rows["CB6DDE1BCB02D34B3C917A9ED7C253B589789C9B"]["curve"] == "P-256"  # the rest of the batch survives


def test_rows_from_an_older_script_still_parse():
    old = ('[{"Store":"My","Subject":"CN=web","Issuer":"CN=ca","Thumbprint":"AB","NotAfter":"2027-01-01T00:00:00Z",'
           '"SignatureAlgorithm":"sha256ECDSA","KeyAlgorithm":"ECC","KeySize":null,"HasPrivateKey":true}]')
    (c,) = W.parse_certificates(old)
    assert (c["key_alg"], c["key_size"], c["curve"]) == ("EC", None, None)
    assert c["key_exportable"] is None and c["exportable_basis"] == "not read: the node's script did not report it"


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
    nonexport = certs["cert:My/106D2A2313CD5A910A016AF9A56AE79C60B16823"]["facts"]
    assert (nonexport["key_provider_class"], nonexport["key_exportable"]) == ("software", False)


def test_certificate_script_reads_keys_without_touching_key_material():
    script = W.SCRIPTS["certificates"]
    for needed in ("GetECDsaPublicKey", "GetRSAPublicKey", "EncodedParameters", "ExportPolicy",
                   "CspKeyContainerInfo", "Dispose()"):
        assert needed in script, needed
    # no export, no use of the key, no certutil (it runs an encryption test with the key)
    assert not re.search(r"\.Export(?!Policy\b|able\b)|ToXmlString|SignData|SignHash|Decrypt|Encrypt|certutil", script, re.I)
    # Windows PowerShell 5.1: none of the PowerShell 7 operators
    assert not re.search(r"\?\?|\?\.|\s\?\s|&&|\|\|", script)
