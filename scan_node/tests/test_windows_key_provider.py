"""CB-24 PR-4b: a Windows certificate's key provider, read from the certificate's KEY_PROV_INFO property (the store's
registry Blob), never from the key: tells hardware-backed keys (TPM, smart card, HSM) from software keys for the
fix class (R-HW / R-HW-UNREAD), and adds NotBefore, serial and SHA-256 fingerprint for certificate identity.

KEY_PROV_INFO bytes are built here by hand from [MS-GPEF] 2.2.1.1.1.1.1 (28-byte header: container name offset,
provider name offset, provider type, flags, 8 reserved bytes, key spec; then the two NUL-terminated UTF-16LE names).
The provider names, containers and serials of the ZSLABDC rows are the C6 lab's recorded oracle (certutil -store -v
My, run as SYSTEM by SSM, /home/claude/work/cb36/runs/C6-windows/oracle/ssm-oracle-before.txt, 2026-11-14): seven
keys in "Microsoft Software Key Storage Provider" (CNG, type 0) and one in "Microsoft RSA SChannel Cryptographic
Provider" (CAPI). The TPM, smart card and HSM rows are SYNTHETIC (no such key in the lab). A unit test on hand-built
bytes encodes this reading of the spec; the acceptance row is the Tier V lab run (plan section 5)."""
from __future__ import annotations

import base64
import json
import re
import struct
import time

from test_windows_cert_keys import CERTS_JSON, ZSLABDC

from zs_scan_node.collectors import windows_winrm as W
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

KSP, SCHANNEL_TYPE, RSA_FULL = 0, 12, 1  # CNG KSP; CAPI PROV_RSA_SCHANNEL, PROV_RSA_FULL
AT_KEYEXCHANGE = 1


def key_prov_info(provider: str, container: str = "te-0000", prov_type: int = KSP, key_spec: int = 0,
                  provider_first: bool = False) -> str:
    """KEY_PROV_INFO as the registry Blob holds it ([MS-GPEF] 2.2.1.1.1.1.1), base64 as the script returns it."""
    cont = container.encode("utf-16-le") + b"\0\0"
    prov = provider.encode("utf-16-le") + b"\0\0"
    first, second = (prov, cont) if provider_first else (cont, prov)
    off_first, off_second = 28, 28 + len(first)
    off_cont, off_prov = (off_second, off_first) if provider_first else (off_first, off_second)
    header = struct.pack("<7I", off_cont, off_prov, prov_type, 0, 0, 0, key_spec)
    return base64.b64encode(header + first + second).decode()


# The lab's providers and serials (oracle), by thumbprint
ORACLE = {
    "FE331BE6A23EF51D9020A198E9613D7754E8AC6C": ("Microsoft Software Key Storage Provider", "te-2116f15e-e13c-4929-860a-a348d8469d8a", KSP, "46488E395AC51F824B6B513D53DE3733"),
    "F531E55FE678496340318D73ADDC9075C1A0CD39": ("Microsoft Software Key Storage Provider", "te-b5f78226-d327-4241-bc76-c5630fb7d454", KSP, "125CB14D7BF7BF9348BF5EF9C551B4A7"),
    "CB6DDE1BCB02D34B3C917A9ED7C253B589789C9B": ("Microsoft Software Key Storage Provider", "te-0ea848d8-bb53-46f6-9ae0-e315d62f33c8", KSP, "6FCEC7EA180461814410B93C8AECED19"),
    "C0DC247958648C9276899D510F55A213681FDC1F": ("Microsoft Software Key Storage Provider", "ZS Lab Enterprise CA", KSP, "432207849A89D5854FF8BD7E175789F3"),
    "8BEB4085ECD0DA5319F4D97283AABD15CC96BCB6": ("Microsoft RSA SChannel Cryptographic Provider", "fda05bd4d73a9d7e33ac7c27b0633d85_2ddd5afb-cdcc-47f7-b0a3-75dfb7afc932", SCHANNEL_TYPE, "4F00000002CA7E6D20A35F20E3000000000002"),
    "87C8207893AEF8E86D27EBC630152548304CA5C1": ("Microsoft Software Key Storage Provider", "te-9cfd2676-053d-4ef9-880f-d536391bf8d6", KSP, "4BC64F8239E63A864DC9A1EF0C7C53A2"),
    "2540244C0B5C4581C0A5EF6B4929D05D88F72016": ("Microsoft Software Key Storage Provider", "te-6fb4fff1-7d81-4135-950c-a89604747e44", KSP, "3DD938D560A5A687455CE26B667B6221"),
    "106D2A2313CD5A910A016AF9A56AE79C60B16823": ("Microsoft Software Key Storage Provider", "te-70d63389-84db-4b89-b6bd-ed12511a9883", KSP, "16C9DB37785714994C2A98009F0BC389"),
}
SHA256 = "3F-9A-1C-2B-7D-4E-5F-60-71-82-93-A4-B5-C6-D7-E8-F9-01-23-45-67-89-AB-CD-EF-01-23-45-67-89-AB-CD"


def lab_rows() -> list[dict]:
    rows = []
    for r in ZSLABDC:
        provider, container, ptype, serial = ORACLE[r["Thumbprint"]]
        rows.append({**r, "NotBefore": "2026-11-12T17:28:31.0000000Z", "Serial": serial, "Sha256": SHA256,
                     "KeyProv": key_prov_info(provider, container, ptype, 0 if ptype == KSP else AT_KEYEXCHANGE),
                     "KeyProvError": None})
    return rows


def _by_thumb(rows):
    return {r["thumbprint"]: r for r in rows}


def _synthetic(thumb, provider, prov_type=KSP, **extra):
    base = dict(ZSLABDC[1], Thumbprint=thumb)
    return {**base, "KeyProv": key_prov_info(provider, "c", prov_type), "KeyProvError": None, **extra}


# --------------------------------------------------------------------------------------------- the lab (oracle)
def test_the_lab_keys_read_as_their_recorded_providers():
    rows = _by_thumb(W.parse_certificates(json.dumps(lab_rows())))
    assert len(rows) == 8
    for thumb, (provider, _container, ptype, serial) in ORACLE.items():
        r = rows[thumb]
        assert r["key_provider"] == provider and r["key_provider_class"] == "software", r
        assert r["key_provider_type"] == ("cng" if ptype == KSP else "capi") and r["key_provider_type_id"] == ptype
        # software provider: exportability is a property of the key, never read (it needs opening the key)
        assert r["key_exportable"] is None and r["exportable_basis"] == "not read: needs opening the key"
        assert r["serial"] == serial and r["not_before"] == "2026-11-12T17:28:31.0000000Z"
        assert r["fingerprint_sha256"] == SHA256.replace("-", "").lower()
        assert "key_not_read_reason" not in r
        assert all("te-" not in str(v) and "ZS Lab Enterprise CA" != v for k, v in r.items() if k.startswith("key_")), \
            "the container name is not kept"


def test_the_capi_schannel_key_is_capi_with_its_key_spec():
    r = _by_thumb(W.parse_certificates(json.dumps(lab_rows())))["8BEB4085ECD0DA5319F4D97283AABD15CC96BCB6"]
    assert (r["key_provider_type"], r["key_provider_type_id"], r["key_spec"]) == ("capi", SCHANNEL_TYPE, AT_KEYEXCHANGE)


# --------------------------------------------------------------------------------------------- plan T9
def test_hardware_providers_are_hardware_and_not_exportable_on_the_providers_basis():
    """SYNTHETIC: TPM, smart card (KSP and CAPI) and HSM vendor KSPs."""
    cases = {
        "T1": ("Microsoft Platform Crypto Provider", "tpm"),
        "T2": ("Microsoft Smart Card Key Storage Provider", "smartcard"),
        "T3": ("Microsoft Base Smart Card Crypto Provider", "smartcard"),
        "T4": ("nCipher Security World Key Storage Provider", "hsm"),
        "T5": ("SafeNet Key Storage Provider", "hsm"),
        "T6": ("CloudHSM Key Storage Provider", "hsm"),
        "T7": ("Cavium Key Storage Provider", "hsm"),
        "T8": ("MICROSOFT PLATFORM CRYPTO PROVIDER", "tpm"),  # names compare case-insensitively
    }
    rows = _by_thumb(W.parse_certificates(json.dumps([_synthetic(t, p) for t, (p, _c) in cases.items()])))
    for thumb, (provider, cls) in cases.items():
        r = rows[thumb]
        assert (r["key_provider"], r["key_provider_class"]) == (provider, cls), r
        assert r["key_exportable"] is False and r["exportable_basis"] == "provider"


def test_an_unlisted_provider_is_other_never_guessed():
    """SYNTHETIC: a vendor KSP not in the reviewed list, and Windows Hello's Passport KSP (TPM or software)."""
    rows = _by_thumb(W.parse_certificates(json.dumps([
        _synthetic("U1", "Contoso Quantum HSM Key Storage Provider"),
        _synthetic("U2", "Microsoft Passport Key Storage Provider")])))
    for t in ("U1", "U2"):
        assert rows[t]["key_provider_class"] == "other" and rows[t]["key_exportable"] is None


def test_the_provider_name_may_come_before_the_container():
    data = key_prov_info("Microsoft Platform Crypto Provider", "c1", provider_first=True)
    assert W.parse_key_prov_info(data)["provider"] == "Microsoft Platform Crypto Provider"


def test_without_the_property_every_key_fact_stays_not_read_with_the_reason():
    base = dict(ZSLABDC[1])
    cases = {
        "N1": ({"KeyProv": None, "KeyProvError": None}, "key_prov_info_absent"),
        "N2": ({"KeyProv": None, "KeyProvError": "UnauthorizedAccessException"},
               "key_prov_info_unreadable: UnauthorizedAccessException"),
        "N3": ({"KeyProv": "AAAA"}, "key_prov_info_malformed"),               # 3 bytes
        "N4": ({"KeyProv": "not base64!"}, "key_prov_info_malformed"),
        "N5": ({}, "needs_key_open"),                                          # a script before PR-4b
    }
    rows = _by_thumb(W.parse_certificates(json.dumps([{**base, "Thumbprint": t, **extra} for t, (extra, _r) in cases.items()])))
    for thumb, (_extra, reason) in cases.items():
        r = rows[thumb]
        assert r["key_provider_class"] is None and r["key_provider"] is None and r["key_exportable"] is None, r
        assert r["key_not_read_reason"] == reason and r["exportable_basis"] == f"not read: {reason}"


def test_malformed_key_prov_info_never_raises():
    header = struct.pack("<7I", 28, 28, 0, 0, 0, 0, 0)
    bad = [
        header,                                                       # no names at all
        struct.pack("<7I", 28, 9999, 0, 0, 0, 0, 0) + b"a\0\0\0",     # provider offset outside
        struct.pack("<7I", 28, 29, 0, 0, 0, 0, 0) + b"ab\0\0" * 4,    # odd offset
        struct.pack("<7I", 28, 28, 0, 0, 0, 0, 0) + "x".encode("utf-16-le") * 300,  # no terminator
        struct.pack("<7I", 28, 28, 0, 0, 0, 0, 0) + b"\0\xd8\0\0",    # lone surrogate
        struct.pack("<7I", 0, 4, 0, 0, 0, 0, 0) + b"\0\0",            # offset into the header
        b"x" * 5000,                                                  # too long
    ]
    for data in bad:
        assert W.parse_key_prov_info(base64.b64encode(data).decode()) is None, data[:40]
    assert W.parse_key_prov_info(None) is None and W.parse_key_prov_info(123) is None


def test_identity_facts_are_normalised_or_dropped():
    row = dict(ZSLABDC[1], Serial="4f00 0000", Sha256="ZZ", NotBefore=None)
    (c,) = W.parse_certificates(json.dumps([row]))
    assert c["serial"] is None and c["fingerprint_sha256"] is None and c["not_before"] is None


def test_a_certificate_without_a_private_key_carries_no_provider():
    row = dict(ZSLABDC[1], HasPrivateKey=False, KeyProv=key_prov_info("Microsoft Platform Crypto Provider"))
    (c,) = W.parse_certificates(json.dumps([row]))
    assert not any(k.startswith("key_provider") or k.startswith("key_export") for k in c)


# --------------------------------------------------------------------------------------------- the script
def test_the_script_reads_key_prov_info_from_the_registry_and_never_opens_a_key():
    script = W.SCRIPTS["certificates"]
    for needed in ("SystemCertificates", "-Name Blob", "ToUInt32($b,$i) -eq 2", "ToBase64String($b,$i+12,$n)",
                   "if ($c.HasPrivateKey)", "NotBefore", "SerialNumber", "SHA256", "RawData"):
        assert needed in script, needed
    # plan section 5 / T9: none of the cmdlets or members that open a private key
    assert not re.search(r"\.PrivateKey|Get\w*PrivateKey|CngKey|CspKeyContainerInfo|certutil|\.Export|SignData|"
                         r"SignHash|Decrypt|Encrypt|NCrypt|CryptAcquire", script, re.I)
    # Windows PowerShell 5.1 only
    assert not re.search(r"\?\?|\?\.|\s\?\s|&&|\|\|", script)


def _ctx() -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="windows_servers",
                      scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + 60)


def test_collect_emits_the_provider_facts(monkeypatch):
    rows = lab_rows() + [_synthetic("ABCDEF", "Microsoft Platform Crypto Provider")]
    outputs = {"certificates": (0, json.dumps(rows), "")}
    monkeypatch.setattr(W, "_run", lambda _s, name: outputs.get(name, (0, "", "")))
    monkeypatch.setattr(W, "_session", lambda *a, **k: object())
    ctx = _ctx()
    W.collect_target(ctx, Target("zslabdc.lab.zs.test", "10.0.0.5"), {}, "pw")
    ctx.flush()
    certs = {a["location"]: a for a in ctx.collected if a["type"] == "certificate"}
    tpm = certs["cert:My/ABCDEF"]["facts"]
    assert (tpm["key_provider_class"], tpm["key_exportable"], tpm["source"]) == ("tpm", False, "windows-store")
    sw = certs["cert:My/106D2A2313CD5A910A016AF9A56AE79C60B16823"]["facts"]
    assert sw["key_provider"] == "Microsoft Software Key Storage Provider" and sw["key_provider_class"] == "software"


def test_older_script_rows_still_parse_as_before():
    rows = W.parse_certificates(CERTS_JSON)
    assert all(r["key_not_read_reason"] == "needs_key_open" and r["key_provider_class"] is None for r in rows)
