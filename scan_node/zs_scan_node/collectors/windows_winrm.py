"""Windows servers over WinRM (HTTPS 5986 by default) with read-only PowerShell.

Every script below only reads: certificate stores, the SCHANNEL protocol registry keys, the TLS cipher suite
order, BitLocker volume status and the RDP security settings.  Output is JSON (``ConvertTo-Json``) and is parsed
by the pure functions at the bottom, which the unit tests cover.  Not exercised against a live Windows host in
the local lab (validated in the AWS lab).
"""
from __future__ import annotations

import concurrent.futures as cf
import contextlib
import json
import os
import shutil
import tempfile
import time
from typing import Any

from urllib.parse import urlsplit

from zs_scan_node import algid, netutil
from zs_scan_node.collectors import ConfigError, skipped_never_scan
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Blocked, Target, checked_ip, expand_targets, is_ip, resolve_checked
from zs_scan_node.scrub import printable

SCRIPTS = {
    # Certificates in the machine stores.  Key size from the key object: PublicKey.Key works only for RSA and DSA on
    # .NET Framework 4.x (it throws for ECC), so RSA and ECC go through GetRSAPublicKey / GetECDsaPublicKey (.NET
    # Framework 4.6 / 4.6.1).  The curve is the named-curve OID in the public key's EncodedParameters (DER, as hex).
    # Public keys only: no private key is ever opened (CB-24 plan section 5; opening one needs key ACLs the
    # least-privilege account does not have, and logs an "Open Key" audit event).  A public key that cannot be read
    # leaves KeySize null and its base exception in KeyError; the row is still emitted.  RSA and ECC are told apart
    # by OID, as FriendlyName is localised.  Windows PowerShell 5.1 syntax only.
    # Key provider (CB-24 PR-4b): for a certificate with a private key, the store's registry value Blob holds the
    # certificate's serialized properties ([MS-GPEF] 2.2.1.1.1.1: PropertyID, reserved, Length, Value); property 2,
    # KEY_PROV_INFO, names the key's provider. Only that property's bytes are returned (base64, parsed below): reading
    # the registry value opens no key. NotBefore, SerialNumber and the SHA-256 of RawData identify the certificate
    # (the same cert_identity / fingerprint_sha256 as the TLS prober and Linux files).
    "certificates": (
        "& { $rsa='1.2.840.113549.1.1.1'; $ec='1.2.840.10045.2.1'; "
        "Get-ChildItem -Path Cert:\\LocalMachine\\My,Cert:\\LocalMachine\\WebHosting,Cert:\\LocalMachine\\Remote` Desktop "
        "-ErrorAction SilentlyContinue | ForEach-Object { $c=$_; $oid=$c.PublicKey.Oid.Value; $size=$null; $k=$null; "
        "$kerr=$null; $par=$null; "
        "try { if ($c.PublicKey.EncodedParameters) { $par=[BitConverter]::ToString($c.PublicKey.EncodedParameters."
        "RawData) } } catch { $par=$null }; "
        "try { if ($oid -eq $rsa) { $k=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::"
        "GetRSAPublicKey($c) } elseif ($oid -eq $ec) { $k=[System.Security.Cryptography.X509Certificates."
        "ECDsaCertificateExtensions]::GetECDsaPublicKey($c) } else { $k=$c.PublicKey.Key }; "
        "if ($k) { $size=$k.KeySize } } "
        "catch { $e=$_.Exception.GetBaseException(); $kerr=$e.GetType().Name + ': ' + $e.Message }; "
        "$st=$c.PSParentPath.Split('\\')[-1]; $kp=$null; $kperr=$null; "
        "if ($c.HasPrivateKey) { try { $b=(Get-ItemProperty -LiteralPath ('HKLM:\\SOFTWARE\\Microsoft\\"
        "SystemCertificates\\'+$st+'\\Certificates\\'+$c.Thumbprint) -Name Blob -ErrorAction Stop).Blob; $i=0; "
        "while ($i+12 -le $b.Length) { $n=[BitConverter]::ToUInt32($b,$i+8); if ([BitConverter]::ToUInt32($b,$i) "
        "-eq 2 -and $i+12+$n -le $b.Length) { $kp=[Convert]::ToBase64String($b,$i+12,$n) }; $i+=12+$n } } "
        "catch { $kperr=$_.Exception.GetBaseException().GetType().Name } }; "
        "$fp=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData)); "
        "[pscustomobject]@{ Store=$st; Subject=$c.Subject; Issuer=$c.Issuer; "
        "Thumbprint=$c.Thumbprint; NotAfter=$c.NotAfter.ToUniversalTime().ToString('o'); "
        "NotBefore=$c.NotBefore.ToUniversalTime().ToString('o'); Serial=$c.SerialNumber; Sha256=$fp; "
        "SignatureAlgorithm=$c.SignatureAlgorithm.FriendlyName; KeyAlgorithm=$c.PublicKey.Oid.FriendlyName; "
        "KeyAlgorithmOid=$oid; KeyParameters=$par; KeySize=$size; KeyError=$kerr; HasPrivateKey=$c.HasPrivateKey; "
        "KeyProv=$kp; KeyProvError=$kperr } "
        "} } | ConvertTo-Json -Depth 3 -Compress"
    ),
    "schannel": (
        "$b='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols'; "
        "Get-ChildItem $b -ErrorAction SilentlyContinue | ForEach-Object { $p=$_.PSChildName; "
        "foreach ($side in 'Server','Client') { $k=Join-Path $_.PSPath $side; if (Test-Path $k) { $v=Get-ItemProperty $k; "
        "[pscustomobject]@{ Protocol=$p; Side=$side; Enabled=$v.Enabled; DisabledByDefault=$v.DisabledByDefault } } } } "
        "| ConvertTo-Json -Compress"
    ),
    # Effective TLS cipher suite order: the Group Policy list overrides the local one when it is set.  Windows
    # PowerShell 5.1 writes Get-TlsCipherSuite's result as ONE List object, so it is unrolled with ForEach-Object
    # (Select-Object -ExpandProperty Name fails on the list).
    "cipher_suites": (
        "& { $p='HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002'; "
        "$f=(Get-ItemProperty $p -Name Functions -ErrorAction SilentlyContinue).Functions; "
        "if ($f) { [pscustomobject]@{ Source='policy'; Suites=@((($f -join ',') -split ',') | Where-Object { $_ }) } } "
        "else { [pscustomobject]@{ Source='local'; Suites=@(Get-TlsCipherSuite | ForEach-Object { $_ } | "
        "ForEach-Object { $_.Name }) } } } | ConvertTo-Json -Compress -Depth 3"
    ),
    # SCHANNEL per-algorithm switches (Ciphers, Hashes, KeyExchangeAlgorithms); a missing key means the OS default.
    "schannel_algorithms": (
        "& { $b='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL'; "
        "foreach ($kind in 'Ciphers','Hashes','KeyExchangeAlgorithms') { Get-ChildItem (Join-Path $b $kind) "
        "-ErrorAction SilentlyContinue | ForEach-Object { $v=Get-ItemProperty $_.PSPath; [pscustomobject]@{ "
        "Kind=$kind; Name=$_.PSChildName; Enabled=$v.Enabled; ServerMinKeyBitLength=$v.ServerMinKeyBitLength } } } } "
        "| ConvertTo-Json -Compress"
    ),
    # .NET Framework TLS: SchUseStrongCrypto=0 lets .NET 4.x apps negotiate SSL 3.0/TLS 1.0 and RC4.
    "dotnet": (
        "& { foreach ($k in 'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319',"
        "'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v2.0.50727') { if (Test-Path $k) { "
        "$v=Get-ItemProperty $k; [pscustomobject]@{ Key=$k; SchUseStrongCrypto=$v.SchUseStrongCrypto; "
        "SystemDefaultTlsVersions=$v.SystemDefaultTlsVersions } } } } | ConvertTo-Json -Compress"
    ),
    "bitlocker": (
        "Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Mount=$_.MountPoint; "
        "Status=\"$($_.VolumeStatus)\"; Method=\"$($_.EncryptionMethod)\"; Protection=\"$($_.ProtectionStatus)\" } } "
        "| ConvertTo-Json -Compress"
    ),
    "rdp": (
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "| Select-Object SecurityLayer,MinEncryptionLevel,UserAuthentication | ConvertTo-Json -Compress"
    ),
    # The registry, not WMI: a non-administrator has no "Remote Enable" on root\\cimv2, so Get-CimInstance is denied.
    "os": (
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | Select-Object "
        "@{n='Caption';e={$_.ProductName}},@{n='Version';e={\"10.0.$($_.CurrentBuild).$($_.UBR)\"}},"
        "@{n='BuildNumber';e={$_.CurrentBuild}},DisplayVersion,EditionID | ConvertTo-Json -Compress"
    ),
}


def _json_list(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, (dict, str))] if isinstance(data, list) else []


_KEY_ALGS = {"1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.2.840.10040.4.1": "DSA"}
_FRIENDLY = {"RSA": "RSA", "ECC": "EC", "DSA": "DSA"}
# Private-key facts: no key is ever opened. The provider comes from the certificate's KEY_PROV_INFO property (CB-24
# PR-4b); exportability is a property of the key itself (CNG export policy, CAPI CRYPT_EXPORTABLE), readable only by
# opening the key, so it is never read for a software provider. A fact that was not read keeps its name, unread, so
# CB-24's R-HW-UNREAD sees it as not read rather than missing.
KEY_NOT_READ = "needs_key_open"

# Reviewed provider names -> key_provider_class (exact names, compared case-insensitively). A name not listed here is
# "other" (CB-24 R-HW-UNREAD: unknown, never guessed). Sources, checked 2026-11-14:
# * Microsoft KSPs: learn.microsoft.com/windows/win32/seccertenroll/cng-key-storage-providers
# * Microsoft CSPs: learn.microsoft.com/windows/win32/seccrypto/cryptographic-provider-names
# * nCipher (Entrust nShield): nshielddocs.entrust.com/interops-docs/ms-adcs-ocsp/adcs.html
# * SafeNet (Thales Luna): thalesdocs.com/gphsm/integrations/guides/microsoft_adcs ("RSA#SafeNet Key Storage Provider")
# * AWS CloudHSM: docs.aws.amazon.com/cloudhsm/latest/userguide/ksp-library-apis-open-provider.html (SDK 5 and SDK 3)
KEY_PROVIDERS: dict[str, str] = {
    "microsoft software key storage provider": "software",
    "microsoft base cryptographic provider v1.0": "software",
    "microsoft enhanced cryptographic provider v1.0": "software",
    "microsoft strong cryptographic provider": "software",
    "microsoft enhanced rsa and aes cryptographic provider": "software",
    "microsoft enhanced rsa and aes cryptographic provider (prototype)": "software",
    "microsoft rsa schannel cryptographic provider": "software",
    "microsoft base dss cryptographic provider": "software",
    "microsoft base dss and diffie-hellman cryptographic provider": "software",
    "microsoft enhanced dss and diffie-hellman cryptographic provider": "software",
    "microsoft dh schannel cryptographic provider": "software",
    "microsoft platform crypto provider": "tpm",
    "microsoft smart card key storage provider": "smartcard",
    "microsoft base smart card crypto provider": "smartcard",
    "ncipher security world key storage provider": "hsm",
    "safenet key storage provider": "hsm",
    "cloudhsm key storage provider": "hsm",
    "cavium key storage provider": "hsm",
}
HARDWARE_PROVIDERS = frozenset({"tpm", "smartcard", "hsm"})
KEY_PROV_INFO_MAX = 4096  # a real one is a few hundred bytes (two names)


def _der_oid(hex_text: Any) -> str | None:
    """The OID in a DER OBJECT IDENTIFIER written as [BitConverter]::ToString hex ("06-08-2A-86-...")."""
    try:
        der = bytes.fromhex(str(hex_text or "").replace("-", ""))
    except ValueError:
        return None
    if len(der) < 3 or der[0] != 0x06 or der[1] != len(der) - 2:
        return None
    parts, value = [], 0
    for b in der[2:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    if not parts or der[-1] & 0x80:
        return None
    first = parts[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(p) for p in head + parts[1:])


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def _key_alg(c: dict) -> tuple[str, str | None, int | None]:
    """(key algorithm, curve, curve bits).  The OID decides (FriendlyName is localised); algid names the curve."""
    oid = str(c.get("KeyAlgorithmOid") or "")
    friendly = str(c.get("KeyAlgorithm") or "")
    alg = _KEY_ALGS.get(oid) or _FRIENDLY.get(friendly)
    if alg is None:
        ident = algid.resolve(oid) if oid else None
        alg = ident.name if ident is not None and ident.name else printable(friendly or oid, 40)
    curve = bits = None
    if alg == "EC":
        curve_oid = _der_oid(c.get("KeyParameters"))
        ident = algid.resolve(curve_oid) if curve_oid else None
        if ident is not None and ident.name:
            curve, bits = ident.name, ident.key_size
        elif curve_oid:
            curve = curve_oid
    return alg, curve, bits


def _utf16z(data: bytes, offset: int) -> str | None:
    """The NUL-terminated UTF-16LE string at ``offset`` (at most 260 characters), or None."""
    if offset < 28 or offset >= len(data) or offset % 2:
        return None
    end = offset
    while end + 1 < len(data) and data[end:end + 2] != b"\0\0" and end - offset < 520:
        end += 2
    if end + 1 >= len(data) or data[end:end + 2] != b"\0\0":
        return None
    try:
        return data[offset:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return None


def parse_key_prov_info(value: Any) -> dict[str, Any] | None:
    """The provider of a certificate's key from its KEY_PROV_INFO property (base64, as the script returns it).

    [MS-GPEF] 2.2.1.1.1.1.1: a 28-byte header (little-endian: offset of the container name, offset of the provider
    name, provider type, flags, 8 reserved bytes, key spec), then the two NUL-terminated UTF-16LE names at those
    offsets from the start of the structure. Provider type 0 is a CNG key storage provider, anything else a CAPI
    provider type. The container name is not kept. None when the bytes do not have that shape."""
    import base64
    import binascii
    import struct

    try:
        data = base64.b64decode(str(value or ""), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not 28 <= len(data) <= KEY_PROV_INFO_MAX:
        return None
    _container, prov_off, prov_type, _flags, _r1, _r2, key_spec = struct.unpack_from("<7I", data)
    name = _utf16z(data, prov_off)
    if not name or not name.strip():
        return None
    return {"provider": printable(name.strip(), 128), "provider_type": prov_type, "key_spec": key_spec}


def provider_class(name: Any) -> str:
    return KEY_PROVIDERS.get(str(name or "").strip().lower(), "other")


def _key_facts(c: dict | None = None) -> dict[str, Any]:
    """Provider and exportability of a certificate's private key, from its KEY_PROV_INFO property (no key is opened).

    tpm / smartcard / hsm providers generate their keys non-exportable, so ``key_exportable`` is False on the provider's
    basis; for a software (or unlisted) provider it is not read, since only opening the key shows its export policy.
    Without the property (an older node script, a registry value that could not be read, malformed bytes) every fact
    stays not read, with the reason."""
    c = c or {}
    info = parse_key_prov_info(c.get("KeyProv")) if c.get("KeyProv") else None
    if info is None:
        if c.get("KeyProvError"):
            reason = "key_prov_info_unreadable: " + printable(str(c.get("KeyProvError")), 60)
        elif c.get("KeyProv"):
            reason = "key_prov_info_malformed"
        elif "KeyProv" in c:
            reason = "key_prov_info_absent"
        else:
            reason = KEY_NOT_READ  # a node script before CB-24 PR-4b
        return {"key_provider": None, "key_provider_type": None, "key_provider_class": None, "key_exportable": None,
                "exportable_basis": f"not read: {reason}", "key_not_read_reason": reason}
    cls = provider_class(info["provider"])
    hardware = cls in HARDWARE_PROVIDERS
    return {"key_provider": info["provider"], "key_provider_type": "cng" if info["provider_type"] == 0 else "capi",
            "key_provider_type_id": info["provider_type"], "key_spec": info["key_spec"], "key_provider_class": cls,
            "key_exportable": False if hardware else None,
            "exportable_basis": "provider" if hardware else "not read: needs opening the key"}


_HEX64 = frozenset("0123456789abcdef")


def _fingerprint(value: Any) -> str | None:
    text = str(value or "").replace("-", "").replace(" ", "").lower()
    return text if len(text) == 64 and set(text) <= _HEX64 else None


def _serial(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if 0 < len(text) <= 64 and all(ch in "0123456789ABCDEF" for ch in text) else None


def parse_certificates(text: str) -> list[dict[str, Any]]:
    out = []
    for c in _json_list(text)[:2000]:
        if not isinstance(c, dict):
            continue
        alg, curve, curve_bits = _key_alg(c)
        row = {"store": printable(str(c.get("Store") or ""), 60), "subject": printable(str(c.get("Subject") or ""), 512),
               "issuer": printable(str(c.get("Issuer") or ""), 512),
               "thumbprint": printable(str(c.get("Thumbprint") or ""), 64),
               "not_after": printable(str(c.get("NotAfter") or ""), 40) or None,
               "not_before": printable(str(c.get("NotBefore") or ""), 40) or None,
               "serial": _serial(c.get("Serial")), "fingerprint_sha256": _fingerprint(c.get("Sha256")),
               "sig_alg": printable(str(c.get("SignatureAlgorithm") or ""), 60) or None,
               "key_alg": alg, "key_size": _int(c.get("KeySize")) or curve_bits, "curve": curve,
               "has_private_key": bool(c.get("HasPrivateKey")), "source": "windows-store"}
        error = printable(" ".join(str(c.get("KeyError") or "").split()), 160)
        if error:
            row["key_read_error"] = error
        if row["has_private_key"]:
            row.update(_key_facts(c))
        out.append(row)
    return out


def parse_schannel(text: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in _json_list(text):
        if not isinstance(row, dict):
            continue
        proto = printable(str(row.get("Protocol") or ""), 40)
        side = str(row.get("Side") or "")
        if not proto or side not in ("Server", "Client"):
            continue
        enabled = row.get("Enabled")
        out.setdefault(proto, {})[side.lower()] = {
            "enabled": None if enabled is None else bool(enabled not in (0, "0")),
            "disabled_by_default": None if row.get("DisabledByDefault") is None else bool(row.get("DisabledByDefault")),
        }
    return out


def parse_bitlocker(text: str) -> list[dict[str, Any]]:
    out = []
    for row in _json_list(text):
        if isinstance(row, dict):
            out.append({"mount": printable(str(row.get("Mount") or ""), 40), "status": printable(str(row.get("Status") or ""), 40),
                        "method": printable(str(row.get("Method") or ""), 40),
                        "protection": printable(str(row.get("Protection") or ""), 40)})
    return out


def parse_cipher_suites(text: str) -> tuple[list[str], str | None]:
    """{Source, Suites} from the cipher_suites script; a bare JSON list (older script) is the local order."""
    text = (text or "").strip()
    try:
        data = json.loads(text) if text else None
    except ValueError:
        return [], None
    if isinstance(data, dict):
        suites, source = data.get("Suites"), str(data.get("Source") or "") or None
    else:
        suites, source = data, "local"
    if isinstance(suites, str):  # ConvertTo-Json writes a one-element array as a scalar
        suites = [suites]
    if not isinstance(suites, list):
        return [], source
    return [printable(str(x).strip(), 80) for x in suites if isinstance(x, str) and x.strip()][:200], source


_DWORD = 0xFFFFFFFF


def _enabled(value: Any) -> bool | None:
    """SCHANNEL 'Enabled' DWORD: 0 is off, anything else (1, 0xffffffff read as 4294967295 or -1) is on."""
    if value is None or isinstance(value, bool):
        return value
    try:
        return int(value) & _DWORD != 0
    except (TypeError, ValueError):
        return None


def parse_schannel_algorithms(text: str) -> dict[str, dict[str, Any]]:
    """{'Ciphers/Triple DES 168': {'kind', 'name', 'enabled', 'server_min_key_bits'}} -- explicit registry switches."""
    out: dict[str, dict[str, Any]] = {}
    for row in _json_list(text):
        if not isinstance(row, dict):
            continue
        kind, name = str(row.get("Kind") or ""), printable(str(row.get("Name") or ""), 60)
        if kind not in ("Ciphers", "Hashes", "KeyExchangeAlgorithms") or not name:
            continue
        bits = row.get("ServerMinKeyBitLength")
        out[f"{kind}/{name}"] = {"kind": kind, "name": name, "enabled": _enabled(row.get("Enabled")),
                                 "server_min_key_bits": bits if isinstance(bits, int) else None}
    return out


def parse_dotnet(text: str) -> list[dict[str, Any]]:
    out = []
    for row in _json_list(text):
        if not isinstance(row, dict):
            continue
        key = printable(str(row.get("Key") or ""), 120)
        strong, sysdef = row.get("SchUseStrongCrypto"), row.get("SystemDefaultTlsVersions")
        out.append({"key": key, "wow64": "WOW6432Node" in key,
                    "framework": "v2.0.50727" if "v2.0" in key else "v4.0.30319",
                    "sch_use_strong_crypto": strong if isinstance(strong, int) else None,
                    "system_default_tls_versions": sysdef if isinstance(sysdef, int) else None})
    return out


RDP_LAYERS = {0: "RDP security (no TLS)", 1: "Negotiate", 2: "TLS"}


def parse_rdp(text: str) -> dict[str, Any]:
    rows = _json_list(text)
    row = rows[0] if rows and isinstance(rows[0], dict) else {}
    layer = row.get("SecurityLayer")
    return {"security_layer": layer, "security_layer_name": RDP_LAYERS.get(layer) if isinstance(layer, int) else None,
            "min_encryption_level": row.get("MinEncryptionLevel"),
            # missing or null means the value was not read, not "NLA off"
            "nla": None if row.get("UserAuthentication") is None else bool(row.get("UserAuthentication"))}


class _Fail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


@contextlib.contextmanager
def _ca_file(config: dict):
    """The customer's CA for WinRM HTTPS certificates, as a temporary file (None: the public trust store)."""
    pem = config.get("ca_pem")
    if not pem:
        yield None
        return
    folder = tempfile.mkdtemp(prefix="zswinrm-")
    try:
        path = os.path.join(folder, "ca.pem")
        with open(path, "w", encoding="ascii") as f:
            f.write(pem)
        yield path
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def endpoint(target: Target, config: dict) -> str:
    """HTTPS only, and by the name the customer gave when there is one, so the certificate can prove the server
    before NTLM sends anything.  WinRM over HTTP (5985) cannot prove the server and is refused."""
    port = int(config.get("port") or 5986)
    if port == 5985:
        raise _Fail("identity_unverified", "WinRM over HTTP (5985) cannot prove the server; use HTTPS (5986). "
                    "The password was not sent")
    host = target.ip if is_ip(target.label) else target.label
    if ":" in str(host):
        host = f"[{host}]"
    return f"https://{host}:{port}/wsman"


def check_name(ctx: JobContext, target: Target) -> str:
    """The address the session connects to.  WinRM speaks to the name (so the certificate can prove the server), so
    the name is resolved again here and every address it has now must be allowed (resolve_checked refuses the name
    if any is listed); the session is then pinned to the first of them (_session), never to a later DNS answer."""
    try:
        if is_ip(target.label):
            # checked again per target: a never-scan entry added after the job started applies to the rest of it
            return checked_ip(target.ip or target.label, ctx.never_scan)
        return resolve_checked(target.label, ctx.never_scan)[0]
    except Blocked as exc:
        raise _Fail("skipped_never_scan", str(exc)) from None
    except OSError:
        raise _Fail("unreachable", f"could not resolve {target.label}") from None


def _session(ctx: JobContext, target: Target, config: dict, password: str, ca_path: str | None = None):
    """The WinRM session for one target, opened only after the name passed the network gate (check_name), and
    pinned to the checked address: pywinrm's requests session connects only there (netutil.requests_adapter), with
    no proxy, while the certificate is still checked against the name."""
    import winrm

    ip = check_name(ctx, target)
    url = endpoint(target, config)
    # message_encryption="never": over HTTPS it is TLS that protects the messages ("auto" is the same there), and it
    # guarantees pywinrm sends nothing while it builds a session, before the pinned adapter is mounted.
    sess = winrm.Session(url, auth=(str(config.get("login_user") or "svc-zscbom"), password), transport="ntlm",
                         server_cert_validation="validate", ca_trust_path=ca_path or "legacy_requests",
                         read_timeout_sec=60, operation_timeout_sec=50, proxy=None, message_encryption="never")
    transport = sess.protocol.transport
    build = transport.build_session
    host = urlsplit(url).hostname or ""
    pin = (host.strip("[]").lower().rstrip("."), ip)

    def build_pinned():
        # pywinrm builds its requests session lazily and again after close_session(); every session it hands out is
        # checked here, however it was built, so none can connect without the pin (fail closed)
        session = build()
        if getattr(session.get_adapter(url), "zs_pinned_to", None) != pin or session.trust_env:
            session.trust_env = False
            session.proxies = {}
            adapter = netutil.requests_adapter(host, ip, ctx.never_scan)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
        return session

    transport.build_session = build_pinned
    return sess


# WS-Management fault codes (Win32 error numbers) the server returns after a successful login
_WSMAN_ACCESS_DENIED = 5
SHELL_DENIED_HELP = (
    "logged in, but Windows refused this account a WinRM shell (Access is denied). Membership of Remote Management "
    "Users is not enough on its own: the account also needs Read and Execute on the WinRM service (RootSDDL). Run the "
    "Windows setup script from the source's Privilege section on the server, then test again")


def _fault(exc: Exception) -> "_Fail | None":
    """A WS-Man fault means the server answered and the login worked; say what it refused instead of 'unreachable'."""
    try:
        from winrm.exceptions import WSManFaultError
    except ImportError:  # pragma: no cover - pywinrm is a hard dependency of the node
        return None
    if not isinstance(exc, WSManFaultError):
        return None
    code = exc.wsman_fault_code
    if code == _WSMAN_ACCESS_DENIED or "access is denied" in (exc.reason or "").lower():
        return _Fail("winrm_denied", SHELL_DENIED_HELP)
    reason = printable(" ".join(str(exc.reason or exc.message or "").split()), 200)
    return _Fail("error", f"WinRM fault {code if code is not None else exc.fault_code or '?'}: {reason}")


def _run(sess, name: str) -> tuple[int, str, str]:
    try:
        r = sess.run_ps(SCRIPTS[name])
    except Blocked as exc:  # the pinned address was listed while the job ran (netutil.requests_adapter)
        raise _Fail("skipped_never_scan", str(exc)) from None
    except Exception as exc:  # requests/winrm raise many types
        fault = _fault(exc)
        if fault is not None:
            raise fault from None
        text = str(exc)
        if "CERTIFICATE_VERIFY_FAILED" in text or "SSLError" in text or "certificate verify failed" in text:
            raise _Fail("identity_unverified", "the WinRM certificate is not trusted for this server: upload the CA "
                        "that issued it, or list the server by the name in its certificate. The password was not "
                        "sent") from None
        if "401" in text or "Unauthorized" in text or "credentials were rejected" in text:
            raise _Fail("auth_failed", "WinRM refused the login") from None
        if "timed out" in text.lower():
            raise _Fail("timeout", "WinRM did not answer") from None
        raise _Fail("unreachable", exc.__class__.__name__) from None
    return r.status_code, r.std_out.decode("utf-8", "replace"), r.std_err.decode("utf-8", "replace")[:300]


def _stderr(err: str) -> str:
    """First error line of a PowerShell stderr stream (CLIXML progress records dropped)."""
    text = " ".join((err or "").split())
    if text.startswith("#< CLIXML"):
        text = ""
    return printable(text, 200)


def collect_target(ctx: JobContext, target: Target, config: dict, password: str, ca_path: str | None = None) -> int:
    sess = _session(ctx, target, config, password, ca_path)
    loc = target.label
    n = 0
    code, out, err = _run(sess, "os")
    os_info = (_json_list(out) or [{}])[0] if code == 0 else {}
    if code != 0:
        ctx.coverage(loc, "Windows version", "error", _stderr(err) or "could not read the Windows version")
    facts: dict[str, Any] = {"os": os_info}
    code, out, err = _run(sess, "schannel")
    facts["schannel_protocols"] = parse_schannel(out) if code == 0 else None
    code, out, err = _run(sess, "schannel_algorithms")
    facts["schannel_algorithms"] = parse_schannel_algorithms(out) if code == 0 else None
    code, out, err = _run(sess, "cipher_suites")
    suites, source = parse_cipher_suites(out)
    # The output is used whenever it parses: PowerShell exits non-zero on any non-terminating error.
    facts["cipher_suites"] = suites if (suites or code == 0) else None
    facts["cipher_suite_source"] = source
    if not suites and code != 0:
        ctx.coverage(loc, "TLS cipher suites", "error", _stderr(err) or "could not read the cipher suite order")
    code, out, err = _run(sess, "dotnet")
    facts["dotnet"] = parse_dotnet(out) if code == 0 else None
    code, out, err = _run(sess, "rdp")
    facts["rdp"] = parse_rdp(out) if code == 0 else None
    code, out, err = _run(sess, "bitlocker")
    if code == 0:
        for v in parse_bitlocker(out):
            ctx.emit("disk_encryption", loc, f"bitlocker:{v['mount']}", name=v["mount"], algorithm=v["method"] or None,
                     facts={**v, "source": "bitlocker"})
            n += 1
    elif "is not recognized" in err or "CommandNotFoundException" in err:
        ctx.coverage(loc, "BitLocker", "not_supported", "BitLocker is not installed on this server")
    else:
        ctx.coverage(loc, "BitLocker", "denied", _stderr(err) or "Get-BitLockerVolume needs administrator rights")
    code, out, err = _run(sess, "certificates")
    certs = parse_certificates(out)
    if code != 0 and not certs:
        ctx.coverage(loc, "Certificate stores", "error", _stderr(err) or "could not read the certificate stores")
    for c in certs:
        ctx.emit("certificate", loc, f"cert:{c['store']}/{c['thumbprint']}", name=c["subject"], algorithm=c["key_alg"],
                 key_size=c["key_size"], facts=c)
        n += 1
    ctx.emit("os_crypto_policy", loc, "os", name=str(os_info.get("Caption") or "Windows"), facts=facts)
    return n + 1


def _password(ctx: JobContext, config: dict, secrets: dict) -> str:
    if config.get("credential_type") == "vault":
        from zs_scan_node import vault

        ref = config.get("vault") or {}
        creds = vault.fetch(str(ref.get("provider")), str(ref.get("path") or ""), ctx.vault_prefix)
        for v in creds.values():
            ctx.scrubber.add(v)
        pw = creds.get("password")
    else:
        pw = secrets.get("password")
    if not pw:
        raise ConfigError("no password is stored for this Windows source")
    return pw


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str | None:
    password = _password(ctx, config, secrets)
    reasons: dict[str, str] = {}  # a skipped target says which address and entry matched
    targets, skipped = expand_targets(scope.get("targets") or [], ctx.never_scan, reasons=reasons)
    skipped_never_scan(ctx, skipped, reasons)

    def one(target: Target):
        started = time.monotonic()
        if ctx.should_stop():
            ctx.outcome(target.label, ctx.should_stop() or "skipped_deadline", started=started)
            return
        if target.ip is None:
            ctx.outcome(target.label, "unreachable", target.error, started=started)
            return
        skip = ctx.login_gate()  # CB-10: WinRM logs in with the account's password
        if skip:
            ctx.outcome(target.label, skip, ctx.credential_skip_note(skip), started=started)
            return
        status = "error"
        try:
            n = collect_target(ctx, target, config, password, ca_path)
            status = "ok"
            ctx.outcome(target.label, "ok", started=started, assets=n)
        except _Fail as fail:
            status = fail.status
            ctx.outcome(target.label, fail.status, fail.error, started=started)
        except Exception as exc:
            ctx.outcome(target.label, "error", exc.__class__.__name__, started=started)
        finally:
            ctx.login_done(status)

    with _ca_file(config) as ca_path, \
            cf.ThreadPoolExecutor(max_workers=max(1, min(int(config.get("parallel") or 8), 32))) as pool:
        list(pool.map(one, targets))
    return None


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    try:
        password = _password(ctx, config, secrets)
    except ConfigError as exc:
        ctx.samples.append({"target": "-", "status": "error", "reachable": None, "login": False, "privilege": None,
                            "note": str(exc)})
        return str(exc)
    reasons: dict[str, str] = {}
    targets, skipped = expand_targets(scope.get("targets") or [], ctx.never_scan, reasons=reasons)
    skipped_never_scan(ctx, skipped, reasons, samples=True)
    with _ca_file(config) as ca_path:
        for target in targets[:5]:
            _test_one(ctx, target, config, password, ca_path)
    return f"{sum(1 for s in ctx.samples if s['status'] == 'ready')} of {len(ctx.samples)} samples ready"


def _test_one(ctx: JobContext, target: Target, config: dict, password: str, ca_path: str | None) -> None:
    sample = {"target": target.label, "status": "ready", "reachable": False, "login": False, "privilege": None,
              "note": ""}
    skip = ctx.login_gate() if target.ip is not None else None  # CB-10
    if target.ip is None:
        sample.update(status="unreachable", note=target.error or "")
    elif skip:
        sample.update(status=skip, reachable=None, note=ctx.credential_skip_note(skip) or skip)
    else:
        status = "error"
        try:
            code, out, err = _run(_session(ctx, target, config, password, ca_path), "os")
            # Any answer from the shell means the login worked; a failing read is a privilege note, not a login failure.
            info = (_json_list(out) or [{}])[0] if code == 0 else {}
            note = (f"{info.get('Caption') or 'Windows'} {info.get('Version') or ''}".strip() if code == 0
                    else f"logged in; reading the Windows version failed: {_stderr(err) or 'exit ' + str(code)}")
            sample.update(reachable=True, login=True, note=printable(note, 160))
            status = "ok"
        except _Fail as fail:
            status = fail.status
            sample.update(status=fail.status, reachable=fail.status not in ("unreachable", "timeout"),
                          login=fail.status == "winrm_denied", note=fail.error)
        finally:
            ctx.login_done(status)
    ctx.samples.append(sample)
