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

from zs_scan_node import netutil
from zs_scan_node.collectors import ConfigError, skipped_never_scan
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Blocked, Target, checked_ip, expand_targets, is_ip, resolve_checked
from zs_scan_node.scrub import printable

SCRIPTS = {
    "certificates": (
        "Get-ChildItem -Path Cert:\\LocalMachine\\My,Cert:\\LocalMachine\\WebHosting,Cert:\\LocalMachine\\Remote` Desktop "
        "-ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Store=$_.PSParentPath.Split('\\')[-1]; "
        "Subject=$_.Subject; Issuer=$_.Issuer; Thumbprint=$_.Thumbprint; NotAfter=$_.NotAfter.ToUniversalTime()."
        "ToString('o'); SignatureAlgorithm=$_.SignatureAlgorithm.FriendlyName; KeyAlgorithm=$_.PublicKey.Oid."
        "FriendlyName; KeySize=$(try { $_.PublicKey.Key.KeySize } catch { $null }); HasPrivateKey=$_.HasPrivateKey } } "
        "| ConvertTo-Json -Depth 3 -Compress"
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


def parse_certificates(text: str) -> list[dict[str, Any]]:
    out = []
    for c in _json_list(text)[:2000]:
        if not isinstance(c, dict):
            continue
        out.append({"store": printable(str(c.get("Store") or ""), 60), "subject": printable(str(c.get("Subject") or ""), 512),
                    "issuer": printable(str(c.get("Issuer") or ""), 512),
                    "thumbprint": printable(str(c.get("Thumbprint") or ""), 64),
                    "not_after": printable(str(c.get("NotAfter") or ""), 40) or None,
                    "sig_alg": printable(str(c.get("SignatureAlgorithm") or ""), 60) or None,
                    "key_alg": {"RSA": "RSA", "ECC": "EC", "DSA": "DSA"}.get(str(c.get("KeyAlgorithm") or ""),
                                                                            printable(str(c.get("KeyAlgorithm") or ""), 40)),
                    "key_size": c.get("KeySize") if isinstance(c.get("KeySize"), int) else None,
                    "has_private_key": bool(c.get("HasPrivateKey")), "source": "windows-store"})
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
        try:
            n = collect_target(ctx, target, config, password, ca_path)
            ctx.outcome(target.label, "ok", started=started, assets=n)
        except _Fail as fail:
            ctx.outcome(target.label, fail.status, fail.error, started=started)
        except Exception as exc:
            ctx.outcome(target.label, "error", exc.__class__.__name__, started=started)

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
    if target.ip is None:
        sample.update(status="unreachable", note=target.error or "")
    else:
        try:
            code, out, err = _run(_session(ctx, target, config, password, ca_path), "os")
            # Any answer from the shell means the login worked; a failing read is a privilege note, not a login failure.
            info = (_json_list(out) or [{}])[0] if code == 0 else {}
            note = (f"{info.get('Caption') or 'Windows'} {info.get('Version') or ''}".strip() if code == 0
                    else f"logged in; reading the Windows version failed: {_stderr(err) or 'exit ' + str(code)}")
            sample.update(reachable=True, login=True, note=printable(note, 160))
        except _Fail as fail:
            sample.update(status=fail.status, reachable=fail.status not in ("unreachable", "timeout"),
                          login=fail.status == "winrm_denied", note=fail.error)
    ctx.samples.append(sample)
