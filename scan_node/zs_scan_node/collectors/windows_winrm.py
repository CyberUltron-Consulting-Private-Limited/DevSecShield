"""Windows servers over WinRM (HTTPS 5986 by default) with read-only PowerShell.

Every script below only reads: certificate stores, the SCHANNEL protocol registry keys, the TLS cipher suite
order, BitLocker volume status and the RDP security settings.  Output is JSON (``ConvertTo-Json``) and is parsed
by the pure functions at the bottom, which the unit tests cover.  Not exercised against a live Windows host in
the local lab (validated in the AWS lab).
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import time
from typing import Any

from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import Target, expand_targets
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
    "cipher_suites": "Get-TlsCipherSuite | Select-Object -ExpandProperty Name | ConvertTo-Json -Compress",
    "bitlocker": (
        "Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Mount=$_.MountPoint; "
        "Status=\"$($_.VolumeStatus)\"; Method=\"$($_.EncryptionMethod)\"; Protection=\"$($_.ProtectionStatus)\" } } "
        "| ConvertTo-Json -Compress"
    ),
    "rdp": (
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "| Select-Object SecurityLayer,MinEncryptionLevel,UserAuthentication | ConvertTo-Json -Compress"
    ),
    "os": "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json -Compress",
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


RDP_LAYERS = {0: "RDP security (no TLS)", 1: "Negotiate", 2: "TLS"}


def parse_rdp(text: str) -> dict[str, Any]:
    rows = _json_list(text)
    row = rows[0] if rows and isinstance(rows[0], dict) else {}
    layer = row.get("SecurityLayer")
    return {"security_layer": layer, "security_layer_name": RDP_LAYERS.get(layer) if isinstance(layer, int) else None,
            "min_encryption_level": row.get("MinEncryptionLevel"), "nla": bool(row.get("UserAuthentication"))}


class _Fail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


def _session(target: Target, config: dict, password: str):
    import winrm

    port = int(config.get("port") or 5986)
    scheme = "http" if port == 5985 else "https"
    return winrm.Session(f"{scheme}://{target.ip}:{port}/wsman", auth=(str(config.get("login_user") or "svc-zscbom"),
                                                                      password),
                         transport="ntlm", server_cert_validation="ignore", read_timeout_sec=60,
                         operation_timeout_sec=50)


def _run(sess, name: str) -> tuple[int, str, str]:
    try:
        r = sess.run_ps(SCRIPTS[name])
    except Exception as exc:  # requests/winrm raise many types
        text = str(exc)
        if "401" in text or "Unauthorized" in text or "credentials were rejected" in text:
            raise _Fail("auth_failed", "WinRM refused the login") from None
        if "timed out" in text.lower():
            raise _Fail("timeout", "WinRM did not answer") from None
        raise _Fail("unreachable", exc.__class__.__name__) from None
    return r.status_code, r.std_out.decode("utf-8", "replace"), r.std_err.decode("utf-8", "replace")[:300]


def collect_target(ctx: JobContext, target: Target, config: dict, password: str) -> int:
    sess = _session(target, config, password)
    loc = target.label
    n = 0
    code, out, _err = _run(sess, "os")
    os_info = (_json_list(out) or [{}])[0] if code == 0 else {}
    facts: dict[str, Any] = {"os": os_info}
    code, out, err = _run(sess, "schannel")
    facts["schannel_protocols"] = parse_schannel(out) if code == 0 else None
    code, out, err = _run(sess, "cipher_suites")
    facts["cipher_suites"] = [printable(str(s), 80) for s in _json_list(out)][:200] if code == 0 else None
    code, out, err = _run(sess, "rdp")
    facts["rdp"] = parse_rdp(out) if code == 0 else None
    code, out, err = _run(sess, "bitlocker")
    if code == 0:
        for v in parse_bitlocker(out):
            ctx.emit("disk_encryption", loc, f"bitlocker:{v['mount']}", name=v["mount"], algorithm=v["method"] or None,
                     facts={**v, "source": "bitlocker"})
            n += 1
    else:
        ctx.coverage(loc, "BitLocker", "denied", err.strip()[:200] or "Get-BitLockerVolume needs administrator rights")
    code, out, err = _run(sess, "certificates")
    for c in parse_certificates(out) if code == 0 else []:
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
    targets, skipped = expand_targets(scope.get("targets") or [], ctx.never_scan)
    for label in skipped:
        ctx.outcome(label, "skipped_never_scan")

    def one(target: Target):
        started = time.monotonic()
        if ctx.should_stop():
            ctx.outcome(target.label, ctx.should_stop() or "skipped_deadline", started=started)
            return
        if target.ip is None:
            ctx.outcome(target.label, "unreachable", target.error, started=started)
            return
        try:
            n = collect_target(ctx, target, config, password)
            ctx.outcome(target.label, "ok", started=started, assets=n)
        except _Fail as fail:
            ctx.outcome(target.label, fail.status, fail.error, started=started)
        except Exception as exc:
            ctx.outcome(target.label, "error", exc.__class__.__name__, started=started)

    with cf.ThreadPoolExecutor(max_workers=max(1, min(int(config.get("parallel") or 8), 32))) as pool:
        list(pool.map(one, targets))
    return None


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    try:
        password = _password(ctx, config, secrets)
    except ConfigError as exc:
        ctx.samples.append({"target": "-", "status": "error", "reachable": None, "login": False, "privilege": None,
                            "note": str(exc)})
        return str(exc)
    targets, _ = expand_targets(scope.get("targets") or [], ctx.never_scan)
    for target in targets[:5]:
        sample = {"target": target.label, "status": "ready", "reachable": False, "login": False, "privilege": None,
                  "note": ""}
        if target.ip is None:
            sample.update(status="unreachable", note=target.error or "")
        else:
            try:
                code, out, _ = _run(_session(target, config, password), "os")
                sample.update(reachable=True, login=code == 0, note=printable(out.strip(), 160))
            except _Fail as fail:
                sample.update(status=fail.status, reachable=fail.status not in ("unreachable", "timeout"), note=fail.error)
        ctx.samples.append(sample)
    return f"{sum(1 for s in ctx.samples if s['status'] == 'ready')} of {len(ctx.samples)} samples ready"
