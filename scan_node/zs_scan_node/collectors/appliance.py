"""Appliance configurations (Cisco IOS/IOS XE, Cisco ASA, FortiOS, PAN-OS, F5 BIG-IP), read-only.

* SSH vendors (Cisco IOS, Cisco ASA, FortiOS) log in with ``linux_ssh.open_session``: the same host-key policy
  (passwords only to pinned host keys), single authentication attempt and network gate.  Only the commands in
  ``COMMANDS[vendor]`` are ever sent; every one is a ``show`` command (plus ASA's session-only ``terminal pager 0``).
  IOS and FortiOS run each command on its own exec channel; the ASA has no exec channel, so its commands are typed
  into one shell with a PTY, waiting for the prompt after each.
* API vendors (PAN-OS XML API, F5 iControl REST) use ``netutil.http_client`` pinned to the checked address, with the
  certificate verified (``ca_pem`` or the system CAs).  Only HTTP GET of the paths in ``API_PATHS[vendor]``.
* Outputs are parsed on the node (``appliance_parsers``); only the extracted settings leave it, never the raw text.
"""
from __future__ import annotations

import re
import ssl
import time
from typing import Any
from urllib.parse import quote

from zs_scan_node import appliance_parsers as AP
from zs_scan_node import netutil
from zs_scan_node.collectors import ConfigError
from zs_scan_node.collectors.linux_ssh import TargetFail, _credentials, _targets, open_session
from zs_scan_node.jobctx import JobContext, register_asset_types
from zs_scan_node.netutil import Blocked, Target

register_asset_types("appliance_config")

COMMANDS: dict[str, list[str]] = {
    "cisco_ios": [
        "show running-config | include ^ip ssh|^ip http",
        "show running-config | section crypto",
        "show crypto key mypubkey rsa",
    ],
    "cisco_asa": [
        "show running-config ssl",
        "show running-config ssh",
        "show running-config crypto ikev1",
        "show running-config crypto ikev2",
        "show crypto key mypubkey rsa",
    ],
    "fortios": [
        "show full-configuration system global",
        "show full-configuration vpn ipsec phase1-interface",
        "show full-configuration vpn ipsec phase2-interface",
    ],
}
SHELL_SETUP = {"cisco_asa": ["terminal pager 0"]}  # session-only (no configuration change)
SHELL_VENDORS = {"cisco_asa"}
ALLOWED_COMMANDS = frozenset(c for cmds in COMMANDS.values() for c in cmds) | frozenset(
    c for cmds in SHELL_SETUP.values() for c in cmds)
_PANOS_XPATHS = {
    "ike-gateways": "/config/devices/entry/network/ike/gateway",
    "ike-crypto-profiles": "/config/devices/entry/network/ike/crypto-profiles/ike-crypto-profiles",
    "ipsec-crypto-profiles": "/config/devices/entry/network/ike/crypto-profiles/ipsec-crypto-profiles",
    "ssl-tls-service-profiles-shared": "/config/shared/ssl-tls-service-profile",
    "ssl-tls-service-profiles-vsys": "/config/devices/entry/vsys/entry/ssl-tls-service-profile",
}
API_PATHS: dict[str, dict[str, str]] = {
    # type=config&action=show reads the RUNNING configuration (read-only; 'get' would read the candidate)
    "panos": {k: f"/api/?type=config&action=show&xpath={quote(x, safe='/')}" for k, x in _PANOS_XPATHS.items()},
    "f5_bigip": {
        "client-ssl": "/mgmt/tm/ltm/profile/client-ssl?$select=name,fullPath,ciphers,options,cipherGroup",
        "crypto-key": "/mgmt/tm/sys/crypto/key?$select=name,fullPath,keyType,keySize,curveName,securityType",
    },
}
SSH_VENDORS = set(COMMANDS)
API_VENDORS = set(API_PATHS)
CMD_TIMEOUT = 60
OUTPUT_CAP = 2 * 1024 * 1024
PROMPT = re.compile(rb"(?m)^[\w.\-()/@:]{1,64}[>#] ?$")


def _shell_run(sess, commands: list[str], setup: list[str], timeout: float) -> dict[str, str]:
    """Type allow-listed commands into one shell (devices without an exec channel), reading up to the prompt."""
    chan = sess.transport.open_session(timeout=10)
    try:
        chan.get_pty(term="vt100", width=511, height=0)
        chan.invoke_shell()
        chan.settimeout(1.0)

        def read_until_prompt(deadline: float) -> bytes:
            buf = bytearray()
            while time.monotonic() < deadline:
                try:
                    data = chan.recv(65536)
                except TimeoutError:
                    data = None
                except Exception:
                    data = None
                if data:
                    if len(buf) < OUTPUT_CAP:
                        buf += data
                    if PROMPT.search(bytes(buf[-200:]).replace(b"\r", b"")):
                        return bytes(buf)
                elif chan.closed or chan.exit_status_ready():
                    break
            return bytes(buf)

        read_until_prompt(time.monotonic() + 20)  # banner / MOTD
        out: dict[str, str] = {}
        for cmd in list(setup) + list(commands):
            if cmd not in ALLOWED_COMMANDS:
                raise ValueError(f"command not allow-listed: {cmd}")
            chan.send((cmd + "\n").encode())
            raw = read_until_prompt(time.monotonic() + timeout).replace(b"\r", b"").decode("utf-8", "replace")
            lines = raw.split("\n")
            if lines and lines[0].strip().endswith(cmd):  # the echoed command
                lines = lines[1:]
            if lines and PROMPT.match(lines[-1].encode()):
                lines = lines[:-1]
            if cmd in commands:
                out[cmd] = "\n".join(lines)
        return out
    finally:
        chan.close()


def _ssh_outputs(ctx: JobContext, target: Target, vendor: str, config: dict, creds: dict) -> tuple[dict[str, str], dict]:
    sess = open_session(ctx, target, config, creds)
    try:
        if vendor in SHELL_VENDORS:
            return _shell_run(sess, COMMANDS[vendor], SHELL_SETUP.get(vendor, []), CMD_TIMEOUT), sess.host_key
        out = {}
        for cmd in COMMANDS[vendor]:
            if cmd not in ALLOWED_COMMANDS:
                raise ValueError(f"command not allow-listed: {cmd}")
            stop = ctx.should_stop()
            if stop:
                raise TargetFail(stop)
            _status, text, _err, _timed_out = sess.run(cmd, timeout=CMD_TIMEOUT)
            out[cmd] = text
        return out, sess.host_key
    finally:
        sess.close()


def _api_outputs(ctx: JobContext, target: Target, vendor: str, config: dict, secrets: dict) -> dict[str, Any]:
    port = int(config.get("port") or 443)
    host = target.label
    url = f"https://{host if ':' not in host else '[' + host + ']'}:{port}"
    ca = config.get("ca_pem")
    verify = ssl.create_default_context(cadata=ca) if ca else ssl.create_default_context()
    if vendor == "panos":
        if not secrets.get("api_key"):
            raise ConfigError("no PAN-OS API key is stored for this source")
        ctx.scrubber.add(secrets["api_key"])
        headers, auth = {"X-PAN-KEY": secrets["api_key"]}, None
    else:
        if not secrets.get("password"):
            raise ConfigError("no password is stored for this source")
        ctx.scrubber.add(secrets["password"])
        headers, auth = {}, (str(config.get("login_user") or ""), secrets["password"])
    try:  # a name is re-checked by every address it resolved to; the client connects only to the checked one
        client = netutil.http_client(url, netutil.checked_target(target, ctx.never_scan), ctx.never_scan,
                                     verify=verify, headers=headers, timeout=20.0, auth=auth)
    except Blocked as exc:
        raise TargetFail("skipped_never_scan", str(exc)) from None
    out: dict[str, Any] = {}
    try:
        for key, path in API_PATHS[vendor].items():
            stop = ctx.should_stop()
            if stop:
                raise TargetFail(stop)
            try:
                r = client.get(path)
            except Exception as exc:
                msg = str(exc)
                if "CERTIFICATE_VERIFY_FAILED" in msg or "certificate" in msg.lower():
                    raise TargetFail("identity_unverified", "the appliance certificate is not trusted (paste its CA "
                                     "in ca_pem); nothing was sent") from None
                raise TargetFail("unreachable", exc.__class__.__name__) from None
            if r.status_code in (401, 403):
                raise TargetFail("auth_failed", f"the appliance refused the credential (HTTP {r.status_code})")
            if r.status_code != 200:
                out[key] = None
                continue
            body = r.content[:OUTPUT_CAP]
            out[key] = r.json() if vendor == "f5_bigip" else body.decode("utf-8", "replace")
    finally:
        client.close()
    return out


def read_target(ctx: JobContext, target: Target, vendor: str, config: dict, secrets: dict,
                creds: dict | None) -> list[AP.Row]:
    if vendor in SSH_VENDORS:
        outputs, _host_key = _ssh_outputs(ctx, target, vendor, config, creds or {})
    else:
        outputs = _api_outputs(ctx, target, vendor, config, secrets)
    return AP.PARSERS[vendor](outputs)


def collect_target(ctx: JobContext, target: Target, vendor: str, config: dict, secrets: dict,
                   creds: dict | None) -> int:
    port = int(config.get("port") or (22 if vendor in SSH_VENDORS else 443))
    rows = read_target(ctx, target, vendor, config, secrets, creds)
    where = f"[{target.ip}]:{port}" if ":" in str(target.ip) else f"{target.ip}:{port}"
    for asset_type, section, name, algorithm, key_size, facts in rows:
        ctx.emit(asset_type, target.label, f"{where}#{section}", name=f"{AP.VENDOR_LABELS[vendor]} {name}",
                 algorithm=algorithm, key_size=key_size,
                 facts={**facts, "vendor_label": AP.VENDOR_LABELS[vendor], "appliance": target.label})
    if not rows:
        ctx.coverage(target.label, f"{vendor} configuration", "not_supported",
                     "the read-only commands returned no TLS, SSH or IKE settings (check the account's privilege "
                     "level: it must be allowed to run the show commands listed for this vendor)")
    ctx.log("appliance read", target=target.label, vendor=vendor, rows=len(rows))
    return len(rows)


def _vendor(config: dict) -> str:
    vendor = str(config.get("vendor") or "")
    if vendor not in AP.PARSERS:
        raise ConfigError(f"unsupported appliance vendor {vendor!r}")
    return vendor


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str | None:
    vendor = _vendor(config)
    creds = _credentials(ctx, config, secrets) if vendor in SSH_VENDORS else None
    for target in _targets(ctx, scope):
        started = time.monotonic()
        stop = ctx.should_stop()
        if stop:
            ctx.outcome(target.label, stop, started=started)
            continue
        if target.ip is None:
            ctx.outcome(target.label, "unreachable", target.error, started=started)
            continue
        try:
            n = collect_target(ctx, target, vendor, config, secrets, creds)
            ctx.outcome(target.label, "ok", started=started, assets=n)
        except TargetFail as fail:
            ctx.outcome(target.label, fail.status, fail.error, started=started)
        except ConfigError:
            raise
        except Exception as exc:  # one appliance must never end the job
            ctx.log("appliance error", target=target.label, error=exc.__class__.__name__, level="warn")
            ctx.outcome(target.label, "error", exc.__class__.__name__, started=started)
    return None


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    vendor = _vendor(config)
    for target in _targets(ctx, scope)[:5]:
        sample = {"target": target.label, "status": "ready", "reachable": False, "login": False, "privilege": None,
                  "note": ""}
        try:
            if target.ip is None:
                raise TargetFail("unreachable", target.error or "could not resolve")
            n = len(read_target(ctx, target, vendor, config, secrets,
                                _credentials(ctx, config, secrets) if vendor in SSH_VENDORS else None))
            sample.update(reachable=True, login=True, privilege=n > 0,
                          note=f"{n} settings read" if n else "logged in, but the show commands returned nothing")
        except TargetFail as fail:
            sample["reachable"] = fail.status not in ("unreachable", "refused", "timeout", "no_route")
            sample.update(status=fail.status, note=fail.error)
        except ConfigError as exc:
            sample.update(status="error", note=str(exc))
        ctx.samples.append(sample)
    ready = sum(1 for s in ctx.samples if s["status"] == "ready")
    return f"{ready} of {len(ctx.samples)} samples ready"
