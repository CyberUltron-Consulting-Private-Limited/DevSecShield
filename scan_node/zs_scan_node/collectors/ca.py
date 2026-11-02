"""Internal certificate authorities and key services read through a scan node (``ca_connector`` sources).

* HashiCorp Vault: ``sys/mounts`` -> PKI mounts (issuers: certificate, key type/bits, signature algorithm, expiry;
  roles: key_type, key_bits, signature_bits, max_ttl, allow_any_name; CRL/OCSP configuration) and transit mounts
  (key type, exportable, allow_plaintext_backup, deletion_allowed, minimum versions, auto_rotate_period; never key
  material: the export and backup endpoints are not called).  Read-only token; the policy is a source template.
* EJBCA REST (``/ejbca/ejbca-rest-api/v1/ca``, the CA certificates, and ``v2/certificate/profile/<name>`` for the
  built-in profile names when that endpoint exists), authenticated with a client certificate.
* Microsoft AD CS over WinRM HTTPS (``windows_winrm``'s session, same network gate and certificate rules): the CA's
  registry configuration (CNGHashAlgorithm, validity, CRL periods, EditFlags), its certificate (public) and the
  published templates (``certutil -catemplates``) with their settings from the local template cache.  Everything
  runs on the CA server itself, so no second hop to a domain controller is needed.

Every HTTP request goes through ``netutil.http_client`` (pinned to the address checked against never-scan).
"""
from __future__ import annotations

import base64
import json
import re
import time
from typing import Any
from urllib.parse import quote, urlsplit

from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import JobContext, register_asset_types
from zs_scan_node.netutil import Blocked, Target, http_client, resolve_checked
from zs_scan_node.scrub import printable

register_asset_types("ca_authority", "ca_template", "managed_key", "key_store")

MAX_MOUNTS = 50
MAX_ITEMS = 2000
EJBCA_PROFILES = ("ENDUSER", "SERVER", "SUBCA", "ROOTCA", "OCSPSIGNER")


class CaFail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


def _target(ctx: JobContext, url: str) -> Target:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    try:
        return Target(host, resolve_checked(host, ctx.never_scan)[0])  # the network gate: resolve once, check
    except Blocked:
        raise CaFail("skipped_never_scan", f"{host} is on the never-scan list") from None
    except OSError as exc:
        raise CaFail("unreachable", f"could not resolve {host}: {exc.__class__.__name__}") from None


def _http_error(exc: Exception, what: str) -> CaFail:
    text = str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text:
        return CaFail("identity_unverified", f"the {what} certificate is not trusted: upload the CA that issued it. "
                                             "Nothing was sent")
    if "timed out" in text.lower() or exc.__class__.__name__.endswith("Timeout"):
        return CaFail("timeout", f"{what} did not answer")
    if "refused" in text.lower():
        return CaFail("refused", "connection refused")
    return CaFail("unreachable", f"could not connect to {what} ({exc.__class__.__name__})")


def _ssl(config: dict):
    import ssl

    ctx = ssl.create_default_context(cadata=config["ca_pem"]) if config.get("ca_pem") else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ----------------------------------------------------------------------------- Vault
VAULT_KEY_BITS = {"aes128-gcm96": ("AES", 128), "aes256-gcm96": ("AES", 256), "chacha20-poly1305": ("ChaCha20", 256),
                  "xchacha20-poly1305": ("XChaCha20", 256), "ed25519": ("Ed25519", 256), "ecdsa-p256": ("ECDSA", 256),
                  "ecdsa-p384": ("ECDSA", 384), "ecdsa-p521": ("ECDSA", 521), "rsa-2048": ("RSA", 2048),
                  "rsa-3072": ("RSA", 3072), "rsa-4096": ("RSA", 4096), "hmac": ("HMAC", None),
                  "managed_key": ("managed", None), "aes128-cmac": ("AES-CMAC", 128), "aes256-cmac": ("AES-CMAC", 256)}
TRANSIT_FIELDS = ("type", "exportable", "allow_plaintext_backup", "deletion_allowed", "min_decryption_version",
                  "min_encryption_version", "min_available_version", "latest_version", "auto_rotate_period",
                  "supports_encryption", "supports_decryption", "supports_signing", "supports_derivation", "derived",
                  "convergent_encryption", "imported_key", "key_size")
ROLE_FIELDS = ("key_type", "key_bits", "signature_bits", "use_pss", "max_ttl", "ttl", "allow_any_name",
               "allowed_domains", "allow_subdomains", "allow_glob_domains", "allow_bare_domains", "allow_localhost",
               "allow_ip_sans", "enforce_hostnames", "server_flag", "client_flag", "code_signing_flag",
               "email_protection_flag", "no_store", "require_cn", "issuer_ref")


class Vault:
    def __init__(self, ctx: JobContext, config: dict, token: str) -> None:
        self.ctx = ctx
        self.base = str(config["api_url"]).rstrip("/")
        self.target = _target(ctx, self.base)
        self.client = http_client(self.base, self.target.ip, ctx.never_scan, verify=_ssl(config), timeout=20.0,
                                  headers={"X-Vault-Token": token, "Accept": "application/json"})

    def close(self) -> None:
        self.client.close()

    def get(self, path: str, listing: bool = False) -> tuple[int, dict]:
        if self.ctx.should_stop():
            raise CaFail(self.ctx.should_stop() or "skipped_deadline", "stopped")
        try:
            r = self.client.get(f"/v1/{path.lstrip('/')}", params={"list": "true"} if listing else None)
        except Exception as exc:  # httpx.HTTPError, ssl errors
            raise _http_error(exc, "Vault") from None
        try:
            body = r.json() if r.content else {}
        except ValueError:
            body = {}
        return r.status_code, body if isinstance(body, dict) else {}


def _data(body: dict) -> dict:
    data = body.get("data")
    return data if isinstance(data, dict) else {}


def vault_mounts(body: dict) -> dict[str, str]:
    """mount path -> engine type from sys/mounts (Vault answers with the mounts at the top level and under data)."""
    src = _data(body) or body
    out = {}
    for path, info in src.items():
        if isinstance(info, dict) and isinstance(info.get("type"), str) and str(path).endswith("/"):
            out[str(path).rstrip("/")] = info["type"]
    return out


def collect_vault(ctx: JobContext, config: dict, token: str) -> tuple[Target, int]:
    v = Vault(ctx, config, token)
    loc = v.base
    n = 0
    try:
        status, body = v.get("sys/mounts")
        if status in (401, 403):
            status, body = v.get("sys/internal/ui/mounts")  # lists only what this token may use
            body = {"data": (_data(body).get("secret") or {})} if status == 200 else body
        if status == 403:
            raise CaFail("auth_failed", "Vault refused the token (403): check the token and its read-only policy")
        if status != 200:
            raise CaFail("error", f"Vault answered {status} to sys/mounts")
        mounts = vault_mounts(body)
        for mount, kind in sorted(mounts.items())[:MAX_MOUNTS]:
            if kind == "pki":
                n += _vault_pki(ctx, v, mount, loc)
            elif kind == "transit":
                n += _vault_transit(ctx, v, mount, loc)
        if not any(k in ("pki", "transit") for k in mounts.values()):
            ctx.coverage(v.target.label, "Vault PKI and transit", "not_supported",
                         "no pki or transit mount is visible to this token", once=True)
        return v.target, n
    finally:
        v.close()


def _list(v: Vault, path: str, what: str) -> list[str]:
    status, body = v.get(path, listing=True)
    if status == 404:
        return []
    if status != 200:
        v.ctx.coverage(v.target.label, f"Vault {what}", "denied" if status == 403 else "error",
                       f"{path}: Vault answered {status}")
        return []
    return [str(k) for k in (_data(body).get("keys") or [])][:MAX_ITEMS]


def _vault_pki(ctx: JobContext, v: Vault, mount: str, loc: str) -> int:
    n = 0
    crl = _data(v.get(f"{mount}/config/crl")[1])
    urls = _data(v.get(f"{mount}/config/urls")[1])
    issuers = _list(v, f"{mount}/issuers", f"{mount} issuers")
    if not issuers:  # Vault before 1.11: one CA per mount
        status, body = v.get(f"{mount}/cert/ca")
        issuers = ["default"] if status == 200 and _data(body).get("certificate") else []
    for issuer in issuers:
        path = f"{mount}/issuer/{quote(issuer, safe='')}" if issuer != "default" else f"{mount}/cert/ca"
        status, body = v.get(path)
        data = _data(body)
        if status != 200 or not data.get("certificate"):
            continue
        certs = load_certs(str(data["certificate"]).encode())
        if not certs:
            continue
        f = cert_facts(certs[0], "vault")
        name = data.get("issuer_name") or issuer
        ctx.emit("certificate", v.target.label, f"{loc}/{mount}/issuer/{issuer}", name=f.get("subject", ""),
                 algorithm=f.get("key_alg"), key_size=f.get("key_size"),
                 facts={**f, "role": "ca", "provider": "vault", "mount": mount, "issuer": name})
        ctx.emit("ca_authority", v.target.label, f"{loc}/{mount}/issuer/{issuer}#config", name=f"{mount}: {name}",
                 algorithm=f.get("key_alg"), key_size=f.get("key_size"),
                 facts={"provider": "vault", "mount": mount, "issuer": name, "subject": f.get("subject"),
                        "key_type": f.get("key_alg"), "signature_algorithm": f.get("sig_alg") if f.get("self_signed")
                        else None, "issuer_signature_algorithm": f.get("sig_alg"),
                        "revocation_signature_algorithm": data.get("revocation_signature_algorithm"),
                        "usage": data.get("usage"), "not_after": f.get("not_after"),
                        "leaf_not_after_behavior": data.get("leaf_not_after_behavior"),
                        "crl": {k: crl.get(k) for k in ("expiry", "disable", "ocsp_disable", "auto_rebuild",
                                                        "enable_delta") if k in crl},
                        "urls": {k: urls.get(k) for k in ("issuing_certificates", "crl_distribution_points",
                                                          "ocsp_servers") if k in urls}})
        n += 2
    for role in _list(v, f"{mount}/roles", f"{mount} roles"):
        status, body = v.get(f"{mount}/roles/{quote(role, safe='')}")
        data = _data(body)
        if status != 200:
            continue
        facts = {k: data.get(k) for k in ROLE_FIELDS if k in data}
        bits = facts.get("key_bits") if isinstance(facts.get("key_bits"), int) else None
        key_type = str(facts.get("key_type") or "").upper()
        ctx.emit("ca_template", v.target.label, f"{loc}/{mount}/roles/{role}", name=f"{mount}/{role}",
                 algorithm=key_type or None, key_size=bits or None,
                 facts={**facts, "provider": "vault", "mount": mount, "name": f"{mount}/{role}", "key_type": key_type,
                        "key_bits": bits, "max_ttl_s": _seconds(facts.get("max_ttl")),
                        "server_auth": bool(facts.get("server_flag", True))})
        n += 1
    return n


def _seconds(value: Any) -> int | None:
    if isinstance(value, (int, float)):
        return int(value)
    m = re.fullmatch(r"(\d+)([smhd]?)", str(value or "").strip())
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _vault_transit(ctx: JobContext, v: Vault, mount: str, loc: str) -> int:
    n = 0
    keys = _list(v, f"{mount}/keys", f"{mount} keys")
    for key in keys:
        status, body = v.get(f"{mount}/keys/{quote(key, safe='')}")
        data = _data(body)
        if status != 200:
            continue
        facts = {k: data.get(k) for k in TRANSIT_FIELDS if k in data}
        algorithm, bits = VAULT_KEY_BITS.get(str(facts.get("type")), (str(facts.get("type") or "") or None, None))
        if facts.get("type") == "hmac" and isinstance(facts.get("key_size"), int):
            bits = facts["key_size"] * 8
        versions = data.get("keys") if isinstance(data.get("keys"), dict) else {}
        ctx.emit("managed_key", v.target.label, f"{loc}/{mount}/keys/{key}", name=str(key), algorithm=algorithm,
                 key_size=bits, facts={**facts, "store": "vault_transit", "mount": mount,
                                       "key_class": "secret" if algorithm in ("AES", "ChaCha20", "XChaCha20", "HMAC",
                                                                              "AES-CMAC") else "private",
                                       "versions": len(versions),
                                       "auto_rotate_period_s": _seconds(facts.get("auto_rotate_period"))})
        n += 1
    ctx.emit("key_store", v.target.label, f"{loc}/{mount}", name=f"Vault transit {mount}",
             facts={"store": "vault_transit", "mount": mount, "keys": len(keys)})
    return n + 1


# ----------------------------------------------------------------------------- EJBCA
def _ejbca_base(url: str) -> str:
    base = url.rstrip("/")
    return base if base.endswith("/ejbca/ejbca-rest-api") else base + "/ejbca/ejbca-rest-api"


def collect_ejbca(ctx: JobContext, config: dict, secrets: dict) -> tuple[Target, int]:
    from zs_scan_node.tlsclient import client_context

    base = _ejbca_base(str(config["api_url"]))
    target = _target(ctx, base)
    sslctx = client_context(config.get("ca_pem"), secrets.get("client_cert"), secrets.get("client_key"), verify=True,
                            what="EJBCA client")
    client = http_client(base, target.ip, ctx.never_scan, verify=sslctx, timeout=20.0,
                         headers={"Accept": "application/json"})
    n = 0
    try:
        def get(sub: str):
            if ctx.should_stop():
                raise CaFail(ctx.should_stop() or "skipped_deadline", "stopped")
            try:
                return client.get(sub)  # relative to the pinned base URL (.../ejbca/ejbca-rest-api/)
            except Exception as exc:
                text = str(exc).lower()
                if "alert" in text or "handshake" in text and "certificate" in text:
                    raise CaFail("auth_failed", "EJBCA refused the client certificate") from None
                raise _http_error(exc, "EJBCA") from None

        r = get("v1/ca")
        if r.status_code in (401, 403):
            raise CaFail("auth_failed", f"EJBCA refused the client certificate ({r.status_code}): it needs a role "
                                        "with read access to CAs")
        if r.status_code != 200:
            raise CaFail("error", f"EJBCA answered {r.status_code} to v1/ca")
        cas = (r.json() or {}).get("certificate_authorities") or []
        for ca in cas[:MAX_ITEMS]:
            if not isinstance(ca, dict):
                continue
            name, subject = str(ca.get("name") or ""), str(ca.get("subject_dn") or "")
            facts: dict[str, Any] = {"provider": "ejbca", "name": name, "subject": subject,
                                     "issuer": ca.get("issuer_dn"), "expiration_date": ca.get("expiration_date"),
                                     "id": ca.get("id")}
            dl = get(f"v1/ca/{quote(subject, safe='')}/certificate/download") if subject else None
            certs = load_certs(dl.content) if dl is not None and dl.status_code == 200 else []
            if certs:
                f = cert_facts(certs[0], "ejbca")
                ctx.emit("certificate", target.label, f"{base}/ca/{name}", name=f.get("subject", ""),
                         algorithm=f.get("key_alg"), key_size=f.get("key_size"), facts={**f, "role": "ca", "provider": "ejbca"})
                n += 1
                facts.update(key_type=f.get("key_alg"), key_size=f.get("key_size"), issuer_signature_algorithm=f.get("sig_alg"),
                             signature_algorithm=f.get("sig_alg") if f.get("self_signed") else None)
            ctx.emit("ca_authority", target.label, f"{base}/ca/{name}#config", name=name or subject,
                     algorithm=facts.get("key_type"), key_size=facts.get("key_size"), facts=facts)
            n += 1
        for profile in EJBCA_PROFILES:
            pr = get(f"v2/certificate/profile/{profile}")
            if pr.status_code == 404:
                continue
            if pr.status_code != 200:
                ctx.coverage(target.label, "EJBCA certificate profiles", "denied" if pr.status_code in (401, 403)
                             else "not_supported", f"v2/certificate/profile answered {pr.status_code}", once=True)
                break
            n += _ejbca_profile(ctx, target, base, profile, pr.json() or {})
        return target, n
    finally:
        client.close()


def _ejbca_profile(ctx: JobContext, target: Target, base: str, profile: str, body: dict) -> int:
    algs = [str(a).upper() for a in body.get("available_key_algs") or body.get("available_key_algorithms") or []]
    bits = [int(b) for b in body.get("available_bit_lengths") or [] if str(b).isdigit()]
    rsa_min = min(bits) if bits and ("RSA" in algs or not algs) else None
    ctx.emit("ca_template", target.label, f"{base}/profile/{profile}", name=f"EJBCA {profile}",
             algorithm="RSA" if "RSA" in algs else (algs[0] if algs else None), key_size=rsa_min,
             facts={"provider": "ejbca", "name": f"EJBCA profile {profile}", "key_type": "RSA" if "RSA" in algs else
                    (algs[0] if algs else None), "key_bits": rsa_min, "available_key_algs": algs[:20],
                    "available_bit_lengths": bits[:20], "available_cas": (body.get("available_cas") or [])[:20],
                    "server_auth": profile in ("SERVER", "ENDUSER")})
    return 1


# ----------------------------------------------------------------------------- AD CS over WinRM
ADCS_SCRIPTS = {
    "adcs_ca": (
        "& { $b='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration'; $n=(Get-ItemProperty $b).Active; "
        "if (-not $n) { return }; $k=Join-Path $b $n; $p=Get-ItemProperty $k; "
        "$c=Get-ItemProperty (Join-Path $k 'CSP') -ErrorAction SilentlyContinue; "
        "$e=Get-ItemProperty (Join-Path $k 'PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy') "
        "-ErrorAction SilentlyContinue; $h=@($p.CACertHash)[-1]; $raw=$null; "
        "if ($h) { $t=($h -replace ' ','').ToUpper(); $x=Get-Item \"Cert:\\LocalMachine\\My\\$t\" -ErrorAction "
        "SilentlyContinue; if ($x) { $raw=[Convert]::ToBase64String($x.RawData) } }; "
        "[pscustomobject]@{ Name=$n; HashAlgorithm=$c.CNGHashAlgorithm; Provider=$c.Provider; "
        "ValidityPeriod=$p.ValidityPeriod; ValidityPeriodUnits=$p.ValidityPeriodUnits; CRLPeriod=$p.CRLPeriod; "
        "CRLPeriodUnits=$p.CRLPeriodUnits; EditFlags=$e.EditFlags; CACert=$raw } } | ConvertTo-Json -Compress"
    ),
    # Templates the CA publishes, with their settings from the CA server's own template cache (no AD second hop)
    "adcs_templates": (
        "& { $c='HKLM:\\SOFTWARE\\Microsoft\\Cryptography\\CertificateTemplateCache'; "
        "certutil -catemplates 2>$null | ForEach-Object { if ($_ -match '^([^:\\s]+):') { $n=$Matches[1]; "
        "$v=Get-ItemProperty (Join-Path $c $n) -ErrorAction SilentlyContinue; [pscustomobject]@{ Name=$n; "
        "Cached=[bool]$v; MinKeySize=$v.'msPKI-Minimal-Key-Size'; NameFlag=$v.'msPKI-Certificate-Name-Flag'; "
        "EnrollmentFlag=$v.'msPKI-Enrollment-Flag'; RASignature=$v.'msPKI-RA-Signature'; "
        "EKU=@($v.ExtKeyUsageSyntax); AppPolicy=@($v.'msPKI-Certificate-Application-Policy'); "
        "RAAppPolicies=@($v.'msPKI-RA-Application-Policies'); "
        "Validity=$(if ($v.ValidityPeriod) { [BitConverter]::ToInt64($v.ValidityPeriod, 0) } else { $null }); "
        "Schema=$v.'msPKI-Template-Schema-Version' } } } } | ConvertTo-Json -Depth 3 -Compress"
    ),
}
EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
CT_FLAG_PEND_ALL_REQUESTS = 0x2
CLIENT_AUTH_EKUS = {"1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2", "1.3.6.1.5.2.3.4", "2.5.29.37.0"}
SERVER_AUTH_EKUS = {"1.3.6.1.5.5.7.3.1", "2.5.29.37.0"}
_VALIDITY = {"Years": 365 * 86400, "Months": 30 * 86400, "Weeks": 7 * 86400, "Days": 86400, "Hours": 3600}


def _json_list(text: str) -> list[dict]:
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        return []
    items = data if isinstance(data, list) else [data]
    return [i for i in items if isinstance(i, dict)]


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_adcs_ca(text: str) -> dict[str, Any] | None:
    items = _json_list(text)
    if not items:
        return None
    raw = items[0]
    period, units = str(raw.get("ValidityPeriod") or ""), _int(raw.get("ValidityPeriodUnits"))
    edit = _int(raw.get("EditFlags"))
    facts = {"provider": "adcs", "name": printable(str(raw.get("Name") or ""), 128), "hash_algorithm": raw.get("HashAlgorithm"),
             "csp": printable(str(raw.get("Provider") or ""), 128) or None,
             "issued_validity_s": units * _VALIDITY[period] if units and period in _VALIDITY else None,
             "crl_period": f"{raw.get('CRLPeriodUnits')} {raw.get('CRLPeriod')}" if raw.get("CRLPeriod") else None,
             "edit_flags": edit,
             "san_from_request_attributes": bool(edit & EDITF_ATTRIBUTESUBJECTALTNAME2) if edit is not None else None}
    cert_der = None
    if raw.get("CACert"):
        try:
            cert_der = base64.b64decode(str(raw["CACert"]))
        except ValueError:
            cert_der = None
    return {"facts": facts, "cert_der": cert_der}


def _asym_algorithm(policies: list[Any]) -> str | None:
    for item in policies or []:
        m = re.search(r"msPKI-Asymmetric-Algorithm`PZPWSTR`([A-Za-z0-9_]+)", str(item))
        if m:
            return m.group(1).upper()
    return None


def parse_adcs_templates(text: str) -> list[dict[str, Any]]:
    out = []
    for raw in _json_list(text):
        name = printable(str(raw.get("Name") or ""), 128)
        if not name:
            continue
        ekus = {str(e) for e in (raw.get("EKU") or []) + (raw.get("AppPolicy") or []) if e}
        name_flag, enroll_flag, ra = _int(raw.get("NameFlag")) or 0, _int(raw.get("EnrollmentFlag")) or 0, _int(raw.get("RASignature")) or 0
        validity = _int(raw.get("Validity"))
        algorithm = _asym_algorithm(raw.get("RAAppPolicies") or []) or "RSA"
        key_type = "EC" if algorithm.startswith(("ECDH", "ECDSA")) else algorithm
        out.append({
            "provider": "adcs", "name": name, "cached": bool(raw.get("Cached")), "key_type": key_type,
            "key_algorithm": algorithm, "key_bits": _int(raw.get("MinKeySize")), "ekus": sorted(ekus)[:20],
            "enrollee_supplies_subject": bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) and not
            (enroll_flag & CT_FLAG_PEND_ALL_REQUESTS) and ra == 0,
            "manager_approval": bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS), "authorized_signatures": ra,
            "client_auth": not ekus or bool(ekus & CLIENT_AUTH_EKUS),
            "server_auth": not ekus or bool(ekus & SERVER_AUTH_EKUS),
            # pKIExpirationPeriod is a negative FILETIME interval (100 ns units)
            "max_ttl_s": int(-validity / 10_000_000) if validity and validity < 0 else None,
            "schema_version": _int(raw.get("Schema")),
        })
    return out


def collect_adcs(ctx: JobContext, config: dict, password: str) -> tuple[Target, int]:
    from zs_scan_node.collectors import windows_winrm as W

    for name, script in ADCS_SCRIPTS.items():
        W.SCRIPTS.setdefault(name, script)
    host = str(config.get("host") or "").strip()
    label = host.strip("[]").lower().rstrip(".")
    try:
        target = Target(label, resolve_checked(host, ctx.never_scan)[0])
    except Blocked:
        raise CaFail("skipped_never_scan", f"{label} is on the never-scan list") from None
    except OSError as exc:
        raise CaFail("unreachable", f"could not resolve {label}: {exc.__class__.__name__}") from None
    wcfg = {"port": int(config.get("port") or 5986), "login_user": config.get("login"), "ca_pem": config.get("ca_pem")}
    n = 0
    with W._ca_file(wcfg) as ca_path:
        try:
            sess = W._session(ctx, target, wcfg, password, ca_path)
            code, out, err = W._run(sess, "adcs_ca")
            ca = parse_adcs_ca(out) if code == 0 else None
            if ca is None:
                raise CaFail("not_supported", "no Active Directory Certificate Services CA is configured on this "
                                              "server" if code == 0 else f"reading the CA configuration failed: "
                                                                          f"{W._stderr(err) or code}")
            facts = ca["facts"]
            certs = load_certs(ca["cert_der"]) if ca["cert_der"] else []
            if certs:
                f = cert_facts(certs[0], "adcs")
                ctx.emit("certificate", label, f"adcs://{label}/{facts['name']}", name=f.get("subject", ""),
                         algorithm=f.get("key_alg"), key_size=f.get("key_size"), facts={**f, "role": "ca", "provider": "adcs"})
                n += 1
                facts.update(key_type=f.get("key_alg"), subject=f.get("subject"), not_after=f.get("not_after"))
            ctx.emit("ca_authority", label, f"adcs://{label}/{facts['name']}#config", name=facts["name"] or label,
                     algorithm=facts.get("key_type"), key_size=(f.get("key_size") if certs else None), facts=facts)
            n += 1
            code, out, err = W._run(sess, "adcs_templates")
            templates = parse_adcs_templates(out)
            if code != 0 and not templates:
                ctx.coverage(label, "AD CS templates", "error", W._stderr(err) or "certutil -catemplates failed")
            for t in templates:
                if not t["cached"]:
                    ctx.coverage(label, "AD CS template settings", "not_supported", f"{t['name']} is published but not "
                                 "in this server's template cache; its key size and flags were not read", once=False)
                ctx.emit("ca_template", label, f"adcs://{label}/{facts['name']}/template/{t['name']}", name=t["name"],
                         algorithm=t["key_type"], key_size=t["key_bits"], facts=t)
                n += 1
        except W._Fail as fail:
            raise CaFail(fail.status, fail.error) from None
    return target, n


# ----------------------------------------------------------------------------- entry points
def _secret(ctx: JobContext, secrets: dict, name: str, what: str) -> str:
    value = secrets.get(name)
    if not value:
        raise ConfigError(f"no {what} is stored for this certificate authority")
    return value


def _run(ctx: JobContext, config: dict, secrets: dict) -> tuple[str, str, str | None, int]:
    provider = config.get("provider")
    label = str(config.get("host") or urlsplit(str(config.get("api_url") or "")).hostname or provider)
    try:
        if provider == "vault":
            target, n = collect_vault(ctx, config, _secret(ctx, secrets, "token", "Vault token"))
        elif provider == "ejbca":
            target, n = collect_ejbca(ctx, config, secrets)
        elif provider == "adcs":
            target, n = collect_adcs(ctx, config, _secret(ctx, secrets, "password", "password"))
        else:
            raise ConfigError(f"{provider} is not collected by this scan node version")
        return target.label, "ok", None, n
    except CaFail as fail:
        return label, fail.status, fail.error, 0
    except Blocked:
        return label, "skipped_never_scan", None, 0


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    label, status, error, n = _run(ctx, config, secrets)
    ctx.outcome(label, status, error, started=started, assets=n)
    return f"{config.get('provider')} {label}: {status}"


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    try:
        label, status, error, n = _run(ctx, config, secrets)
    except ConfigError as exc:
        ctx.samples.append({"target": str(config.get("provider")), "status": "error", "reachable": None, "login": False,
                            "privilege": None, "note": str(exc)})
        return str(exc)
    ctx.samples.append({"target": label, "status": "ready" if status == "ok" else status,
                        "reachable": status not in ("unreachable", "refused", "timeout", "no_route"),
                        "login": status == "ok", "privilege": None,
                        "note": error or f"{n} items read in {int(time.monotonic() - started)} s"})
    return error or "ready"
