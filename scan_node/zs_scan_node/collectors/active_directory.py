"""Active Directory over LDAPS / StartTLS: read-only crypto posture of the domain controllers and the directory.

Per domain controller (each target line):

1. the never-scan gate on the name and every address it resolves to (``check_name``), then everything connects to
   the checked address only;
2. without credentials: the DC's TLS posture on the LDAP port, read by the network prober
   (``network.NetworkScan.scan_endpoint``, protocol ``tls`` for LDAPS or ``starttls-ldap``): versions, every cipher
   suite per version (so RC4 or 3DES that is accepted but not preferred is found), groups, PQ key exchange and the
   chain, the same facts as every other TLS endpoint of D7, within the target's ``timeout_s``: a ``tls_endpoint`` and
   its ``certificate`` chain;
3. a TLS session that verifies the DC's certificate (the customer's CA, else the system store) and its name; only
   then is the read-only account's password sent (a simple bind).  A certificate that does not verify ends the
   target with ``identity_unverified`` and the password is not sent;
4. RootDSE (functional levels, naming contexts) and, once per domain, the directory metadata that decides Kerberos
   crypto: ``msDS-SupportedEncryptionTypes`` on the domain controllers, krbtgt, service accounts (users with an SPN)
   and group managed service accounts, a count over computer accounts, the krbtgt key age, and the AD CS enrollment
   services with their CA certificates.  Each account is read once (by DN) under the first search that finds it.

An account without ``msDS-SupportedEncryptionTypes`` gets the domain controller's default, which this collector cannot
read: Microsoft KB5073381 (CVE-2026-20833) made a DC patched from April 2026 assume AES-SHA1 only (0x18) unless the
registry value ``DefaultDomainSupportedEncTypes`` says otherwise, while an older DC assumes RC4.  Such an account is
recorded as "DC default" (RC4 and AES unknown), never as RC4.  krbtgt's TGT keys follow the domain functional level and
its password age, not this attribute.

Never read: any secret-bearing attribute (``ldapmini.SECRET_ATTRIBUTES`` is refused before a request is sent and
dropped if a server returns one), and ``*``.  The client has no write operation at all.  LDAP signing and channel
binding requirements live in each DC's registry / Group Policy and are not readable over LDAP: a coverage row says so.
"""
from __future__ import annotations

import concurrent.futures as cf
import datetime as _dt
import ssl
import threading
import time
from typing import Any

from zs_scan_node import ldapmini as L
from zs_scan_node import netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.collectors import ConfigError, skipped_never_scan, target_error
from zs_scan_node.collectors import network as NW
from zs_scan_node.jobctx import JobContext, LeaseLost, register_asset_types
from zs_scan_node.netutil import (
    Blocked,
    Target,
    checked_ip,
    expand_targets,
    is_ip,
    resolve_checked,
)
from zs_scan_node.scrub import printable

register_asset_types("ad_domain", "kerberos_account")

LDAPS_PORTS = frozenset({636, 3269})
PLAIN_PORTS = frozenset({389, 3268})
MAX_ACCOUNT_ASSETS = 2000  # kerberos_account rows per domain (service accounts, gMSAs, DCs, krbtgt); the rest counted
MAX_COMPUTERS = 50_000  # computer accounts counted per domain
SAMPLE_NAMES = 25
CONNECT_TIMEOUT_S = 10.0
POSTURE_HANDSHAKES = 48  # TLS handshakes for one DC's LDAP endpoint (the network prober's budget; bounded by timeout_s)

# msDS-SupportedEncryptionTypes bits (MS-KILE 2.2.7)
ENCTYPE_BITS = ((0x1, "DES-CBC-CRC"), (0x2, "DES-CBC-MD5"), (0x4, "RC4-HMAC"), (0x8, "AES128-CTS-HMAC-SHA1-96"),
                (0x10, "AES256-CTS-HMAC-SHA1-96"), (0x20, "AES256-CTS-HMAC-SHA1-96-SK"))
USE_DES_KEY_ONLY = 0x200000
FUNCTIONAL_LEVELS = {0: "Windows 2000", 1: "Windows Server 2003 interim", 2: "Windows Server 2003",
                     3: "Windows Server 2008", 4: "Windows Server 2008 R2", 5: "Windows Server 2012",
                     6: "Windows Server 2012 R2", 7: "Windows Server 2016", 10: "Windows Server 2025"}
ROOT_DSE_ATTRS = ["defaultNamingContext", "configurationNamingContext", "rootDomainNamingContext", "dnsHostName",
                  "domainFunctionality", "forestFunctionality", "domainControllerFunctionality", "serverName",
                  "supportedLDAPVersion", "supportedSASLMechanisms"]
ACCOUNT_ATTRS = ["sAMAccountName", "dNSHostName", "msDS-SupportedEncryptionTypes", "userAccountControl", "pwdLastSet",
                 "operatingSystem", "operatingSystemVersion", "objectClass"]
# strongest first: the account's ``algorithm`` (never the lowest bit, which is the weakest); -SK is a flag, not a key
STRENGTH = ("AES256-CTS-HMAC-SHA1-96", "AES128-CTS-HMAC-SHA1-96", "RC4-HMAC", "DES-CBC-MD5", "DES-CBC-CRC")
DC_DEFAULT_NOTE = ("msDS-SupportedEncryptionTypes is not set, so the domain controller's default applies: AES only on a "
                   "DC with the April 2026 update (KB5073381, CVE-2026-20833) unless DefaultDomainSupportedEncTypes "
                   "enables RC4, RC4 on an older DC; neither is readable over LDAP")
LDAP_POLICY_NOTE = ("LDAP signing (LDAPServerIntegrity) and channel binding (LdapEnforceChannelBinding) are set in each "
                    "domain controller's registry or Group Policy and cannot be read over LDAP; read them with a Windows "
                    "servers source on the domain controllers")


class _Fail(Exception):
    def __init__(self, status: str, error: str) -> None:
        super().__init__(error)
        self.status, self.error = status, error


# ----------------------------------------------------------------------------- pure helpers (unit tested)
def enctypes(value: int | None) -> list[str]:
    return [name for bit, name in ENCTYPE_BITS if value and value & bit]


def enctype_facts(value: int | None, uac: int | None, account_type: str) -> dict[str, Any]:
    """What the KDC will issue for this account.  An explicit attribute says it.  An unset one (or 0) means the DC's
    default, which LDAP cannot read (KB5073381: AES-SHA1 only on a DC patched from April 2026 unless
    DefaultDomainSupportedEncTypes enables RC4; RC4 on an older DC): RC4 and AES are then unknown (None), never
    assumed.  USE_DES_KEY_ONLY is DES whatever the attribute says."""
    names = enctypes(value)
    des_only = bool(uac and uac & USE_DES_KEY_ONLY)
    source = "attribute" if value else "default"
    des = any(n.startswith("DES") for n in names) or des_only
    rc4: bool | None
    aes: bool | None
    if source == "attribute":
        aes = any(n.startswith("AES") and not n.endswith("-SK") for n in names)
        rc4 = "RC4-HMAC" in names
        rc4_only: bool | None = rc4 and not aes and not des
    else:
        aes = rc4 = rc4_only = None
    return {"account_type": account_type, "enc_types": names, "enc_types_value": value, "enc_types_source": source,
            "use_des_key_only": des_only, "des_enabled": des, "rc4_enabled": rc4, "aes_enabled": aes,
            "rc4_only": rc4_only, "dc_default": source == "default", "weak": des or rc4 is True}


def strongest(names: list[str]) -> str | None:
    """The strongest Kerberos encryption type of the list (the account's ``algorithm``), or None."""
    return next((n for n in STRENGTH if n in names), None)


def filetime_to_iso(value: str | None) -> str | None:
    try:
        n = int(value or 0)
    except ValueError:
        return None
    if n <= 0 or n >= 0x7FFFFFFFFFFFFFFF:
        return None
    moment = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC) + _dt.timedelta(microseconds=n // 10)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def dn_to_dns(dn: str | None) -> str | None:
    if not dn:
        return None
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().lower().startswith("dc=") and "=" in p]
    return ".".join(parts).lower() or None


def level_name(value: int | None) -> str | None:
    return None if value is None else FUNCTIONAL_LEVELS.get(value, f"level {value}")


# ----------------------------------------------------------------------------- connections
def check_name(ctx: JobContext, target: Target) -> str:
    """The address to connect to, after the never-scan list (the name and every address it has now)."""
    try:
        if is_ip(target.label):
            return checked_ip(target.ip or target.label, ctx.never_scan)
        return resolve_checked(target.label, ctx.never_scan)[0]
    except Blocked as exc:
        raise _Fail("skipped_never_scan", str(exc)) from None
    except OSError:
        raise _Fail("unreachable", f"could not resolve {target.label}") from None


def tls_mode(config: dict) -> str:
    return "starttls" if config.get("tls_mode") == "starttls" else "ldaps"


def port_of(config: dict) -> int:
    return int(config.get("port") or (389 if tls_mode(config) == "starttls" else 636))


def _tls_context(config: dict) -> ssl.SSLContext:
    """Verifying context: the customer's CA for the DC certificates when given, else the system store; TLS 1.2+."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    pem = config.get("ca_pem")
    try:
        if pem:
            context.load_verify_locations(cadata=pem)
        else:
            context.load_default_certs()
    except (ssl.SSLError, ValueError):
        raise ConfigError("the CA certificate for the domain controllers does not load (PEM expected)") from None
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def open_session(ctx: JobContext, target: Target, ip: str, config: dict, deadline: float) -> L.LdapClient:
    """A verified TLS LDAP session to ``ip`` (LDAPS, or StartTLS on a plain port).  Nothing secret is sent before the
    certificate and the name were verified."""
    mode, port = tls_mode(config), port_of(config)
    if mode == "ldaps" and port in PLAIN_PORTS:
        raise _Fail("identity_unverified", f"port {port} is plain LDAP; use LDAPS (636) or StartTLS. The password was "
                    "not sent")
    try:  # the gate again (a never-scan entry added while the job runs applies to the rest of it)
        sock = netutil.connect(ip, port, ctx.never_scan, min(CONNECT_TIMEOUT_S, max(0.5, deadline - time.monotonic())))
    except Blocked as exc:
        raise _Fail("skipped_never_scan", str(exc)) from None
    except OSError as exc:
        err = T.connect_error(exc, ip)
        raise _Fail(err.code if err.code in ("refused", "timeout", "no_route", "unreachable") else "unreachable",
                    f"{err.detail}"[:200]) from None
    hostname = target.label if not is_ip(target.label) else ip
    try:
        if mode == "starttls":
            try:
                L.LdapClient(sock, deadline).start_tls()
            except L.LdapError as exc:
                raise _Fail("tls_unavailable", f"{exc}; the password was not sent") from None
        try:
            tls = L.wrap_tls(sock, _tls_context(config), hostname, deadline)
        except ssl.SSLCertVerificationError as exc:
            reason = getattr(exc, "verify_message", None) or "certificate not trusted"
            raise _Fail("identity_unverified", f"the domain controller's certificate did not verify ({reason}); the "
                        "password was not sent") from None
        except ssl.SSLError as exc:
            raise _Fail("tls_unavailable", f"no TLS 1.2+ session ({exc.reason or exc.__class__.__name__}); the "
                        "password was not sent") from None
        return L.LdapClient(tls, deadline)
    except BaseException:
        try:
            sock.close()
        except OSError:
            pass
        raise


# ----------------------------------------------------------------------------- TLS posture (no credentials)
class _PostureScan(NW.NetworkScan):
    """The network prober's TLS read of one LDAP endpoint (#488 review M5), every handshake bounded by the target's
    deadline (m2: ``timeout_s`` is the whole posture read, not a per-probe allowance).  Each prober handshake takes its
    timeout as the fifth argument (``tlsprobe.probe``/``s_client``/``python_handshake``); past the deadline a
    handshake is not sent and reads as the prober's own "handshake budget" stop, so the enumeration ends cleanly."""

    def __init__(self, ctx: Any, scope: dict, deadline: float) -> None:
        super().__init__(ctx, scope)
        self.deadline = deadline
        # no SNI names: a domain controller serves its certificate to a hello without one (the verified session in
        # ``open_session`` checks the name), and the prober never resolves the DC's name a second time
        self._sni_order, self._sni_addresses, self._sni_reported = [], {}, True

    def handshake(self, ep: NW.Endpoint, budget: Any, fn: Any, *args: Any) -> Any:
        left = self.deadline - time.monotonic()
        if left <= 0.05:
            return "budget"
        if len(args) >= 5 and isinstance(args[4], (int, float)) and not isinstance(args[4], bool):
            args = (*args[:4], max(0.2, min(float(args[4]), left)), *args[5:])
        return super().handshake(ep, budget, fn, *args)


class _LdapView:
    """The job context as the prober sees it for one domain controller: assets and coverage rows carry the DC's name
    (as the target was written) instead of its address, the endpoint says it is LDAP (``service``,
    ``ldap_tls_mode``) and the leaf certificate is the DC's.  Everything else is the job context itself."""

    def __init__(self, ctx: JobContext, label: str, ip_where: str, where: str, mode: str) -> None:
        self._ctx, self._label, self._ip_where, self._where, self._mode = ctx, label, ip_where, where, mode

    def __getattr__(self, name: str) -> Any:
        return getattr(self._ctx, name)

    def _place(self, text: str) -> str:
        return text.replace(self._ip_where, self._where, 1) if isinstance(text, str) else text

    def emit(self, asset_type: str, _target: str, location: str, **kw: Any) -> Any:
        facts = dict(kw.pop("facts", None) or {})
        if asset_type == "tls_endpoint":
            facts.update(service="ldap", ldap_tls_mode=self._mode, prober="network")
            kw["name"] = f"LDAP {'StartTLS' if self._mode == 'starttls' else 'LDAPS'} {self._where}"
        elif asset_type == "certificate" and facts.get("chain_index") == 0:
            facts["role"] = "domain_controller"
        elif "name" in kw:
            kw["name"] = self._place(kw["name"])
        return self._ctx.emit(asset_type, self._label, self._place(location), facts=facts, **kw)

    def coverage(self, _target: str, check: str, status: str, detail: str = "", **kw: Any) -> Any:
        if isinstance(kw.get("scope"), list):
            kw["scope"] = [self._place(v) for v in kw["scope"]]
        return self._ctx.coverage(self._label, self._place(check), status, self._place(detail), **kw)


def tls_posture(ctx: JobContext, target: Target, ip: str, port: int, mode: str,
                deadline: float) -> tuple[str, str | None, int]:
    """Read the DC's LDAP TLS service without credentials with the network prober; its assets are emitted under the
    target's name.  Returns the prober's (status, detail, assets emitted); ``skipped_never_scan`` raises Blocked."""
    checked_ip(ip, ctx.never_scan)  # raises Blocked: the caller's target ends skipped_never_scan
    protocol = "starttls-ldap" if mode == "starttls" else "tls"
    label = f"LDAP {'StartTLS' if mode == 'starttls' else 'LDAPS'}"
    endpoint = NW.Endpoint(ip, port, protocol, label)
    where = f"{target.label}:{port}"
    # a DC is one endpoint: a larger handshake budget than a sweep's default (12) lets the suite enumeration finish
    scope = {"rate_limits": {"handshakes_per_endpoint": POSTURE_HANDSHAKES}}
    view = _LdapView(ctx, target.label, endpoint.where, where, mode)
    scan = _PostureScan(view, scope, deadline)
    status, detail, assets = scan.scan_endpoint(endpoint, "full")  # type: ignore[arg-type]
    if status == "skipped_never_scan":
        raise Blocked(f"{ip} is on the never-scan list")
    return status, detail, assets


# ----------------------------------------------------------------------------- directory reads
def read_root_dse(client: L.LdapClient) -> dict[str, Any]:
    entries = list(client.search("", L.SCOPE_BASE, "(objectClass=*)", ROOT_DSE_ATTRS))
    attrs = entries[0][1] if entries else {}
    return {
        "default_nc": L.first(attrs, "defaultNamingContext"),
        "configuration_nc": L.first(attrs, "configurationNamingContext"),
        "root_domain_nc": L.first(attrs, "rootDomainNamingContext"),
        "dns_host_name": L.first(attrs, "dnsHostName"),
        "domain_functionality": L.int_value(attrs, "domainFunctionality"),
        "forest_functionality": L.int_value(attrs, "forestFunctionality"),
        "dc_functionality": L.int_value(attrs, "domainControllerFunctionality"),
        "ldap_versions": [v.decode("ascii", "replace") for v in L.all_values(attrs, "supportedLDAPVersion")][:4],
        "sasl_mechanisms": [v.decode("ascii", "replace") for v in L.all_values(attrs, "supportedSASLMechanisms")][:10],
    }


def _account(attrs: dict[str, list[bytes]], account_type: str) -> dict[str, Any]:
    facts = enctype_facts(L.int_value(attrs, "msDS-SupportedEncryptionTypes"), L.int_value(attrs, "userAccountControl"),
                          account_type)
    facts["account"] = L.first(attrs, "sAMAccountName")
    host = L.first(attrs, "dNSHostName")
    if host:
        facts["dns_host_name"] = host
    os_name = L.first(attrs, "operatingSystem")
    if os_name:
        facts["operating_system"] = printable(os_name, 80)
    os_version = L.first(attrs, "operatingSystemVersion")
    if os_version:
        facts["operating_system_version"] = printable(os_version, 40)
    last = filetime_to_iso(L.first(attrs, "pwdLastSet"))
    if last:
        facts["password_last_set"] = last
    return facts


def read_domain(ctx: JobContext, client: L.LdapClient, dse: dict[str, Any], target: str) -> int:
    """The domain-wide Kerberos and AD CS facts (once per domain).  Returns the assets emitted."""
    base = dse.get("default_nc")
    if not base:
        ctx.coverage(target, "Active Directory domain", "error", "RootDSE named no default naming context")
        return 0
    domain = dn_to_dns(base) or base
    loc = f"ad:{domain}"
    n = 0
    accounts: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    samples: dict[str, list[str]] = {}

    def tally(facts: dict[str, Any]) -> None:
        kind = facts["account_type"]
        for flag in ("des_enabled", "rc4_enabled", "rc4_only", "aes_enabled", "dc_default"):
            if facts.get(flag) is True:
                counts[f"{kind}_{flag}"] = counts.get(f"{kind}_{flag}", 0) + 1
                names = samples.setdefault(f"{kind}_{flag}", [])
                if len(names) < SAMPLE_NAMES and facts.get("account"):
                    names.append(str(facts["account"]))
        counts[f"{kind}_total"] = counts.get(f"{kind}_total", 0) + 1

    searches = (
        ("domain_controller", "(|(primaryGroupID=516)(primaryGroupID=521))", True),
        ("krbtgt", "(sAMAccountName=krbtgt)", True),
        # krbtgt carries the SPN kadmin/changepw: it is read once, as krbtgt (#488 review M3)
        ("service_account", "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)"
                            "(!(sAMAccountName=krbtgt)))", True),
        ("gmsa", "(objectClass=msDS-GroupManagedServiceAccount)", True),
        ("computer", "(&(objectCategory=computer)(!(primaryGroupID=516))(!(primaryGroupID=521)))", False),
    )
    krbtgt: dict[str, Any] | None = None
    truncated: list[str] = []
    seen: set[str] = set()  # DNs already read: an account found by two searches is one account (M3)
    for account_type, filt, emit_each in searches:
        if ctx.should_stop():
            truncated.append(account_type)
            continue
        try:
            limit = MAX_COMPUTERS if account_type == "computer" else 20_000
            for dn, attrs in client.search(base, L.SCOPE_SUB, filt, ACCOUNT_ATTRS, max_entries=limit):
                key = str(dn).strip().lower()
                if key in seen:
                    continue
                seen.add(key)
                facts = _account(attrs, account_type)
                facts["domain"] = domain
                if account_type == "krbtgt":
                    # TGTs are encrypted with krbtgt's keys, which the domain functional level and the password age
                    # decide; its msDS-SupportedEncryptionTypes is not what the KDC uses for them (M2)
                    facts["judged_by"] = "domain_functional_level_and_key_age"
                    krbtgt = facts
                tally(facts)
                if emit_each and (facts["weak"] or facts["dc_default"] or account_type in ("domain_controller",
                                                                                           "krbtgt")):
                    accounts.append(facts)
            if client.truncated:
                truncated.append(account_type)
        except L.LdapError as exc:
            ctx.coverage(target, f"Kerberos encryption types ({account_type})",
                         "denied" if exc.code == 50 else "error", str(exc))
    for facts in accounts[:MAX_ACCOUNT_ASSETS]:
        name = str(facts.get("account") or "?")
        ctx.emit("kerberos_account", target, f"{loc}/{facts['account_type']}/{name}", name=name,
                 algorithm=strongest(facts["enc_types"]), protocol="kerberos", facts=facts)
        n += 1
    if len(accounts) > MAX_ACCOUNT_ASSETS:
        truncated.append(f"kerberos_account rows over {MAX_ACCOUNT_ASSETS}")
    # AD CS enrollment services (public configuration data: name, host, templates offered, CA certificate)
    enrollment: list[dict[str, Any]] = []
    config_nc = dse.get("configuration_nc")
    if config_nc and not ctx.should_stop():
        where = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_nc}"
        try:
            for _dn, attrs in client.search(where, L.SCOPE_ONE, "(objectClass=pKIEnrollmentService)",
                                            ["cn", "dNSHostName", "cACertificate", "certificateTemplates"],
                                            max_entries=200):
                name = L.first(attrs, "cn") or "?"
                templates = sorted(v.decode("utf-8", "replace") for v in L.all_values(attrs, "certificateTemplates"))
                enrollment.append({"name": name, "dns_host_name": L.first(attrs, "dNSHostName"),
                                   "templates": templates[:100], "template_count": len(templates)})
                for der in L.all_values(attrs, "cACertificate")[:5]:
                    for cert in load_certs(der):
                        f = cert_facts(cert, "ad_cs")
                        ctx.emit("certificate", target, f"{loc}/adcs/{name}", name=f.get("subject", ""),
                                 algorithm=f.get("key_alg"), key_size=f.get("key_size"),
                                 facts={**f, "role": "ca", "enrollment_service": name, "domain": domain})
                        n += 1
        except L.LdapError as exc:
            if exc.code != 32:  # noSuchObject: no AD CS in this forest
                ctx.coverage(target, "AD CS enrollment services", "error", str(exc))
    ctx.coverage(target, "LDAP signing and channel binding", "not_supported", LDAP_POLICY_NOTE, once=True)
    facts = {
        "domain": domain, "naming_context": base,
        "domain_functional_level": dse.get("domain_functionality"),
        "domain_functional_level_name": level_name(dse.get("domain_functionality")),
        "forest_functional_level": dse.get("forest_functionality"),
        "forest_functional_level_name": level_name(dse.get("forest_functionality")),
        "krbtgt_password_last_set": (krbtgt or {}).get("password_last_set"),
        "krbtgt_enc_types": (krbtgt or {}).get("enc_types"),
        "dc_operating_systems": sorted({f"{a.get('operating_system') or '?'} {a.get('operating_system_version') or ''}"
                                        .strip() for a in accounts if a["account_type"] == "domain_controller"})[:20],
        "dc_default_note": DC_DEFAULT_NOTE,
        "accounts": counts, "samples": samples, "enrollment_services": enrollment,
        "read_from": dse.get("dns_host_name") or target, "truncated": truncated,
        "ldap_signing": "not_readable", "ldap_channel_binding": "not_readable",
    }
    ctx.emit("ad_domain", target, loc, name=domain, protocol="kerberos", facts=facts)
    return n + 1


# ----------------------------------------------------------------------------- per target
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
        raise ConfigError("no password is stored for this Active Directory source")
    ctx.scrubber.add(pw)
    return pw


def _ldap_fail(exc: L.LdapError) -> _Fail:
    if exc.code == 49:
        return _Fail("auth_failed", "the directory refused the bind (invalidCredentials)")
    if exc.code in (8, 13):
        return _Fail("tls_unavailable", str(exc))
    if exc.code == 50:
        return _Fail("rbac_denied", str(exc))
    return _Fail("error", str(exc))


class _Domains:
    """Which domains were already read in this job (several DCs of one domain read it once)."""

    def __init__(self) -> None:
        self.done: set[str] = set()
        self.lock = threading.Lock()

    def claim(self, base: str | None) -> bool:
        if not base:
            return False
        with self.lock:
            if base.lower() in self.done:
                return False
            self.done.add(base.lower())
            return True


def collect_target(ctx: JobContext, target: Target, config: dict, password: str, domains: _Domains) -> int:
    ip = check_name(ctx, target)
    port, mode = port_of(config), tls_mode(config)
    timeout = float(min(int(config.get("timeout_s") or 300), max(1, ctx.time_left())))
    deadline = time.monotonic() + timeout
    where = f"{target.label}:{port}"
    n = 0
    try:
        status, detail, assets = tls_posture(ctx, target, ip, port, mode, deadline)
    except Blocked as exc:
        raise _Fail("skipped_never_scan", str(exc)) from None
    if status != "ok":
        ctx.coverage(target.label, f"LDAP TLS posture {where}", "incomplete",
                     f"the TLS read of {where} ended {status}" + (f": {detail}" if detail else ""), scope=[where],
                     incomplete=True)
    n += assets
    if time.monotonic() >= deadline:
        raise TimeoutError("the domain controller did not answer within timeout_s")
    client = open_session(ctx, target, ip, config, deadline)
    try:
        try:
            client.bind(str(config.get("login_user") or ""), password)
        except L.LdapError as exc:
            raise _ldap_fail(exc) from None
        try:
            dse = read_root_dse(client)
            if domains.claim(dse.get("default_nc")):
                n += read_domain(ctx, client, dse, target.label)
        except L.LdapError as exc:
            raise _ldap_fail(exc) from None
    finally:
        client.unbind()
        try:
            client.sock.close()
        except OSError:
            pass
    return n


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str | None:
    password = _password(ctx, config, secrets)
    reasons: dict[str, str] = {}
    targets, skipped = expand_targets(scope.get("targets") or [], ctx.never_scan, reasons=reasons)
    skipped_never_scan(ctx, skipped, reasons)
    _tls_context(config)  # a CA that does not load fails the job before any connection (ConfigError)
    domains = _Domains()

    def one(target: Target) -> None:
        started = time.monotonic()
        stop = ctx.should_stop()
        if stop:
            ctx.outcome(target.label, stop, started=started)
            return
        if target.ip is None:
            ctx.outcome(target.label, "unreachable", target.error, started=started)
            return
        skip = ctx.login_gate()  # CB-10: a simple bind with the account's password
        if skip:
            ctx.outcome(target.label, skip, ctx.credential_skip_note(skip), started=started)
            return
        status = "error"
        try:
            n = collect_target(ctx, target, config, password, domains)
            status = "ok"
            ctx.outcome(target.label, "ok", started=started, assets=n)
        except _Fail as fail:
            status = fail.status
            ctx.outcome(target.label, fail.status, fail.error, started=started)
        except LeaseLost:
            raise
        except TimeoutError:
            status = "timeout"
            ctx.outcome(target.label, "timeout", "the domain controller did not answer in time", started=started)
        except (ConnectionError, OSError) as exc:
            ctx.outcome(target.label, "unreachable", exc.__class__.__name__, started=started)
        except Exception as exc:  # noqa: BLE001 - one DC's error is its outcome, never the job's
            ctx.log("ad target error", target=target.label, error=exc.__class__.__name__, level="warn")
            ctx.outcome(target.label, "error", exc.__class__.__name__, started=started)
        finally:
            ctx.login_done(status)

    with cf.ThreadPoolExecutor(max_workers=max(1, min(int(config.get("parallel") or 4), 16))) as pool:
        list(pool.map(one, targets))
    return None


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    try:
        password = _password(ctx, config, secrets)
        _tls_context(config)
    except ConfigError as exc:
        ctx.samples.append({"target": "-", "status": "error", "reachable": None, "login": False, "privilege": None,
                            "note": str(exc)})
        return str(exc)
    reasons: dict[str, str] = {}
    targets, skipped = expand_targets(scope.get("targets") or [], ctx.never_scan, reasons=reasons)
    skipped_never_scan(ctx, skipped, reasons, samples=True)
    for target in targets[:5]:
        try:
            _test_one(ctx, target, config, password)
        except LeaseLost:
            raise
        except Exception as exc:  # noqa: BLE001 - one DC's error fails its sample, never the test job
            ctx.log("test target error", target=target.label, error=exc.__class__.__name__, level="warn")
            reachable, note = target_error(exc)
            ctx.samples.append({"target": target.label, "status": "error", "reachable": reachable, "login": False,
                                "privilege": None, "note": ctx.scrubber.text(note)})
    return f"{sum(1 for s in ctx.samples if s['status'] == 'ready')} of {len(ctx.samples)} samples ready"


def _test_one(ctx: JobContext, target: Target, config: dict, password: str) -> None:
    sample = {"target": target.label, "status": "ready", "reachable": False, "login": False, "privilege": None,
              "note": ""}
    if target.ip is None:
        sample.update(status="unreachable", note=target.error or "")
        ctx.samples.append(sample)
        return
    skip = ctx.login_gate()
    if skip:
        sample.update(status=skip, reachable=None, note=ctx.credential_skip_note(skip) or skip)
        ctx.samples.append(sample)
        return
    status = "error"
    try:
        ip = check_name(ctx, target)
        timeout = float(min(int(config.get("timeout_s") or 300), 60, max(1, ctx.time_left())))
        client = open_session(ctx, target, ip, config, time.monotonic() + timeout)
        sample["reachable"] = True
        try:
            client.bind(str(config.get("login_user") or ""), password)
            sample["login"] = True
            dse = read_root_dse(client)
        except L.LdapError as exc:
            raise _ldap_fail(exc) from None
        finally:
            client.unbind()
            client.sock.close()
        domain = dn_to_dns(dse.get("default_nc")) or "unknown domain"
        sample.update(privilege="read", note=printable(
            f"{dse.get('dns_host_name') or target.label}: {domain}, domain functional level "
            f"{level_name(dse.get('domain_functionality')) or 'not readable'}", 160))
        status = "ok"
    except _Fail as fail:
        status = fail.status
        sample.update(status=fail.status, reachable=fail.status not in ("unreachable", "timeout", "skipped_never_scan"),
                      login=False, note=fail.error)
    finally:
        ctx.login_done(status)
    ctx.samples.append(sample)
