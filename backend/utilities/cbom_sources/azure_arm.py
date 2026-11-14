"""Azure control-plane TLS policies, certificate stores and storage encryption (cloud worker; ARM GET calls only).

Per subscription, each a list-by-subscription call (``nextLink`` paging) with the reader role's ``*/read`` actions:
* Storage accounts (Microsoft.Storage 2023-05-01): encryption key source (Microsoft-managed or a Key Vault key),
  infrastructure encryption, and the endpoints' TLS policy (``minimumTlsVersion``, ``supportsHttpsTrafficOnly``).
  https://learn.microsoft.com/rest/api/storagerp/storage-accounts/list
* App Service apps (Microsoft.Web 2023-12-01): ``httpsOnly`` and host-name TLS bindings from the list, and per app
  ``config/web`` (``minTlsVersion``, ``scmMinTlsVersion``, ``minTlsCipherSuite``, ``ftpsState``).  App settings and
  connection strings are never read (they need the ``config/list`` action, which the reader role does not have).
  https://learn.microsoft.com/rest/api/appservice/web-apps/list, .../web-apps/get-configuration
* App Service certificates: the public ``cerBlob``, thumbprint, expiry and Key Vault link; ``in_use`` when an app binds
  its thumbprint.  ``pfxBlob`` and ``password`` are never kept.  https://learn.microsoft.com/rest/api/appservice/certificates/list
* Application Gateways (Microsoft.Network 2024-05-01): one row per listener with the SSL policy it serves (its SSL
  profile's, else the gateway's, else ``defaultPredefinedSslPolicy``); predefined policies expand to the protocols and
  cipher suites Microsoft documents. https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview
* Front Door Standard/Premium (Microsoft.Cdn 2024-02-01): each custom domain's ``tlsSettings``.
  https://learn.microsoft.com/rest/api/frontdoor/azurefrontdoorstandardpremium/afd-custom-domains/list-by-profile
* Azure SQL logical servers (Microsoft.Sql 2021-11-01): ``minimalTlsVersion``, public network access and the TDE
  customer-managed key id.  https://learn.microsoft.com/rest/api/sql/servers/list

Every failure is a coverage row (denied, error, throttled); an unregistered resource provider
(``MissingSubscriptionRegistration``) means the subscription has none of that service: a by-choice gap, not a failure.
"""
from __future__ import annotations

from typing import Any, Callable

from backend.utilities.cbom_sources.cloud_http import CloudHttp, CloudHttpError

ARM = "https://management.azure.com"
ITEM_CAP = 1000  # resources per service per subscription
Emit = Callable[[dict[str, Any]], None]

_TLS = {"TLS1_0": "TLSv1.0", "TLS1_1": "TLSv1.1", "TLS1_2": "TLSv1.2", "TLS1_3": "TLSv1.3",
        "TLSV1_0": "TLSv1.0", "TLSV1_1": "TLSv1.1", "TLSV1_2": "TLSv1.2", "TLSV1_3": "TLSv1.3",
        "TLS10": "TLSv1.0", "TLS12": "TLSv1.2", "TLS13": "TLSv1.3",
        "1.0": "TLSv1.0", "1.1": "TLSv1.1", "1.2": "TLSv1.2", "1.3": "TLSv1.3"}
_ORDER = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def tls_name(value: Any) -> str | None:
    return _TLS.get(str(value or "").upper())


# Application Gateway predefined policies: (enabled protocols, cipher suites in priority order), as tabled in
# https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview
_C2015 = (
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 "
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA "
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 TLS_DHE_RSA_WITH_AES_256_CBC_SHA "
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_128_GCM_SHA256 "
    "TLS_RSA_WITH_AES_256_CBC_SHA256 TLS_RSA_WITH_AES_128_CBC_SHA256 TLS_RSA_WITH_AES_256_CBC_SHA TLS_RSA_WITH_AES_128_CBC_SHA "
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 "
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA "
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 TLS_DHE_DSS_WITH_AES_256_CBC_SHA "
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA TLS_RSA_WITH_3DES_EDE_CBC_SHA TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA").split()
_C2017 = (
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA "
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA TLS_RSA_WITH_AES_256_GCM_SHA384 TLS_RSA_WITH_AES_128_GCM_SHA256 "
    "TLS_RSA_WITH_AES_256_CBC_SHA256 TLS_RSA_WITH_AES_128_CBC_SHA256 TLS_RSA_WITH_AES_256_CBC_SHA TLS_RSA_WITH_AES_128_CBC_SHA "
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 "
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA").split()
_C2022 = (
    "TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 "
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256").split()
_C2022S = ("TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "
           "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256").split()
APPGW_PREDEFINED: dict[str, tuple[list[str], list[str]]] = {
    "AppGwSslPolicy20150501": (["TLSv1.0", "TLSv1.1", "TLSv1.2"], _C2015),
    "AppGwSslPolicy20170401": (["TLSv1.1", "TLSv1.2"], _C2017),
    "AppGwSslPolicy20170401S": (["TLSv1.2"], _C2017),
    "AppGwSslPolicy20220101": (["TLSv1.2", "TLSv1.3"], _C2022),
    "AppGwSslPolicy20220101S": (["TLSv1.2", "TLSv1.3"], _C2022S),
}

# Each service's list call, the role action it needs (named in a denied coverage row) and its row label.
SERVICES: dict[str, tuple[str, str, str, str]] = {
    # service: (resource type path, api-version, action the reader role grants, words for the coverage row)
    "storage": ("Microsoft.Storage/storageAccounts", "2023-05-01", "Microsoft.Storage/storageAccounts/read", "storage accounts"),
    "appservice": ("Microsoft.Web/sites", "2023-12-01", "Microsoft.Web/sites/read and Microsoft.Web/sites/config/read", "app service apps"),
    "appservice_certificates": ("Microsoft.Web/certificates", "2023-12-01", "Microsoft.Web/certificates/read", "app service certificates"),
    "appgateway": ("Microsoft.Network/applicationGateways", "2024-05-01", "Microsoft.Network/applicationGateways/read", "application gateways"),
    "frontdoor": ("Microsoft.Cdn/profiles", "2024-02-01", "Microsoft.Cdn/profiles/read and Microsoft.Cdn/profiles/customdomains/read", "front door profiles"),
    "sql": ("Microsoft.Sql/servers", "2021-11-01", "Microsoft.Sql/servers/read", "sql servers"),
}


def status_of(exc: CloudHttpError) -> str:
    if exc.code in ("MissingSubscriptionRegistration", "SubscriptionNotRegistered"):
        return "not_enabled"
    if exc.status in (401, 403) or exc.code in ("AuthorizationFailed", "LinkedAuthorizationFailed"):
        return "denied"
    if exc.status == 404:
        return "not_found"
    return "error"


def _props(item: dict[str, Any]) -> dict[str, Any]:
    props = item.get("properties")
    return props if isinstance(props, dict) else {}


def _name(resource_id: Any) -> str:
    return str(resource_id or "").rstrip("/").rsplit("/", 1)[-1]


class _Subscription:
    def __init__(self, http: CloudHttp, token: Callable[[], str], sub: str, label: str, emit: Emit):
        self.http, self.token, self.sub, self.label, self.emit = http, token, sub, label, emit
        self.bound_thumbprints: set[str] | None = None  # App Service bindings, once the apps were read

    def list(self, service: str, url: str | None = None) -> tuple[list[dict[str, Any]], bool]:
        path, version, _action, _words = SERVICES[service]
        return self.http.azure_pages(url or f"{ARM}/subscriptions/{self.sub}/providers/{path}?api-version={version}",
                                     self.token(), cap=ITEM_CAP)

    def gap(self, service: str, where: str, check: str, status: str, detail: str, scope: list[str] | None = None,
            **extra: Any) -> None:
        facts: dict[str, Any] = {"check": check, "status": status, "detail": detail[:200], **extra}
        if scope:
            facts["scope"] = scope
        self.emit({"type": "coverage", "target": self.label, "location": where, "facts": facts})

    def capped(self, service: str, items_cut: bool) -> bool:
        if items_cut:
            words = SERVICES[service][3]
            self.gap(service, f"/subscriptions/{self.sub}/providers/{SERVICES[service][0]}#cap", f"{words} in subscription {self.sub}",
                     "truncated", f"More than {ITEM_CAP} {words}; the first {ITEM_CAP} were read")
        return items_cut

    # -- storage accounts
    def storage(self) -> str:
        accounts, cut = self.list("storage")
        for acct in accounts:
            rid, props = str(acct.get("id") or ""), _props(acct)
            if not rid:
                continue
            name = acct.get("name") or _name(rid)
            enc = props.get("encryption") if isinstance(props.get("encryption"), dict) else {}
            source = str(enc.get("keySource") or "Microsoft.Storage")
            kv = enc.get("keyvaultproperties") if isinstance(enc.get("keyvaultproperties"), dict) else {}
            key_id = (f"{str(kv.get('keyvaulturi') or '').rstrip('/')}/keys/{kv.get('keyname')}"
                      if source.lower() == "microsoft.keyvault" and kv.get("keyname") else "microsoft-managed")
            services = enc.get("services") if isinstance(enc.get("services"), dict) else {}
            self.emit({"type": "storage_encryption", "target": self.label, "location": rid, "name": name,
                       "facts": {"provider": "azure", "resource": f"Storage account {name}", "encrypted": True,
                                 "key_source": source, "kms_key_id": key_id,
                                 "infrastructure_encryption": bool(enc.get("requireInfrastructureEncryption")),
                                 "services_encrypted": sorted(k for k, v in services.items() if isinstance(v, dict) and v.get("enabled")),
                                 "identity": rid}})
            public = str(props.get("publicNetworkAccess") or "Enabled")
            acls = props.get("networkAcls") if isinstance(props.get("networkAcls"), dict) else {}
            default_action = str(acls.get("defaultAction") or "Allow")
            internet = (False if public.lower() == "disabled" else None if default_action.lower() == "deny" else True)
            https_only = props.get("supportsHttpsTrafficOnly")
            setting = props.get("minimumTlsVersion")
            # "default interpretation is TLS 1.0" when the account sets no minimum (Storage Accounts - List)
            self.emit({"type": "api_tls", "target": self.label, "location": f"{rid}#tls", "name": f"{name} storage endpoints",
                       "protocol": "TLS",
                       "facts": {"provider": "azure", "service": "storage", "min_version": tls_name(setting) or "TLSv1.0",
                                 "minimum_tls_setting": setting, "https_only": https_only,
                                 "http_listener": https_only is False, "internet_facing": internet,
                                 "exposure_basis": f"storage account public network access {public}, firewall default action {default_action}",
                                 "identity": rid}})
        return "truncated" if self.capped("storage", cut) else "ok"

    # -- App Service apps and their TLS configuration
    def appservice(self) -> str:
        sites, cut = self.list("appservice")
        bound: set[str] = set()
        unread: list[str] = []
        first: CloudHttpError | None = None
        for site in sites:
            rid, props = str(site.get("id") or ""), _props(site)
            if not rid:
                continue
            states = [s for s in props.get("hostNameSslStates") or [] if isinstance(s, dict)]
            bound.update(str(s.get("thumbprint")).upper() for s in states if s.get("thumbprint") and s.get("sslState") != "Disabled")
            config: dict[str, Any] = {}
            try:
                config = _props(self.http.get(f"{ARM}{rid}/config/web?api-version={SERVICES['appservice'][1]}", self.token()))
            except CloudHttpError as exc:
                unread.append(rid)
                first = first or exc
            public = str(props.get("publicNetworkAccess") or "Enabled") or "Enabled"
            exposure = {"internet_facing": public.lower() != "disabled",
                        "exposure_basis": f"app public network access {public}"}
            https_only = props.get("httpsOnly")
            facts = {"provider": "azure", "service": "app_service", "kind": site.get("kind"),
                     "min_version": tls_name(config.get("minTlsVersion")), "minimum_tls_setting": config.get("minTlsVersion"),
                     "scm_min_version": tls_name(config.get("scmMinTlsVersion")),
                     "min_cipher_suite": config.get("minTlsCipherSuite"), "ftps_state": config.get("ftpsState"),
                     "http2": config.get("http20Enabled"), "https_only": https_only, "http_listener": https_only is False,
                     "client_cert_mode": props.get("clientCertMode") if props.get("clientCertEnabled") else None,
                     "bindings": [{"host": s.get("name"), "ssl_state": s.get("sslState"), "thumbprint": s.get("thumbprint")}
                                  for s in states if s.get("sslState") and s.get("sslState") != "Disabled"][:20],
                     "config_read": rid not in unread, **exposure, "identity": rid}
            host = props.get("defaultHostName") or site.get("name") or _name(rid)
            self.emit({"type": "api_tls", "target": self.label, "location": rid, "name": host, "protocol": "TLS", "facts": facts})
            scm = facts["scm_min_version"]
            if scm and facts["min_version"] and _ORDER.index(scm) < _ORDER.index(facts["min_version"]):
                # the Kudu / deployment (SCM) endpoint accepts an older TLS than the app itself
                self.emit({"type": "api_tls", "target": self.label, "location": f"{rid}#scm", "name": f"{host} (SCM / Kudu)",
                           "protocol": "TLS", "facts": {"provider": "azure", "service": "app_service_scm", "min_version": scm,
                                                        "minimum_tls_setting": config.get("scmMinTlsVersion"), **exposure,
                                                        "identity": f"{rid}#scm"}})
        if unread and first is not None:
            self.gap("appservice", f"/subscriptions/{self.sub}/providers/Microsoft.Web/sites#config",
                     f"app service configuration in subscription {self.sub}", status_of(first),
                     f"TLS settings of {len(unread)} app(s) not read: {first}; grant Microsoft.Web/sites/config/read", unread)
        self.bound_thumbprints = bound
        if self.capped("appservice", cut):
            return "truncated"
        return "partial" if unread else "ok"

    def appservice_certificates(self) -> str:
        import base64

        from backend.utilities.cbom_sources.idp_collect import cert_facts

        certs, cut = self.list("appservice_certificates")
        unparsed = 0
        for cert in certs:
            rid, props = str(cert.get("id") or ""), _props(cert)
            if not rid:
                continue
            alg = bits = None
            facts: dict[str, Any] = {}
            blob = props.get("cerBlob")
            if isinstance(blob, str) and blob:
                try:
                    alg, bits, facts = cert_facts(base64.b64decode(blob), "azure")
                except Exception:
                    unparsed += 1
                    self.gap("appservice_certificates", f"{rid}#parse", f"app service certificate {cert.get('name')}", "error",
                             "the certificate could not be parsed", [rid])
                    continue
            thumb = str(props.get("thumbprint") or "").upper()
            facts.update({"provider": "azure", "service": "app_service", "thumbprint": props.get("thumbprint"),
                          "subject": facts.get("subject") or props.get("subjectName"),
                          "issuer": facts.get("issuer") or props.get("issuer"),
                          "not_after": facts.get("not_after") or props.get("expirationDate"),
                          "not_before": facts.get("not_before") or props.get("issueDate"),
                          "host_names": [str(h) for h in props.get("hostNames") or []][:50],
                          "key_vault_id": props.get("keyVaultId"), "key_vault_secret_status": props.get("keyVaultSecretStatus"),
                          "in_use": (thumb in self.bound_thumbprints) if self.bound_thumbprints is not None and thumb else None,
                          "identity": rid})
            self.emit({"type": "certificate", "target": self.label, "location": rid,
                       "name": props.get("subjectName") or cert.get("name") or _name(rid), "algorithm": alg, "key_size": bits,
                       "facts": facts})
        if self.capped("appservice_certificates", cut):
            return "truncated"
        return "partial" if unparsed else "ok"

    # -- Application Gateway listeners
    @staticmethod
    def _policy(policy: dict[str, Any] | None) -> tuple[str | None, list[str], list[str]]:
        """(policy name, protocols, cipher suites) of an Application Gateway sslPolicy."""
        if not policy:
            return None, [], []
        kind = str(policy.get("policyType") or ("Predefined" if policy.get("policyName") else ""))
        if kind == "Predefined" or (not kind and policy.get("policyName")):
            name = str(policy.get("policyName") or "")
            protocols, ciphers = APPGW_PREDEFINED.get(name, ([], []))
            return name, list(protocols), list(ciphers)
        top = "TLSv1.3" if kind == "CustomV2" else "TLSv1.2"
        start = tls_name(policy.get("minProtocolVersion"))
        if start:
            protocols = _ORDER[_ORDER.index(start):_ORDER.index(top) + 1]
        else:  # the older form: every protocol except the disabled ones
            off = {tls_name(p) for p in policy.get("disabledSslProtocols") or []}
            protocols = [p for p in _ORDER[:_ORDER.index(top) + 1] if p not in off]
        return kind or "Custom", protocols, [str(c) for c in policy.get("cipherSuites") or []]

    def appgateway(self) -> str:
        gateways, cut = self.list("appgateway")
        for gw in gateways:
            gid, props = str(gw.get("id") or ""), _props(gw)
            if not gid or not props:
                continue
            gname = gw.get("name") or _name(gid)
            by_id = {str(x.get("id")): x for key in ("frontendIPConfigurations", "frontendPorts", "sslProfiles", "sslCertificates")
                     for x in props.get(key) or [] if isinstance(x, dict) and x.get("id")}
            own = props.get("sslPolicy") if isinstance(props.get("sslPolicy"), dict) and props.get("sslPolicy") else None
            default_name = props.get("defaultPredefinedSslPolicy")
            for listener in props.get("httpListeners") or []:
                if not isinstance(listener, dict) or not listener.get("id"):
                    continue
                lp = _props(listener)
                fip = _props(by_id.get(str((lp.get("frontendIPConfiguration") or {}).get("id")), {}))
                port = _props(by_id.get(str((lp.get("frontendPort") or {}).get("id")), {})).get("port")
                public = bool(fip.get("publicIPAddress"))
                exposure = {"internet_facing": True if public else (False if fip else None),
                            "exposure_basis": ("listener on the gateway's public frontend IP" if public else
                                               "listener on a private frontend IP" if fip else "frontend IP not found")}
                where, name = str(listener["id"]), f"{gname}:{listener.get('name') or _name(listener['id'])}"
                proto = str(lp.get("protocol") or "").upper()
                if proto != "HTTPS":
                    if proto == "HTTP":
                        self.emit({"type": "load_balancer_tls", "target": self.label, "location": where, "name": name,
                                   "protocol": "HTTP", "facts": {"provider": "azure", "tls": False, "port": port, **exposure}})
                    continue
                profile = by_id.get(str((lp.get("sslProfile") or {}).get("id"))) if lp.get("sslProfile") else None
                policy = _props(profile).get("sslPolicy") if profile else None
                is_default = False
                if not policy:
                    policy = own
                if not policy and default_name:
                    policy, is_default = {"policyType": "Predefined", "policyName": default_name}, True
                pname, protocols, ciphers = self._policy(policy)
                cert = by_id.get(str((lp.get("sslCertificate") or {}).get("id")), {})
                self.emit({"type": "load_balancer_tls", "target": self.label, "location": where, "name": name, "protocol": "HTTPS",
                           "facts": {"provider": "azure", "ssl_policy": pname, "policy_type": (policy or {}).get("policyType"),
                                     "default_policy": is_default, "ssl_profile": profile.get("name") if profile else None,
                                     "port": port, "protocols": protocols, "ciphers": ciphers[:100],
                                     "static_rsa_kex": any(c.startswith("TLS_RSA_") for c in ciphers),
                                     "certificates": [cert.get("name")] if cert.get("name") else [],
                                     "certificate_key_vault_secret": _props(cert).get("keyVaultSecretId"),
                                     **exposure, "identity": where}})
        return "truncated" if self.capped("appgateway", cut) else "ok"

    # -- Front Door Standard / Premium custom domains
    def frontdoor(self) -> str:
        profiles, cut = self.list("frontdoor")
        unread = 0
        for profile in profiles:
            pid = str(profile.get("id") or "")
            sku = str((profile.get("sku") or {}).get("name") or "") if isinstance(profile.get("sku"), dict) else ""
            if not pid or not sku.endswith("_AzureFrontDoor"):  # classic CDN profiles have no AFD custom domains
                continue
            try:
                domains, _d = self.http.azure_pages(f"{ARM}{pid}/customDomains?api-version={SERVICES['frontdoor'][1]}",
                                                    self.token(), cap=ITEM_CAP)
            except CloudHttpError as exc:
                unread += 1
                self.gap("frontdoor", f"{pid}#customDomains", f"front door custom domains of {profile.get('name')}",
                         status_of(exc), str(exc), [f"{pid}/"])
                continue
            for domain in domains:
                did, props = str(domain.get("id") or ""), _props(domain)
                if not did:
                    continue
                tls = props.get("tlsSettings") if isinstance(props.get("tlsSettings"), dict) else {}
                custom = tls.get("customizedCipherSuiteSet") if isinstance(tls.get("customizedCipherSuiteSet"), dict) else {}
                ciphers = [str(c) for c in (custom.get("cipherSuiteSetForTls12") or []) + (custom.get("cipherSuiteSetForTls13") or [])]
                self.emit({"type": "cdn_tls", "target": self.label, "location": did, "name": props.get("hostName") or _name(did),
                           "protocol": "TLS",
                           "facts": {"provider": "azure", "service": "front_door", "profile": profile.get("name"),
                                     "min_version": tls_name(tls.get("minimumTlsVersion")),
                                     "minimum_tls_setting": tls.get("minimumTlsVersion"),
                                     "certificate_type": tls.get("certificateType"), "cipher_suite_set": tls.get("cipherSuiteSetType"),
                                     "ciphers": ciphers[:50], "secret": ((tls.get("secret") or {}).get("id") or None)
                                     if isinstance(tls.get("secret"), dict) else None,
                                     "validation_state": props.get("domainValidationState"),
                                     "internet_facing": True, "exposure_basis": "Front Door custom domain (served from the public edge)",
                                     "identity": did}})
        if self.capped("frontdoor", cut):
            return "truncated"
        return "partial" if unread else "ok"

    # -- Azure SQL logical servers
    def sql(self) -> str:
        servers, cut = self.list("sql")
        for server in servers:
            rid, props = str(server.get("id") or ""), _props(server)
            if not rid:
                continue
            setting = props.get("minimalTlsVersion")
            public = str(props.get("publicNetworkAccess") or "Enabled")
            self.emit({"type": "database_tls", "target": self.label, "location": rid,
                       "name": props.get("fullyQualifiedDomainName") or server.get("name") or _name(rid), "protocol": "TLS",
                       "facts": {"provider": "azure", "service": "sql", "engine": "mssql",
                                 # "None": no minimum is enforced, so a client may still use TLS 1.0
                                 "min_version": tls_name(setting) or ("TLSv1.0" if str(setting) == "None" else None),
                                 "minimum_tls_setting": setting, "public_network_access": public,
                                 "cmek_key_id": props.get("keyId"),
                                 "internet_facing": public.lower() == "enabled",
                                 "exposure_basis": f"server public network access {public} (server firewall rules apply)",
                                 "identity": rid}})
        return "truncated" if self.capped("sql", cut) else "ok"


def collect_subscription(http: CloudHttp, token: Callable[[], str], sub: str, label: str, emit: Emit) -> dict[str, str]:
    """Read every control-plane service of one subscription.  Returns {service: status}."""
    reader = _Subscription(http, token, sub, label, emit)
    out: dict[str, str] = {}
    for service in SERVICES:
        try:
            out[service] = getattr(reader, service)()
        except CloudHttpError as exc:
            status = status_of(exc)
            out[service] = status
            path, _v, action, words = SERVICES[service]
            detail = f"grant {action}: {exc}" if status == "denied" else str(exc)
            extra: dict[str, Any] = {}
            scope = None
            if status == "not_enabled":  # the provider is not registered: the subscription has none of these
                extra["by_choice"] = True
                scope = [f"/subscriptions/{sub}/providers/{path.split('/')[0]}/"]
            reader.gap(service, f"/subscriptions/{sub}/providers/{path}", f"{words} in subscription {sub}", status, detail,
                       scope, **extra)
    return out
