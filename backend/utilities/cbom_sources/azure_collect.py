"""Azure Key Vault inventory and control-plane TLS / encryption settings over the public REST APIs (cloud worker; no SDK).

* Token: Entra ID client credentials (client secret, or a certificate-signed client assertion), one token for ARM
  (https://management.azure.com/.default) and one for the Key Vault data plane (https://vault.azure.net/.default).
* ARM (Vaults - List By Subscription, api-version 2023-07-01): vault settings -- SKU, soft delete, purge protection,
  RBAC, public network access, firewall default action, private endpoints.
* Data plane (api-version 7.4): keys (Get Key: kty, key_ops, size/curve; Get Key Rotation Policy), certificates (Get
  Certificate: the public certificate and its policy) and secrets (Get Secrets: id, attributes, contentType).  Values
  are never requested: no GET of a secret, no key operation.  Keys and secrets that only back a certificate
  (``managed: true``) are left to the certificate row.
* Control plane (``azure_arm``): storage accounts, App Service apps and certificates, Application Gateway listeners,
  Front Door custom domains and Azure SQL servers -- TLS policy, encryption key source and public certificates.
* Every failure becomes a coverage row (denied, blocked by the vault firewall, error) -- never a silent "nothing found".
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import time
import uuid
from typing import Any, Callable
from urllib.parse import urlsplit

from backend.utilities.cbom_sources import azure_arm
from backend.utilities.cbom_sources.cloud_http import CloudHttp, CloudHttpError
from backend.utilities.cbom_sources.common import log

ARM = "https://management.azure.com"
LOGIN = "https://login.microsoftonline.com"
ARM_VAULTS_API = "2023-07-01"
SUBSCRIPTIONS_API = "2022-12-01"
KV_API = "7.4"
VAULT_CAP = 500  # vaults per subscription
ITEM_CAP = 300  # keys / certificates / secrets per vault
SUBSCRIPTION_CAP = 200

Emit = Callable[[dict[str, Any]], None]


class AzureCollectError(Exception):
    """``str(err)`` is safe to show."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _client_assertion(tenant: str, client_id: str, pem: str) -> str:
    """RS256 client assertion signed with the app's certificate key (x5t = SHA-1 thumbprint of the certificate).
    https://learn.microsoft.com/entra/identity-platform/certificate-credentials"""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    data = pem.encode()
    cert = x509.load_pem_x509_certificates(data)[0]
    key = serialization.load_pem_private_key(data, password=None)
    der = cert.public_bytes(serialization.Encoding.DER)
    header = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(hashlib.sha1(der).digest())}  # noqa: S324 - the format asks for SHA-1
    now = int(time.time())
    claims = {"aud": f"{LOGIN}/{tenant}/oauth2/v2.0/token", "iss": client_id, "sub": client_id,
              "jti": str(uuid.uuid4()), "nbf": now - 60, "iat": now, "exp": now + 600}
    import json

    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}.{_b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr,call-arg]
    return f"{signing_input}.{_b64url(signature)}"


def token(http: CloudHttp, cfg: dict[str, Any], secrets: dict[str, str], scope: str) -> str:
    """Client-credentials token for one resource.  Raises AzureCollectError with a safe message."""
    tenant, client_id = cfg["tenant_id"], cfg["client_id"]
    form = {"client_id": client_id, "scope": scope, "grant_type": "client_credentials"}
    if cfg.get("credential_type") == "certificate":
        pem = secrets.get("client_certificate") or ""
        if not pem:
            raise AzureCollectError("No client certificate is stored for this source")
        form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        form["client_assertion"] = _client_assertion(tenant, client_id, pem)
    else:
        secret = secrets.get("client_secret") or ""
        if not secret:
            raise AzureCollectError("No client secret is stored for this source")
        form["client_secret"] = secret
    try:
        out = http.request("POST", f"{LOGIN}/{tenant}/oauth2/v2.0/token", data=form)
    except CloudHttpError as exc:
        raise AzureCollectError(f"Azure sign-in failed: {exc}") from None
    value = out.get("access_token")
    if not isinstance(value, str) or not value:
        raise AzureCollectError("Azure sign-in returned no access token")
    return value


def _status(exc: CloudHttpError) -> str:
    if exc.code in ("ForbiddenByFirewall", "ForbiddenByConnection"):
        return "blocked_by_firewall"
    if exc.status in (401, 403):
        return "denied"
    if exc.status == 404 or exc.code in ("SubscriptionNotFound", "InvalidSubscriptionId"):
        return "not_found"
    return "error"


def _iso(epoch: Any) -> str | None:
    if isinstance(epoch, (int, float)) and epoch > 0:
        return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _b64url_bits(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        number = int.from_bytes(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)), "big")
    except Exception:
        return None
    return number.bit_length() or None


_CRV_BITS = {"P-256": 256, "P-384": 384, "P-521": 521, "P-256K": 256}


def _vault_asset(vault: dict[str, Any], label: str) -> dict[str, Any]:
    props = vault.get("properties") or {}
    acls = props.get("networkAcls") or {}
    public = str(props.get("publicNetworkAccess") or "Enabled")
    default_action = str(acls.get("defaultAction") or "Allow")
    rules = len(acls.get("ipRules") or []) + len(acls.get("virtualNetworkRules") or [])
    endpoints = len(props.get("privateEndpointConnections") or [])
    if public.lower() == "disabled":
        internet, basis = False, "Key Vault public network access Disabled"
    elif default_action.lower() == "deny":
        internet, basis = (None, f"Key Vault firewall default action Deny with {rules} allowed network rule(s)")
    else:
        internet, basis = True, "Key Vault public network access Enabled, firewall default action Allow"
    sku = (props.get("sku") or {}).get("name")
    return {"type": "key_vault", "target": label, "location": vault.get("id") or props.get("vaultUri"),
            "name": vault.get("name"),
            "facts": {"provider": "azure", "vault_uri": props.get("vaultUri"), "sku": sku, "location": vault.get("location"),
                      "soft_delete_enabled": props.get("enableSoftDelete") if props.get("enableSoftDelete") is not None else True,
                      "soft_delete_retention_days": props.get("softDeleteRetentionInDays"),
                      "purge_protection": bool(props.get("enablePurgeProtection")),
                      "rbac_authorization": bool(props.get("enableRbacAuthorization")),
                      "public_network_access": public, "network_default_action": default_action,
                      "network_rules": rules, "private_endpoints": endpoints,
                      "internet_facing": internet, "exposure_basis": basis, "identity": vault.get("id")}}


def _key_asset(bundle: dict[str, Any], rotation: dict[str, Any] | None, rotation_error: str | None, vault: str,
               label: str) -> dict[str, Any]:
    jwk = bundle.get("key") or {}
    attrs = bundle.get("attributes") or {}
    kty = str(jwk.get("kty") or "")
    kid = str(jwk.get("kid") or "")
    base_kid = kid.rsplit("/", 1)[0] if kid.count("/") >= 5 else kid  # .../keys/<name>/<version> -> .../keys/<name>
    if kty.startswith("RSA"):
        algorithm, bits = "RSA", _b64url_bits(jwk.get("n"))
    elif kty.startswith("EC"):
        algorithm, bits = "ECDSA", _CRV_BITS.get(str(jwk.get("crv")))
    elif kty.startswith("oct"):
        algorithm, bits = "AES", None
    else:
        algorithm, bits = kty or None, None
    actions = [(a.get("action") or {}).get("type") for a in (rotation or {}).get("lifetimeActions") or []]
    triggers = [a.get("trigger") or {} for a in (rotation or {}).get("lifetimeActions") or []
                if str((a.get("action") or {}).get("type") or "").lower() == "rotate"]
    spec = f"{kty} {jwk.get('crv') or bits or ''}".strip()
    return {"type": "kms_key", "target": label, "location": base_kid, "name": base_kid.rsplit("/", 1)[-1],
            "algorithm": algorithm, "key_size": bits,
            "facts": {"provider": "azure", "vault": vault, "key_spec": spec, "kty": kty,
                      "key_ops": [str(o) for o in jwk.get("key_ops") or []][:12],
                      "hsm_backed": kty.endswith("-HSM"), "key_manager": "CUSTOMER",
                      "key_state": "Enabled" if attrs.get("enabled", True) else "Disabled",
                      "not_before": _iso(attrs.get("nbf")), "not_after": _iso(attrs.get("exp")),
                      "created": _iso(attrs.get("created")), "exportable": attrs.get("exportable"),
                      "recovery_level": attrs.get("recoveryLevel"),
                      "rotation_enabled": (any(str(a or "").lower() == "rotate" for a in actions)
                                           if rotation is not None else None),
                      "rotation_interval": (triggers[0].get("timeAfterCreate") or triggers[0].get("timeBeforeExpiry"))
                      if triggers else None,
                      "rotation_policy_error": rotation_error, "identity": base_kid}}


def _certificate_asset(bundle: dict[str, Any], vault: str, label: str) -> dict[str, Any] | None:
    from backend.utilities.cbom_sources.idp_collect import cert_facts

    cer = bundle.get("cer")
    if not isinstance(cer, str) or not cer:
        return None
    alg, bits, facts = cert_facts(base64.b64decode(cer), "azure")
    policy = bundle.get("policy") or {}
    key_props = policy.get("key_props") or {}
    lifetime = [str((a.get("action") or {}).get("action_type") or "") for a in policy.get("lifetime_actions") or []]
    ident = str(bundle.get("id") or "")
    base_id = ident.rsplit("/", 1)[0] if ident.count("/") >= 5 else ident
    facts.update({"provider": "azure", "vault": vault, "issuer_name": (policy.get("issuer") or {}).get("name"),
                  "policy_key_type": key_props.get("kty"), "policy_key_size": key_props.get("key_size"),
                  "policy_curve": key_props.get("crv"), "key_exportable": key_props.get("exportable"),
                  "reuse_key": key_props.get("reuse_key"), "auto_renew": "AutoRenew" in lifetime,
                  "validity_months": (policy.get("x509_props") or {}).get("validity_months"),
                  "enabled": (bundle.get("attributes") or {}).get("enabled"), "identity": base_id})
    return {"type": "certificate", "target": label, "location": base_id, "name": facts.get("subject") or base_id.rsplit("/", 1)[-1],
            "algorithm": alg, "key_size": bits, "facts": facts}


def _secret_asset(item: dict[str, Any], vault: str, label: str) -> dict[str, Any]:
    attrs = item.get("attributes") or {}
    ident = str(item.get("id") or "")
    return {"type": "cloud_secret", "target": label, "location": ident, "name": ident.rsplit("/", 1)[-1],
            "facts": {"provider": "azure", "vault": vault, "content_type": item.get("contentType"),
                      "enabled": attrs.get("enabled"), "expires": _iso(attrs.get("exp")), "created": _iso(attrs.get("created")),
                      "updated": _iso(attrs.get("updated")), "rotation_enabled": None, "identity": ident}}


def _vault_data_plane(http: CloudHttp, data_token: str, vault: dict[str, Any], label: str, emit: Emit) -> dict[str, str]:
    """Keys, certificates and secrets of one vault.  Returns {part: status}."""
    props = vault.get("properties") or {}
    uri = str(props.get("vaultUri") or "").rstrip("/")
    name = str(vault.get("name") or urlsplit(uri).hostname or "")
    out: dict[str, str] = {}

    def gap(part: str, exc: CloudHttpError) -> None:
        status = _status(exc)
        out[part] = status
        detail = (f"{exc}: the vault firewall blocks ZeroShield; its settings are listed, its {part} are not"
                  if status == "blocked_by_firewall" else
                  f"{exc}: give the app Key Vault Reader (RBAC vaults) or list/get access policies" if status == "denied"
                  else str(exc))
        emit({"type": "coverage", "target": label, "location": f"{vault.get('id') or uri}#{part}",
              "facts": {"check": f"key vault {name} {part}", "status": status, "detail": detail[:200],
                        "scope": [f"{uri}/{part}/"]}})

    host = urlsplit(uri).hostname

    def own(url: Any) -> str | None:
        """An item URL from this vault's own answer, on this vault's host (the token never goes anywhere else)."""
        text = str(url or "")
        return text if text and urlsplit(text).hostname == host else None

    try:
        items, truncated = http.azure_pages(f"{uri}/keys?api-version={KV_API}&maxresults=25", data_token, cap=ITEM_CAP)
        for item in items:
            kid = own(item.get("kid"))
            if item.get("managed") or not kid:  # the key behind a certificate is reported with the certificate
                continue
            bundle = http.get(f"{kid}?api-version={KV_API}", data_token)
            rotation, rotation_error = None, None
            try:
                rotation = http.get(f"{kid}/rotationpolicy?api-version={KV_API}", data_token)
            except CloudHttpError as exc:
                rotation_error = str(exc)[:120]
            emit(_key_asset(bundle, rotation, rotation_error, name, label))
        out["keys"] = "truncated" if truncated else "ok"
    except CloudHttpError as exc:
        gap("keys", exc)
        if out["keys"] == "blocked_by_firewall":  # the same firewall answers every part
            for part in ("certificates", "secrets"):
                gap(part, exc)
            return out
    try:
        items, truncated = http.azure_pages(f"{uri}/certificates?api-version={KV_API}&maxresults=25", data_token, cap=ITEM_CAP)
        unparsed = 0
        for item in items:
            cid = own(item.get("id"))
            if not cid:
                continue
            bundle = http.get(f"{cid}?api-version={KV_API}", data_token)
            try:
                asset = _certificate_asset(bundle, name, label)
            except ValueError:  # one certificate that does not parse is a gap of its own, not the end of the list
                unparsed += 1
                asset = {"type": "coverage", "target": label, "location": f"{cid}#parse",
                         "facts": {"check": f"key vault {name} certificate {cid.rsplit('/', 1)[-1]}", "status": "error",
                                   "detail": "the certificate could not be parsed", "scope": [cid]}}
            if asset:
                emit(asset)
        out["certificates"] = "truncated" if truncated else ("partial" if unparsed else "ok")
    except CloudHttpError as exc:
        gap("certificates", exc)
    try:
        items, truncated = http.azure_pages(f"{uri}/secrets?api-version={KV_API}&maxresults=25", data_token, cap=ITEM_CAP)
        for item in items:  # list only: names and attributes; a secret's value is never requested
            if not item.get("managed") and own(item.get("id")):
                emit(_secret_asset(item, name, label))
        out["secrets"] = "truncated" if truncated else "ok"
    except CloudHttpError as exc:
        gap("secrets", exc)
    for part, status in out.items():
        if status == "truncated":
            emit({"type": "coverage", "target": label, "location": f"{vault.get('id') or uri}#{part}-cap",
                  "facts": {"check": f"key vault {name} {part}", "status": "truncated",
                            "detail": f"More than {ITEM_CAP} {part}; the first {ITEM_CAP} were read",
                            "scope": [f"{uri}/{part}/"]}})
    return out


TOKEN_REUSE_S = 45 * 60  # Entra ID access tokens live 60-90 minutes: sign in again well before


class _Tokens:
    """One token per scope, signed in again after TOKEN_REUSE_S so a long run never uses an expired one."""

    def __init__(self, http: CloudHttp, cfg: dict[str, Any], secrets: dict[str, str]):
        self.http, self.cfg, self.secrets = http, cfg, secrets
        self._cache: dict[str, tuple[str, float]] = {}

    def get(self, scope: str) -> str:
        value, at = self._cache.get(scope, ("", 0.0))
        if not value or time.monotonic() - at > TOKEN_REUSE_S:
            value = token(self.http, self.cfg, self.secrets, scope)
            self._cache[scope] = (value, time.monotonic())
        return value


ARM_SCOPE, VAULT_SCOPE = f"{ARM}/.default", "https://vault.azure.net/.default"


def _subscriptions(http: CloudHttp, arm_token: str, cfg: dict[str, Any]) -> list[str]:
    if cfg.get("subscription_ids"):
        return list(cfg["subscription_ids"])[:SUBSCRIPTION_CAP]
    items, _t = http.azure_pages(f"{ARM}/subscriptions?api-version={SUBSCRIPTIONS_API}", arm_token, cap=SUBSCRIPTION_CAP)
    return [str(s.get("subscriptionId")) for s in items if s.get("subscriptionId") and s.get("state") in (None, "Enabled")]


def collect_azure(team_id: int, cfg: dict[str, Any], secrets: dict[str, str], emit: Emit,
                  should_stop: Callable[[], str | None], *, transport: Any = None) -> dict[str, Any]:
    """Collect one Azure source.  Raises AzureCollectError when nothing can be read (sign-in failed)."""
    started = time.monotonic()
    targets: list[dict[str, Any]] = []
    with CloudHttp(transport) as http:
        tokens = _Tokens(http, cfg, secrets)
        data_token_error: str | None = None
        try:
            subscriptions = _subscriptions(http, tokens.get(ARM_SCOPE), cfg)
        except CloudHttpError as exc:
            raise AzureCollectError(f"Could not list subscriptions: {exc}") from None
        if not subscriptions:
            raise AzureCollectError("No subscriptions are visible to this app; list them on the source or grant the app a role")
        for sub in subscriptions:
            label = f"azure:{sub}"
            reason = should_stop()
            if reason:
                targets.append({"target": label, "status": "skipped_cancelled", "error": reason[:256], "assets": 0})
                continue
            t0 = time.monotonic()
            parts: dict[str, str] = {}
            vaults: list[dict[str, Any]] = []
            truncated, vault_status = False, "ok"
            try:
                vaults, truncated = http.azure_pages(
                    f"{ARM}/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults?api-version={ARM_VAULTS_API}",
                    tokens.get(ARM_SCOPE), cap=VAULT_CAP)
            except AzureCollectError as exc:  # signing in again failed mid-run
                targets.append({"target": label, "status": "auth_failed", "error": str(exc)[:256], "assets": 0})
                continue
            except CloudHttpError as exc:
                vault_status = _status(exc)
                emit({"type": "coverage", "target": label, "location": f"/subscriptions/{sub}/providers/Microsoft.KeyVault",
                      "facts": {"check": f"key vaults in subscription {sub}", "status": vault_status, "detail": str(exc)[:200]}})
            if truncated:  # no scope: the vaults past the cap (and their keys) are unknown, so it covers the target
                emit({"type": "coverage", "target": label, "location": f"/subscriptions/{sub}/providers/Microsoft.KeyVault#cap",
                      "facts": {"check": f"key vaults in subscription {sub}", "status": "truncated",
                                "detail": f"More than {VAULT_CAP} vaults; the first {VAULT_CAP} were read"}})
            for vault in vaults:
                emit(_vault_asset(vault, label))
                if should_stop():
                    break
                data_token = None
                if data_token_error is None:
                    try:
                        data_token = tokens.get(VAULT_SCOPE)
                    except AzureCollectError as exc:  # remembered: one failed sign-in is not retried per vault
                        data_token_error = str(exc)
                if data_token is None:
                    emit({"type": "coverage", "target": label, "location": f"{vault.get('id')}#data-plane",
                          "facts": {"check": f"key vault {vault.get('name')} keys, certificates and secrets",
                                    "status": "error", "detail": (data_token_error or "no token")[:200]}})
                    parts[str(vault.get("name"))] = "error"
                    continue
                result = _vault_data_plane(http, data_token, vault, label, emit)
                parts[str(vault.get("name"))] = (
                    "error" if any(s not in ("ok", "truncated", "partial") for s in result.values())
                    else ("partial" if any(s != "ok" for s in result.values()) else "ok"))
            # the control plane: storage, App Service, Application Gateway, Front Door, SQL (TLS policy, encryption)
            try:
                services = azure_arm.collect_subscription(http, lambda: tokens.get(ARM_SCOPE), sub, label, emit)
            except AzureCollectError as exc:
                targets.append({"target": label, "status": "auth_failed", "error": str(exc)[:256], "assets": 0})
                continue
            bad = sorted(n for n, s in parts.items() if s == "error")
            # a cut list (vaults, or a vault's keys / certificates / secrets) or an unparsable certificate: read, not
            # complete -- the target is partial, never "ok"; each gap row carries the scope drift must not call gone.
            # A vault whose keys, certificates or secrets were refused (access policy, firewall) is a gap of that vault:
            # its settings and every other vault were read, so the subscription is read with gaps, not failed (C4).
            gappy = sorted(n for n, s in parts.items() if s == "partial") + (["(vault list)"] if truncated else [])
            # a control-plane service the reader role from before this release cannot read is a gap (its coverage row
            # names the action to add), never a failed subscription: Key Vault was read as before
            failed = [f"{svc}: {st}" for svc, st in services.items()
                      if st not in ("ok", "truncated", "partial", "not_enabled", "denied")]
            gappy += [f"{svc}: {st}" for svc, st in services.items() if st in ("truncated", "partial", "denied")]
            if vault_status != "ok":
                failed.insert(0, f"keyvault: {vault_status}")
            keyvault = (vault_status if vault_status != "ok" else
                        "partial" if bad or truncated or "partial" in parts.values() else "ok")
            denied_everywhere = vault_status == "denied" and all(st == "denied" for st in services.values())
            status = ("auth_failed" if denied_everywhere else "error") if (failed or denied_everywhere) else (
                "partial" if gappy or bad else "ok")
            error = "; ".join(failed + ([f"{len(bad)} vault(s) not fully read: " + ", ".join(bad)] if bad else [])
                              + ([f"read with gaps: {', '.join(gappy)}"] if gappy else [])) or None
            targets.append({"target": label, "status": status, "error": error[:256] if error else None,
                            "duration_ms": int((time.monotonic() - t0) * 1000), "vaults": len(vaults),
                            "services": {"keyvault": keyvault, **services}})
    ok = sum(1 for t in targets if t["status"] == "ok")
    partial = sum(1 for t in targets if t["status"] == "partial")
    skipped = sum(1 for t in targets if t["status"].startswith("skipped"))
    log("azure collected", team=team_id, subscriptions=len(targets), ok=ok, partial=partial,
        duration_s=int(time.monotonic() - started))
    return {"targets": targets, "counts": {"total": len(targets), "ok": ok, "partial": partial,
                                           "failed": len(targets) - ok - partial - skipped, "skipped": skipped},
            "duration_s": int(time.monotonic() - started)}


def test_azure(cfg: dict[str, Any], secrets: dict[str, str], *, transport: Any = None) -> dict[str, Any]:
    """Validation: sign in (ARM and Key Vault scopes) and make one list call.  Never raises."""
    checks: list[dict[str, str]] = []
    with CloudHttp(transport) as http:
        try:
            arm_token = token(http, cfg, secrets, f"{ARM}/.default")
            checks.append({"check": "Signed in to Azure Resource Manager", "status": "pass", "detail": "Client credentials accepted"})
        except AzureCollectError as exc:
            return {"status": "failed", "message": str(exc), "checks": [
                {"check": "Signed in to Azure Resource Manager", "status": "fail", "detail": str(exc)[:240]}]}
        try:
            token(http, cfg, secrets, "https://vault.azure.net/.default")
            checks.append({"check": "Signed in to the Key Vault data plane", "status": "pass", "detail": "Token issued"})
        except AzureCollectError as exc:
            checks.append({"check": "Signed in to the Key Vault data plane", "status": "fail", "detail": str(exc)[:240]})
        try:
            subs = _subscriptions(http, arm_token, cfg)
        except CloudHttpError as exc:
            checks.append({"check": "List key vaults", "status": "fail", "detail": str(exc)[:240]})
            subs = []
        else:
            if not subs:
                checks.append({"check": "List key vaults", "status": "fail", "detail": "No subscription is visible to this app"})
        # every configured subscription is read once (the collector lists its vaults the same way): one the app cannot
        # read fails the validation, instead of passing on the first subscription alone (C1)
        readable = []
        for sub in subs[:VALIDATE_SUBSCRIPTION_CAP]:
            check = "List key vaults" if len(subs) == 1 else f"List key vaults in {sub}"
            try:
                vaults, _t = http.azure_pages(
                    f"{ARM}/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults?api-version={ARM_VAULTS_API}", arm_token, cap=VAULT_CAP)
                checks.append({"check": check, "status": "pass", "detail": f"{len(vaults)} vault(s) in subscription {sub}"})
                readable.append(sub)
            except CloudHttpError as exc:
                status = _status(exc)
                checks.append({"check": check, "status": "fail", "detail": (
                    f"The app cannot read subscription {sub} ({exc}): give it the Reader role there (run the ZeroShield "
                    "reader script), or remove the subscription from the source" if status in ("denied", "not_found")
                    else str(exc))[:240]})
        if len(subs) > VALIDATE_SUBSCRIPTION_CAP:
            checks.append({"check": "Subscriptions checked", "status": "warning", "detail": (
                f"The first {VALIDATE_SUBSCRIPTION_CAP} of {len(subs)} subscriptions were checked; one the app cannot "
                "read is reported as a failed target on the run")[:240]})
        if readable:
            checks += _probe_control_plane(http, arm_token, readable[0])
    return _verdict(checks)


VALIDATE_SUBSCRIPTION_CAP = 25  # subscriptions read one by one at Save and validate


def _probe_control_plane(http: CloudHttp, arm_token: str, sub: str) -> list[dict[str, str]]:
    """One list call per control-plane service.  A missing grant is a warning, never a failed validation: the run reads
    everything else and reports the service as a coverage gap that names the action to add."""
    out: list[dict[str, str]] = []
    for path, version, action, words in azure_arm.SERVICES.values():
        check = f"Read {words}"
        try:
            http.get(f"{ARM}/subscriptions/{sub}/providers/{path}?api-version={version}", arm_token)
            out.append({"check": check, "status": "pass", "detail": f"Readable in subscription {sub}"})
        except CloudHttpError as exc:
            status = azure_arm.status_of(exc)
            if status == "not_enabled":
                out.append({"check": check, "status": "pass", "detail": "Resource provider not registered: nothing to read"})
            else:
                out.append({"check": check, "status": "warning",
                            "detail": (f"Not granted: {action}. Re-run the reader script to add it; until then runs "
                                       f"report {words} as a coverage gap" if status == "denied" else str(exc))[:240]})
    return out


def _verdict(checks: list[dict[str, str]]) -> dict[str, Any]:
    failed = [c for c in checks if c["status"] not in ("pass", "warning")]
    warned = [c for c in checks if c["status"] == "warning"]
    main = next((c for c in checks if c["check"].startswith("List ")), checks[-1])  # the vault / KMS list call
    message = (failed[0]["detail"] if failed else
               f"Passed with {len(warned)} warning(s): {warned[0]['detail']}" if warned else main["detail"])
    return {"status": "failed" if failed else "passed", "checks": checks, "message": message[:512]}
