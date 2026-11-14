"""Google Cloud KMS, CA Service and Secret Manager inventory over the public REST APIs (cloud worker; no Google SDK).

* Token: the service account's JSON key signs an RS256 JWT (iss = client_email, aud = the token endpoint, scope
  cloud-platform) exchanged at https://oauth2.googleapis.com/token
  (https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests).  The token endpoint is
  fixed: the ``token_uri`` inside an uploaded key is never used.
* Projects: the configured ids, or with an organization id ``projects:search`` (Resource Manager v3), which returns
  the projects the account holds resourcemanager.projects.get on (all three viewer roles include it).
* Cloud KMS v1: locations -> keyRings -> cryptoKeys (purpose, versionTemplate algorithm and protection level, primary
  version state, rotation period).  CA Service v1: locations -> caPools -> certificateAuthorities (the CA certificate).
  Secret Manager v1: secrets (metadata only; versions are never accessed).
* Cloud KMS key versions (cryptoKeyVersions.list: state, protection level, algorithm; never attestations or key
  material) on each key row.  Load-balancer TLS policies and SSL certificates (Compute Engine), Certificate Manager
  certificates and Cloud Storage bucket encryption: see ``gcp_tls``.
* Every failure becomes a coverage row: denied, API not enabled (SERVICE_DISABLED), or error.  An optional API the
  project has not enabled (Compute Engine, Certificate Manager, Cloud Storage) is a by-choice coverage row that does not
  fail the project: nothing of that service exists in it.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable

from backend.utilities.cbom_sources import algid, gcp_tls
from backend.utilities.cbom_sources.cloud_http import CloudHttp, CloudHttpError
from backend.utilities.cbom_sources.common import log

TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/cloud-platform"
KMS = "https://cloudkms.googleapis.com/v1"
CAS = "https://privateca.googleapis.com/v1"
SM = "https://secretmanager.googleapis.com/v1"
CRM = "https://cloudresourcemanager.googleapis.com/v3"
PROJECT_CAP = 200
TOKEN_REUSE_S = 45 * 60  # Google access tokens live one hour: sign in again well before
ITEM_CAP = 1000  # keys / CAs / secrets per project
LOCATION_CAP = 100
VERSION_CAP = 200  # key versions listed per key
VERSION_ROWS = 20  # of which kept on the key row (oldest first, as Cloud KMS lists them)

Emit = Callable[[dict[str, Any]], None]


class GcpCollectError(Exception):
    """``str(err)`` is safe to show."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def service_account(cfg: dict[str, Any], secrets: dict[str, str]) -> dict[str, Any]:
    try:
        key = json.loads(secrets.get("service_account_key") or "")
    except ValueError:
        raise GcpCollectError("The stored service account key is not valid JSON") from None
    if not isinstance(key, dict) or key.get("type") != "service_account" or not key.get("private_key"):
        raise GcpCollectError("The stored key is not a service account key")
    if str(key.get("client_email") or "").lower() != str(cfg.get("service_account_email") or "").lower():
        raise GcpCollectError("The key belongs to a different service account than the one configured on this source")
    return key


def token(http: CloudHttp, key: dict[str, Any]) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", **({"kid": key["private_key_id"]} if key.get("private_key_id") else {})}
    claims = {"iss": key["client_email"], "scope": SCOPE, "aud": TOKEN_URL, "iat": now, "exp": now + 600}
    signing_input = (f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}."
                     f"{_b64url(json.dumps(claims, separators=(',', ':')).encode())}")
    try:
        private = serialization.load_pem_private_key(str(key["private_key"]).encode(), password=None)
    except Exception:
        raise GcpCollectError("The service account key's private_key could not be read") from None
    signature = private.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr,call-arg]
    try:
        out = http.request("POST", TOKEN_URL, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                    "assertion": f"{signing_input}.{_b64url(signature)}"})
    except CloudHttpError as exc:
        raise GcpCollectError(f"Google sign-in failed: {exc}") from None
    value = out.get("access_token")
    if not isinstance(value, str) or not value:
        raise GcpCollectError("Google sign-in returned no access token")
    return value


def _status(exc: CloudHttpError) -> str:
    if exc.code in ("SERVICE_DISABLED", "accessNotConfigured"):
        return "not_enabled"
    if exc.status in (401, 403):
        return "denied"
    if exc.status == 404:
        return "not_found"
    return "error"


# Cloud KMS CryptoKeyVersionAlgorithm -> (algorithm family, bits), named by algid.gcp.  Symmetric Google keys are
# AES-256-GCM, the same primitive as AWS KMS SYMMETRIC_DEFAULT, so they share that normalised key_spec (and the rotation
# rule).  EXTERNAL_SYMMETRIC_ENCRYPTION (Cloud EKM) is the same AES-256 key held outside Google.
def _kms_algorithm(name: str) -> tuple[str | None, int | None]:
    text = str(name or "").strip().upper()
    if text == "EXTERNAL_SYMMETRIC_ENCRYPTION":
        return "AES", 256
    ident = algid.gcp(text)
    if ident is None:
        return name or None, None
    family = ident.family_label
    if family is None:  # symmetric: AES-*, HMAC-*
        if str(ident.name).startswith("AES"):
            return "AES", ident.key_size
        if str(ident.name).startswith("HMAC"):
            return "HMAC", None
        return ident.name, ident.key_size
    if family == "EC":
        return ("ECDH" if text.startswith("KEM_") else "ECDSA"), ident.key_size
    if family == "PQ":
        return ident.name, None
    return family, ident.key_size


def _ca_key_algorithm(name: str) -> tuple[str | None, int | None]:
    """CA Service KeySpec.algorithm (SignHashAlgorithm: RSA_PSS_2048_SHA256, EC_P384_SHA384, ...) when the CA has no
    certificate yet: the key family and size its name states."""
    text = str(name or "").upper()
    if text.startswith("RSA_"):
        size = next((int(p) for p in text.split("_") if p.isdigit() and int(p) >= 1024), None)
        return "RSA", size
    for curve, bits in (("P256", 256), ("P384", 384), ("P521", 521)):
        if curve in text:
            return "ECDSA", bits
    return name or None, None


_STATE = {"ENABLED": "Enabled", "DISABLED": "Disabled", "DESTROY_SCHEDULED": "PendingDeletion", "DESTROYED": "Destroyed",
          "PENDING_GENERATION": "Creating", "PENDING_IMPORT": "Creating"}


def _version_row(version: dict[str, Any]) -> dict[str, Any]:
    """The metadata of one CryptoKeyVersion (never its attestation or any key material)."""
    row = {"version": str(version.get("name") or "").rsplit("/", 1)[-1], "state": version.get("state"),
           "protection_level": version.get("protectionLevel"), "algorithm": version.get("algorithm"),
           "created": version.get("createTime")}
    if version.get("destroyTime"):
        row["destroy_time"] = version.get("destroyTime")
    return row


def _key_asset(key: dict[str, Any], label: str, versions: list[dict[str, Any]] | None = None,
               versions_error: str | None = None) -> dict[str, Any]:
    template = key.get("versionTemplate") or {}
    primary = key.get("primary") or {}
    provider_alg = str(primary.get("algorithm") or template.get("algorithm") or "")
    family, bits = _kms_algorithm(provider_alg)
    purpose = str(key.get("purpose") or "")
    symmetric = provider_alg.upper() in ("GOOGLE_SYMMETRIC_ENCRYPTION", "EXTERNAL_SYMMETRIC_ENCRYPTION")
    name = str(key.get("name") or "")
    listed = versions or []
    state = primary.get("state")
    if not state and listed:  # asymmetric keys have no primary: the key is usable while any version is enabled
        states = [str(v.get("state") or "") for v in listed]
        state = ("ENABLED" if "ENABLED" in states else
                 "DESTROY_SCHEDULED" if all(x in ("DESTROY_SCHEDULED", "DESTROYED") for x in states) and "DESTROY_SCHEDULED" in states
                 else states[-1] or None)
    protection = primary.get("protectionLevel") or template.get("protectionLevel")
    return {"type": "kms_key", "target": label, "location": name, "name": name.rsplit("/", 1)[-1],
            "algorithm": family, "key_size": bits,
            "facts": {"provider": "gcp", "key_spec": "SYMMETRIC_DEFAULT" if symmetric else provider_alg,
                      "provider_algorithm": provider_alg, "purpose": purpose, "key_usage": purpose,
                      "protection_level": protection, "hsm_backed": protection == "HSM",
                      "key_manager": "CUSTOMER", "key_state": _STATE.get(str(state or ""), state),
                      # automatic rotation exists for symmetric ENCRYPT_DECRYPT keys only; for the others it is not applicable
                      "rotation_enabled": bool(key.get("rotationPeriod") or key.get("nextRotationTime")) if purpose == "ENCRYPT_DECRYPT" else None,
                      "rotation_period": key.get("rotationPeriod"), "next_rotation": key.get("nextRotationTime"),
                      "import_only": key.get("importOnly"), "destroy_scheduled_duration": key.get("destroyScheduledDuration"),
                      "created": key.get("createTime"), "identity": name,
                      "version_count": None if versions_error else len(listed),
                      "enabled_versions": None if versions_error else sum(1 for v in listed if v.get("state") == "ENABLED"),
                      "version_algorithms": sorted({str(v.get("algorithm")) for v in listed if v.get("algorithm")}),
                      "versions": [_version_row(v) for v in listed[:VERSION_ROWS]],
                      "versions_error": versions_error}}


def _ca_asset(ca: dict[str, Any], label: str) -> dict[str, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from backend.utilities.cbom_sources.idp_collect import cert_facts

    name = str(ca.get("name") or "")
    spec = ca.get("keySpec") or {}
    pems = [p for p in ca.get("pemCaCertificates") or [] if isinstance(p, str)]
    alg = bits = None
    facts: dict[str, Any] = {}
    if pems:
        der = x509.load_pem_x509_certificate(pems[0].encode()).public_bytes(serialization.Encoding.DER)
        alg, bits, facts = cert_facts(der, "gcp")
    facts.update({"provider": "gcp", "ca_type": ca.get("type"), "tier": ca.get("tier"), "status": ca.get("state"),
                  "key_spec_algorithm": spec.get("algorithm"), "kms_key_version": spec.get("cloudKmsKeyVersion"),
                  "lifetime": ca.get("lifetime"), "is_ca": True, "identity": name,
                  "not_after": facts.get("not_after") or ca.get("expireTime")})
    if not alg and spec.get("algorithm"):
        alg, bits = _ca_key_algorithm(str(spec["algorithm"]))
    return {"type": "cloud_ca", "target": label, "location": name, "name": facts.get("subject") or name.rsplit("/", 1)[-1],
            "algorithm": alg, "key_size": bits, "facts": facts}


def _secret_asset(secret: dict[str, Any], label: str) -> dict[str, Any]:
    name = str(secret.get("name") or "")
    replication = secret.get("replication") or {}
    cmek = ((replication.get("automatic") or {}).get("customerManagedEncryption") or {}).get("kmsKeyName")
    if not cmek:
        replicas = (replication.get("userManaged") or {}).get("replicas") or []
        keys = [((r.get("customerManagedEncryption") or {}).get("kmsKeyName")) for r in replicas]
        cmek = next((k for k in keys if k), None)
    rotation = secret.get("rotation") or {}
    return {"type": "cloud_secret", "target": label, "location": name, "name": name.rsplit("/", 1)[-1],
            "facts": {"provider": "gcp", "rotation_enabled": bool(rotation.get("rotationPeriod") or rotation.get("nextRotationTime")),
                      "rotation_period": rotation.get("rotationPeriod"), "kms_key_id": cmek or "google-managed",
                      "replication": "automatic" if "automatic" in replication else ("user_managed" if replication else None),
                      "expires": secret.get("expireTime"), "created": secret.get("createTime"), "identity": name}}


def _projects(http: CloudHttp, access: str, cfg: dict[str, Any]) -> list[str]:
    if cfg.get("project_ids"):
        return list(cfg["project_ids"])[:PROJECT_CAP]
    found, _t = http.google_pages(f"{CRM}/projects:search", access, "projects", cap=PROJECT_CAP)
    return [str(p.get("projectId")) for p in found if p.get("projectId") and p.get("state") in (None, "ACTIVE")]


def _project(http: CloudHttp, access: str, project: str, label: str, emit: Emit) -> dict[str, str]:
    """{service: status}: ok, ``truncated`` / ``partial`` (read, with coverage gaps whose ``scope`` names the location
    prefixes left out -- drift never reports those assets gone), or the failure status."""
    services: dict[str, str] = {}

    def run(service: str, fn: Callable[[], str]) -> None:
        try:
            services[service] = fn()
        except (AttributeError, TypeError, ValueError, KeyError) as exc:  # a valid-JSON answer of an unexpected shape
            services[service] = "error"
            emit({"type": "coverage", "target": label, "location": f"projects/{project}#{service}-shape",
                  "facts": {"check": f"{service} in project {project}", "status": "error",
                            "detail": f"unexpected answer shape from {service} ({type(exc).__name__})"}})
        except CloudHttpError as exc:
            status = _status(exc)
            services[service] = status
            emit({"type": "coverage", "target": label, "location": f"projects/{project}#{service}",
                  "facts": {"check": f"{service} in project {project}", "status": status, "detail": str(exc)[:200]}})

    def truncated(service: str, what: str, scope: str) -> str:
        emit({"type": "coverage", "target": label, "location": f"projects/{project}#{service}-cap",
              "facts": {"check": f"{service} in project {project}", "status": "truncated",
                        "detail": f"More than {ITEM_CAP} {what}; the first {ITEM_CAP} were read", "scope": [scope]}})
        return "truncated"

    def kms() -> str:
        locations, _t = http.google_pages(f"{KMS}/projects/{project}/locations", access, "locations", cap=LOCATION_CAP)
        count = 0
        unread: list[str] = []  # keys whose versions could not be listed (the key itself is still reported)
        first_error: CloudHttpError | None = None

        def versions_gap() -> None:
            if unread and first_error is not None:
                emit({"type": "coverage", "target": label, "location": f"projects/{project}#cloudkms-versions",
                      "facts": {"check": f"cloudkms key versions in project {project}", "status": _status(first_error),
                                "detail": f"versions of {len(unread)} key(s) not listed: {first_error}"[:200],
                                "scope": unread[:ITEM_CAP]}})

        for loc in locations:
            if not loc.get("name"):
                continue
            rings, _r = http.google_pages(f"{KMS}/{loc['name']}/keyRings", access, "keyRings", cap=ITEM_CAP)
            for ring in (r for r in rings if r.get("name")):
                keys, _k = http.google_pages(f"{KMS}/{ring['name']}/cryptoKeys", access, "cryptoKeys", cap=ITEM_CAP)
                for key in keys:
                    versions, versions_error = None, None
                    if key.get("name"):
                        try:
                            versions, _v = http.google_pages(f"{KMS}/{key['name']}/cryptoKeyVersions", access,
                                                             "cryptoKeyVersions", cap=VERSION_CAP)
                        except CloudHttpError as exc:  # one key's versions: a gap of that key, not of the service
                            versions_error, first_error = str(exc)[:120], first_error or exc
                            unread.append(str(key["name"]))
                    emit(_key_asset(key, label, versions, versions_error))
                    count += 1
                    if count >= ITEM_CAP:  # key rings and CA pools share this prefix: both are covered (safe side)
                        versions_gap()
                        return truncated("cloudkms", "keys", f"projects/{project}/locations/")
        versions_gap()
        return "partial" if unread else "ok"

    def cas() -> str:
        locations, _t = http.google_pages(f"{CAS}/projects/{project}/locations", access, "locations", cap=LOCATION_CAP)
        count = unparsed = 0
        for loc in locations:
            if not loc.get("name"):
                continue
            pools, _p = http.google_pages(f"{CAS}/{loc['name']}/caPools", access, "caPools", cap=ITEM_CAP)
            for pool in (p for p in pools if p.get("name")):
                cas_, _c = http.google_pages(f"{CAS}/{pool['name']}/certificateAuthorities", access,
                                             "certificateAuthorities", cap=ITEM_CAP)
                for ca in cas_:
                    try:
                        emit(_ca_asset(ca, label))
                    except ValueError:
                        unparsed += 1
                        emit({"type": "coverage", "target": label, "location": f"{ca.get('name')}#parse",
                              "facts": {"check": f"CA {str(ca.get('name')).rsplit('/', 1)[-1]}", "status": "error",
                                        "detail": "the CA certificate could not be parsed",
                                        "scope": [str(ca.get("name") or "")]}})
                    count += 1
                    if count >= ITEM_CAP:
                        return truncated("privateca", "certificate authorities", f"projects/{project}/locations/")
        return "partial" if unparsed else "ok"

    def secret_manager() -> str:
        secrets, cut = http.google_pages(f"{SM}/projects/{project}/secrets", access, "secrets", cap=ITEM_CAP)
        for secret in secrets:  # metadata only; secretmanager.versions.access is never called
            emit(_secret_asset(secret, label))
        return truncated("secretmanager", "secrets", f"projects/{project}/secrets/") if cut else "ok"

    for service, fn in (("cloudkms", kms), ("privateca", cas), ("secretmanager", secret_manager)):
        run(service, fn)
    for service in gcp_tls.SERVICES:  # load-balancer TLS, Certificate Manager, Cloud Storage
        services[service] = gcp_tls.read(service, http, access, project, label, emit, _status)
    return services


def collect_gcp(team_id: int, cfg: dict[str, Any], secrets: dict[str, str], emit: Emit,
                should_stop: Callable[[], str | None], *, transport: Any = None) -> dict[str, Any]:
    """Collect one Google Cloud source.  Raises GcpCollectError when nothing can be read."""
    started = time.monotonic()
    key = service_account(cfg, secrets)
    targets: list[dict[str, Any]] = []
    with CloudHttp(transport) as http:
        access, issued = token(http, key), time.monotonic()
        try:
            projects = _projects(http, access, cfg)
        except CloudHttpError as exc:
            raise GcpCollectError(f"Could not list the organization's projects: {exc}") from None
        if not projects:
            raise GcpCollectError("No projects are visible to this service account; list them on the source or grant the roles")
        for project in projects:
            label = f"gcp:{project}"
            reason = should_stop()
            if reason:
                targets.append({"target": label, "status": "skipped_cancelled", "error": reason[:256], "assets": 0})
                continue
            t0 = time.monotonic()
            if t0 - issued > TOKEN_REUSE_S:
                try:
                    access, issued = token(http, key), time.monotonic()
                except GcpCollectError as exc:
                    targets.append({"target": label, "status": "auth_failed", "error": str(exc)[:256], "assets": 0})
                    continue
            services = _project(http, access, project, label, emit)
            # an API the project never enabled (Compute Engine, Certificate Manager) holds nothing: a by-choice gap.  A
            # permission the reader role from before these services lacks is a gap too (the row names the grant), so a
            # project that was read before this release never turns into a failed run.
            added = gcp_tls.SERVICES
            bad = [f"{svc}: {status}" for svc, status in services.items() if status not in ("ok", "truncated", "partial")
                   and not (svc in added and status in ("not_enabled", "denied"))]
            gappy = [f"{svc}: {status}" for svc, status in services.items()
                     if status in ("truncated", "partial") or (svc in added and status == "denied")]
            enabled = [s for s in services.values() if s != "not_enabled"]
            # a cut list is read, not complete: the target is partial (never "ok"), and its gap rows carry their scope
            status = ("error" if enabled else "not_supported") if bad else ("partial" if gappy else "ok")
            targets.append({"target": label, "status": status, "error": "; ".join(bad + gappy)[:256] or None,
                            "services": services, "duration_ms": int((time.monotonic() - t0) * 1000)})
    ok = sum(1 for t in targets if t["status"] == "ok")
    partial = sum(1 for t in targets if t["status"] == "partial")
    skipped = sum(1 for t in targets if t["status"].startswith("skipped"))
    log("gcp collected", team=team_id, projects=len(targets), ok=ok, partial=partial,
        duration_s=int(time.monotonic() - started))
    return {"targets": targets, "counts": {"total": len(targets), "ok": ok, "partial": partial,
                                           "failed": len(targets) - ok - partial - skipped, "skipped": skipped},
            "duration_s": int(time.monotonic() - started)}


def test_gcp(cfg: dict[str, Any], secrets: dict[str, str], *, transport: Any = None) -> dict[str, Any]:
    """Validation: sign in and make one list call (Cloud KMS locations of the first project).  Never raises."""
    checks: list[dict[str, str]] = []
    try:
        key = service_account(cfg, secrets)
    except GcpCollectError as exc:
        return {"status": "failed", "message": str(exc), "checks": [{"check": "Service account key", "status": "fail", "detail": str(exc)}]}
    with CloudHttp(transport) as http:
        try:
            access = token(http, key)
            checks.append({"check": "Signed in to Google Cloud", "status": "pass", "detail": f"Token issued for {key['client_email']}"})
        except GcpCollectError as exc:
            return {"status": "failed", "message": str(exc), "checks": [{"check": "Signed in to Google Cloud", "status": "fail", "detail": str(exc)[:240]}]}
        try:
            projects = _projects(http, access, cfg)
            if not projects:
                checks.append({"check": "List Cloud KMS locations", "status": "fail", "detail": "No project is visible to this service account"})
            else:
                locations, _t = http.google_pages(f"{KMS}/projects/{projects[0]}/locations", access, "locations", cap=LOCATION_CAP)
                checks.append({"check": "List Cloud KMS locations", "status": "pass",
                               "detail": f"{len(locations)} location(s) in project {projects[0]}"})
        except CloudHttpError as exc:
            checks.append({"check": "List Cloud KMS locations", "status": "fail",
                           "detail": ("Cloud KMS API is not enabled: " if _status(exc) == "not_enabled" else "") + str(exc)[:220]})
            projects = []
        if projects:
            checks += _probe_optional(http, access, projects[0])
    from backend.utilities.cbom_sources.azure_collect import _verdict

    return _verdict(checks)


def _probe_optional(http: CloudHttp, access: str, project: str) -> list[dict[str, str]]:
    """One small list call per service added after the first reader script (Certificate Manager, load balancing,
    Cloud Storage).  A missing grant is a warning, never a failed validation."""
    probes = {
        "certificatemanager": ("Read Certificate Manager", f"{gcp_tls.CERTMGR}/projects/{project}/locations", {"pageSize": 1}),
        "compute": ("Read load-balancer TLS policies", f"{gcp_tls.COMPUTE}/projects/{project}/aggregated/sslPolicies",
                    {"maxResults": 1, "returnPartialSuccess": "true"}),
        "storage": ("Read Cloud Storage bucket settings", f"{gcp_tls.STORAGE}/b", {"project": project, "maxResults": 1}),
    }
    out: list[dict[str, str]] = []
    for service, (check, url, params) in probes.items():
        try:
            http.get(url, access, params=params)
            out.append({"check": check, "status": "pass", "detail": f"Readable in project {project}"})
        except CloudHttpError as exc:
            status = _status(exc)
            if status == "not_enabled":
                out.append({"check": check, "status": "pass", "detail": "API not enabled in this project: nothing to read"})
            else:
                out.append({"check": check, "status": "warning", "detail": (
                    f"Not granted: {gcp_tls.PERMISSIONS[service]}. Re-run the reader script to add it; until then runs "
                    "report it as a coverage gap" if status == "denied" else str(exc))[:240]})
    return out
