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
* Every failure becomes a coverage row: denied, API not enabled (SERVICE_DISABLED), or error.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any, Callable

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


# Cloud KMS CryptoKeyVersionAlgorithm -> (algorithm family, bits).  Symmetric Google keys are AES-256-GCM, the same
# primitive as AWS KMS SYMMETRIC_DEFAULT, so they share that normalised key_spec (and the rotation rule).
def _kms_algorithm(name: str) -> tuple[str | None, int | None]:
    text = name.upper()
    if text in ("GOOGLE_SYMMETRIC_ENCRYPTION", "EXTERNAL_SYMMETRIC_ENCRYPTION") or text.startswith("AES_"):
        return "AES", int(text.split("_")[1]) if text.startswith("AES_") and text.split("_")[1].isdigit() else 256
    if text.startswith("HMAC_"):
        return "HMAC", None
    if "RSA" in text:
        for part in text.split("_"):
            if part.isdigit() and int(part) >= 1024:
                return "RSA", int(part)
        return "RSA", None
    if "ED25519" in text:
        return "ED25519", 256
    if "SECP256K1" in text:
        return "ECDSA", 256
    for curve, bits in (("P256", 256), ("P384", 384), ("P521", 521)):
        if curve in text:
            return "ECDSA", bits
    if text.startswith("PQ_") or "ML_DSA" in text or "SLH_DSA" in text or "ML_KEM" in text:
        return text.replace("PQ_SIGN_", "").replace("PQ_", "").replace("_", "-"), None
    return name or None, None


_STATE = {"ENABLED": "Enabled", "DISABLED": "Disabled", "DESTROY_SCHEDULED": "PendingDeletion", "DESTROYED": "Destroyed",
          "PENDING_GENERATION": "Creating", "PENDING_IMPORT": "Creating"}


def _key_asset(key: dict[str, Any], label: str) -> dict[str, Any]:
    template = key.get("versionTemplate") or {}
    primary = key.get("primary") or {}
    provider_alg = str(primary.get("algorithm") or template.get("algorithm") or "")
    family, bits = _kms_algorithm(provider_alg)
    purpose = str(key.get("purpose") or "")
    symmetric = provider_alg.upper() in ("GOOGLE_SYMMETRIC_ENCRYPTION", "EXTERNAL_SYMMETRIC_ENCRYPTION")
    name = str(key.get("name") or "")
    return {"type": "kms_key", "target": label, "location": name, "name": name.rsplit("/", 1)[-1],
            "algorithm": family, "key_size": bits,
            "facts": {"provider": "gcp", "key_spec": "SYMMETRIC_DEFAULT" if symmetric else provider_alg,
                      "provider_algorithm": provider_alg, "purpose": purpose, "key_usage": purpose,
                      "protection_level": primary.get("protectionLevel") or template.get("protectionLevel"),
                      "hsm_backed": (primary.get("protectionLevel") or template.get("protectionLevel")) == "HSM",
                      "key_manager": "CUSTOMER", "key_state": _STATE.get(str(primary.get("state") or ""), primary.get("state")),
                      # automatic rotation exists for symmetric ENCRYPT_DECRYPT keys only; for the others it is not applicable
                      "rotation_enabled": bool(key.get("rotationPeriod") or key.get("nextRotationTime")) if purpose == "ENCRYPT_DECRYPT" else None,
                      "rotation_period": key.get("rotationPeriod"), "next_rotation": key.get("nextRotationTime"),
                      "import_only": key.get("importOnly"), "destroy_scheduled_duration": key.get("destroyScheduledDuration"),
                      "created": key.get("createTime"), "identity": name}}


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
        alg, bits = _kms_algorithm(str(spec["algorithm"]))
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
        for loc in locations:
            if not loc.get("name"):
                continue
            rings, _r = http.google_pages(f"{KMS}/{loc['name']}/keyRings", access, "keyRings", cap=ITEM_CAP)
            for ring in (r for r in rings if r.get("name")):
                keys, _k = http.google_pages(f"{KMS}/{ring['name']}/cryptoKeys", access, "cryptoKeys", cap=ITEM_CAP)
                for key in keys:
                    emit(_key_asset(key, label))
                    count += 1
                    if count >= ITEM_CAP:  # key rings and CA pools share this prefix: both are covered (safe side)
                        return truncated("cloudkms", "keys", f"projects/{project}/locations/")
        return "ok"

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
            bad = [f"{svc}: {status}" for svc, status in services.items() if status not in ("ok", "truncated", "partial")]
            gappy = [f"{svc}: {status}" for svc, status in services.items() if status in ("truncated", "partial")]
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
    failed = [c for c in checks if c["status"] != "pass"]
    return {"status": "failed" if failed else "passed", "checks": checks,
            "message": failed[0]["detail"] if failed else checks[-1]["detail"]}
