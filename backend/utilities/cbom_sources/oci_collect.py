"""Oracle Cloud Infrastructure inventory over the public REST APIs (cloud worker; no OCI SDK), metadata only.

* Auth: every request is signed with the source's API signing key (OCI HTTP signature version 1: ``date``,
  ``(request-target)`` and ``host``, RSA-SHA256; keyId ``<tenancy>/<user>/<fingerprint>``;
  https://docs.oracle.com/iaas/Content/API/Concepts/signingrequests.htm).  The fingerprint is derived from the stored key.
* Scope: the configured compartments, or every ACTIVE compartment the user can reach in the tenancy (IAM
  ListCompartments with ``compartmentIdInSubtree``) plus the root; the configured regions, or every region the tenancy
  subscribes to (ListRegionSubscriptions).  IAM is read in the home region.  One target per region (``oci:<region>``).
* Vault: ListVaults (kms.<region>), then for each vault its management endpoint: ListKeys per compartment, GetKey
  (key shape, protection mode, auto-rotation) and ListKeyVersions.  Never a cryptographic endpoint and never key
  material; the policy grants ``read keys`` only (no ``use keys``).
* Secrets: ListSecrets (summaries: vault, key, rotation, expiry).  Never a secret bundle (``read secret-bundles`` is not
  granted).
* Certificates: ListCertificates and ListCertificateAuthorities (summaries: key and signing algorithm, subject, validity;
  ``inspect certificate-authority-family``, which reads no certificate contents or private keys).  A CA's key size comes
  from its Vault key when that key was read in the same run.
* Load balancing: ListLoadBalancers (listeners' SSL configuration, the load balancer's certificate bundles -- public
  certificates only, the private key is write-only in the API) and ListSSLCipherSuites for the ciphers of a suite.
* Object Storage: GetNamespace, ListBuckets and GetBucket (``kmsKeyId``: a customer-managed Vault key, else Oracle-managed).

Locations are ``oci://<region>/<service>/<OCID or name>``, so a coverage row can name what it left out with the scope
``oci://<region>/<service>/``.  Every failure becomes a coverage row (denied, error, truncated), never a silent "nothing
found"; a failure in one compartment covers the whole region-service (the safe side for drift).
"""
from __future__ import annotations

import base64
import email.utils
import time
from typing import Any, Callable
from urllib.parse import quote, urlsplit

from backend.utilities.cbom_sources import oci_keys
from backend.utilities.cbom_sources.cloud_http import CloudHttp, CloudHttpError, Signer, host_allowed
from backend.utilities.cbom_sources.common import log

IDENTITY = "https://identity.{r}.oci.oraclecloud.com/20160918"
KMS = "https://kms.{r}.oraclecloud.com/20180608"
SECRETS = "https://vaults.{r}.oci.oraclecloud.com/20180608"
CERTS = "https://certificatesmanagement.{r}.oci.oraclecloud.com/20210224"
LB = "https://iaas.{r}.oraclecloud.com/20170115"
OBJECTSTORAGE = "https://objectstorage.{r}.oraclecloud.com"
COMPARTMENT_CAP = 200
REGION_CAP = 60
ITEM_CAP = 1000  # keys / secrets / certificates / load balancers / buckets per region and service
VERSION_CAP = 200
VERSION_ROWS = 20
BUCKET_READ_CAP = 500  # GetBucket calls per region (the list has no kmsKeyId)

SERVICES = ("kms", "secrets", "certificates", "loadbalancer", "objectstorage")
# the policy statement a denied service needs (named in coverage rows and validation warnings)
POLICY = {
    "regions": "inspect tenancies in tenancy",
    "compartments": "inspect compartments in tenancy",
    "kms": "read vaults in tenancy and read keys in tenancy",
    "secrets": "inspect secrets in tenancy",
    "certificates": "inspect certificate-authority-family in tenancy",
    "loadbalancer": "read load-balancers in tenancy",
    "objectstorage": "read objectstorage-namespaces in tenancy and read buckets in tenancy",
}
POLICY_STATEMENTS = (
    "inspect tenancies in tenancy",  # ListRegionSubscriptions (TENANCY_INSPECT)
    "inspect compartments in tenancy",
    "read vaults in tenancy",
    "read keys in tenancy",
    "inspect secrets in tenancy",
    "inspect certificate-authority-family in tenancy",
    "read load-balancers in tenancy",
    "read objectstorage-namespaces in tenancy",
    "read buckets in tenancy",
)

Emit = Callable[[dict[str, Any]], None]


class OciCollectError(Exception):
    """``str(err)`` is safe to show."""


# ----------------------------------------------------------------------------------------------------------- signing
def signer(cfg: dict[str, Any], secrets: dict[str, str]) -> Signer:
    """The request signer of a source.  Raises OciCollectError when the source cannot sign yet."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    pem = secrets.get("api_signing_key") or ""
    if not pem:
        raise OciCollectError("No API signing key is stored on this source; save it again")
    if not cfg.get("user_ocid"):
        raise OciCollectError("Enter the user OCID the API key belongs to (the stack's user_ocid output), then save "
                              "and validate")
    try:
        private = oci_keys.load_private_key(pem)
        fingerprint, _pub = oci_keys.public_facts(pem)
    except Exception:
        raise OciCollectError("The stored API signing key could not be read; upload it again") from None
    key_id = f"{cfg['tenancy_ocid']}/{cfg['user_ocid']}/{fingerprint}"

    def sign(method: str, url: str) -> dict[str, str]:
        parts = urlsplit(url)
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        date = email.utils.formatdate(usegmt=True)
        text = f"date: {date}\n(request-target): {method.lower()} {target}\nhost: {parts.hostname}"
        signature = private.sign(text.encode(), padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr,call-arg]
        auth = (f'Signature version="1",headers="date (request-target) host",keyId="{key_id}",'
                f'algorithm="rsa-sha256",signature="{base64.b64encode(signature).decode()}"')
        return {"date": date, "authorization": auth}

    return sign


def _status(exc: CloudHttpError) -> str:
    if exc.status == 401 or exc.code == "NotAuthenticated":
        return "auth_failed"
    if exc.status in (403, 404) or exc.code in ("NotAuthorizedOrNotFound", "NotAuthorized", "Forbidden"):
        return "denied"
    return "error"


def _short(ocid: Any) -> str:
    text = str(ocid or "")
    return text if len(text) <= 24 else f"{text[:14]}...{text[-6:]}"


def _loc(region: str, service: str, ident: str) -> str:
    return f"oci://{region}/{service}/{ident}"


def _scope(region: str, service: str) -> str:
    return f"oci://{region}/{service}/"


# ------------------------------------------------------------------------------------------------------ asset rows
_CURVE_BITS = {"NIST_P256": 256, "NIST_P384": 384, "NIST_P521": 521}
_STATE = {"ENABLED": "Enabled", "DISABLED": "Disabled", "PENDING_DELETION": "PendingDeletion", "SCHEDULING_DELETION":
          "PendingDeletion", "DELETED": "Destroyed", "DELETING": "PendingDeletion", "CREATING": "Creating",
          "ENABLING": "Creating", "RESTORING": "Creating"}


def key_shape(key: dict[str, Any]) -> tuple[str | None, int | None, str | None]:
    """(algorithm family, bits, normalised key_spec) of a Vault key: AES keys are symmetric (the AWS / Google
    SYMMETRIC_DEFAULT spec, so the rotation and quantum rules treat them alike), RSA_<bits>, ECC_NIST_P<bits>."""
    shape = key.get("keyShape") if isinstance(key.get("keyShape"), dict) else {}
    alg = str(shape.get("algorithm") or key.get("algorithm") or "").upper()
    length = shape.get("length") if isinstance(shape.get("length"), int) else None
    if alg == "AES":
        return "AES", (length * 8 if length else None), "SYMMETRIC_DEFAULT"
    if alg == "RSA":
        bits = length * 8 if length else None
        return "RSA", bits, f"RSA_{bits}" if bits else None
    if alg == "ECDSA":
        bits = _CURVE_BITS.get(str(shape.get("curveId") or "").upper()) or ({32: 256, 48: 384, 66: 521}.get(length or 0))
        return "ECDSA", bits, f"ECC_NIST_P{bits}" if bits else None
    return (alg or None), None, None


def _key_asset(key: dict[str, Any], vault: dict[str, Any], region: str, label: str, versions: list[dict[str, Any]] | None,
               versions_error: str | None, detail_error: str | None) -> dict[str, Any]:
    ocid = str(key.get("id") or "")
    family, bits, spec = key_shape(key)
    protection = key.get("protectionMode")
    rotation = key.get("autoKeyRotationDetails") if isinstance(key.get("autoKeyRotationDetails"), dict) else {}
    auto = key.get("isAutoRotationEnabled")
    # automatic rotation exists only for keys in a virtual private vault; elsewhere it is not applicable (None), and
    # the key is rotated by hand (a new key version)
    private_vault = vault.get("vaultType") == "VIRTUAL_PRIVATE"
    listed = versions or []
    interval = rotation.get("rotationIntervalInDays")
    return {"type": "kms_key", "target": label, "location": _loc(region, "kms", ocid), "name": key.get("displayName") or _short(ocid),
            "algorithm": family, "key_size": bits,
            "facts": {"provider": "oci", "key_spec": spec, "provider_algorithm": f"{family}_{bits}" if family and bits else family,
                      "protection_level": protection, "hsm_backed": protection == "HSM",
                      # a key held outside OCI (External KMS, HYOK) rotates where it lives: not OCI's rotation rule
                      "origin": "EXTERNAL" if protection == "EXTERNAL" else None,
                      "key_manager": "CUSTOMER", "key_state": _STATE.get(str(key.get("lifecycleState") or ""), key.get("lifecycleState")),
                      "rotation_enabled": (auto if isinstance(auto, bool) else None) if private_vault else None,
                      "auto_rotation_supported": private_vault,
                      "rotation_period": f"{interval}d" if isinstance(interval, int) else None,
                      "next_rotation": rotation.get("timeOfNextRotation") or rotation.get("timeOfScheduleStart"),
                      "last_rotation": rotation.get("timeOfLastRotation"),
                      "created": key.get("timeCreated"), "deletion_time": key.get("timeOfDeletion"),
                      "current_version": key.get("currentKeyVersion"), "vault": vault.get("displayName"),
                      "vault_id": vault.get("id"), "vault_type": vault.get("vaultType"),
                      "compartment_id": key.get("compartmentId"), "region": region, "identity": ocid,
                      "version_count": None if versions_error else len(listed),
                      "enabled_versions": None if versions_error else sum(1 for v in listed if v.get("lifecycleState") == "ENABLED"),
                      "versions": [{"version": _short(v.get("id")), "state": v.get("lifecycleState"), "origin": v.get("origin"),
                                    "created": v.get("timeCreated")} for v in listed[:VERSION_ROWS]],
                      "versions_error": versions_error, "detail_error": detail_error,
                      **({"incomplete": True} if detail_error else {})}}


_SIG_ALG = {"SHA256_WITH_RSA": "sha256WithRSAEncryption", "SHA384_WITH_RSA": "sha384WithRSAEncryption",
            "SHA512_WITH_RSA": "sha512WithRSAEncryption", "SHA256_WITH_ECDSA": "ecdsa-with-SHA256",
            "SHA384_WITH_ECDSA": "ecdsa-with-SHA384", "SHA512_WITH_ECDSA": "ecdsa-with-SHA512"}


def cert_key_algorithm(name: Any) -> tuple[str | None, int | None]:
    """Certificates KeyAlgorithm (RSA2048, RSA4096, ECDSA_P256, ECDSA_P384) -> (family, bits)."""
    text = str(name or "").upper()
    if text.startswith("RSA"):
        digits = "".join(c for c in text if c.isdigit())
        return "RSA", int(digits) if digits else None
    if text.startswith("ECDSA"):
        return "ECDSA", _CURVE_BITS.get("NIST_" + text.split("_", 1)[-1]) if "_" in text else None
    return (text or None), None


def _subject(subject: Any) -> str | None:
    if not isinstance(subject, dict):
        return None
    order = (("commonName", "CN"), ("organizationalUnit", "OU"), ("organization", "O"), ("country", "C"))
    parts = [f"{abbr}={subject[k]}" for k, abbr in order if subject.get(k)]
    return ",".join(parts)[:255] or None


def _validity(item: dict[str, Any]) -> tuple[Any, Any]:
    summary = item.get("currentVersionSummary") if isinstance(item.get("currentVersionSummary"), dict) else {}
    validity = summary.get("validity") if isinstance(summary.get("validity"), dict) else {}
    return validity.get("timeOfValidityNotBefore"), validity.get("timeOfValidityNotAfter")


def _certificate_asset(cert: dict[str, Any], region: str, label: str) -> dict[str, Any]:
    ocid = str(cert.get("id") or "")
    alg, bits = cert_key_algorithm(cert.get("keyAlgorithm"))
    not_before, not_after = _validity(cert)
    subject = _subject(cert.get("subject"))
    sig = cert.get("signatureAlgorithm")
    return {"type": "certificate", "target": label, "location": _loc(region, "certificates", ocid),
            "name": subject or cert.get("name") or _short(ocid), "algorithm": alg, "key_size": bits,
            "facts": {"provider": "oci", "service": "certificates", "subject": subject, "not_before": not_before,
                      "not_after": not_after, "sig_alg": _SIG_ALG.get(str(sig or ""), sig), "key_alg": alg, "key_size": bits,
                      "config_type": cert.get("configType"), "profile": cert.get("certificateProfileType"),
                      "issuer_ca_id": cert.get("issuerCertificateAuthorityId"), "status": cert.get("lifecycleState"),
                      "renewal_rules": [r.get("ruleType") for r in cert.get("certificateRules") or [] if isinstance(r, dict)][:5],
                      "is_ca": False, "compartment_id": cert.get("compartmentId"), "region": region, "identity": ocid}}


def _ca_asset(ca: dict[str, Any], region: str, label: str, kms_keys: dict[str, tuple[str | None, int | None]]) -> dict[str, Any]:
    ocid = str(ca.get("id") or "")
    sig = str(ca.get("signingAlgorithm") or "")
    alg, bits = kms_keys.get(str(ca.get("kmsKeyId") or ""), (None, None))
    if not alg:
        alg = "ECDSA" if sig.endswith("ECDSA") else ("RSA" if sig.endswith("RSA") else None)
    not_before, not_after = _validity(ca)
    subject = _subject(ca.get("subject"))
    return {"type": "cloud_ca", "target": label, "location": _loc(region, "certificates", ocid),
            "name": subject or ca.get("name") or _short(ocid), "algorithm": alg, "key_size": bits,
            "facts": {"provider": "oci", "service": "certificates", "subject": subject, "not_before": not_before,
                      "not_after": not_after, "sig_alg": _SIG_ALG.get(sig, sig or None), "key_alg": alg, "key_size": bits,
                      "ca_type": ca.get("configType"), "status": ca.get("lifecycleState"), "kms_key_id": ca.get("kmsKeyId"),
                      "issuer_ca_id": ca.get("issuerCertificateAuthorityId"), "is_ca": True,
                      "compartment_id": ca.get("compartmentId"), "region": region, "identity": ocid,
                      **({"incomplete": True} if bits is None else {})}}


def _secret_asset(secret: dict[str, Any], region: str, label: str) -> dict[str, Any]:
    ocid = str(secret.get("id") or "")
    rotation = secret.get("rotationConfig") if isinstance(secret.get("rotationConfig"), dict) else {}
    scheduled = rotation.get("isScheduledRotationEnabled")
    return {"type": "cloud_secret", "target": label, "location": _loc(region, "secrets", ocid),
            "name": secret.get("secretName") or _short(ocid),
            "facts": {"provider": "oci", "kms_key_id": secret.get("keyId"), "vault_id": secret.get("vaultId"),
                      "rotation_enabled": scheduled if isinstance(scheduled, bool) else (False if rotation == {} else None),
                      "rotation_period": rotation.get("rotationInterval"), "rotation_status": secret.get("rotationStatus"),
                      "expires": secret.get("timeOfCurrentVersionExpiry"), "deletion_time": secret.get("timeOfDeletion"),
                      "status": secret.get("lifecycleState"), "created": secret.get("timeCreated"),
                      "compartment_id": secret.get("compartmentId"), "region": region, "identity": ocid}}


def _static_rsa(ciphers: list[str]) -> bool:
    """An OpenSSL-named suite without (EC)DHE key exchange (AES128-SHA, DES-CBC3-SHA, ...): RSA key transport."""
    return any(not c.upper().startswith(("ECDHE", "DHE", "ECDH-", "DH-", "TLS_", "PSK", "SRP"))
               and any(x in c.upper() for x in ("AES", "DES", "CAMELLIA", "RC4", "SEED", "IDEA")) for c in ciphers)


def _cert_from_pem(pem: Any) -> tuple[str | None, int | None, dict[str, Any]]:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from backend.utilities.cbom_sources.idp_collect import cert_facts

    der = x509.load_pem_x509_certificate(str(pem).encode()).public_bytes(serialization.Encoding.DER)
    return cert_facts(der, "oci")


# ------------------------------------------------------------------------------------------------------ the region
class _Region:
    """One region: every service over every compartment.  ``services`` maps a service to its status."""

    def __init__(self, http: CloudHttp, sign: Signer, region: str, compartments: list[str], label: str, emit: Emit):
        self.http, self.sign, self.region, self.compartments, self.label, self.emit = http, sign, region, compartments, label, emit
        self.services: dict[str, str] = {}
        self.kms_keys: dict[str, tuple[str | None, int | None]] = {}

    def gap(self, service: str, status: str, detail: str, suffix: str = "", **extra: Any) -> None:
        self.emit({"type": "coverage", "target": self.label, "location": f"oci://{self.region}#{service}{suffix}",
                   "facts": {"check": f"{service} in {self.region}", "status": status, "detail": detail[:200],
                             "scope": [_scope(self.region, service)], **extra}})

    def run(self, service: str, fn: Callable[[], str]) -> None:
        try:
            self.services[service] = fn()
        except (AttributeError, TypeError, ValueError, KeyError) as exc:  # a valid-JSON answer of an unexpected shape
            self.services[service] = "error"
            self.gap(service, "error", f"unexpected answer shape from {service} ({type(exc).__name__})", "-shape")
        except CloudHttpError as exc:
            status = _status(exc)
            self.services[service] = status
            detail = f"{POLICY[service]} needed: {exc}" if status == "denied" else str(exc)
            self.gap(service, status, detail)

    def per_compartment(self, service: str, fn: Callable[[str], int]) -> str:
        """Run ``fn(compartment)`` (returns items read) for every compartment.  One compartment that fails is a gap of
        the whole region-service (scope), not a failure of the others."""
        failed: list[tuple[str, CloudHttpError]] = []
        total = 0
        for compartment in self.compartments:
            try:
                total += fn(compartment)
            except CloudHttpError as exc:
                failed.append((compartment, exc))
            if total >= ITEM_CAP:
                self.gap(service, "truncated", f"More than {ITEM_CAP} items; the first {ITEM_CAP} were read", "-cap")
                if failed:
                    self.gap(service, _status(failed[0][1]), f"{len(failed)} compartment(s) not read before the cap: "
                             f"{failed[0][1]}", "-compartments", compartments=[c for c, _e in failed][:50])
                return "truncated"
        if failed and len(failed) == len(self.compartments):
            raise failed[0][1]
        if failed:
            first = failed[0][1]
            self.gap(service, _status(first), (f"{len(failed)} of {len(self.compartments)} compartment(s) not read "
                                               f"({POLICY[service]} needed in them): {first}"),
                     "-compartments", compartments=[c for c, _e in failed][:50])
            return "partial"
        return "ok"

    # Vault keys -------------------------------------------------------------------------------------------------
    def kms(self) -> str:
        vaults: list[dict[str, Any]] = []
        # a compartment whose vaults cannot be listed is its own gap: keys are still read from the vaults that were
        # found (R-oci1: one stale compartment used to drop every key of the region)
        status = self.per_compartment("kms", lambda c: self._vaults(c, vaults))
        unread: list[str] = []
        count = 0
        for vault in vaults:
            endpoint = str(vault.get("managementEndpoint") or "").rstrip("/")
            if vault.get("lifecycleState") not in (None, "ACTIVE", "UPDATING") or not endpoint:
                continue
            if not host_allowed(endpoint + "/"):
                unread.append(str(vault.get("id")))
                continue
            for compartment in self.compartments:
                try:
                    keys, _cut = self.http.oci_pages(f"{endpoint}/20180608/keys", self.sign, cap=ITEM_CAP,
                                                     params={"compartmentId": compartment})
                except CloudHttpError as exc:
                    if _status(exc) == "denied":
                        unread.append(f"{vault.get('id')} in {_short(compartment)}")
                        continue
                    raise
                for summary in keys:
                    self.emit(self._key(endpoint, vault, summary))
                    count += 1
                    if count >= ITEM_CAP:
                        self.gap("kms", "truncated", f"More than {ITEM_CAP} keys; the first {ITEM_CAP} were read", "-cap")
                        return "truncated"
        if unread:
            self.gap("kms", "denied", f"keys of {len(unread)} vault/compartment pair(s) not listed ({POLICY['kms']} needed)",
                     "-vaults", vaults=unread[:50])
            return "partial"
        return status

    def _vaults(self, compartment: str, into: list[dict[str, Any]]) -> int:
        found, _cut = self.http.oci_pages(f"{KMS.format(r=self.region)}/vaults", self.sign, cap=ITEM_CAP,
                                          params={"compartmentId": compartment})
        into.extend(found)
        return 0  # vaults are not items: keys are counted

    def _key(self, endpoint: str, vault: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
        key, detail_error = dict(summary), None
        ocid = str(summary.get("id") or "")
        try:
            key.update(self.http.oci_get(f"{endpoint}/20180608/keys/{quote(ocid, safe='')}", self.sign))
        except CloudHttpError as exc:  # the listed key is still reported, without its shape and rotation
            detail_error = str(exc)[:120]
        versions, versions_error = None, None
        try:
            versions, _cut = self.http.oci_pages(f"{endpoint}/20180608/keys/{quote(ocid, safe='')}/keyVersions",
                                                 self.sign, cap=VERSION_CAP)
        except CloudHttpError as exc:
            versions_error = str(exc)[:120]
        asset = _key_asset(key, vault, self.region, self.label, versions, versions_error, detail_error)
        self.kms_keys[ocid] = (asset["algorithm"], asset["key_size"])
        return asset

    # Secrets ----------------------------------------------------------------------------------------------------
    def secrets(self) -> str:
        def one(compartment: str) -> int:
            found, _cut = self.http.oci_pages(f"{SECRETS.format(r=self.region)}/secrets", self.sign, cap=ITEM_CAP,
                                              params={"compartmentId": compartment})
            for secret in found:  # summaries only: GetSecretBundle is never called
                self.emit(_secret_asset(secret, self.region, self.label))
            return len(found)
        return self.per_compartment("secrets", one)

    # Certificates ------------------------------------------------------------------------------------------------
    def certificates(self) -> str:
        base = CERTS.format(r=self.region)

        def one(compartment: str) -> int:
            certs, _c = self.http.oci_pages(f"{base}/certificates", self.sign, cap=ITEM_CAP, params={"compartmentId": compartment})
            cas, _a = self.http.oci_pages(f"{base}/certificateAuthorities", self.sign, cap=ITEM_CAP,
                                          params={"compartmentId": compartment})
            for cert in certs:
                if cert.get("lifecycleState") not in ("DELETED",):
                    self.emit(_certificate_asset(cert, self.region, self.label))
            for ca in cas:
                if ca.get("lifecycleState") not in ("DELETED",):
                    self.emit(_ca_asset(ca, self.region, self.label, self.kms_keys))
            return len(certs) + len(cas)
        return self.per_compartment("certificates", one)

    # Load balancers ----------------------------------------------------------------------------------------------
    def loadbalancer(self) -> str:
        incomplete: list[str] = []

        def one(compartment: str) -> int:
            found, _cut = self.http.oci_pages(f"{LB.format(r=self.region)}/loadBalancers", self.sign, cap=ITEM_CAP,
                                              params={"compartmentId": compartment})
            for lb in found:
                if not self._load_balancer(lb):
                    incomplete.append(str(lb.get("id")))
            return len(found)
        status = self.per_compartment("loadbalancer", one)
        if incomplete and status == "ok":
            self.gap("loadbalancer", "partial", f"cipher suites of {len(incomplete)} load balancer(s) not read",
                     "-ciphers", incomplete=True, load_balancers=incomplete[:50])
            return "partial"
        return status

    def _load_balancer(self, lb: dict[str, Any]) -> bool:
        """Rows for one load balancer; False when its cipher suites could not be read (the rows are kept)."""
        ocid = str(lb.get("id") or "")
        listeners = lb.get("listeners") if isinstance(lb.get("listeners"), dict) else {}
        bundles = lb.get("certificates") if isinstance(lb.get("certificates"), dict) else {}
        suites: dict[str, list[str]] = {}
        for name, suite in (lb.get("sslCipherSuites") or {}).items() if isinstance(lb.get("sslCipherSuites"), dict) else []:
            if isinstance(suite, dict):
                suites[str(name)] = [str(c) for c in suite.get("ciphers") or [] if isinstance(c, str)]
        tls = {n: lsn for n, lsn in listeners.items() if isinstance(lsn, dict) and isinstance(lsn.get("sslConfiguration"), dict)}
        read_ok = True
        wanted = {str(lsn["sslConfiguration"].get("cipherSuiteName") or "") for lsn in tls.values()} - set(suites) - {""}
        if wanted:
            try:
                answer = self.http.oci_get(f"{LB.format(r=self.region)}/loadBalancers/{quote(ocid, safe='')}/sslCipherSuites", self.sign)
                for suite in answer.get("value") or []:
                    if isinstance(suite, dict) and suite.get("name"):
                        suites[str(suite["name"])] = [str(c) for c in suite.get("ciphers") or [] if isinstance(c, str)]
            except CloudHttpError:
                read_ok = False
        internet = None if lb.get("isPrivate") is None else not bool(lb.get("isPrivate"))
        used: set[str] = set()
        for name, listener in tls.items():
            ssl = listener["sslConfiguration"]
            suite_name = str(ssl.get("cipherSuiteName") or "")
            ciphers = suites.get(suite_name, [])
            certs = [str(ssl.get("certificateName"))] if ssl.get("certificateName") else []
            certs += [str(c) for c in ssl.get("certificateIds") or [] if isinstance(c, str)]
            used.update(certs)
            self.emit({"type": "load_balancer_tls", "target": self.label,
                       "location": _loc(self.region, "loadbalancer", f"{ocid}/listener/{name}"),
                       "name": f"{lb.get('displayName') or _short(ocid)}:{listener.get('port') or name}", "protocol": listener.get("protocol") or "TLS",
                       "facts": {"provider": "oci", "load_balancer": lb.get("displayName"), "listener": name,
                                 "port": listener.get("port"), "protocols": [str(p) for p in ssl.get("protocols") or []][:10],
                                 "cipher_suite": suite_name or None, "ciphers": ciphers[:100],
                                 "ciphers_known": bool(ciphers) or not suite_name,
                                 "static_rsa_kex": _static_rsa(ciphers), "server_order_preference": ssl.get("serverOrderPreference"),
                                 "verify_peer_certificate": ssl.get("verifyPeerCertificate"), "certificates": certs[:20],
                                 "internet_facing": internet, "exposure_basis": "load balancer isPrivate" if internet is not None else None,
                                 "shape": lb.get("shapeName"), "compartment_id": lb.get("compartmentId"), "region": self.region,
                                 "identity": f"{ocid}/listener/{name}"}})
        for name, bundle in bundles.items():
            if not isinstance(bundle, dict) or not bundle.get("publicCertificate"):
                continue
            where = _loc(self.region, "loadbalancer", f"{ocid}/certificate/{name}")
            try:
                alg, bits, facts = _cert_from_pem(bundle["publicCertificate"])
            except Exception:
                self.emit({"type": "coverage", "target": self.label, "location": f"{where}#parse",
                           "facts": {"check": f"load balancer certificate {name}", "status": "error",
                                     "detail": "the certificate could not be parsed", "scope": [where]}})
                continue
            facts.update({"provider": "oci", "service": "load_balancing", "load_balancer": lb.get("displayName"),
                          "in_use": str(name) in used, "region": self.region, "identity": where})
            self.emit({"type": "certificate", "target": self.label, "location": where,
                       "name": facts.get("subject") or str(name), "algorithm": alg, "key_size": bits, "facts": facts})
        return read_ok

    # Object Storage ----------------------------------------------------------------------------------------------
    def objectstorage(self) -> str:
        base = OBJECTSTORAGE.format(r=self.region)
        namespace = self.http.oci_get(f"{base}/n/", self.sign).get("value")
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("no namespace")
        unread: list[str] = []
        reads = 0

        def one(compartment: str) -> int:
            nonlocal reads
            buckets, _cut = self.http.oci_pages(f"{base}/n/{quote(namespace)}/b", self.sign, cap=ITEM_CAP,
                                                params={"compartmentId": compartment})
            for bucket in buckets:
                name = str(bucket.get("name") or "")
                if not name:
                    continue
                detail: dict[str, Any] = {}
                if reads < BUCKET_READ_CAP:
                    reads += 1
                    try:
                        detail = self.http.oci_get(f"{base}/n/{quote(namespace)}/b/{quote(name, safe='')}", self.sign)
                    except CloudHttpError:
                        unread.append(name)
                else:
                    unread.append(name)
                where = _loc(self.region, "objectstorage", f"{namespace}/{name}")
                known = bool(detail)
                self.emit({"type": "storage_encryption", "target": self.label, "location": where, "name": name,
                           "facts": {"provider": "oci", "resource": f"Object Storage bucket {name}", "encrypted": True,
                                     "kms_key_id": (detail.get("kmsKeyId") or "oracle-managed") if known else None,
                                     "public_access": detail.get("publicAccessType") if known else None,
                                     "compartment_id": bucket.get("compartmentId") or compartment, "region": self.region,
                                     "identity": where, **({} if known else {"incomplete": True})}})
            return len(buckets)
        status = self.per_compartment("objectstorage", one)
        if unread and status == "ok":
            self.gap("objectstorage", "partial", f"encryption key of {len(unread)} bucket(s) not read", "-buckets",
                     incomplete=True, buckets=unread[:50])
            return "partial"
        return status


# --------------------------------------------------------------------------------------------------- scope listing
class RegionsUnlisted(Exception):
    """ListRegionSubscriptions was refused (the policy lacks ``inspect tenancies``): the key itself was accepted."""

    def __init__(self, exc: CloudHttpError):
        self.exc = exc
        super().__init__(str(exc))


def _regions(http: CloudHttp, sign: Signer, cfg: dict[str, Any], *, fallback: bool = True) -> tuple[list[str], list[str]]:
    """(regions to read, configured regions the tenancy does not subscribe to).  When the subscriptions cannot be
    listed for want of ``inspect tenancies`` (404 NotAuthorizedOrNotFound -- OCI answered, so the signature was
    accepted), the home region and the configured regions are read instead (``fallback``), else RegionsUnlisted."""
    home = cfg["home_region"]
    try:
        answer = http.oci_get(f"{IDENTITY.format(r=home)}/tenancies/{quote(cfg['tenancy_ocid'], safe='')}/regionSubscriptions", sign)
    except CloudHttpError as exc:
        if _status(exc) != "denied":
            raise
        if not fallback:
            raise RegionsUnlisted(exc) from None
        return list(dict.fromkeys([home, *(cfg.get("regions") or [])]))[:REGION_CAP], []
    ready = [str(s.get("regionName")) for s in answer.get("value") or []
             if isinstance(s, dict) and s.get("regionName") and s.get("status") in (None, "READY")]
    wanted = list(cfg.get("regions") or [])
    if wanted:
        return [r for r in wanted if r in ready][:REGION_CAP], [r for r in wanted if r not in ready]
    return (ready or [home])[:REGION_CAP], []


def _compartments(http: CloudHttp, sign: Signer, cfg: dict[str, Any]) -> list[str]:
    if cfg.get("compartment_ocids"):
        return list(cfg["compartment_ocids"])[:COMPARTMENT_CAP]
    tenancy = cfg["tenancy_ocid"]
    found, _cut = http.oci_pages(f"{IDENTITY.format(r=cfg['home_region'])}/compartments", sign, cap=COMPARTMENT_CAP - 1,
                                 params={"compartmentId": tenancy, "compartmentIdInSubtree": "true",
                                         "accessLevel": "ACCESSIBLE", "lifecycleState": "ACTIVE"})
    return [tenancy] + [str(c["id"]) for c in found if c.get("id") and c.get("lifecycleState") in (None, "ACTIVE")]


def collect_oci(team_id: int, cfg: dict[str, Any], secrets: dict[str, str], emit: Emit,
                should_stop: Callable[[], str | None], *, transport: Any = None) -> dict[str, Any]:
    """Collect one Oracle Cloud source.  Raises OciCollectError when nothing can be read."""
    started = time.monotonic()
    sign = signer(cfg, secrets)
    targets: list[dict[str, Any]] = []
    with CloudHttp(transport) as http:
        fell_back = False
        try:
            try:
                regions, unsubscribed = _regions(http, sign, cfg, fallback=False)
            except RegionsUnlisted:
                fell_back = True
                regions, unsubscribed = _regions(http, sign, cfg)
            compartments = _compartments(http, sign, cfg)
        except CloudHttpError as exc:
            status = _status(exc)
            if status == "auth_failed":
                raise OciCollectError(f"Oracle Cloud refused the API key ({exc}): check the user OCID and that the "
                                      "public key is added to that user") from None
            raise OciCollectError(f"Could not list the tenancy's regions and compartments ({POLICY['compartments']} "
                                  f"needed): {exc}" if status == "denied" else f"Could not read the tenancy: {exc}") from None
        for region in unsubscribed:
            targets.append({"target": f"oci:{region}", "status": "not_supported", "assets": 0,
                            "error": "the tenancy does not subscribe to this region"})
        if fell_back:
            # no target: the gap covers every region of the job, not only the home region's assets (R-oci1 re-review)
            emit({"type": "coverage", "target": "", "location": "oci://tenancy#regions",
                  "facts": {"check": "subscribed regions", "status": "denied", "scope": ["oci://"],
                            "detail": f"{POLICY['regions']} needed: only the home region and the source's regions were read"}})
        for region in regions:
            label = f"oci:{region}"
            reason = should_stop()
            if reason:
                targets.append({"target": label, "status": "skipped_cancelled", "error": reason[:256], "assets": 0})
                continue
            t0 = time.monotonic()
            reader = _Region(http, sign, region, compartments, label, emit)
            for service in SERVICES:  # kms first: a CA's key size comes from its Vault key
                reader.run(service, getattr(reader, service))
            services = reader.services
            bad = [f"{svc}: {s}" for svc, s in services.items() if s not in ("ok", "truncated", "partial", "denied")]
            gappy = [f"{svc}: {s}" for svc, s in services.items() if s in ("truncated", "partial", "denied")]
            read = [s for s in services.values() if s in ("ok", "truncated", "partial")]
            # a service the policy does not grant is a named gap (coverage row), not a failed region, as long as
            # something was read; a region where nothing could be read is an error
            status = "error" if not read else ("partial" if bad or gappy else "ok")
            targets.append({"target": label, "status": status, "error": "; ".join(bad + gappy)[:256] or None,
                            "services": services, "duration_ms": int((time.monotonic() - t0) * 1000)})
    ok = sum(1 for t in targets if t["status"] == "ok")
    partial = sum(1 for t in targets if t["status"] == "partial")
    skipped = sum(1 for t in targets if t["status"].startswith("skipped") or t["status"] == "not_supported")
    log("oci collected", team=team_id, regions=len(targets), compartments=len(compartments), ok=ok, partial=partial,
        duration_s=int(time.monotonic() - started))
    return {"targets": targets, "counts": {"total": len(targets), "ok": ok, "partial": partial,
                                           "failed": len(targets) - ok - partial - skipped, "skipped": skipped},
            "duration_s": int(time.monotonic() - started)}


# ------------------------------------------------------------------------------------------------------ validation
VALIDATE_REGION_CAP = 6
VALIDATE_DEADLINE_S = 45.0


def _probes(region: str, tenancy: str) -> dict[str, tuple[str, str, dict[str, Any]]]:
    params = {"compartmentId": tenancy, "limit": 1}
    return {
        "kms": ("List Vault vaults", f"{KMS.format(r=region)}/vaults", params),
        "secrets": ("List Vault secrets", f"{SECRETS.format(r=region)}/secrets", params),
        "certificates": ("List certificates", f"{CERTS.format(r=region)}/certificates", params),
        "loadbalancer": ("List load balancers", f"{LB.format(r=region)}/loadBalancers", params),
        "objectstorage": ("Read the Object Storage namespace", f"{OBJECTSTORAGE.format(r=region)}/n/", {}),
    }


def test_oci(cfg: dict[str, Any], secrets: dict[str, str], *, transport: Any = None) -> dict[str, Any]:
    """Save and validate: sign a request (GetTenancy-free: ListRegionSubscriptions in the home region proves the key),
    list the compartments, then one small list call per service in the home region and each configured region (up to
    VALIDATE_REGION_CAP).  A service the policy lacks is a warning naming the statement; a key OCI refuses fails.
    Never raises."""
    from backend.utilities.cbom_sources.azure_collect import _verdict

    started = time.monotonic()
    checks: list[dict[str, str]] = []
    try:
        sign = signer(cfg, secrets)
    except OciCollectError as exc:
        return {"status": "failed", "message": str(exc), "checks": [{"check": "API signing key", "status": "fail", "detail": str(exc)}]}
    with CloudHttp(transport) as http:
        try:
            regions, unsubscribed = _regions(http, sign, cfg, fallback=False)
            checks.append({"check": "Signed in to Oracle Cloud", "status": "pass",
                           "detail": f"API key accepted; the tenancy subscribes to {len(regions) + len(unsubscribed) if cfg.get('regions') else len(regions)} region(s)"})
        except RegionsUnlisted as exc:
            regions, unsubscribed = _regions(http, sign, cfg)  # the fallback: home and configured regions
            checks.append({"check": "Signed in to Oracle Cloud", "status": "pass", "detail": "API key accepted"})
            checks.append({"check": "List subscribed regions", "status": "warning", "detail": (
                f"Not granted: allow group ZeroShieldCBOMReaders to {POLICY['regions']}. Until it is, runs read the home "
                f"region and the regions listed on the source only ({exc.exc.code})")[:240]})
        except CloudHttpError as exc:
            status = _status(exc)
            detail = (f"Oracle Cloud refused the key ({exc.code}): check the user OCID, the home region, and that the "
                      "public key (fingerprint shown on the source) is added to that user" if status == "auth_failed"
                      else f"Could not reach Oracle Cloud identity in {cfg.get('home_region')}: {exc}")
            return {"status": "failed", "message": detail[:512], "checks": [{"check": "Signed in to Oracle Cloud", "status": "fail", "detail": detail[:240]}]}
        for region in unsubscribed:
            checks.append({"check": f"Region {region}", "status": "warning",
                           "detail": f"The tenancy does not subscribe to {region}: it is skipped"})
        try:
            compartments = _compartments(http, sign, cfg)
            checks.append({"check": "List compartments", "status": "pass",
                           "detail": f"{len(compartments)} compartment(s) in scope" + ("" if cfg.get("compartment_ocids") else " (the root and every accessible compartment)")})
        except CloudHttpError as exc:
            checks.append({"check": "List compartments", "status": "fail", "detail": (
                f"{POLICY['compartments']} is needed to read the whole tenancy, or list the compartments on the source: {exc}"
                if _status(exc) == "denied" else str(exc))[:240]})
        home = cfg["home_region"]
        probe_regions = [home] + [r for r in regions if r != home]
        checked: list[str] = []
        for region in probe_regions[:VALIDATE_REGION_CAP]:
            if checked and time.monotonic() - started > VALIDATE_DEADLINE_S:
                break
            checked.append(region)
            for service, (check, url, params) in _probes(region, cfg["tenancy_ocid"]).items():
                try:
                    http.oci_get(url, sign, params=params or None)
                    checks.append({"check": f"{check} in {region}", "status": "pass", "detail": f"Readable in {region}"})
                except CloudHttpError as exc:
                    status = _status(exc)
                    checks.append({"check": f"{check} in {region}", "status": "warning" if status == "denied" else "fail",
                                   "detail": (f"Not granted: allow group ZeroShieldCBOMReaders to {POLICY[service]}. Until "
                                              "it is, runs report it as a coverage gap" if status == "denied" else str(exc))[:240]})
        if len(checked) < len(probe_regions):
            checks.append({"check": "Regions checked", "status": "warning", "detail": (
                f"{len(checked)} of {len(probe_regions)} regions were checked; the others are read on the run, where a "
                "region that cannot be read is a failed target")[:240]})
    out = _verdict(checks)
    if out["status"] == "passed" and not any(c["status"] == "warning" for c in checks):
        out["message"] = f"Read access proven in {len(checked)} region(s): {', '.join(checked)}"[:512]
    return out
