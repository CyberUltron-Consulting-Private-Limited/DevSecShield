"""Azure Key Vault and Google Cloud KMS / CA Service / Secret Manager collectors against recorded responses.

Responses are the providers' documented formats (httpx.MockTransport, no network):
* Entra ID token: https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow (success
  response; error response with error / error_description / error_codes).
* ARM Vaults - List By Subscription (2023-07-01) sample response:
  https://learn.microsoft.com/rest/api/keyvault/keyvault/vaults/list-by-subscription
* Key Vault data plane 7.4 samples: Get Keys, Get Key, Get Key Rotation Policy, Get Certificate, Get Secrets
  (https://learn.microsoft.com/rest/api/keyvault/keys/get-keys/get-keys, .../get-key/get-key,
  .../get-key-rotation-policy/get-key-rotation-policy, .../certificates/get-certificate/get-certificate,
  .../secrets/get-secrets/get-secrets) -- values copied from those samples where the sample has them.
* Key Vault firewall refusal (403, innererror ForbiddenByFirewall):
  https://learn.microsoft.com/azure/key-vault/general/rest-error-codes
* Google: OAuth token (service-account JWT bearer), Cloud KMS v1 CryptoKey / KeyRing / Location, CA Service v1
  CertificateAuthority, Secret Manager v1 Secret JSON representations (https://cloud.google.com/kms/docs/reference/rest,
  https://cloud.google.com/certificate-authority-service/docs/reference/rest, https://cloud.google.com/secret-manager/docs/reference/rest)
  and the google.rpc.ErrorInfo SERVICE_DISABLED error (https://cloud.google.com/apis/design/errors).

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cbom_azure_gcp_collect.py -q
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from backend.utilities.cbom_sources import azure_collect, cloud_http, gcp_collect  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.kinds import KINDS, validate_secret_value  # noqa: E402

TENANT = "72f988bf-86f1-41af-91ab-2d7cd011db47"
CLIENT = "6731de76-14a6-49ae-97bc-6eba6914391e"
SUB = "00000000-0000-0000-0000-000000000000"
CLIENT_SECRET = "Az-Client-Secret~9f8e7d6c5b4a"
ARM_TOKEN, KV_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.arm", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.kv"

# ----- documented Azure sample bodies (see module docstring)
KEY_N = ("2HJAE5fU3Cw2Rt9hEuq-F6XjINKGa-zskfISVqopqUy60GOs2eyhxbWbJBeUXNor_gf-tXtNeuqeBgitLeVa640UDvnEjYTKWjCniTxZRaU7ewY8BfTSk-7KxoDdLsPSpX_MX4rwlAx-_1UGk5t4sQgTbm9T6Fm2oqFd37dsz5-Gj27UP2GTAShfJPFD7MqU_zIgOI0pfqsbNL5xTQVM29K6rX4jSPtylZV3uWJtkoQIQnrIHhk1d0SC0KwlBV3V7R_LVYjiXLyIXsFzSNYgQ68ZjAwt8iL7I8Osa-ehQLM13DVvLASaf7Jnu3sC3CWl3Gyirgded6cfMmswJzY87w")
GET_KEY = {"key": {"kid": "https://myvault.vault.azure.net/keys/CreateSoftKeyTest/78deebed173b48e48f55abf87ed4cf71",
                   "kty": "RSA", "key_ops": ["encrypt", "decrypt", "sign", "verify", "wrapKey", "unwrapKey"], "n": KEY_N, "e": "AQAB"},
           "attributes": {"enabled": True, "created": 1493942451, "updated": 1493942451, "recoveryLevel": "Recoverable+Purgeable"},
           "tags": {"purpose": "unit test", "test name ": "CreateGetDeleteKeyTest"}}
ROTATION = {"id": "https://myvault.vault.azure.net/keys/key01/rotationpolicy",
            "lifetimeActions": [{"trigger": {"timeAfterCreate": "P90D"}, "action": {"type": "Rotate"}},
                                {"trigger": {"timeBeforeExpiry": "P30D"}, "action": {"type": "Notify"}}],
            "attributes": {"expiryTime": "P2Y", "created": 1482188947, "updated": 1482188948}}
SAMPLE_VAULT = {
    "id": f"/subscriptions/{SUB}/resourceGroups/sample-group/providers/Microsoft.KeyVault/vaults/sample-vault",
    "name": "sample-vault", "type": "Microsoft.KeyVault/vaults", "location": "westus", "tags": {},
    "properties": {"sku": {"family": "A", "name": "premium"}, "tenantId": SUB, "accessPolicies": [],
                   "enabledForDeployment": True, "enabledForDiskEncryption": True, "enabledForTemplateDeployment": True,
                   "enableSoftDelete": True, "hsmPoolResourceId": SUB, "vaultUri": "https://sample-vault.vault.azure.net/",
                   "provisioningState": "Succeeded"}}
LOCKED_VAULT = {
    "id": f"/subscriptions/{SUB}/resourceGroups/sec/providers/Microsoft.KeyVault/vaults/locked-vault", "name": "locked-vault",
    "location": "centralindia",
    "properties": {"sku": {"family": "A", "name": "standard"}, "tenantId": TENANT, "enableSoftDelete": True,
                   "enablePurgeProtection": True, "enableRbacAuthorization": True, "publicNetworkAccess": "Disabled",
                   "networkAcls": {"defaultAction": "Deny", "bypass": "AzureServices", "ipRules": [], "virtualNetworkRules": []},
                   "vaultUri": "https://locked-vault.vault.azure.net/"}}
FIREWALL_403 = {"error": {"code": "Forbidden", "message": "Public network access is disabled and request is not from a trusted "
                          "service nor via an approved private link.\r\nCaller: appid=" + CLIENT + "\r\nVault: locked-vault;location=centralindia",
                          "innererror": {"code": "ForbiddenByFirewall"}}}


def _self_signed(cn="KeyVaultTest", key=None, ca=False, sig=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = sig or hashes.SHA256()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
               .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return key, builder.sign(key, sig)


_CERT_KEY, _CERT = _self_signed()
GET_CERT = {
    "id": "https://sample-vault.vault.azure.net/certificates/selfSignedCert01/f60f2a4f8ae442cfb41ca2090bd4b769",
    "kid": "https://sample-vault.vault.azure.net/keys/selfSignedCert01/f60f2a4f8ae442cfb41ca2090bd4b769",
    "sid": "https://sample-vault.vault.azure.net/secrets/selfSignedCert01/f60f2a4f8ae442cfb41ca2090bd4b769",
    "x5t": "fLi3U52HunIVNXubkEnf8tP6Wbo", "cer": base64.b64encode(_CERT.public_bytes(serialization.Encoding.DER)).decode(),
    "attributes": {"enabled": True, "nbf": 1430344421, "exp": 2208988799, "created": 1493938289, "updated": 1493938291,
                   "recoveryLevel": "Recoverable+Purgeable"},
    "policy": {"id": "https://sample-vault.vault.azure.net/certificates/selfSignedCert01/policy",
               "key_props": {"exportable": True, "kty": "RSA", "key_size": 2048, "reuse_key": False},
               "secret_props": {"contentType": "application/x-pkcs12"},
               "x509_props": {"subject": "CN=KeyVaultTest", "ekus": [], "key_usage": [], "validity_months": 297},
               "lifetime_actions": [{"trigger": {"lifetime_percentage": 80}, "action": {"action_type": "EmailContacts"}}],
               "issuer": {"name": "Self"}, "attributes": {"enabled": True, "created": 1493938289, "updated": 1493938291}}}


class Recorder:
    """httpx transport that answers from a route table and records every request (method, url, auth, form)."""

    def __init__(self, routes):
        self.routes, self.seen = routes, []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode()) if request.method == "POST" else {}
        self.seen.append({"method": request.method, "url": str(request.url), "host": request.url.host,
                          "auth": request.headers.get("authorization"), "form": form})
        for match, answer in self.routes:
            if match(request, form):
                status, body = answer(request, form) if callable(answer) else answer
                return httpx.Response(status, json=body)
        return httpx.Response(404, json={"error": {"code": "NotRecorded", "message": str(request.url)}})


def _path(prefix):
    return lambda r, _f: str(r.url).startswith(prefix)


def _at(url):
    """Exact scheme://host/path (Google list calls carry only pageToken in the query)."""
    return lambda r, _f: f"{r.url.scheme}://{r.url.host}{r.url.path}" == url


def _azure_routes(*, vaults=(SAMPLE_VAULT,), secret_ok=True):
    kv = "https://sample-vault.vault.azure.net"

    def token(_r, form):
        if form.get("client_secret", [""])[0] != CLIENT_SECRET and "client_assertion" not in form:
            return 401, {"error": "invalid_client", "error_description": "AADSTS7000215: Invalid client secret provided. "
                         "Ensure the secret being sent in the request is the client secret value. Trace ID: 0000",
                         "error_codes": [7000215]}
        scope = form["scope"][0]
        return 200, {"token_type": "Bearer", "expires_in": 3599, "ext_expires_in": 3599,
                     "access_token": KV_TOKEN if scope.startswith("https://vault.azure.net") else ARM_TOKEN}

    return [
        (_path(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"), token),
        (_path("https://management.azure.com/subscriptions?"), (200, {"value": [
            {"id": f"/subscriptions/{SUB}", "subscriptionId": SUB, "tenantId": TENANT, "displayName": "Example", "state": "Enabled"}]})),
        (_path(f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.KeyVault/vaults?"),
         (200, {"value": list(vaults)})),
        (_path(f"{kv}/keys?"), (200, {"value": [
            {"kid": f"{kv}/keys/CreateSoftKeyTest", "attributes": {"enabled": True, "created": 1493937656, "updated": 1493937656,
                                                                    "recoveryLevel": "Recoverable+Purgeable"}},
            {"kid": f"{kv}/keys/selfSignedCert01", "managed": True, "attributes": {"enabled": True}},
            {"kid": "https://other-vault.vault.azure.net/keys/elsewhere", "attributes": {"enabled": True}}]})),
        (_path(f"{kv}/keys/CreateSoftKeyTest/rotationpolicy?"), (200, ROTATION)),
        (_path(f"{kv}/keys/CreateSoftKeyTest?"), (200, GET_KEY)),
        (_path(f"{kv}/certificates?"), (200, {"value": [{"id": f"{kv}/certificates/selfSignedCert01", "x5t": "fLi3U52HunIVNXubkEnf8tP6Wbo",
                                                         "attributes": {"enabled": True}}]})),
        (_path(f"{kv}/certificates/selfSignedCert01?"), (200, GET_CERT)),
        (_path(f"{kv}/secrets?"), (200 if secret_ok else 403, {"value": [
            {"contentType": "plainText", "id": f"{kv}/secrets/listsecrettest0",
             "attributes": {"enabled": True, "created": 1482189047, "updated": 1482189047}},
            {"contentType": "application/x-pkcs12", "id": f"{kv}/secrets/selfSignedCert01", "managed": True,
             "attributes": {"enabled": True}}]} if secret_ok else
            {"error": {"code": "Forbidden", "message": "Caller is not authorized", "innererror": {"code": "ForbiddenByRbac"}}})),
        (_path("https://locked-vault.vault.azure.net/"), (403, FIREWALL_403)),
        *_ARM_EMPTY,
    ]


# Control-plane services the collector also lists (test_cbom_azure_gcp_controlplane.py has their documented bodies);
# by default each answers an empty documented list ({"value": []}), so the Key Vault tests above stay about Key Vault.
_ARM_EMPTY = [(_path(f"https://management.azure.com/subscriptions/{SUB}/providers/{rp}?"), (200, {"value": []}))
              for rp in ("Microsoft.Storage/storageAccounts", "Microsoft.Web/sites", "Microsoft.Web/certificates",
                         "Microsoft.Network/applicationGateways", "Microsoft.Cdn/profiles", "Microsoft.Sql/servers")]


AZ_CFG = {"tenant_id": TENANT, "client_id": CLIENT, "subscription_ids": [], "credential_type": "client_secret"}


def _azure(routes, cfg=None, secrets=None):
    rec = Recorder(routes)
    found: list[dict] = []
    out = azure_collect.collect_azure(1, cfg or AZ_CFG, secrets or {"client_secret": CLIENT_SECRET}, found.append, lambda: None,
                                      transport=httpx.MockTransport(rec))
    return out, found, rec


def test_azure_key_vault_inventory_from_documented_samples():
    out, found, rec = _azure(_azure_routes(vaults=(SAMPLE_VAULT, LOCKED_VAULT)))
    vaults = {a["name"]: a for a in found if a["type"] == "key_vault"}
    sample = vaults["sample-vault"]["facts"]
    assert sample["purge_protection"] is False and sample["internet_facing"] is True and sample["sku"] == "premium"
    assert classify("key_vault", None, None, None, sample)["finding_codes"] == ["KV_NO_PURGE_PROTECTION", "KV_PUBLIC_NETWORK"]
    locked = vaults["locked-vault"]["facts"]
    assert locked["internet_facing"] is False and classify("key_vault", None, None, None, locked)["finding_codes"] == []

    key = next(a for a in found if a["type"] == "kms_key")
    assert key["algorithm"] == "RSA" and key["key_size"] == 2048 and key["location"] == "https://myvault.vault.azure.net/keys/CreateSoftKeyTest"
    assert key["facts"]["rotation_enabled"] is True and key["facts"]["rotation_interval"] == "P90D" and key["facts"]["hsm_backed"] is False
    assert "n" not in key["facts"] and KEY_N not in repr(found)  # only the size of the public key is kept
    verdict = classify("kms_key", key["algorithm"], key["key_size"], None, key["facts"])
    assert verdict["quantum_vulnerable"] is True and verdict["finding_codes"] == ["QUANTUM_VULNERABLE"]

    cert = next(a for a in found if a["type"] == "certificate")
    assert cert["facts"]["issuer_name"] == "Self" and cert["facts"]["auto_renew"] is False and cert["key_size"] == 2048
    secret = next(a for a in found if a["type"] == "cloud_secret")
    assert secret["name"] == "listsecrettest0" and secret["facts"]["content_type"] == "plainText"
    assert len([a for a in found if a["type"] == "cloud_secret"]) == 1  # the certificate's backing secret is skipped

    gaps = [a for a in found if a["type"] == "coverage"]
    assert {g["facts"]["status"] for g in gaps} == {"blocked_by_firewall"} and len(gaps) == 3  # keys, certificates, secrets
    assert out["targets"][0]["status"] == "error" and "locked-vault" in out["targets"][0]["error"]

    # the ARM token only ever went to ARM, the vault token only to vault hosts; no secret value or other vault was read
    for req in rec.seen:
        if req["auth"] == f"Bearer {ARM_TOKEN}":
            assert req["host"] == "management.azure.com"
        if req["auth"] == f"Bearer {KV_TOKEN}":
            assert req["host"].endswith(".vault.azure.net")
    paths = [urlsplit(r["url"]).path for r in rec.seen]
    assert "/secrets/listsecrettest0" not in paths and not any("other-vault" in r["url"] for r in rec.seen)
    assert CLIENT_SECRET not in repr(found)


def test_azure_wrong_secret_and_denied_secrets_list():
    with pytest.raises(azure_collect.AzureCollectError, match="AADSTS7000215") as err:
        _azure(_azure_routes(), secrets={"client_secret": "wrong"})
    assert "Trace ID" not in str(err.value)
    _out, found, _rec = _azure(_azure_routes(secret_ok=False))
    gap = next(a for a in found if a["type"] == "coverage")
    assert gap["facts"]["status"] == "denied" and "Key Vault Reader" in gap["facts"]["detail"]


def test_azure_certificate_credential_signs_a_verifiable_client_assertion():
    pem = (_CERT_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
           + _CERT.public_bytes(serialization.Encoding.PEM).decode())
    assert validate_secret_value("client_certificate", pem)
    rec = Recorder(_azure_routes())
    with cloud_http.CloudHttp(httpx.MockTransport(rec)) as http:
        azure_collect.token(http, {**AZ_CFG, "credential_type": "certificate"}, {"client_certificate": pem}, "https://management.azure.com/.default")
    form = rec.seen[0]["form"]
    assert form["client_assertion_type"] == ["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"] and "client_secret" not in form
    head, body, sig = form["client_assertion"][0].split(".")
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    header, claims = json.loads(pad(head)), json.loads(pad(body))
    assert header["alg"] == "RS256" and header["x5t"] == base64.urlsafe_b64encode(
        hashlib.sha1(_CERT.public_bytes(serialization.Encoding.DER)).digest()).rstrip(b"=").decode()  # noqa: S324
    assert claims["aud"] == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token" and claims["iss"] == claims["sub"] == CLIENT
    _CERT.public_key().verify(pad(sig), f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert KINDS["azure_subscription"].secret_fields(KINDS["azure_subscription"].model.model_validate(
        {**AZ_CFG, "credential_type": "certificate"})) == {"client_certificate"}


@pytest.mark.parametrize("bad", ["not pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"])
def test_azure_certificate_secret_is_checked_at_save(bad):
    with pytest.raises(ValueError, match="client_certificate"):
        validate_secret_value("client_certificate", bad)


def test_next_links_and_item_urls_never_leave_their_host():
    assert not cloud_http.host_allowed("https://evil.example/keys")
    assert not cloud_http.host_allowed("http://sample-vault.vault.azure.net/keys")
    assert not cloud_http.host_allowed("https://sample-vault.vault.azure.net.evil.example/")
    assert not cloud_http.host_allowed("https://user:pw@management.azure.com/")
    assert cloud_http.host_allowed("https://sample-vault.vault.azure.net/keys?api-version=7.4")
    routes = _azure_routes()
    routes.insert(1, (_path("https://management.azure.com/subscriptions?"), (200, {
        "value": [{"subscriptionId": SUB, "state": "Enabled"}], "nextLink": "https://evil.example/subscriptions?page=2"})))
    with pytest.raises(azure_collect.AzureCollectError, match="NextLinkHostChanged"):
        _azure(routes)


# ----------------------------------------------------------------------------- Google Cloud
PROJECT = "payments-prod"
GCP_TOKEN = "ya29.c.recorded-token"
_SA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SA_JSON = json.dumps({
    "type": "service_account", "project_id": PROJECT, "private_key_id": "3f1c2b",
    "private_key": _SA_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()).decode(),
    "client_email": f"zs-cbom@{PROJECT}.iam.gserviceaccount.com", "client_id": "1234567890",
    "token_uri": "https://evil.example/token",  # must never be used
})
GCP_CFG = {"organization_id": None, "project_ids": [PROJECT], "service_account_email": f"zs-cbom@{PROJECT}.iam.gserviceaccount.com"}
_CA_KEY, _CA = _self_signed("Payments Root CA", key=ec.generate_private_key(ec.SECP384R1()), ca=True, sig=hashes.SHA384())
LOC = f"projects/{PROJECT}/locations/asia-south1"
SERVICE_DISABLED = {"error": {"code": 403, "status": "PERMISSION_DENIED",
                              "message": "Certificate Authority Service API has not been used in project 123 before or it is disabled.",
                              "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED",
                                           "domain": "googleapis.com", "metadata": {"service": "privateca.googleapis.com",
                                                                                    "consumer": "projects/123"}}]}}


def _gcp_routes(*, cas_disabled=False):
    def token(_r, form):
        return 200, {"access_token": GCP_TOKEN, "expires_in": 3599, "token_type": "Bearer"}

    kms_keys = {"cryptoKeys": [
        {"name": f"{LOC}/keyRings/payments/cryptoKeys/no-rotation", "purpose": "ENCRYPT_DECRYPT", "createTime": "2026-01-02T03:04:05Z",
         "primary": {"name": f"{LOC}/keyRings/payments/cryptoKeys/no-rotation/cryptoKeyVersions/1", "state": "ENABLED",
                     "protectionLevel": "SOFTWARE", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "generateTime": "2026-01-02T03:04:05Z"},
         "versionTemplate": {"protectionLevel": "SOFTWARE", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
         "destroyScheduledDuration": "2592000s"},
        {"name": f"{LOC}/keyRings/payments/cryptoKeys/rotated", "purpose": "ENCRYPT_DECRYPT", "rotationPeriod": "7776000s",
         "nextRotationTime": "2027-01-01T00:00:00Z",
         "primary": {"name": "v1", "state": "ENABLED", "protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"},
         "versionTemplate": {"protectionLevel": "HSM", "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}},
        {"name": f"{LOC}/keyRings/payments/cryptoKeys/signer", "purpose": "ASYMMETRIC_SIGN",
         "versionTemplate": {"protectionLevel": "HSM", "algorithm": "RSA_SIGN_PSS_2048_SHA256"}},
        {"name": f"{LOC}/keyRings/payments/cryptoKeys/ec-signer", "purpose": "ASYMMETRIC_SIGN",
         "versionTemplate": {"protectionLevel": "SOFTWARE", "algorithm": "EC_SIGN_P256_SHA256"}}], "totalSize": 4}
    ca = {"name": f"{LOC}/caPools/root-pool/certificateAuthorities/root-ca", "type": "SELF_SIGNED", "tier": "ENTERPRISE",
          "state": "ENABLED", "lifetime": "315576000s", "keySpec": {"algorithm": "EC_P384_SHA384"},
          "pemCaCertificates": [_CA.public_bytes(serialization.Encoding.PEM).decode()], "createTime": "2026-01-01T00:00:00Z"}
    return [
        (_at("https://oauth2.googleapis.com/token"), token),
        (_at(f"https://cloudkms.googleapis.com/v1/projects/{PROJECT}/locations"),
         (200, {"locations": [{"name": LOC, "locationId": "asia-south1"}, {"name": f"projects/{PROJECT}/locations/global", "locationId": "global"}]})),
        (_at(f"https://cloudkms.googleapis.com/v1/{LOC}/keyRings"), (200, {"keyRings": [{"name": f"{LOC}/keyRings/payments"}], "totalSize": 1})),
        (_at(f"https://cloudkms.googleapis.com/v1/projects/{PROJECT}/locations/global/keyRings"), (200, {})),
        (_at(f"https://cloudkms.googleapis.com/v1/{LOC}/keyRings/payments/cryptoKeys"), (200, kms_keys)),
        (_at(f"https://privateca.googleapis.com/v1/projects/{PROJECT}/locations"),
         (403, SERVICE_DISABLED) if cas_disabled else (200, {"locations": [{"name": LOC, "locationId": "asia-south1"}]})),
        (_at(f"https://privateca.googleapis.com/v1/{LOC}/caPools"), (200, {"caPools": [{"name": f"{LOC}/caPools/root-pool", "tier": "ENTERPRISE"}]})),
        (_at(f"https://privateca.googleapis.com/v1/{LOC}/caPools/root-pool/certificateAuthorities"), (200, {"certificateAuthorities": [ca]})),
        (_at(f"https://secretmanager.googleapis.com/v1/projects/{PROJECT}/secrets"), (200, {"secrets": [
            {"name": "projects/123/secrets/db-password", "createTime": "2026-02-01T00:00:00Z", "replication": {"automatic": {}}, "etag": "\"1\""},
            {"name": "projects/123/secrets/api-key", "replication": {"userManaged": {"replicas": [
                {"location": "asia-south1", "customerManagedEncryption": {"kmsKeyName": f"{LOC}/keyRings/payments/cryptoKeys/rotated"}}]}},
             "rotation": {"rotationPeriod": "2592000s", "nextRotationTime": "2026-12-01T00:00:00Z"}, "topics": [{"name": "projects/123/topics/rot"}]}],
            "totalSize": 2})),
        (_at("https://cloudresourcemanager.googleapis.com/v3/projects:search"),
         (200, {"projects": [{"name": "projects/123", "projectId": PROJECT, "state": "ACTIVE", "parent": "organizations/42"},
                             {"name": "projects/999", "projectId": "old-sandbox", "state": "DELETE_REQUESTED"}]})),
        *_GCP_EMPTY,
    ]


# The other services the collector reads answer empty documented lists by default (Google omits empty repeated fields):
# key versions, Certificate Manager, Compute Engine load-balancer TLS and Cloud Storage.
_GCP_EMPTY = [
    (lambda r, _f: r.url.host == "cloudkms.googleapis.com" and r.url.path.endswith("/cryptoKeyVersions"), (200, {})),
    (lambda r, _f: r.url.host in ("certificatemanager.googleapis.com", "compute.googleapis.com", "storage.googleapis.com"),
     (200, {})),
]


def _gcp(routes, cfg=None, key=SA_JSON):
    rec = Recorder(routes)
    found: list[dict] = []
    out = gcp_collect.collect_gcp(1, cfg or GCP_CFG, {"service_account_key": key}, found.append, lambda: None,
                                  transport=httpx.MockTransport(rec))
    return out, found, rec


def test_gcp_kms_cas_and_secret_manager_from_documented_shapes():
    out, found, rec = _gcp(_gcp_routes())
    assert out["targets"][0]["status"] == "ok" and out["targets"][0]["services"] == {
        "cloudkms": "ok", "privateca": "ok", "secretmanager": "ok", "certificatemanager": "ok", "compute": "ok", "storage": "ok"}
    keys = {a["name"]: a for a in found if a["type"] == "kms_key"}
    no_rot = keys["no-rotation"]
    assert no_rot["algorithm"] == "AES" and no_rot["key_size"] == 256 and no_rot["facts"]["rotation_enabled"] is False
    assert classify("kms_key", no_rot["algorithm"], no_rot["key_size"], None, no_rot["facts"])["finding_codes"] == ["KMS_NO_ROTATION"]
    assert classify("kms_key", "AES", 256, None, keys["rotated"]["facts"])["finding_codes"] == []
    signer = keys["signer"]
    assert (signer["algorithm"], signer["key_size"], signer["facts"]["rotation_enabled"]) == ("RSA", 2048, None)
    assert classify("kms_key", "RSA", 2048, None, signer["facts"])["quantum_vulnerable"] is True
    assert (keys["ec-signer"]["algorithm"], keys["ec-signer"]["key_size"]) == ("ECDSA", 256)
    ca = next(a for a in found if a["type"] == "cloud_ca")
    assert ca["algorithm"] == "ECDSA" and ca["key_size"] == 384 and ca["facts"]["tier"] == "ENTERPRISE"
    assert classify("cloud_ca", ca["algorithm"], ca["key_size"], None, ca["facts"])["finding_codes"] == ["QUANTUM_VULNERABLE"]
    secrets = {a["name"]: a["facts"] for a in found if a["type"] == "cloud_secret"}
    assert secrets["db-password"]["rotation_enabled"] is False and secrets["db-password"]["kms_key_id"] == "google-managed"
    assert secrets["api-key"]["kms_key_id"].endswith("cryptoKeys/rotated") and secrets["api-key"]["rotation_enabled"] is True
    # the token went to the fixed Google endpoint (never the key file's token_uri) and only Google hosts saw it
    assert rec.seen[0]["url"] == "https://oauth2.googleapis.com/token" and not any("evil" in r["url"] for r in rec.seen)
    assert all(r["host"].endswith(".googleapis.com") for r in rec.seen)
    assert not any(":access" in r["url"] or "/versions" in r["url"] for r in rec.seen)  # never a secret payload
    head, body, sig = rec.seen[0]["form"]["assertion"][0].split(".")
    pad = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))  # noqa: E731
    claims = json.loads(pad(body))
    assert claims["aud"] == "https://oauth2.googleapis.com/token" and claims["scope"] == "https://www.googleapis.com/auth/cloud-platform"
    _SA_KEY.public_key().verify(pad(sig), f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert "PRIVATE KEY" not in repr(found)


def test_gcp_disabled_api_is_not_enabled_coverage_and_org_search_skips_inactive_projects():
    out, found, _rec = _gcp(_gcp_routes(cas_disabled=True), cfg={**GCP_CFG, "project_ids": [], "organization_id": "42"})
    assert [t["target"] for t in out["targets"]] == [f"gcp:{PROJECT}"]
    gap = next(a for a in found if a["type"] == "coverage")
    assert gap["facts"]["status"] == "not_enabled" and "SERVICE_DISABLED" in gap["facts"]["detail"]
    assert out["targets"][0]["services"]["privateca"] == "not_enabled" and out["targets"][0]["status"] == "error"


def test_gcp_key_must_belong_to_the_configured_account():
    other = json.loads(SA_JSON)
    other["client_email"] = "someone@else-project.iam.gserviceaccount.com"
    with pytest.raises(gcp_collect.GcpCollectError, match="different service account"):
        _gcp(_gcp_routes(), key=json.dumps(other))
    with pytest.raises(ValueError, match="service_account_key"):
        validate_secret_value("service_account_key", json.dumps({"type": "authorized_user"}))
    assert validate_secret_value("service_account_key", SA_JSON) == SA_JSON


def test_validation_calls_sign_in_and_list_once():
    rec = Recorder(_azure_routes())
    out = azure_collect.test_azure({**AZ_CFG, "subscription_ids": [SUB]}, {"client_secret": CLIENT_SECRET}, transport=httpx.MockTransport(rec))
    assert out["status"] == "passed" and [c["status"] for c in out["checks"]] == ["pass"] * 9  # + one probe per ARM service
    assert not any(".vault.azure.net" in r["host"] for r in rec.seen)  # validation never touches vault contents
    bad = azure_collect.test_azure(AZ_CFG, {"client_secret": "nope"}, transport=httpx.MockTransport(Recorder(_azure_routes())))
    assert bad["status"] == "failed" and "AADSTS7000215" in bad["message"]
    rec = Recorder(_gcp_routes())
    out = gcp_collect.test_gcp(GCP_CFG, {"service_account_key": SA_JSON}, transport=httpx.MockTransport(rec))
    assert out["status"] == "passed" and "2 location(s)" in out["message"] and len(rec.seen) == 5  # + 3 service probes


def test_kinds_are_collectable_by_the_cloud_worker():
    for kind in ("azure_subscription", "gcp_project"):
        spec = KINDS[kind]
        assert spec.node_less and spec.collectable(None) and not spec.needs_node(None)


def test_long_runs_sign_in_again_instead_of_using_an_expired_token(monkeypatch):
    monkeypatch.setattr(azure_collect, "TOKEN_REUSE_S", -1)  # every use counts as "older than the reuse window"
    out, found, rec = _azure(_azure_routes())
    sign_ins = [r for r in rec.seen if r["host"] == "login.microsoftonline.com"]
    assert out["targets"][0]["status"] == "ok" and len(sign_ins) >= 3 and any(a["type"] == "kms_key" for a in found)
    monkeypatch.setattr(gcp_collect, "TOKEN_REUSE_S", -1)
    out, _found, rec = _gcp(_gcp_routes())
    assert out["targets"][0]["status"] == "ok" and sum(r["host"] == "oauth2.googleapis.com" for r in rec.seen) == 2
