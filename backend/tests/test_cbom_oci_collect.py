"""Oracle Cloud (OCI) CBOM source: request signing, the collector over every service, validation, the API (generated
key pair, public facts, Resource Manager stack, reader script) and collection by the cloud worker.

The fake OCI answers below follow the documented REST shapes (httpx.MockTransport, no network): every request must carry
a valid OCI signature (version 1, headers "date (request-target) host", RSA-SHA256), checked against the source's public
key, else the fake answers 401 NotAuthenticated as OCI does.
* Identity 20160918: ListRegionSubscriptions (array of RegionSubscription), ListCompartments (array of Compartment).
* Vault 20180608: ListVaults (array of VaultSummary with managementEndpoint), ListKeys / GetKey (keyShape algorithm,
  length in bytes, curveId; protectionMode; isAutoRotationEnabled) / ListKeyVersions, ListSecrets (SecretSummary).
* Certificates 20210224: ListCertificates / ListCertificateAuthorities ({"items": [...]} collections).
* Load Balancing 20170115: ListLoadBalancers (listeners with sslConfiguration, certificates, sslCipherSuites) and
  ListSSLCipherSuites (array).
* Object Storage: GetNamespace (a JSON string), ListBuckets (array of BucketSummary), GetBucket (kmsKeyId).
* Errors: {"code": "NotAuthorizedOrNotFound", "message": ...} with 404, {"code": "NotAuthenticated"} with 401.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cbom_oci_collect.py -q
"""
from __future__ import annotations

import base64
import datetime as dt
import io
import json
import re
import sys
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from backend.utilities.cbom_sources import cloud_http, oci_collect, oci_keys  # noqa: E402
from backend.utilities.cbom_sources.asset_keys import cloud_resource_id  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.kinds import KINDS, OciConfig, validate_secret_value  # noqa: E402

TENANCY = "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq"
USER = "ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq"
COMP = "ocid1.compartment.oc1..aaaaaaaaxbm2t7mi6xa6yd3k3ad7wr5pfbtoz5jnbsmxbpsqu3nbkjuq4ndq"
HOME, OTHER = "us-ashburn-1", "eu-frankfurt-1"
VAULT = "ocid1.vault.oc1.iad.bbqfl5ymaaaaa.abuwcljrz2zrtvxyq5k3mr2rx5xwkoqbvvhxiq4bmlz5jinfdvo3rdgxjbka"
MGMT = "https://bbqfl5ymaaaaa-management.kms.us-ashburn-1.oraclecloud.com"
AES_KEY = "ocid1.key.oc1.iad.bbqfl5ymaaaaa.abuwcljsaes256keyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
RSA_KEY = "ocid1.key.oc1.iad.bbqfl5ymaaaaa.abuwcljsrsa2048keyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EC_KEY = "ocid1.key.oc1.iad.bbqfl5ymaaaaa.abuwcljsecp384keyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CERT_ID = "ocid1.certificate.oc1.iad.amaaaaaaexamplecertaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
CA_ID = "ocid1.certificateauthority.oc1.iad.amaaaaaaexamplecaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
SECRET_ID = "ocid1.vaultsecret.oc1.iad.amaaaaaaexamplesecretaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
LB_ID = "ocid1.loadbalancer.oc1.iad.aaaaaaaaexamplelbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
PRIVATE_PEM = oci_keys.generate_private_key_pem()
FINGERPRINT, PUBLIC_PEM = oci_keys.public_facts(PRIVATE_PEM)
CFG = {"tenancy_ocid": TENANCY, "user_ocid": USER, "home_region": HOME, "regions": [], "compartment_ocids": [],
       "key_origin": "uploaded"}
SECRETS = {"api_signing_key": PRIVATE_PEM}


def _lb_cert_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "shop.example.com")])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


LB_CERT = _lb_cert_pem()


def _routes(region: str) -> list[tuple[str, object]]:
    ident = f"https://identity.{HOME}.oci.oraclecloud.com/20160918"
    return [
        (f"{ident}/tenancies/{TENANCY}/regionSubscriptions", [
            {"regionKey": "IAD", "regionName": HOME, "status": "READY", "isHomeRegion": True},
            {"regionKey": "FRA", "regionName": OTHER, "status": "READY", "isHomeRegion": False}]),
        (f"{ident}/compartments", [{"id": COMP, "name": "prod", "compartmentId": TENANCY, "lifecycleState": "ACTIVE"}]),
        (f"https://kms.{region}.oraclecloud.com/20180608/vaults", lambda q: [
            {"id": VAULT, "displayName": "prod-vault", "vaultType": "VIRTUAL_PRIVATE", "lifecycleState": "ACTIVE",
             "compartmentId": COMP, "managementEndpoint": MGMT, "cryptoEndpoint": MGMT.replace("management", "crypto")}]
            if region == HOME and q.get("compartmentId") == COMP else []),
        (f"{MGMT}/20180608/keys/{AES_KEY}/keyVersions", [{"id": "ocid1.keyversion.oc1.iad.v1", "keyId": AES_KEY,
                                                          "lifecycleState": "ENABLED", "origin": "INTERNAL",
                                                          "timeCreated": "2026-01-01T00:00:00Z"}]),
        (f"{MGMT}/20180608/keys/{RSA_KEY}/keyVersions", []),
        (f"{MGMT}/20180608/keys/{EC_KEY}/keyVersions", (404, {"code": "NotAuthorizedOrNotFound", "message": "nope"})),
        (f"{MGMT}/20180608/keys/{AES_KEY}", {"id": AES_KEY, "displayName": "data-key", "compartmentId": COMP,
                                             "keyShape": {"algorithm": "AES", "length": 32}, "protectionMode": "HSM",
                                             "lifecycleState": "ENABLED", "isAutoRotationEnabled": False,
                                             "currentKeyVersion": "ocid1.keyversion.oc1.iad.v1", "timeCreated": "2026-01-01T00:00:00Z"}),
        (f"{MGMT}/20180608/keys/{RSA_KEY}", {"id": RSA_KEY, "displayName": "sign-key", "compartmentId": COMP,
                                             "keyShape": {"algorithm": "RSA", "length": 256}, "protectionMode": "SOFTWARE",
                                             "lifecycleState": "ENABLED"}),
        (f"{MGMT}/20180608/keys/{EC_KEY}", {"id": EC_KEY, "displayName": "ec-key", "compartmentId": COMP,
                                            "keyShape": {"algorithm": "ECDSA", "length": 48, "curveId": "NIST_P384"},
                                            "protectionMode": "HSM", "lifecycleState": "ENABLED",
                                            "isAutoRotationEnabled": True, "autoKeyRotationDetails": {"rotationIntervalInDays": 90}}),
        (f"{MGMT}/20180608/keys", lambda q: [
            {"id": AES_KEY, "displayName": "data-key", "algorithm": "AES", "protectionMode": "HSM", "lifecycleState": "ENABLED", "compartmentId": COMP},
            {"id": RSA_KEY, "displayName": "sign-key", "algorithm": "RSA", "protectionMode": "SOFTWARE", "lifecycleState": "ENABLED", "compartmentId": COMP},
            {"id": EC_KEY, "displayName": "ec-key", "algorithm": "ECDSA", "protectionMode": "HSM", "lifecycleState": "ENABLED", "compartmentId": COMP},
        ] if q.get("compartmentId") == COMP else []),
        (f"https://vaults.{region}.oci.oraclecloud.com/20180608/secrets", lambda q: [
            {"id": SECRET_ID, "secretName": "db-password", "vaultId": VAULT, "keyId": AES_KEY, "compartmentId": COMP,
             "lifecycleState": "ACTIVE", "timeCreated": "2026-01-01T00:00:00Z"}] if region == HOME and q.get("compartmentId") == COMP else []),
        (f"https://certificatesmanagement.{region}.oci.oraclecloud.com/20210224/certificates", lambda q: {"items": [
            {"id": CERT_ID, "name": "api-cert", "compartmentId": COMP, "lifecycleState": "ACTIVE",
             "configType": "ISSUED_BY_INTERNAL_CA", "keyAlgorithm": "RSA2048", "signatureAlgorithm": "SHA256_WITH_RSA",
             "issuerCertificateAuthorityId": CA_ID, "subject": {"commonName": "api.example.com"},
             "currentVersionSummary": {"validity": {"timeOfValidityNotBefore": "2026-01-01T00:00:00Z",
                                                    "timeOfValidityNotAfter": "2026-02-01T00:00:00Z"}}}]
            if region == HOME and q.get("compartmentId") == COMP else []}),
        (f"https://certificatesmanagement.{region}.oci.oraclecloud.com/20210224/certificateAuthorities", lambda q: {"items": [
            {"id": CA_ID, "name": "root-ca", "compartmentId": COMP, "lifecycleState": "ACTIVE",
             "configType": "ROOT_CA_GENERATED_INTERNALLY", "signingAlgorithm": "SHA384_WITH_ECDSA", "kmsKeyId": EC_KEY,
             "subject": {"commonName": "Example Root CA"},
             "currentVersionSummary": {"validity": {"timeOfValidityNotBefore": "2026-01-01T00:00:00Z",
                                                    "timeOfValidityNotAfter": "2036-01-01T00:00:00Z"}}}]
            if region == HOME and q.get("compartmentId") == COMP else []}),
        (f"https://iaas.{region}.oraclecloud.com/20170115/loadBalancers/{LB_ID}/sslCipherSuites", [
            {"name": "oci-compatible-ssl-cipher-suite-v1", "ciphers": ["ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA", "DES-CBC3-SHA"]}]),
        (f"https://iaas.{region}.oraclecloud.com/20170115/loadBalancers", lambda q: [
            {"id": LB_ID, "displayName": "shop-lb", "compartmentId": COMP, "isPrivate": False, "shapeName": "flexible",
             "listeners": {"https": {"name": "https", "port": 443, "protocol": "HTTP",
                                     "sslConfiguration": {"protocols": ["TLSv1.1", "TLSv1.2"],
                                                          "cipherSuiteName": "oci-compatible-ssl-cipher-suite-v1",
                                                          "certificateName": "shop-cert"}},
                           "http": {"name": "http", "port": 80, "protocol": "HTTP"}},
             "certificates": {"shop-cert": {"certificateName": "shop-cert", "publicCertificate": LB_CERT}},
             "sslCipherSuites": {}}] if region == HOME and q.get("compartmentId") == COMP else []),
        (f"https://objectstorage.{region}.oraclecloud.com/n/acme/b/backups", {"name": "backups", "kmsKeyId": AES_KEY,
                                                                              "publicAccessType": "NoPublicAccess"}),
        (f"https://objectstorage.{region}.oraclecloud.com/n/acme/b/logs", {"name": "logs", "kmsKeyId": None,
                                                                           "publicAccessType": "NoPublicAccess"}),
        (f"https://objectstorage.{region}.oraclecloud.com/n/acme/b", lambda q: [
            {"name": "backups", "namespace": "acme", "compartmentId": COMP},
            {"name": "logs", "namespace": "acme", "compartmentId": COMP}] if region == HOME and q.get("compartmentId") == COMP else []),
        (f"https://objectstorage.{region}.oraclecloud.com/n/", "acme"),
    ]


class FakeOci:
    """Answers signed requests; 401 for a missing or wrong signature (a different key, a tampered target)."""

    def __init__(self, public_pem: str = PUBLIC_PEM, overrides: dict[str, object] | None = None):
        self.public = serialization.load_pem_public_key(public_pem.encode())
        self.overrides = overrides or {}
        self.calls: list[str] = []

    def _verify(self, request: httpx.Request) -> bool:
        auth = request.headers.get("authorization", "")
        fields = dict(re.findall(r'(\w+)="([^"]*)"', auth))
        if fields.get("version") != "1" or fields.get("algorithm") != "rsa-sha256" \
                or fields.get("headers") != "date (request-target) host":
            return False
        if fields.get("keyId") != f"{TENANCY}/{USER}/{FINGERPRINT}":
            return False
        target = request.url.raw_path.decode()
        text = f"date: {request.headers['date']}\n(request-target): {request.method.lower()} {target}\nhost: {request.url.host}"
        try:
            self.public.verify(base64.b64decode(fields["signature"]), text.encode(), padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            return False
        return True

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url).split("?", 1)[0]
        self.calls.append(str(request.url))
        if not self._verify(request):
            return httpx.Response(401, json={"code": "NotAuthenticated", "message": "The required information to complete authentication was not provided or was incorrect."})
        query = {k: v[0] for k, v in parse_qs(urlsplit(str(request.url)).query).items()}
        region = urlsplit(url).hostname.split(".")[1] if url.count(".") > 2 else HOME  # type: ignore[union-attr]
        if "management.kms" in url:
            region = HOME
        for prefix, body in list(self.overrides.items()) + _routes(region):
            if url == prefix:
                break
        else:
            return httpx.Response(404, json={"code": "NotAuthorizedOrNotFound", "message": f"no route {url}"})
        if callable(body):
            body = body(query)
        if isinstance(body, tuple):
            return httpx.Response(body[0], json=body[1])
        return httpx.Response(200, json=body)


def _collect(fake: FakeOci, cfg: dict | None = None):
    rows: list[dict] = []
    out = oci_collect.collect_oci(1, cfg or CFG, SECRETS, rows.append, lambda: None, transport=httpx.MockTransport(fake))
    return out, rows


# ------------------------------------------------------------------------------------------------------------ tests
def test_signature_is_verifiable_and_covers_the_exact_query():
    sign = oci_collect.signer(CFG, SECRETS)
    url = f"https://kms.{HOME}.oraclecloud.com/20180608/vaults?compartmentId={COMP}&limit=100"
    headers = sign("GET", url)
    request = httpx.Request("GET", url, headers=headers)
    assert FakeOci()._verify(request)
    tampered = httpx.Request("GET", url.replace("limit=100", "limit=1"), headers=headers)
    assert not FakeOci()._verify(tampered)  # the signature names the exact query
    assert not FakeOci(oci_keys.public_facts(oci_keys.generate_private_key_pem())[1])._verify(request)


def test_fingerprint_matches_openssl_md5_of_the_der_public_key():
    import hashlib

    der = oci_keys.load_private_key(PRIVATE_PEM).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert FINGERPRINT == ":".join(re.findall("..", hashlib.md5(der).hexdigest()))
    assert re.fullmatch(r"([0-9a-f]{2}:){15}[0-9a-f]{2}", FINGERPRINT)


def test_collect_reads_every_service_in_every_subscribed_region():
    fake = FakeOci()
    out, rows = _collect(fake)
    targets = {t["target"]: t for t in out["targets"]}
    assert set(targets) == {f"oci:{HOME}", f"oci:{OTHER}"}
    home = targets[f"oci:{HOME}"]
    assert home["services"] == {"kms": "ok", "secrets": "ok", "certificates": "ok", "loadbalancer": "ok", "objectstorage": "ok"}
    assert home["status"] == "ok" and targets[f"oci:{OTHER}"]["status"] == "ok"
    by_type: dict[str, list[dict]] = {}
    for row in rows:
        by_type.setdefault(row["type"], []).append(row)
    keys = {r["name"]: r for r in by_type["kms_key"]}
    assert (keys["data-key"]["algorithm"], keys["data-key"]["key_size"], keys["data-key"]["facts"]["key_spec"]) == ("AES", 256, "SYMMETRIC_DEFAULT")
    assert (keys["sign-key"]["algorithm"], keys["sign-key"]["key_size"], keys["sign-key"]["facts"]["key_spec"]) == ("RSA", 2048, "RSA_2048")
    assert (keys["ec-key"]["algorithm"], keys["ec-key"]["key_size"], keys["ec-key"]["facts"]["key_spec"]) == ("ECDSA", 384, "ECC_NIST_P384")
    assert keys["data-key"]["facts"]["hsm_backed"] is True and keys["data-key"]["facts"]["version_count"] == 1
    assert keys["ec-key"]["facts"]["versions_error"] and keys["ec-key"]["facts"]["rotation_period"] == "90d"
    assert keys["data-key"]["location"] == f"oci://{HOME}/kms/{AES_KEY}"
    ca = by_type["cloud_ca"][0]
    assert (ca["algorithm"], ca["key_size"]) == ("ECDSA", 384)  # from its Vault key, read in the same run
    cert = next(r for r in by_type["certificate"] if r["facts"]["service"] == "certificates")
    assert (cert["algorithm"], cert["key_size"], cert["facts"]["sig_alg"]) == ("RSA", 2048, "sha256WithRSAEncryption")
    assert by_type["cloud_secret"][0]["facts"]["kms_key_id"] == AES_KEY
    tls = by_type["load_balancer_tls"]
    assert len(tls) == 1 and tls[0]["facts"]["internet_facing"] is True and tls[0]["facts"]["static_rsa_kex"] is True
    assert "DES-CBC3-SHA" in tls[0]["facts"]["ciphers"]
    lb_cert = next(r for r in by_type["certificate"] if r["facts"]["service"] == "load_balancing")
    assert lb_cert["facts"]["in_use"] is True and lb_cert["key_size"] == 2048
    buckets = {r["name"]: r["facts"]["kms_key_id"] for r in by_type["storage_encryption"]}
    assert buckets == {"backups": AES_KEY, "logs": "oracle-managed"}
    # read-only: no crypto endpoint, no secret bundle, no certificate bundle, no object read
    assert not any(x in c for c in fake.calls for x in ("crypto.kms", "secretbundles", "Bundles", "/o/", "/encrypt", "/decrypt"))
    assert all(c.startswith("https://") for c in fake.calls)


def test_findings_from_the_rows():
    _out, rows = _collect(FakeOci())
    now = dt.datetime(2026, 1, 25)  # classify works in naive UTC; 7 days before the certificate's not_after
    codes = {r["name"]: classify(r["type"], r.get("algorithm"), r.get("key_size"), r.get("protocol"), r["facts"], now=now)["finding_codes"]
             for r in rows if r["type"] in ("kms_key", "load_balancer_tls", "certificate")}
    assert "KMS_NO_ROTATION" in codes["data-key"]  # auto-rotation off in a virtual private vault
    assert "KMS_NO_ROTATION" not in codes["sign-key"]  # no rotation setting read: unknown, not "off"
    assert "KMS_NO_ROTATION" not in codes["ec-key"]  # rotates every 90 days
    # a DEFAULT (virtual) vault has no auto-rotation: not applicable, never a finding (R-oci1)
    default_vault = {"id": VAULT, "vaultType": "DEFAULT", "displayName": "v"}
    row = oci_collect._key_asset({"id": AES_KEY, "keyShape": {"algorithm": "AES", "length": 32}, "isAutoRotationEnabled": False},
                                 default_vault, HOME, "oci:x", [], None, None)
    assert row["facts"]["rotation_enabled"] is None and row["facts"]["auto_rotation_supported"] is False
    assert "KMS_NO_ROTATION" not in classify("kms_key", "AES", 256, None, row["facts"], now=now)["finding_codes"]
    lb = next(k for k in codes if k.startswith("shop-lb"))
    assert {"PROTO_TLS11", "WEAK_CIPHER", "STATIC_RSA_KEX"} <= set(codes[lb])
    assert "CERT_EXPIRES_30D" in codes["CN=api.example.com"]


def test_one_unreadable_compartment_keeps_the_keys_of_the_others():
    """R-oci1: a stale configured compartment used to drop every Vault key of the region."""
    stale = "ocid1.compartment.oc1..aaaaaaaastalestalestalestalestalestalestalestalestale"
    deny = (404, {"code": "NotAuthorizedOrNotFound", "message": "x"})

    class Stale(FakeOci):
        def __call__(self, request):
            if stale in str(request.url) and "/vaults" in str(request.url):
                self.calls.append(str(request.url))
                return httpx.Response(*deny[:1], json=deny[1])
            return super().__call__(request)

    out, rows = _collect(Stale(), {**CFG, "regions": [HOME], "compartment_ocids": [COMP, stale]})
    keys = [r for r in rows if r["type"] == "kms_key"]
    assert len(keys) == 3 and next(r for r in rows if r["type"] == "cloud_ca")["key_size"] == 384
    assert out["targets"][0]["services"]["kms"] == "partial"
    assert any(r["location"] == f"oci://{HOME}#kms-compartments" and stale in r["facts"]["compartments"] for r in rows)


def test_static_ecdh_is_not_rsa_key_exchange():
    assert oci_collect._static_rsa(["AES128-SHA"]) and not oci_collect._static_rsa(["ECDH-RSA-AES128-SHA", "ECDHE-RSA-AES128-GCM-SHA256"])


def test_denied_service_is_a_named_gap_not_a_failed_region():
    deny = (404, {"code": "NotAuthorizedOrNotFound", "message": "Authorization failed or requested resource not found."})
    fake = FakeOci(overrides={f"https://vaults.{r}.oci.oraclecloud.com/20180608/secrets": deny for r in (HOME, OTHER)})
    out, rows = _collect(fake)
    home = next(t for t in out["targets"] if t["target"] == f"oci:{HOME}")
    assert home["services"]["secrets"] == "denied" and home["status"] == "partial"
    gap = next(r for r in rows if r["type"] == "coverage" and r["location"] == f"oci://{HOME}#secrets")
    assert "inspect secrets in tenancy" in gap["facts"]["detail"] and gap["facts"]["scope"] == [f"oci://{HOME}/secrets/"]


def test_wrong_key_is_refused_with_a_reason():
    other = oci_keys.generate_private_key_pem()
    with pytest.raises(oci_collect.OciCollectError, match="refused the API key"):
        oci_collect.collect_oci(1, CFG, {"api_signing_key": other}, lambda r: None, lambda: None,
                                transport=httpx.MockTransport(FakeOci()))
    with pytest.raises(oci_collect.OciCollectError, match="user OCID"):
        oci_collect.signer({**CFG, "user_ocid": None}, SECRETS)


def test_regions_fall_back_when_the_policy_lacks_inspect_tenancies():
    """R-oci2 M2: a 404 on ListRegionSubscriptions is a missing statement, not a refused key."""
    deny = (404, {"code": "NotAuthorizedOrNotFound", "message": "Authorization failed or requested resource not found."})
    over = {f"https://identity.{HOME}.oci.oraclecloud.com/20160918/tenancies/{TENANCY}/regionSubscriptions": deny}
    out, rows = _collect(FakeOci(overrides=over), {**CFG, "regions": [OTHER]})
    assert {t["target"] for t in out["targets"]} == {f"oci:{HOME}", f"oci:{OTHER}"}
    gap = next(r for r in rows if r["location"] == "oci://tenancy#regions")
    assert "inspect tenancies in tenancy" in gap["facts"]["detail"]
    checked = oci_collect.test_oci(CFG, SECRETS, transport=httpx.MockTransport(FakeOci(overrides=over)))
    assert checked["status"] == "passed" and checked["checks"][0]["status"] == "pass"
    assert any(c["status"] == "warning" and "inspect tenancies" in c["detail"] for c in checked["checks"])


def test_configured_scope_and_unsubscribed_region():
    fake = FakeOci()
    out, _rows = _collect(fake, {**CFG, "regions": [HOME, "ap-mumbai-1"], "compartment_ocids": [COMP]})
    assert {t["target"]: t["status"] for t in out["targets"]} == {"oci:ap-mumbai-1": "not_supported", f"oci:{HOME}": "ok"}
    assert not any("/compartments" in c for c in fake.calls)  # configured compartments: no tenancy-wide listing
    assert not any(OTHER in c for c in fake.calls)


def test_validation_passes_and_names_missing_policy_statements():
    ok = oci_collect.test_oci(CFG, SECRETS, transport=httpx.MockTransport(FakeOci()))
    assert ok["status"] == "passed" and ok["checks"][0]["check"] == "Signed in to Oracle Cloud"
    deny = (404, {"code": "NotAuthorizedOrNotFound", "message": "x"})
    partly = oci_collect.test_oci(CFG, SECRETS, transport=httpx.MockTransport(FakeOci(overrides={
        f"https://iaas.{HOME}.oraclecloud.com/20170115/loadBalancers": deny})))
    assert partly["status"] == "passed" and "read load-balancers in tenancy" in partly["message"]
    bad = oci_collect.test_oci(CFG, {"api_signing_key": oci_keys.generate_private_key_pem()},
                               transport=httpx.MockTransport(FakeOci()))
    assert bad["status"] == "failed" and "public key" in bad["message"]


def test_hosts_are_allow_listed():
    for url in (f"https://identity.{HOME}.oci.oraclecloud.com/20160918/compartments", MGMT + "/20180608/keys",
                f"https://objectstorage.{OTHER}.oraclecloud.com/n/", f"https://iaas.{HOME}.oraclecloud.com/20170115/loadBalancers"):
        assert cloud_http.host_allowed(url), url
    for url in ("https://evil.example.com/x", "http://kms.us-ashburn-1.oraclecloud.com/x",
                "https://kms.us-ashburn-1.oraclecloud.com.evil.com/x", "https://x-management.kms.evil.com/x"):
        assert not cloud_http.host_allowed(url), url


def test_config_and_secret_validation():
    cfg = OciConfig.model_validate({"tenancy_ocid": TENANCY, "home_region": "US-ASHBURN-1", "regions": [OTHER, OTHER]})
    assert cfg.home_region == HOME and cfg.regions == [OTHER] and cfg.user_ocid is None and cfg.key_origin == "generated"
    for bad in ({"tenancy_ocid": "ocid1.user.oc1..aaaa", "home_region": HOME}, {"tenancy_ocid": TENANCY, "home_region": "ashburn"},
                {"tenancy_ocid": TENANCY, "home_region": HOME, "compartment_ocids": ["nope"]}):
        with pytest.raises(Exception):
            OciConfig.model_validate(bad)
    assert validate_secret_value("api_signing_key", PRIVATE_PEM.replace("\n", "\r\n")).startswith("-----BEGIN")
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    with pytest.raises(ValueError, match="too short"):
        validate_secret_value("api_signing_key", weak)
    with pytest.raises(ValueError, match="encrypted"):
        validate_secret_value("api_signing_key", rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"pw")).decode())
    spec = KINDS["oci_tenancy"]
    assert spec.node_less and spec.group == "cloud" and spec.where_fields == ("tenancy_ocid",)


def test_resource_ids_of_oci_locations():
    assert cloud_resource_id(f"oci://{HOME}/kms/{AES_KEY}") == AES_KEY == cloud_resource_id(AES_KEY)
    assert cloud_resource_id(f"oci://{HOME}/loadbalancer/{LB_ID}/listener/https") == LB_ID


def test_stack_zip_and_reader_script_are_read_only():
    from backend.utilities.cbom_sources.templates import oci_reader_text, oci_stack_zip

    data = oci_stack_zip(PUBLIC_PEM, FINGERPRINT)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = {n: archive.read(n).decode() for n in archive.namelist()}
    assert set(files) == {"main.tf", "variables.tf", "schema.yaml"}
    assert PUBLIC_PEM.strip().splitlines()[1] in files["variables.tf"] and FINGERPRINT in files["variables.tf"]
    assert "PRIVATE KEY" not in "".join(files.values())
    grants = json.loads(re.search(r"grants\s+=\s+(\[.*\])", files["main.tf"]).group(1))  # type: ignore[union-attr]
    assert grants == list(oci_collect.POLICY_STATEMENTS)
    # the statements name the group the stack creates, so a renamed group keeps its grants (R-oci2 M1)
    assert '"Allow group ${oci_identity_group.zs.name} to ${grant}"' in files["main.tf"]
    assert "name           = var.policy_name" in files["main.tf"] and "policy_name" in files["schema.yaml"]
    statements = [f"Allow group ZeroShieldCBOMReaders to {g}" for g in grants]
    assert all(s.split()[0] in ("inspect", "read") for s in oci_collect.POLICY_STATEMENTS)  # never use / manage
    assert not any(x in s for s in oci_collect.POLICY_STATEMENTS for x in ("bundle", "secret-family", " objects in"))
    script = oci_reader_text()
    assert json.dumps(statements, indent=2) in script  # the script grants exactly the stack's statements
    assert "inspect tenancies in tenancy" in grants  # ListRegionSubscriptions needs TENANCY_INSPECT (R-oci2 M2)
    # one model (R-oci2 M3): an existing user (USER_OCID) or a created one; the key is added only when missing
    assert 'USER_OCID=""' in script and "api-key list --user-id" in script and '${OCI_TENANCY:-' in script
    assert oci_stack_zip(PUBLIC_PEM, FINGERPRINT) == data  # stable bytes for one key


# ------------------------------------------------------------------------------------------------------------- API
def _api(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet  # noqa: F401
    from fastapi.testclient import TestClient
    from sqlalchemy import event
    from sqlmodel import Session, SQLModel, create_engine

    from backend.main import app
    from backend.new_models import Team, TeamMembership, User
    from backend.routers import cbom_node, cbom_vendor_public
    from backend.utilities.auth import auth_utils
    from backend.utilities.cbom_sources import http as cbom_http
    from backend.utilities.db.encryption import _get_fernet

    _get_fernet.cache_clear()
    engine = create_engine(f"sqlite:///{tmp_path / 'oci.db'}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _fk(dbapi_conn, _record):
        dbapi_conn.execute("PRAGMA foreign_keys=ON")

    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="Bank One", credit_balance=100.0))
        s.commit()
        user = User(email="oci@test.example", password="x", first_name="a", last_name="t", profile_photo=None,
                    session_active=True, default_team_id=1)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        s.commit()
    for module in (cbom_http, cbom_node, cbom_vendor_public):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    for limiter in (cbom_http.read_limiter, cbom_http.write_limiter, cbom_http.node_limiter, cbom_http.enroll_limiter,
                    cbom_http.vendor_limiter):
        limiter.requests.clear()
    client = TestClient(app)
    token = auth_utils.create_access_token("oci@test.example")
    seen: list[str] = []

    def call(method, url, **kwargs):
        response = client.request(method, url, headers={"Authorization": f"Bearer {token}"}, **kwargs)
        seen.append(response.text)
        return response

    call.engine, call.seen = engine, seen  # type: ignore[attr-defined]
    return call


def _fake_transport(monkeypatch, public_pem: str):
    fake = FakeOci(public_pem)
    real = cloud_http.CloudHttp.__init__

    def init(self, transport=None):
        real(self, httpx.MockTransport(fake))

    monkeypatch.setattr(cloud_http.CloudHttp, "__init__", init)
    return fake


def test_generated_key_flow_end_to_end(tmp_path, monkeypatch):
    from sqlmodel import Session, select

    from backend.new_models import CbomCollectedAsset, CbomCollectionJob
    from backend.workers import cbom_cloud_worker

    api = _api(tmp_path, monkeypatch)
    # 1. save with a generated key: no user yet, no test; the public half is on the source, the private one never
    r = api("POST", "/1/cbom/sources/items", json={"kind": "oci_tenancy", "name": "oci-prod", "test_after_save": False,
                                                   "config": {"tenancy_ocid": TENANCY, "home_region": HOME, "key_origin": "generated",
                                                              "fingerprint": "00:00", "public_key_pem": "forged"}})
    assert r.status_code == 201, r.text
    src = r.json()["source"]
    cfg = src["config"]
    assert cfg["fingerprint"] != "00:00" and cfg["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "PRIVATE KEY" not in r.text and src["last_test_status"] == "never"
    est = api("POST", "/1/cbom/sources/estimate", json={"include": {"cloud": True}}).json()
    assert est["total_credits"] == 0 and "Oracle Cloud tenancy is connected" in est["skipped"][0]["reason"]
    # 2. the stack carries that public key; the reader script is served
    stack = api("GET", f"/1/cbom/sources/items/{src['id']}/oci/stack")
    assert stack.status_code == 200 and stack.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(stack.content)) as archive:
        assert cfg["fingerprint"] in archive.read("variables.tf").decode()
    assert "oci iam user api-key upload" in api("GET", "/1/cbom/sources/templates/oci-reader").text
    # 3. the user OCID from the stack output, then Save and validate (the fake OCI trusts the source's public key)
    global FINGERPRINT
    saved_fp, FINGERPRINT = FINGERPRINT, cfg["fingerprint"]
    try:
        _fake_transport(monkeypatch, cfg["public_key_pem"])
        r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
            "config": {"tenancy_ocid": TENANCY, "home_region": HOME, "key_origin": "generated", "user_ocid": USER},
            "expected_version": src["row_version"], "test_after_save": True})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["source"]["config"]["fingerprint"] == cfg["fingerprint"]  # the key was kept
        assert body["test"]["status"] == "passed", body["test"]
        # 4. a run is collected by the cloud worker
        run = api("POST", "/1/cbom/sources/runs", json={"include": {"cloud": True}, "client_request_id": "oci-run-01"})
        assert run.status_code == 201, run.text
        assert cbom_cloud_worker.run_once(api.engine, "test-worker") is True
        with Session(api.engine) as s:
            job = s.exec(select(CbomCollectionJob)).one()
            rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id)).all()
        assert job.status == "success" and {r.asset_type for r in rows} >= {"kms_key", "certificate", "cloud_ca",
                                                                            "cloud_secret", "load_balancer_tls", "storage_encryption"}
        # 5. replacing the generated key makes a new pair (the old public key no longer matches)
        latest = api("GET", f"/1/cbom/sources/items/{src['id']}").json()
        latest = latest.get("source", latest)
        r = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={
            "config": {"tenancy_ocid": TENANCY, "home_region": HOME, "key_origin": "generated", "user_ocid": USER},
            "clear_secrets": ["api_signing_key"], "expected_version": latest["row_version"]})
        assert r.status_code == 200, r.text
        assert r.json()["source"]["config"]["fingerprint"] != cfg["fingerprint"]
    finally:
        FINGERPRINT = saved_fp
    assert not any("PRIVATE KEY" in text for text in api.seen)


def test_uploaded_key_is_checked_and_never_returned(tmp_path, monkeypatch):
    api = _api(tmp_path, monkeypatch)
    _fake_transport(monkeypatch, PUBLIC_PEM)
    bad = api("POST", "/1/cbom/sources/items", json={"kind": "oci_tenancy", "name": "oci-own", "config": {**CFG},
                                                     "secrets": {"api_signing_key": "not a key"}})
    assert bad.status_code == 400 and "api_signing_key" in bad.text
    missing = api("POST", "/1/cbom/sources/items", json={"kind": "oci_tenancy", "name": "oci-own", "config": {**CFG}})
    assert missing.status_code == 400 and "api_signing_key" in missing.text
    r = api("POST", "/1/cbom/sources/items", json={"kind": "oci_tenancy", "name": "oci-own", "config": {**CFG},
                                                   "secrets": SECRETS, "test_after_save": True})
    assert r.status_code == 201, r.text
    assert r.json()["source"]["config"]["fingerprint"] == FINGERPRINT and r.json()["test"]["status"] == "passed"
    src = r.json()["source"]
    # switching to a generated key never keeps the customer's key under the new label (R-oci1): a new pair is made
    gen = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**CFG, "key_origin": "generated"},
                                                                    "expected_version": src["row_version"]})
    assert gen.status_code == 200, gen.text
    assert gen.json()["source"]["config"]["fingerprint"] not in (None, FINGERPRINT)
    # and back to an uploaded key: the customer's key is required, the generated one is not relabelled
    back = api("PATCH", f"/1/cbom/sources/items/{src['id']}", json={"config": {**CFG, "key_origin": "uploaded"},
                                                                     "expected_version": gen.json()["source"]["row_version"]})
    assert back.status_code == 400 and "api_signing_key" in back.text
    body_line = PRIVATE_PEM.splitlines()[2]
    assert not any(body_line in text for text in api.seen)  # the stored key is never returned
