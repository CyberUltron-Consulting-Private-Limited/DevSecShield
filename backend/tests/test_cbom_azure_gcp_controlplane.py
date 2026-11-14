"""Azure and Google Cloud control-plane collection (TLS policies, storage encryption, certificate stores, key versions)
against recorded responses built from the providers' REST references (httpx.MockTransport, no network).

Azure Resource Manager (every field parsed below is in the documented response):
* Storage Accounts - List: https://learn.microsoft.com/rest/api/storagerp/storage-accounts/list (properties.
  minimumTlsVersion TLS1_0..TLS1_3, supportsHttpsTrafficOnly, encryption.keySource Microsoft.Storage|Microsoft.Keyvault,
  encryption.keyvaultproperties.keyvaulturi/keyname, encryption.requireInfrastructureEncryption, publicNetworkAccess,
  networkAcls.defaultAction; StorageAccountListResult value / nextLink)
* Web Apps - List and Web Apps - Get Configuration: https://learn.microsoft.com/rest/api/appservice/web-apps/list,
  .../web-apps/get-configuration (properties.httpsOnly, clientCertEnabled, clientCertMode, hostNameSslStates[].name /
  sslState / thumbprint, defaultHostName, publicNetworkAccess; config: minTlsVersion and scmMinTlsVersion 1.0..1.3,
  minTlsCipherSuite, ftpsState AllAllowed|FtpsOnly|Disabled, http20Enabled; appSettings are never returned)
* App Service Certificates - List: https://learn.microsoft.com/rest/api/appservice/certificates/list (thumbprint,
  expirationDate, issuer, subjectName, hostNames, cerBlob "Raw bytes of .cer file", keyVaultId)
* Application Gateways - List All: https://learn.microsoft.com/rest/api/application-gateway/application-gateways/list-all
  (sslPolicy policyType / policyName / minProtocolVersion / cipherSuites, sslProfiles, sslCertificates with
  publicCertData masked "*****", httpListeners protocol Http|Https, frontendIPConfigurations publicIPAddress,
  defaultPredefinedSslPolicy) and the predefined policies' protocols and cipher suites:
  https://learn.microsoft.com/azure/application-gateway/application-gateway-ssl-policy-overview
* AFD Custom Domains - List By Profile: https://learn.microsoft.com/rest/api/frontdoor/azurefrontdoorstandardpremium/afd-custom-domains/list-by-profile
  (tlsSettings.minimumTlsVersion TLS10|TLS12|TLS13, certificateType, cipherSuiteSetType, customizedCipherSuiteSet)
* SQL Servers - List: https://learn.microsoft.com/rest/api/sql/servers/list (minimalTlsVersion None|1.0..1.3,
  publicNetworkAccess, fullyQualifiedDomainName, keyId)
* ARM errors: AuthorizationFailed (403) and MissingSubscriptionRegistration (409),
  https://learn.microsoft.com/azure/azure-resource-manager/troubleshooting/common-deployment-errors

Google Cloud:
* Cloud KMS cryptoKeyVersions.list: https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/list
  (cryptoKeyVersions[], nextPageToken; CryptoKeyVersion state / protectionLevel / algorithm / createTime / destroyTime)
* Certificate Manager certificates.list: https://cloud.google.com/certificate-manager/docs/reference/certificate-manager/rest/v1/projects.locations.certificates/list
  (certificates[], nextPageToken, unreachable[]; Certificate name, sanDnsnames, pemCertificate, expireTime, scope,
  managed.state, usedBy)
* Compute Engine aggregatedList for sslPolicies / sslCertificates / targetHttpsProxies / forwardingRules and
  targetSslProxies.list: https://cloud.google.com/compute/docs/reference/rest/v1/sslPolicies/aggregatedList (items map
  of scope -> {sslPolicies[] | warning}, nextPageToken, unreachables[]); SslPolicy profile / minTlsVersion /
  enabledFeatures; SslCertificate certificate (PEM chain) / type / managed / expireTime; TargetHttpsProxy sslPolicy /
  sslCertificates / certificateMap; and "If no SSL policy is attached, the load balancer behaves as if it had the
  COMPATIBLE profile with a minimum TLS version of 1.0": https://cloud.google.com/load-balancing/docs/ssl-policies-concepts
* Cloud Storage buckets.list: https://cloud.google.com/storage/docs/json_api/v1/buckets/list (items[], nextPageToken;
  bucket encryption.defaultKmsKeyName)

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_cbom_azure_gcp_controlplane.py -q
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import httpx
import pytest

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from test_cbom_azure_gcp_collect import (  # noqa: E402
    LOC, PROJECT, SUB, Recorder, _at, _azure, _azure_routes, _gcp, _gcp_routes, _path, _self_signed)

from backend.utilities.cbom_sources import cloud_http  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

ARM = "https://management.azure.com"
RG = f"/subscriptions/{SUB}/resourceGroups/rg1"


def _codes(asset):
    return classify(asset["type"], asset.get("algorithm"), asset.get("key_size"), asset.get("protocol"), asset["facts"])["finding_codes"]


def _by(found, kind):
    return [a for a in found if a["type"] == kind]


def _first(routes, match, answer):
    """A test's own answer, checked before the defaults."""
    routes.insert(0, (match, answer))
    return routes


# ----------------------------------------------------------------------------- Azure: documented bodies
STORAGE_OLD = {
    "id": f"{RG}/providers/Microsoft.Storage/storageAccounts/sto1125", "name": "sto1125", "location": "eastus",
    "kind": "StorageV2", "type": "Microsoft.Storage/storageAccounts",
    "properties": {"minimumTlsVersion": "TLS1_0", "supportsHttpsTrafficOnly": False, "publicNetworkAccess": "Enabled",
                   "networkAcls": {"defaultAction": "Allow", "bypass": "AzureServices"},
                   "primaryEndpoints": {"blob": "https://sto1125.blob.core.windows.net/"},
                   "encryption": {"keySource": "Microsoft.Keyvault", "requireInfrastructureEncryption": False,
                                  "keyvaultproperties": {"keyvaulturi": "https://myvault8569.vault.azure.net", "keyname": "wrappingKey",
                                                         "keyversion": "", "lastKeyRotationTimestamp": "2019-12-13T20:36:23.7023290Z"},
                                  "services": {"blob": {"enabled": True, "keyType": "Account"},
                                               "file": {"enabled": True, "keyType": "Account"}}}}}
STORAGE_NEW = {
    "id": f"{RG}/providers/Microsoft.Storage/storageAccounts/sto2", "name": "sto2", "location": "eastus",
    "properties": {"minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": True, "publicNetworkAccess": "Disabled",
                   "encryption": {"keySource": "Microsoft.Storage", "requireInfrastructureEncryption": True,
                                  "services": {"blob": {"enabled": True}}}}}

_CERT_KEY, _APP_CERT = _self_signed("www.contoso.com")
CER_BLOB = base64.b64encode(_APP_CERT.public_bytes(serialization.Encoding.DER)).decode()
SITE = {"id": f"{RG}/providers/Microsoft.Web/sites/sitef6141", "name": "sitef6141", "kind": "app", "location": "East US",
        "properties": {"httpsOnly": False, "clientCertEnabled": True, "clientCertMode": "Optional",
                       "defaultHostName": "sitef6141.azurewebsites.net", "publicNetworkAccess": "Enabled",
                       "enabledHostNames": ["sitef6141.azurewebsites.net", "www.contoso.com"],
                       "hostNameSslStates": [{"name": "www.contoso.com", "sslState": "SniEnabled", "thumbprint": "AAAABBBB", "hostType": "Standard"},
                                             {"name": "sitef6141.azurewebsites.net", "sslState": "Disabled", "hostType": "Standard"}],
                       "siteConfig": None}}
SITE_CONFIG = {"id": f"{SITE['id']}/config/web", "name": "web", "type": "Microsoft.Web/sites/config",
               "properties": {"minTlsVersion": "1.2", "scmMinTlsVersion": "1.0", "minTlsCipherSuite": "TLS_RSA_WITH_AES_128_CBC_SHA",
                              "ftpsState": "AllAllowed", "http20Enabled": True}}
WEB_CERTS = [
    {"id": f"{RG}/providers/Microsoft.Web/certificates/bound", "name": "bound", "location": "East US",
     "properties": {"thumbprint": "AAAABBBB", "subjectName": "www.contoso.com", "issuer": "www.contoso.com", "hostNames": ["www.contoso.com"],
                    "issueDate": "2026-01-01T00:00:00Z", "expirationDate": "2027-01-01T00:00:00Z", "cerBlob": CER_BLOB,
                    "pfxBlob": "TUlJS2pBSUJBekNDQ2t3R0NTcUdTSWIzRFFF", "password": "pfx-password-never-kept"}},
    {"id": f"{RG}/providers/Microsoft.Web/certificates/orphan", "name": "orphan", "location": "East US",
     "properties": {"thumbprint": "CCCCDDDD", "subjectName": "old.contoso.com", "issuer": "Contoso CA",
                    "expirationDate": "2026-01-01T00:00:00Z", "keyVaultId": f"{RG}/providers/Microsoft.KeyVault/vaults/kv1",
                    "keyVaultSecretName": "old-cert", "keyVaultSecretStatus": "Succeeded"}},
]
APPGW = {
    "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw", "name": "appgw", "location": "eastus",
    "properties": {
        "sku": {"name": "Standard_v2", "tier": "Standard_v2", "capacity": 3},
        "sslPolicy": {"policyType": "Predefined", "policyName": "AppGwSslPolicy20150501"},
        "defaultPredefinedSslPolicy": "AppGwSslPolicy20220101",
        "sslProfiles": [{"name": "sslProfile1", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/sslProfiles/sslProfile1",
                         "properties": {"sslPolicy": {"cipherSuites": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"],
                                                      "minProtocolVersion": "TLSv1_1", "policyType": "Custom"}}}],
        "sslCertificates": [{"name": "sslcert", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/sslCertificates/sslcert",
                             "properties": {"provisioningState": "Succeeded", "publicCertData": "*****"}}],
        "frontendIPConfigurations": [
            {"name": "appgwfip", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendIPConfigurations/appgwfip",
             "properties": {"privateIPAllocationMethod": "Dynamic",
                            "publicIPAddress": {"id": f"{RG}/providers/Microsoft.Network/publicIPAddresses/appgwpip"}}},
            {"name": "appgwpriv", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendIPConfigurations/appgwpriv",
             "properties": {"privateIPAddress": "10.0.0.10", "privateIPAllocationMethod": "Static",
                            "subnet": {"id": f"{RG}/providers/Microsoft.Network/virtualNetworks/vnet/subnets/appgwsubnet"}}}],
        "frontendPorts": [{"name": "appgwfp", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendPorts/appgwfp", "properties": {"port": 443}},
                          {"name": "appgwfp80", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendPorts/appgwfp80", "properties": {"port": 80}},
                          {"name": "appgwfp8443", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendPorts/appgwfp8443", "properties": {"port": 8443}}],
        "httpListeners": [
            {"name": "appgwhl", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/httpListeners/appgwhl",
             "properties": {"frontendIPConfiguration": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendIPConfigurations/appgwfip"},
                            "frontendPort": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendPorts/appgwfp"},
                            "protocol": "Https", "requireServerNameIndication": False,
                            "sslCertificate": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/sslCertificates/sslcert"}}},
            {"name": "appgwhttplistener", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/httpListeners/appgwhttplistener",
             "properties": {"frontendIPConfiguration": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendIPConfigurations/appgwfip"},
                            "frontendPort": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendPorts/appgwfp80"},
                            "protocol": "Http"}},
            {"name": "internal", "id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/httpListeners/internal",
             "properties": {"frontendIPConfiguration": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendIPConfigurations/appgwpriv"},
                            "frontendPort": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/frontendPorts/appgwfp8443"},
                            "protocol": "Https",
                            "sslProfile": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/sslProfiles/sslProfile1"},
                            "sslCertificate": {"id": f"{RG}/providers/Microsoft.Network/applicationGateways/appgw/sslCertificates/sslcert"}}}]}}
AFD_PROFILE = {"id": f"{RG}/providers/Microsoft.Cdn/profiles/profile1", "name": "profile1", "location": "Global",
               "sku": {"name": "Premium_AzureFrontDoor"}, "kind": "frontdoor", "properties": {"provisioningState": "Succeeded"}}
CLASSIC_CDN = {"id": f"{RG}/providers/Microsoft.Cdn/profiles/cdn1", "name": "cdn1", "sku": {"name": "Standard_Microsoft"}}
AFD_DOMAINS = {"value": [
    {"id": f"{RG}/providers/Microsoft.Cdn/profiles/profile1/customdomains/domain1", "name": "domain1",
     "type": "Microsoft.Cdn/profiles/customdomains",
     "properties": {"profileName": "profile1", "hostName": "www.contoso.com",
                    "tlsSettings": {"certificateType": "ManagedCertificate", "cipherSuiteSetType": "Customized", "minimumTlsVersion": "TLS12",
                                    "customizedCipherSuiteSet": {"cipherSuiteSetForTls12": ["ECDHE_RSA_AES128_GCM_SHA256"],
                                                                 "cipherSuiteSetForTls13": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]},
                                    "secret": {"id": ""}},
                    "domainValidationState": "Approved", "provisioningState": "Succeeded"}},
    {"id": f"{RG}/providers/Microsoft.Cdn/profiles/profile1/customdomains/legacy", "name": "legacy",
     "properties": {"hostName": "legacy.contoso.com", "domainValidationState": "Approved",
                    "tlsSettings": {"certificateType": "CustomerCertificate", "minimumTlsVersion": "TLS10", "cipherSuiteSetType": "TLS10_2019",
                                    "secret": {"id": f"{RG}/providers/Microsoft.Cdn/profiles/profile1/secrets/legacy-cert"}}}}]}
SQL_SERVERS = {"value": [
    {"id": f"{RG}/providers/Microsoft.Sql/servers/sqlcrudtest-4645", "name": "sqlcrudtest-4645", "location": "japaneast",
     "kind": "v12.0", "properties": {"fullyQualifiedDomainName": "sqlcrudtest-4645.database.windows.net", "minimalTlsVersion": "1.0",
                                      "publicNetworkAccess": "Enabled", "state": "Ready", "version": "12.0"}},
    {"id": f"{RG}/providers/Microsoft.Sql/servers/modern", "name": "modern",
     "properties": {"fullyQualifiedDomainName": "modern.database.windows.net", "minimalTlsVersion": "1.2",
                    "publicNetworkAccess": "Disabled", "keyId": "https://kv1.vault.azure.net/keys/tde/abc"}}]}
AUTH_FAILED = {"error": {"code": "AuthorizationFailed", "message": "The client 'x' with object id 'y' does not have authorization "
                         "to perform action 'Microsoft.Storage/storageAccounts/read' over scope '/subscriptions/s'."}}
NOT_REGISTERED = {"error": {"code": "MissingSubscriptionRegistration",
                            "message": "The subscription is not registered to use namespace 'Microsoft.Cdn'."}}


def _arm(rp):
    return _path(f"{ARM}/subscriptions/{SUB}/providers/{rp}?")


def _azure_cp(**override):
    """Key Vault defaults plus documented control-plane bodies; override maps a provider path to an answer."""
    answers = {
        "Microsoft.Storage/storageAccounts": (200, {"value": [STORAGE_OLD, STORAGE_NEW]}),
        "Microsoft.Web/sites": (200, {"value": [SITE]}),
        "Microsoft.Web/certificates": (200, {"value": WEB_CERTS}),
        "Microsoft.Network/applicationGateways": (200, {"value": [APPGW]}),
        "Microsoft.Cdn/profiles": (200, {"value": [AFD_PROFILE, CLASSIC_CDN]}),
        "Microsoft.Sql/servers": (200, SQL_SERVERS),
        **override,
    }
    routes = _azure_routes()
    routes[:0] = [(_arm(rp), answer) for rp, answer in answers.items()] + [
        (_path(f"{ARM}{SITE['id']}/config/web?"), (200, SITE_CONFIG)),
        (_path(f"{ARM}{AFD_PROFILE['id']}/customDomains?"), (200, AFD_DOMAINS)),
    ]
    return routes


def test_azure_storage_account_encryption_and_tls_policy():
    out, found, rec = _azure(_azure_cp())
    enc = {a["name"]: a for a in _by(found, "storage_encryption")}
    old = enc["sto1125"]["facts"]
    assert old["encrypted"] is True and old["key_source"] == "Microsoft.Keyvault"
    assert old["kms_key_id"] == "https://myvault8569.vault.azure.net/keys/wrappingKey" and old["infrastructure_encryption"] is False
    assert enc["sto2"]["facts"]["kms_key_id"] == "microsoft-managed" and enc["sto2"]["facts"]["infrastructure_encryption"] is True
    assert _codes(enc["sto1125"]) == [] and _codes(enc["sto2"]) == []
    tls = {a["location"]: a for a in _by(found, "api_tls") if "storageAccounts" in a["location"]}
    weak = tls[f"{STORAGE_OLD['id']}#tls"]
    assert weak["facts"]["min_version"] == "TLSv1.0" and weak["facts"]["https_only"] is False and weak["facts"]["internet_facing"] is True
    assert set(_codes(weak)) == {"MIN_TLS10", "PLAINTEXT_LISTENER"}
    strong = tls[f"{STORAGE_NEW['id']}#tls"]
    assert strong["facts"]["min_version"] == "TLSv1.2" and strong["facts"]["internet_facing"] is False and _codes(strong) == []
    assert out["targets"][0]["services"]["storage"] == "ok"
    # read-only: every control-plane call is a GET on ARM; nothing lists keys of a storage account (listKeys is a POST)
    arm = [r for r in rec.seen if r["host"] == "management.azure.com"]
    assert all(r["method"] == "GET" for r in arm) and not any("listKeys" in r["url"] for r in rec.seen)


def test_azure_app_service_tls_config_and_certificates():
    out, found, rec = _azure(_azure_cp())
    sites = {a["location"]: a for a in _by(found, "api_tls") if "Microsoft.Web/sites" in a["location"]}
    site = sites[SITE["id"]]
    assert site["name"] == "sitef6141.azurewebsites.net"
    facts = site["facts"]
    assert facts["min_version"] == "TLSv1.2" and facts["https_only"] is False and facts["ftps_state"] == "AllAllowed"
    assert facts["min_cipher_suite"] == "TLS_RSA_WITH_AES_128_CBC_SHA" and facts["client_cert_mode"] == "Optional"
    assert {"host": "www.contoso.com", "ssl_state": "SniEnabled", "thumbprint": "AAAABBBB"} in facts["bindings"]
    assert _codes(site) == ["PLAINTEXT_LISTENER"]  # HTTPS only is off
    scm = sites[f"{SITE['id']}#scm"]  # the Kudu (SCM) site allows an older TLS than the app
    assert scm["facts"]["min_version"] == "TLSv1.0" and _codes(scm) == ["MIN_TLS10"]

    certs = {a["location"]: a for a in _by(found, "certificate") if "Microsoft.Web/certificates" in a["location"]}
    bound = certs[WEB_CERTS[0]["id"]]
    assert bound["algorithm"] == "RSA" and bound["key_size"] == 2048 and bound["facts"]["in_use"] is True
    assert bound["facts"]["thumbprint"] == "AAAABBBB" and bound["facts"]["host_names"] == ["www.contoso.com"]
    orphan = certs[WEB_CERTS[1]["id"]]
    assert orphan["algorithm"] is None and orphan["facts"]["not_after"] == "2026-01-01T00:00:00Z"
    assert orphan["facts"]["key_vault_id"].endswith("/vaults/kv1") and orphan["facts"]["in_use"] is False
    assert "CERT_UNUSED" in _codes(orphan) and "CERT_EXPIRED" in _codes(orphan)
    assert "pfx-password-never-kept" not in repr(found) and "TUlJS2pBSUJB" not in repr(found)  # private parts never kept
    assert out["targets"][0]["services"]["appservice"] == "ok" and out["targets"][0]["status"] == "ok"
    assert not any("/config/appsettings" in r["url"] or "/list" in r["url"].split("?")[0] for r in rec.seen)


def test_azure_application_gateway_listener_policies():
    _out, found, _rec = _azure(_azure_cp())
    rows = {a["name"]: a for a in _by(found, "load_balancer_tls")}
    public = rows["appgw:appgwhl"]
    facts = public["facts"]
    assert public["protocol"] == "HTTPS" and facts["ssl_policy"] == "AppGwSslPolicy20150501" and facts["port"] == 443
    assert facts["protocols"] == ["TLSv1.0", "TLSv1.1", "TLSv1.2"] and "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in facts["ciphers"]
    assert facts["internet_facing"] is True and facts["certificates"] == ["sslcert"]
    assert {"PROTO_TLS10", "PROTO_TLS11", "WEAK_CIPHER", "STATIC_RSA_KEX"} <= set(_codes(public))
    internal = rows["appgw:internal"]["facts"]  # the listener's SSL profile overrides the gateway policy
    assert internal["ssl_profile"] == "sslProfile1" and internal["protocols"] == ["TLSv1.1", "TLSv1.2"]
    assert internal["ciphers"] == ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"] and internal["internet_facing"] is False
    plain = rows["appgw:appgwhttplistener"]
    assert plain["protocol"] == "HTTP" and plain["facts"]["tls"] is False and "NO_TLS" in _codes(plain)
    assert "*****" not in repr(found)


def test_azure_application_gateway_without_a_policy_uses_the_documented_default():
    gw = {**APPGW, "properties": {**APPGW["properties"]}}
    del gw["properties"]["sslPolicy"]
    _out, found, _rec = _azure(_azure_cp(**{"Microsoft.Network/applicationGateways": (200, {"value": [gw]})}))
    row = next(a for a in _by(found, "load_balancer_tls") if a["name"] == "appgw:appgwhl")
    assert row["facts"]["ssl_policy"] == "AppGwSslPolicy20220101" and row["facts"]["protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert row["facts"]["default_policy"] is True and "STATIC_RSA_KEX" not in _codes(row)


def test_azure_front_door_custom_domains_and_sql_minimal_tls():
    _out, found, rec = _azure(_azure_cp())
    cdn = {a["name"]: a for a in _by(found, "cdn_tls")}
    assert set(cdn) == {"www.contoso.com", "legacy.contoso.com"}  # the classic CDN profile has no AFD custom domains
    assert cdn["www.contoso.com"]["facts"]["min_version"] == "TLSv1.2" and _codes(cdn["www.contoso.com"]) == []
    assert cdn["www.contoso.com"]["facts"]["ciphers"] == ["ECDHE_RSA_AES128_GCM_SHA256", "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"]
    legacy = cdn["legacy.contoso.com"]
    assert legacy["facts"]["certificate_type"] == "CustomerCertificate" and _codes(legacy) == ["MIN_TLS10"]
    assert not any("/profiles/cdn1/" in r["url"] for r in rec.seen)
    sql = {a["name"]: a for a in _by(found, "database_tls")}
    assert sql["sqlcrudtest-4645.database.windows.net"]["facts"]["min_version"] == "TLSv1.0"
    assert _codes(sql["sqlcrudtest-4645.database.windows.net"]) == ["MIN_TLS10"]
    modern = sql["modern.database.windows.net"]["facts"]
    assert modern["internet_facing"] is False and modern["cmek_key_id"].endswith("/keys/tde/abc")
    assert _codes(sql["modern.database.windows.net"]) == []


def test_azure_permission_denied_per_service_is_a_coverage_row_and_the_rest_is_read():
    out, found, _rec = _azure(_azure_cp(**{"Microsoft.Storage/storageAccounts": (403, AUTH_FAILED)}))
    gaps = [a for a in _by(found, "coverage") if "storage" in a["facts"]["check"]]
    assert len(gaps) == 1 and gaps[0]["facts"]["status"] == "denied" and "AuthorizationFailed" in gaps[0]["facts"]["detail"]
    assert "Microsoft.Storage/storageAccounts/read" in gaps[0]["facts"]["detail"]  # names the permission to grant
    target = out["targets"][0]
    assert target["services"]["storage"] == "denied" and target["status"] == "error" and "storage" in target["error"]
    assert _by(found, "database_tls") and _by(found, "load_balancer_tls") and _by(found, "kms_key")  # others still read
    assert not _by(found, "storage_encryption")


def test_azure_unregistered_resource_provider_is_not_enabled_not_an_error():
    out, found, _rec = _azure(_azure_cp(**{"Microsoft.Cdn/profiles": (409, NOT_REGISTERED)}))
    gap = next(a for a in _by(found, "coverage") if "front door" in a["facts"]["check"].lower())
    assert gap["facts"]["status"] == "not_enabled" and gap["facts"]["by_choice"] is True
    assert gap["facts"]["scope"] == [f"/subscriptions/{SUB}/providers/Microsoft.Cdn/"]
    assert out["targets"][0]["services"]["frontdoor"] == "not_enabled" and out["targets"][0]["status"] == "ok"


def test_azure_paging_follows_next_link_and_429_is_retried(monkeypatch):
    monkeypatch.setattr(cloud_http.time, "sleep", lambda _s: None)
    calls = {"n": 0}

    def sql(_r, _f):
        calls["n"] += 1
        return (429, {"error": {"code": "TooManyRequests", "message": "throttled"}}) if calls["n"] == 1 else (200, SQL_SERVERS)

    page1 = {"value": [STORAGE_OLD], "nextLink": f"{ARM}/subscriptions/{SUB}/providers/Microsoft.Storage/storageAccounts?api-version=2023-05-01&$skipToken=p2"}
    routes = _azure_cp(**{"Microsoft.Sql/servers": sql})
    routes.insert(0, (lambda r, _f: "skipToken=p2" in str(r.url), (200, {"value": [STORAGE_NEW]})))
    routes.insert(1, (_arm("Microsoft.Storage/storageAccounts"), (200, page1)))
    out, found, _rec = _azure(routes)
    assert {a["name"] for a in _by(found, "storage_encryption")} == {"sto1125", "sto2"}
    assert calls["n"] == 2 and len(_by(found, "database_tls")) == 2 and out["targets"][0]["status"] == "ok"


def test_azure_throttled_past_the_retries_and_malformed_answers_are_coverage_rows(monkeypatch):
    monkeypatch.setattr(cloud_http.time, "sleep", lambda _s: None)
    routes = _azure_cp(**{"Microsoft.Sql/servers": (429, {"error": {"code": "TooManyRequests", "message": "slow down"}}),
                          "Microsoft.Network/applicationGateways": (200, {"value": [{"name": "broken"}, "not-an-object"]})})
    routes.insert(0, (_arm("Microsoft.Web/certificates"), lambda _r, _f: (200, None)))
    routes.insert(0, (_path(f"{ARM}{SITE['id']}/config/web?"), (200, {"properties": "nonsense"})))
    rec = Recorder(routes)
    rec_call = rec.__call__

    def html_storage(request):
        if "Microsoft.Storage/storageAccounts" in str(request.url):
            return httpx.Response(200, text="<html>proxy error</html>")
        return rec_call(request)

    from backend.utilities.cbom_sources import azure_collect

    found: list[dict] = []
    out = azure_collect.collect_azure(1, {"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47", "client_id": "6731de76-14a6-49ae-97bc-6eba6914391e",
                                          "subscription_ids": [], "credential_type": "client_secret"},
                                      {"client_secret": "Az-Client-Secret~9f8e7d6c5b4a"}, found.append, lambda: None,
                                      transport=httpx.MockTransport(html_storage))
    target = out["targets"][0]
    assert target["services"]["sql"] == "error" and target["services"]["storage"] == "error"
    checks = {a["facts"]["check"]: a["facts"] for a in _by(found, "coverage")}
    assert any("NotJson" in f["detail"] for f in checks.values()) and any("Throttled" in f["detail"] for f in checks.values())
    assert not [a for a in _by(found, "load_balancer_tls")]  # a gateway without properties has no listeners: nothing invented
    assert target["status"] == "error"
    site = next(a for a in _by(found, "api_tls") if a["location"] == SITE["id"])
    assert site["facts"]["min_version"] is None  # the config answer had no readable properties


# ----------------------------------------------------------------------------- Google Cloud: documented bodies
KMS = "https://cloudkms.googleapis.com/v1"
COMPUTE = "https://compute.googleapis.com/compute/v1"
SELF = f"https://www.googleapis.com/compute/v1/projects/{PROJECT}"
_LB_KEY, _LB_CERT = _self_signed("shop.example.com", key=ec.generate_private_key(ec.SECP256R1()), sig=hashes.SHA256())
LB_PEM = _LB_CERT.public_bytes(serialization.Encoding.PEM).decode()
VERSIONS = {"cryptoKeyVersions": [
    {"name": f"{LOC}/keyRings/payments/cryptoKeys/signer/cryptoKeyVersions/1", "state": "DESTROY_SCHEDULED", "protectionLevel": "HSM",
     "algorithm": "RSA_SIGN_PKCS1_2048_SHA256", "createTime": "2025-01-01T00:00:00Z", "destroyTime": "2026-12-01T00:00:00Z"},
    {"name": f"{LOC}/keyRings/payments/cryptoKeys/signer/cryptoKeyVersions/2", "state": "ENABLED", "protectionLevel": "HSM",
     "algorithm": "RSA_SIGN_PSS_2048_SHA256", "createTime": "2026-01-01T00:00:00Z", "generateTime": "2026-01-01T00:00:01Z",
     "attestation": {"format": "CAVIUM_V2_COMPRESSED", "content": "QUJD"}}], "totalSize": 2}
SSL_POLICIES = {"kind": "compute#sslPoliciesAggregatedList", "items": {
    "global": {"sslPolicies": [
        {"kind": "compute#sslPolicy", "name": "restricted", "selfLink": f"{SELF}/global/sslPolicies/restricted", "profile": "RESTRICTED",
         "minTlsVersion": "TLS_1_2", "enabledFeatures": ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]},
        {"kind": "compute#sslPolicy", "name": "legacy-custom", "selfLink": f"{SELF}/global/sslPolicies/legacy-custom", "profile": "CUSTOM",
         "minTlsVersion": "TLS_1_1", "customFeatures": ["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"],
         "enabledFeatures": ["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}]},
    "regions/asia-south1": {"warning": {"code": "NO_RESULTS_ON_PAGE", "message": "There are no results for scope 'regions/asia-south1' on this page."}}}}
SSL_CERTS = {"items": {"global": {"sslCertificates": [
    {"name": "shop-cert", "selfLink": f"{SELF}/global/sslCertificates/shop-cert", "type": "SELF_MANAGED", "certificate": LB_PEM,
     "subjectAlternativeNames": ["shop.example.com"], "expireTime": "2027-01-01T00:00:00.000-08:00", "creationTimestamp": "2026-01-01T00:00:00.000-08:00"},
    {"name": "managed-cert", "selfLink": f"{SELF}/global/sslCertificates/managed-cert", "type": "MANAGED",
     "managed": {"domains": ["www.example.com"], "status": "PROVISIONING", "domainStatus": {"www.example.com": "PROVISIONING"}}}]}}}
PROXIES = {"items": {"global": {"targetHttpsProxies": [
    {"name": "web-proxy", "selfLink": f"{SELF}/global/targetHttpsProxies/web-proxy", "urlMap": f"{SELF}/global/urlMaps/web",
     "sslCertificates": [f"{SELF}/global/sslCertificates/shop-cert"]},
    {"name": "api-proxy", "selfLink": f"{SELF}/global/targetHttpsProxies/api-proxy", "sslPolicy": f"{SELF}/global/sslPolicies/legacy-custom",
     "certificateMap": f"//certificatemanager.googleapis.com/projects/{PROJECT}/locations/global/certificateMaps/api-map", "quicOverride": "NONE"}]}}}
SSL_PROXIES = {"items": [{"name": "tcp-proxy", "selfLink": f"{SELF}/global/targetSslProxies/tcp-proxy",
                          "sslPolicy": f"{SELF}/global/sslPolicies/restricted", "sslCertificates": [f"{SELF}/global/sslCertificates/shop-cert"]}]}
RULES = {"items": {"global": {"forwardingRules": [
    {"name": "web-fr", "selfLink": f"{SELF}/global/forwardingRules/web-fr", "IPAddress": "34.1.2.3", "portRange": "443-443",
     "target": f"{SELF}/global/targetHttpsProxies/web-proxy", "loadBalancingScheme": "EXTERNAL_MANAGED"}]},
    "regions/asia-south1": {"forwardingRules": [
        {"name": "api-fr", "selfLink": f"{SELF}/regions/asia-south1/forwardingRules/api-fr", "IPAddress": "10.0.0.5",
         "target": f"{SELF}/global/targetHttpsProxies/api-proxy", "loadBalancingScheme": "INTERNAL_MANAGED"}]}}}
CM_CERTS = {"certificates": [
    {"name": f"projects/{PROJECT}/locations/global/certificates/api-cert", "createTime": "2026-01-01T00:00:00Z",
     "sanDnsnames": ["api.example.com"], "pemCertificate": LB_PEM, "expireTime": "2027-01-01T00:00:00Z", "scope": "DEFAULT",
     "managed": {"domains": ["api.example.com"], "state": "ACTIVE"},
     "usedBy": [{"name": f"//certificatemanager.googleapis.com/projects/{PROJECT}/locations/global/certificateMaps/api-map/certificateMapEntries/api"}]},
    {"name": f"projects/{PROJECT}/locations/global/certificates/pending", "sanDnsnames": ["new.example.com"],
     "managed": {"domains": ["new.example.com"], "state": "PROVISIONING"}}], "unreachable": ["asia-south2"]}
BUCKETS = {"kind": "storage#buckets", "items": [
    {"kind": "storage#bucket", "id": "pay-logs", "name": "pay-logs", "location": "ASIA-SOUTH1",
     "encryption": {"defaultKmsKeyName": f"{LOC}/keyRings/payments/cryptoKeys/rotated"}},
    {"kind": "storage#bucket", "id": "public-assets", "name": "public-assets", "location": "US"}]}
SERVICE_DISABLED_COMPUTE = {"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "Compute Engine API has not been used in project 123 before or it is disabled.",
                                      "details": [{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED",
                                                   "metadata": {"service": "compute.googleapis.com"}}]}}
STORAGE_DENIED = {"error": {"code": 403, "message": f"zs-cbom@{PROJECT}.iam.gserviceaccount.com does not have storage.buckets.list access to the Google Cloud project.",
                            "errors": [{"message": "denied", "domain": "global", "reason": "forbidden"}]}}


def _gcp_cp(**override):
    answers = {
        f"{KMS}/{LOC}/keyRings/payments/cryptoKeys/signer/cryptoKeyVersions": (200, VERSIONS),
        f"{COMPUTE}/projects/{PROJECT}/aggregated/sslPolicies": (200, SSL_POLICIES),
        f"{COMPUTE}/projects/{PROJECT}/aggregated/sslCertificates": (200, SSL_CERTS),
        f"{COMPUTE}/projects/{PROJECT}/aggregated/targetHttpsProxies": (200, PROXIES),
        f"{COMPUTE}/projects/{PROJECT}/global/targetSslProxies": (200, SSL_PROXIES),
        f"{COMPUTE}/projects/{PROJECT}/aggregated/forwardingRules": (200, RULES),
        f"https://certificatemanager.googleapis.com/v1/projects/{PROJECT}/locations": (200, {"locations": [
            {"name": f"projects/{PROJECT}/locations/global", "locationId": "global"}]}),
        f"https://certificatemanager.googleapis.com/v1/projects/{PROJECT}/locations/global/certificates": (200, CM_CERTS),
        "https://storage.googleapis.com/storage/v1/b": (200, BUCKETS),
        **override,
    }
    routes = _gcp_routes()
    routes[:0] = [(_at(url), answer) for url, answer in answers.items()]
    return routes


def test_gcp_kms_key_versions_with_protection_level_and_state():
    out, found, rec = _gcp(_gcp_cp())
    signer = next(a for a in _by(found, "kms_key") if a["name"] == "signer")
    facts = signer["facts"]
    assert facts["version_count"] == 2 and facts["enabled_versions"] == 1 and facts["key_state"] == "Enabled"
    assert facts["versions"][0] == {"version": "1", "state": "DESTROY_SCHEDULED", "protection_level": "HSM",
                                    "algorithm": "RSA_SIGN_PKCS1_2048_SHA256", "created": "2025-01-01T00:00:00Z",
                                    "destroy_time": "2026-12-01T00:00:00Z"}
    assert facts["version_algorithms"] == ["RSA_SIGN_PKCS1_2048_SHA256", "RSA_SIGN_PSS_2048_SHA256"]
    assert "attestation" not in repr(facts) and "QUJD" not in repr(found)
    assert (signer["algorithm"], signer["key_size"]) == ("RSA", 2048)  # the name comes from algid.gcp
    assert out["targets"][0]["services"]["cloudkms"] == "ok"
    assert not any(":asymmetricSign" in r["url"] or "publicKey" in r["url"] for r in rec.seen)  # never a key operation


def test_gcp_load_balancer_tls_policies_certificates_and_exposure():
    out, found, rec = _gcp(_gcp_cp())
    rows = {a["name"]: a for a in _by(found, "load_balancer_tls")}
    web = rows["web-proxy"]["facts"]  # no SSL policy: Google documents COMPATIBLE with TLS 1.0 as the minimum
    assert web["ssl_policy"] is None and web["default_policy"] is True and web["profile"] == "COMPATIBLE"
    assert web["protocols"] == ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"] and web["internet_facing"] is True
    assert web["certificates"] == ["shop-cert"] and web["forwarding_rules"] == ["web-fr"]
    assert {"PROTO_TLS10", "PROTO_TLS11"} <= set(_codes(rows["web-proxy"]))
    api = rows["api-proxy"]
    assert api["facts"]["ssl_policy"] == "legacy-custom" and api["facts"]["protocols"] == ["TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert api["facts"]["static_rsa_kex"] is True and api["facts"]["internet_facing"] is False
    assert api["facts"]["certificate_map"].endswith("certificateMaps/api-map")
    assert {"PROTO_TLS11", "STATIC_RSA_KEX"} <= set(_codes(api)) and "PROTO_TLS10" not in _codes(api)
    tcp = rows["tcp-proxy"]
    assert tcp["protocol"] == "SSL" and tcp["facts"]["protocols"] == ["TLSv1.2", "TLSv1.3"]
    assert not {"PROTO_TLS10", "PROTO_TLS11", "STATIC_RSA_KEX"} & set(_codes(tcp))

    certs = {a["name"]: a for a in _by(found, "certificate") if a["location"].startswith(SELF)}
    shop = next(a for a in _by(found, "certificate") if a["location"] == f"{SELF}/global/sslCertificates/shop-cert")
    assert shop["algorithm"] == "ECDSA" and shop["key_size"] == 256 and shop["facts"]["in_use"] is True
    managed = next(a for a in _by(found, "certificate") if a["location"] == f"{SELF}/global/sslCertificates/managed-cert")
    assert managed["facts"]["managed_status"] == "PROVISIONING" and managed["facts"]["in_use"] is False
    assert "CERT_UNUSED" in _codes(managed) and certs
    assert out["targets"][0]["services"]["compute"] == "ok"
    assert all(r["method"] in ("GET", "POST") for r in rec.seen)
    assert all(r["method"] == "GET" for r in rec.seen if r["host"] == "compute.googleapis.com")


def test_gcp_certificate_manager_and_storage_buckets():
    out, found, _rec = _gcp(_gcp_cp())
    cm = {a["location"]: a for a in _by(found, "certificate") if a["location"].startswith("//certificatemanager")}
    api = cm[f"//certificatemanager.googleapis.com/projects/{PROJECT}/locations/global/certificates/api-cert"]
    assert api["algorithm"] == "ECDSA" and api["facts"]["managed_state"] == "ACTIVE" and api["facts"]["used_by"] == 1
    pending = cm[f"//certificatemanager.googleapis.com/projects/{PROJECT}/locations/global/certificates/pending"]
    assert pending["algorithm"] is None and pending["facts"]["managed_state"] == "PROVISIONING"
    gap = next(a for a in _by(found, "coverage") if a["facts"]["check"].startswith("certificatemanager"))
    assert gap["facts"]["status"] == "unreachable" and gap["facts"]["scope"] == [
        f"//certificatemanager.googleapis.com/projects/{PROJECT}/locations/asia-south2/"]
    buckets = {a["name"]: a["facts"] for a in _by(found, "storage_encryption")}
    assert buckets["pay-logs"]["kms_key_id"].endswith("cryptoKeys/rotated") and buckets["public-assets"]["kms_key_id"] == "google-managed"
    assert all(f["encrypted"] is True for f in buckets.values())
    services = out["targets"][0]["services"]
    assert services["certificatemanager"] == "partial" and services["storage"] == "ok" and out["targets"][0]["status"] == "partial"


def test_gcp_disabled_compute_api_is_not_enabled_and_denied_storage_is_a_coverage_row():
    """The live test project's shape: Compute Engine and Certificate Manager APIs disabled, storage.buckets.list denied."""
    routes = _gcp_cp(**{f"{COMPUTE}/projects/{PROJECT}/aggregated/sslPolicies": (403, SERVICE_DISABLED_COMPUTE),
                        "https://storage.googleapis.com/storage/v1/b": (403, STORAGE_DENIED)})
    out, found, rec = _gcp(routes)
    gaps = {a["facts"]["check"].split(" ")[0]: a["facts"] for a in _by(found, "coverage")}
    assert gaps["compute"]["status"] == "not_enabled" and gaps["compute"]["by_choice"] is True
    assert gaps["compute"]["scope"] == [f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/"]
    assert gaps["storage"]["status"] == "denied" and "storage.buckets.list" in gaps["storage"]["detail"]
    assert gaps["storage"]["scope"] == ["//storage.googleapis.com/projects/_/buckets/"]
    assert not [r for r in rec.seen if "targetHttpsProxies" in r["url"]]  # one disabled answer stops the service
    target = out["targets"][0]
    assert target["services"]["compute"] == "not_enabled" and target["services"]["storage"] == "denied"
    assert target["status"] == "error" and "storage: denied" in target["error"] and "compute" not in target["error"]


def test_gcp_aggregated_paging_unreachable_scopes_and_429(monkeypatch):
    monkeypatch.setattr(cloud_http.time, "sleep", lambda _s: None)
    page1 = {"items": {"global": {"targetHttpsProxies": [PROXIES["items"]["global"]["targetHttpsProxies"][0]]}},
             "nextPageToken": "p2", "unreachables": ["regions/me-central2"]}
    page2 = {"items": {"global": {"targetHttpsProxies": [PROXIES["items"]["global"]["targetHttpsProxies"][1]]}}}
    throttled = {"n": 0}

    def proxies(request, _f):
        if "pageToken=p2" in str(request.url):
            throttled["n"] += 1
            if throttled["n"] == 1:
                return 429, {"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", "message": "Quota exceeded"}}
            return 200, page2
        return 200, page1

    out, found, rec = _gcp(_gcp_cp(**{f"{COMPUTE}/projects/{PROJECT}/aggregated/targetHttpsProxies": proxies}))
    assert {a["name"] for a in _by(found, "load_balancer_tls")} == {"web-proxy", "api-proxy", "tcp-proxy"} and throttled["n"] == 2
    gap = next(a for a in _by(found, "coverage") if a["facts"]["status"] == "unreachable" and a["facts"]["check"].startswith("compute"))
    assert gap["facts"]["scope"] == [f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/regions/me-central2/"]
    assert out["targets"][0]["services"]["compute"] == "partial"
    assert any("returnPartialSuccess=true" in r["url"] for r in rec.seen if "aggregated" in r["url"])


def test_gcp_malformed_answers_are_coverage_rows_not_crashes():
    routes = _gcp_cp(**{f"{COMPUTE}/projects/{PROJECT}/aggregated/sslCertificates": (200, {"items": ["not", "a", "map"]}),
                        f"{KMS}/{LOC}/keyRings/payments/cryptoKeys/signer/cryptoKeyVersions": (500, {"error": {"code": 500, "status": "INTERNAL", "message": "backend"}}),
                        "https://storage.googleapis.com/storage/v1/b": (200, {"items": [{"name": "no-encryption-field"}, 7]})})
    out, found, _rec = _gcp(routes)
    signer = next(a for a in _by(found, "kms_key") if a["name"] == "signer")
    assert signer["facts"]["versions_error"] and signer["facts"]["version_count"] is None
    gap = next(a for a in _by(found, "coverage") if "key versions" in a["facts"]["check"])
    assert gap["facts"]["status"] == "error" and gap["facts"]["scope"] == [f"{LOC}/keyRings/payments/cryptoKeys/signer"]
    assert out["targets"][0]["services"]["cloudkms"] == "partial"
    assert {a["name"] for a in _by(found, "storage_encryption")} == {"no-encryption-field"}
    assert not [a for a in _by(found, "certificate") if "sslCertificates" in a["location"]]
    assert out["targets"][0]["status"] == "partial"


@pytest.mark.parametrize("value,expected", [
    ("GOOGLE_SYMMETRIC_ENCRYPTION", ("AES", 256)), ("AES_128_GCM", ("AES", 128)), ("HMAC_SHA256", ("HMAC", None)),
    ("EC_SIGN_SECP256K1_SHA256", ("ECDSA", 256)), ("KEM_ECDH_P384", ("ECDH", 384)), ("EC_SIGN_ED25519", ("ED25519", 256)),
    ("RSA_DECRYPT_OAEP_4096_SHA512", ("RSA", 4096)), ("EXTERNAL_SYMMETRIC_ENCRYPTION", ("AES", 256)),
])
def test_gcp_kms_algorithms_resolve_through_algid(value, expected):
    from backend.utilities.cbom_sources import gcp_collect

    assert gcp_collect._kms_algorithm(value) == expected


def test_reader_scripts_grant_exactly_the_read_actions_the_collectors_use():
    import re

    from backend.utilities.cbom_sources import azure_arm, templates

    azure, gcp = templates.template_text("azure-reader"), templates.template_text("gcp-reader")
    for _path_, _version, action, _words in azure_arm.SERVICES.values():
        for one in re.findall(r"Microsoft\.[A-Za-z]+/[A-Za-z/]+/read", action):
            assert f'"{one}"' in azure, one  # a denied coverage row names the same action the script grants
    actions = azure[azure.index('"Actions": ['):azure.index('"NotActions"')]
    assert "config/list" not in actions and "listKeys" not in actions and "/action" not in actions.lower()
    assert all(line.strip().strip('",').endswith("/read") for line in actions.splitlines()[1:] if line.strip().startswith('"'))
    assert '"DataActions": []' in azure
    for permission in ("compute.sslPolicies.list", "compute.regionSslPolicies.list", "compute.sslCertificates.list",
                       "compute.regionSslCertificates.list", "compute.targetHttpsProxies.list",
                       "compute.regionTargetHttpsProxies.list", "compute.targetSslProxies.list", "compute.forwardingRules.list",
                       "compute.globalForwardingRules.list", "storage.buckets.list", "roles/certificatemanager.viewer"):
        assert permission in gcp, permission
    assert "roles/compute.viewer" not in gcp and "versions.access" not in gcp.replace("no secretmanager.versions.access", "")


# ----------------------------------------------------------------------------- Google Cloud: recorded LIVE
LIVE = _HERE / "fixtures" / "gcp_live_zeroshield_cbom_testing_2026-11-14.json"
LIVE_PROJECT = "zeroshield-cbom-testing"


def _live_transport():
    """Replays what Google answered the collector live (fixtures/gcp_live_*.json); a list it left out was empty."""
    import json
    from urllib.parse import parse_qs

    calls = json.loads(LIVE.read_text())["calls"]

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "ya29.replayed", "expires_in": 3599, "token_type": "Bearer"})
        base = f"{request.url.scheme}://{request.url.host}{request.url.path}"
        query = {k: v[0] for k, v in parse_qs(request.url.query.decode()).items()}
        for call in calls:
            if call["url"] == base and {k: str(v) for k, v in call["params"].items()} == {k: query[k] for k in call["params"] if k in query} \
                    and set(call["params"]) == set(query):
                if call["status"] == 200:
                    return httpx.Response(200, json=call["body"])
                err = call["error"]
                details = ([{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": err["code"]}]
                           if not err["code"].isdigit() else [])
                return httpx.Response(call["status"], json={"error": {"code": call["status"], "message": err["message"],
                                                                      "status": "PERMISSION_DENIED", "details": details}})
        return httpx.Response(200, json={})

    return httpx.MockTransport(answer)


def test_gcp_live_recording_replays_to_the_rows_the_oracle_confirmed():
    """The live run (2026-11-14) gave 10 rows that gcloud confirmed one by one: 4 KMS keys, 1 CA, 2 secrets and 3
    coverage rows (Certificate Manager and Compute Engine APIs not enabled, storage.buckets.list denied)."""
    from backend.utilities.cbom_sources import gcp_collect

    found: list[dict] = []
    cfg = {"organization_id": None, "project_ids": [LIVE_PROJECT], "service_account_email": f"zs-cbom@{LIVE_PROJECT}.iam.gserviceaccount.com"}
    key = rsa_key_json(cfg["service_account_email"])
    out = gcp_collect.collect_gcp(1, cfg, {"service_account_key": key}, found.append, lambda: None, transport=_live_transport())
    keys = {a["name"]: a for a in _by(found, "kms_key")}
    assert {n: (a["algorithm"], a["key_size"], a["facts"]["protection_level"], a["facts"]["version_count"]) for n, a in keys.items()} == {
        "key-asymmetric-decrypt-rsa3072": ("RSA", 3072, "SOFTWARE", 1), "key-asymmetric-sign-ec256": ("ECDSA", 256, "SOFTWARE", 1),
        "key-symmetric-rotated": ("AES", 256, "SOFTWARE", 1), "key-symmetric-unrotated": ("AES", 256, "SOFTWARE", 1)}
    assert _codes(keys["key-symmetric-unrotated"]) == ["KMS_NO_ROTATION"] and _codes(keys["key-symmetric-rotated"]) == []
    ca = _by(found, "cloud_ca")[0]
    assert (ca["algorithm"], ca["key_size"], ca["facts"]["tier"]) == ("ECDSA", 256, "DEVOPS")
    assert sorted(a["name"] for a in _by(found, "cloud_secret")) == ["dummy-api-key-with-expiry", "dummy-db-password-no-expiry"]
    gaps = {a["location"].rsplit("#", 1)[-1]: a["facts"] for a in _by(found, "coverage")}
    assert {k: (f["status"], f.get("by_choice", False)) for k, f in gaps.items()} == {
        "certificatemanager": ("not_enabled", True), "compute": ("not_enabled", True), "storage": ("denied", False)}
    assert len(found) == 10
    target = out["targets"][0]
    assert target["status"] == "error" and target["error"] == "storage: denied"


def rsa_key_json(email: str) -> str:
    import json

    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return json.dumps({"type": "service_account", "client_email": email, "private_key_id": "replay",
                       "private_key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()).decode()})
