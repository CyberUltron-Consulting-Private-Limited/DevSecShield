"""CB-04 PR-3b: the cloud and IdP collectors name algorithms through algid (plan cb-04 DA §6 / §9: T-B5, T-B16,
T-B17, T-B18), so a post-quantum key or certificate collected from AWS, Azure, GCP or an identity provider is named
as what it is and judged quantum safe instead of being misread (ML-DSA as ECDSA), dropped (a parse error) or left
without a verdict.

Recorded responses go through botocore's Stubber (validated against the service model; enum values are not, so the
AWS spellings RSA_2048 and RSA-2048 both reach the code, EC-8). The ML-DSA-65 certificate is the CB-02 lab's z05b
certificate (e2e/cbom/lab/tests/fixtures/cert-z05b-mldsa.crt.txt, copied to fixtures/idp). No network."""
from __future__ import annotations

import base64
import datetime as dt
import ssl
import sys
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from test_cbom_aws_collect_wp4 import ACCOUNT, REGION, _run  # noqa: E402

from backend.utilities.cbom_sources import algid, algid_tables, aws_collect, idp_collect  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "idp"
MLDSA_PEM = (FIX / "cert-z05b-mldsa.crt.txt").read_text()
MLDSA_DER = ssl.PEM_cert_to_DER_cert(MLDSA_PEM)
NOW = dt.datetime(2026, 11, 14)


def _judge(asset):
    return classify(asset["type"], asset.get("algorithm"), asset.get("key_size"), asset.get("protocol"),
                    asset.get("facts") or {}, NOW)


# ------------------------------------------------------------------------------------------------ T-B5 AWS
def test_pca_kms_acm_stubber():
    pca_arn = f"arn:aws:acm-pca:{REGION}:{ACCOUNT}:certificate-authority/"
    cas = [{"Arn": pca_arn + n, "Status": "ACTIVE", "Type": "ROOT",
            "CertificateAuthorityConfiguration": {"KeyAlgorithm": alg, "SigningAlgorithm": sig,
                                                  "Subject": {"CommonName": n}}}
           for n, alg, sig in (("pq", "ML_DSA_65", "ML_DSA_65"), ("rsa", "RSA_2048", "SHA256WITHRSA"),
                               ("ec", "EC_secp384r1", "SHA384WITHECDSA"), ("sm2", "SM2", "SM3WITHSM2"))]
    key_arn = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/"
    specs = {"k-mldsa": "ML_DSA_65", "k-ed": "ECC_NIST_EDWARDS25519", "k-sm2": "SM2", "k-rsa": "RSA_3072",
             "k-p256": "ECC_NIST_P256"}
    usage = {"k-mldsa": "SIGN_VERIFY", "k-ed": "SIGN_VERIFY", "k-sm2": "SIGN_VERIFY", "k-rsa": "SIGN_VERIFY",
             "k-p256": "SIGN_VERIFY"}
    kms_calls = [("list_keys", {"Keys": [{"KeyId": k, "KeyArn": key_arn + k} for k in specs]}, None)]
    for k, spec in specs.items():
        kms_calls.append(("describe_key", {"KeyMetadata": {
            "KeyId": k, "Arn": key_arn + k, "KeySpec": spec, "KeyUsage": usage[k], "KeyState": "Enabled",
            "KeyManager": "CUSTOMER", "Origin": "AWS_KMS", "Enabled": True}}, {"KeyId": k}))
    acm_arn = f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/"
    acm_calls = [("list_certificates", {"CertificateSummaryList": [
        {"CertificateArn": acm_arn + "rsa", "DomainName": "a.bank.example"},
        {"CertificateArn": acm_arn + "ec", "DomainName": "b.bank.example"}]}, None)]
    for name, alg in (("rsa", "RSA-2048"), ("ec", "EC-prime256v1")):
        acm_calls.append(("describe_certificate", {"Certificate": {
            "CertificateArn": acm_arn + name, "DomainName": f"{name}.bank.example", "KeyAlgorithm": alg,
            "SignatureAlgorithm": "SHA256WITHRSA", "Status": "ISSUED", "Type": "AMAZON_ISSUED"}},
            {"CertificateArn": acm_arn + name}))
    plan = {"acm-pca": [("list_certificate_authorities", {"CertificateAuthorities": cas}, None)],
            "kms": kms_calls, "acm": acm_calls}
    _s, found = _run(plan)

    ca = {a["location"].rsplit("/", 1)[-1]: a for a in found if a["type"] == "cloud_ca"}
    assert (ca["pq"]["algorithm"], ca["pq"]["key_size"]) == ("ML-DSA-65", None)  # not "ECDSA"
    assert (ca["rsa"]["algorithm"], ca["rsa"]["key_size"]) == ("RSA", 2048)
    assert (ca["ec"]["algorithm"], ca["ec"]["key_size"]) == ("ECDSA", 384)
    assert (ca["sm2"]["algorithm"], ca["sm2"]["key_size"]) == ("SM2", 256)  # not "ECDSA"
    assert ca["pq"]["facts"]["key_alg"] == "ML_DSA_65"  # the raw enum is kept
    assert _judge(ca["pq"])["quantum_vulnerable"] is False and "QUANTUM_VULNERABLE" not in _judge(ca["pq"])["finding_codes"]
    assert _judge(ca["rsa"])["quantum_vulnerable"] is True and _judge(ca["sm2"])["quantum_vulnerable"] is True

    keys = {a["location"].rsplit("/", 1)[-1]: a for a in found if a["type"] == "kms_key"}
    assert keys["k-ed"]["key_size"] == 256  # not 25519
    assert keys["k-sm2"]["key_size"] == 256
    assert keys["k-mldsa"]["key_size"] is None and keys["k-rsa"]["key_size"] == 3072 and keys["k-p256"]["key_size"] == 256
    assert _judge(keys["k-mldsa"])["quantum_vulnerable"] is False and _judge(keys["k-ed"])["quantum_vulnerable"] is True

    certs = {a["location"].rsplit("/", 1)[-1]: a for a in found if a["type"] == "certificate"}
    assert (certs["rsa"]["algorithm"], certs["rsa"]["key_size"], certs["rsa"]["facts"]["key_alg_raw"]) == ("RSA", 2048, "RSA-2048")
    assert (certs["ec"]["algorithm"], certs["ec"]["key_size"], certs["ec"]["facts"]["key_alg_raw"]) == ("ECDSA", 256, "EC-prime256v1")


def test_both_aws_spellings_of_a_key_algorithm_read_the_same():
    """EC-8: Stubber accepts any string; AWS documents RSA_2048 (acm-pca, kms) and RSA-2048 (acm)."""
    for raw in ("RSA_2048", "RSA-2048", "rsa_2048"):
        assert aws_collect._bits(raw) == 2048, raw
    assert aws_collect._bits("EC_prime256v1") == 256 and aws_collect._bits("ECC_NIST_EDWARDS25519") == 256
    assert aws_collect._bits("ML_DSA_87") is None and aws_collect._bits(None) is None


def test_the_acm_key_types_asked_for_are_algids_captured_enum():
    assert aws_collect.ACM_KEY_TYPES == list(algid_tables.AWS["acm.KeyAlgorithm"])


# ------------------------------------------------------------------------------------------------ T-B16 ELB / API GW
def test_elb_apigw_pq_policies_are_hybrid_and_classical_ones_unchanged():
    from backend.utilities.cbom_sources.posture import classify_pqc

    elb = list(algid_tables.AWS_TLS_POLICY["elbv2"])
    apigw = list(algid_tables.AWS_TLS_POLICY["apigateway"])
    assert len(elb) == 13 and len(apigw) >= 3
    for name in elb:
        facts = {"ssl_policy": name, "protocols": ["TLSv1.2", "TLSv1.3"]}
        v = classify("load_balancer_tls", None, None, "TLS", facts, NOW)
        assert v["quantum_vulnerable"] is False and "QUANTUM_VULNERABLE" not in v["finding_codes"], name
        row = {"asset_type": "load_balancer_tls", "quantum_vulnerable": False, "facts": facts}
        assert classify_pqc(row, v["finding_codes"])[0] == "hybrid", name
    for name in apigw:
        v = classify("api_tls", None, None, "TLS", {"security_policy": name, "protocols": ["TLSv1.2", "TLSv1.3"]}, NOW)
        assert v["quantum_vulnerable"] is False, name
    for name in ("ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-2016-08"):
        v = classify("load_balancer_tls", None, None, "TLS", {"ssl_policy": name, "protocols": ["TLSv1.2"]}, NOW)
        assert v["quantum_vulnerable"] is True, name


# ------------------------------------------------------------------------------------------------ T-B17 certificates
def test_backend_cert_facts_reads_a_pq_certificate():
    alg, bits, facts = idp_collect.cert_facts(MLDSA_DER, "idp")
    assert (alg, bits) == ("ML-DSA-65", None)
    assert facts["key_alg"] == "ML-DSA-65" and facts["sig_alg"] == "ML-DSA-65"
    assert facts["key_alg_oid"] == "2.16.840.1.101.3.4.3.18" and facts["subject"] == "CN=z05b.lab"
    assert len(facts["fingerprint_sha256"]) == 64
    v = classify("certificate", alg, bits, None, facts, NOW)
    assert v["quantum_vulnerable"] is False and "QUANTUM_VULNERABLE" not in v["finding_codes"]


def test_classical_certificates_keep_their_names(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import NameOID

    def make(key, digest):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c.bank.example")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(7).not_valid_before(dt.datetime(2026, 1, 1)).not_valid_after(dt.datetime(2027, 1, 1))
                .sign(key, digest))
        return cert.public_bytes(serialization.Encoding.DER)

    alg, bits, facts = idp_collect.cert_facts(make(rsa.generate_private_key(65537, 2048), hashes.SHA256()), "x")
    assert (alg, bits, facts["sig_alg"]) == ("RSA", 2048, "sha256WithRSAEncryption")
    alg, bits, facts = idp_collect.cert_facts(make(ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()), "x")
    assert (alg, bits, facts["curve"], facts["sig_alg"]) == ("ECDSA", 384, "secp384r1", "ecdsa-with-SHA384")


def _saml(cert_b64: str) -> bytes:
    return (f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
            f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.bank.example">'
            f'<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}'
            f'</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor>'
            f'</md:EntityDescriptor>').encode()


def test_backend_cert_facts_pq_all_lanes(monkeypatch):
    b64 = base64.b64encode(MLDSA_DER).decode()
    seen: dict[str, dict] = {}

    # SAML metadata
    assets = idp_collect.saml_assets_from_xml(_saml(b64), "https://idp.bank.example/md", "idp")
    assert not [a for a in assets if a["type"] == "coverage"], assets
    seen["saml"] = next(a for a in assets if a["type"] == "certificate")
    assert next(a for a in assets if a["type"] == "signing_key")["algorithm"] == "ML-DSA-65"

    # OIDC JWKS x5c
    docs = {"https://idp.bank.example/.well-known/openid-configuration":
            b'{"issuer":"https://idp.bank.example","jwks_uri":"https://idp.bank.example/jwks"}',
            "https://idp.bank.example/jwks":
            ('{"keys":[{"kty":"AKP","alg":"ML-DSA-65","kid":"k1","pub":"AAAA","x5c":["%s"]}]}' % b64).encode()}

    class _Doc:
        def __init__(self, body):
            self.status, self.body = 200, body

    monkeypatch.setattr(idp_collect, "fetch", lambda url, **_k: _Doc(docs[url]))
    assets, gaps = idp_collect._oidc("https://idp.bank.example/.well-known/openid-configuration", "idp")
    assert not gaps, gaps
    seen["oidc"] = next(a for a in assets if a["type"] == "certificate")

    # Azure Key Vault certificate, GCP CA Service CA, an AWS configuration value holding the PEM
    from backend.utilities.cbom_sources import azure_collect, gcp_collect

    seen["azure"] = azure_collect._certificate_asset(
        {"cer": b64, "id": "https://v.vault.azure.net/certificates/pq/1", "policy": {}}, "v", "azure")
    seen["gcp"] = gcp_collect._ca_asset({"name": "projects/p/locations/l/caPools/x/certificateAuthorities/pq",
                                         "pemCaCertificates": [MLDSA_PEM], "keySpec": {}}, "gcp")
    shape = aws_collect._public_shape(MLDSA_PEM, MLDSA_PEM.replace("\n", ""))
    assert shape and shape["material"] == "certificate" and shape["algorithm"] == "ML-DSA-65", shape

    for lane, asset in seen.items():
        assert asset is not None and asset["algorithm"] == "ML-DSA-65", (lane, asset)
        assert _judge(asset)["quantum_vulnerable"] is False, lane


# ------------------------------------------------------------------------------------------------ T-B18 JWKS / GCP
def test_jwks_akp_gcp_xwing(monkeypatch):
    docs = {"https://idp.bank.example/.well-known/openid-configuration":
            b'{"issuer":"https://idp.bank.example","jwks_uri":"https://idp.bank.example/jwks"}',
            "https://idp.bank.example/jwks":
            b'{"keys":[{"kty":"AKP","alg":"ML-DSA-44","kid":"pq","pub":"AAAA"},'
            b'{"kty":"RSA","alg":"RS256","kid":"rsa","n":"' + base64.urlsafe_b64encode(b"\xc5" * 256).rstrip(b"=") +
            b'","e":"AQAB"},{"kty":"OKP","crv":"Ed25519","kid":"ed","x":"AAAA"},{"kty":"EC","crv":"P-256","kid":"ec","x":"A","y":"B"}]}'}

    class _Doc:
        def __init__(self, body):
            self.status, self.body = 200, body

    monkeypatch.setattr(idp_collect, "fetch", lambda url, **_k: _Doc(docs[url]))
    assets, _gaps = idp_collect._oidc("https://idp.bank.example/.well-known/openid-configuration", "idp")
    keys = {a["facts"]["kid"]: a for a in assets if a["type"] == "signing_key"}
    assert (keys["pq"]["algorithm"], keys["pq"]["key_size"]) == ("ML-DSA-44", None)
    assert _judge(keys["pq"])["quantum_vulnerable"] is False
    # classical keys unchanged
    assert (keys["rsa"]["algorithm"], keys["rsa"]["key_size"]) == ("RSA", 2048)
    assert keys["ed"]["algorithm"] == "Ed25519" and keys["ec"]["algorithm"] == "ECDSA"

    from backend.utilities.cbom_sources import gcp_collect

    alg, bits = gcp_collect._kms_algorithm("KEM_XWING")
    assert alg == "X-Wing" and bits is None
    assert algid.quantum_vulnerable(alg) is False
