"""CB-17: certificate validity, chain and keystore facts on the node (R5 X7/X9a probes).

* SAN-heavy certificates keep their count (``san_count``, ``san_truncated``) and a ``wildcard`` fact;
* every certificate of a served chain carries how its issuer is reached (``chain_issuer``), whether it is the top of
  the chain (``chain_top``) and whether it is an extra cross-sign clients do not need (``chain_extra``);
* a Kubernetes TLS secret has every certificate of ``tls.crt`` and ``ca.crt`` judged, not only the first;
* a JKS lists one certificate asset per entry, and a password-protected store or a missing keytool is a coverage row.
"""
from __future__ import annotations

import base64
import datetime as dt
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from zs_scan_node import certparse
from zs_scan_node import linux_parsers as P
from zs_scan_node.collectors import kubernetes as K
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) if cn else x509.Name([])


def _cert(subject: str, issuer: str, key, signer, *, ca: bool, days=(-10, 80), sans=(), aia: str | None = None):
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW + dt.timedelta(days=days[0])).not_valid_after(NOW + dt.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    if aia:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]), critical=False)
    return b.sign(signer, hashes.SHA256())


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _pem(*certs) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def test_san_heavy_certificate_keeps_its_count_and_a_wildcard_fact():
    k = _key()
    sans = [f"h{i}.example.com" for i in range(120)] + ["*.example.com"]
    f = certparse.cert_facts(_cert("", "", k, k, ca=False, sans=sans), "tls")
    assert len(f["san"]) == 50 and f["san_count"] == 121 and f["san_truncated"] is True
    assert f["wildcard"] is True and f["subject"] == ""
    small = certparse.cert_facts(_cert("web", "web", k, k, ca=False, sans=["a.example.com"]), "tls")
    assert small["san_count"] == 1 and small["san_truncated"] is False and small["wildcard"] is False


def _pki():
    """root (self-signed) -> intermediate -> leaf, plus an expired cross-sign of the root by an old root."""
    old_k, root_k, int_k, leaf_k = _key(), _key(), _key(), _key()
    root = _cert("Root X1", "Root X1", root_k, root_k, ca=True, days=(-900, 3000))
    cross = _cert("Root X1", "Old Root", root_k, old_k, ca=True, days=(-900, -30))  # same subject and key as root
    inter = _cert("Issuing R3", "Root X1", int_k, root_k, ca=True, days=(-300, 700), aia="http://ca.example/x1.der")
    leaf = _cert("shop.example.com", "Issuing R3", leaf_k, int_k, ca=False, sans=["shop.example.com"],
                 aia="http://ca.example/r3.der")
    return root, cross, inter, leaf


def test_chain_links_name_how_each_issuer_is_reached_and_the_extra_cross_sign():
    root, cross, inter, leaf = _pki()
    chain = [certparse.cert_facts(c, "tls") for c in (leaf, inter, cross)]
    anchors = certparse.anchor_index([root])  # the node's trust store holds Root X1 itself
    certparse.chain_links(chain, anchors)
    assert [c["chain_issuer"] for c in chain] == ["sent", "sent", "missing"]
    assert [c["chain_top"] for c in chain] == [False, False, True]
    assert [c["chain_extra"] for c in chain] == [False, False, True]  # clients that trust Root X1 skip the cross-sign
    assert chain[0]["aia_ca_issuers"] is True


def test_a_leaf_served_alone_says_its_issuer_is_missing():
    _root, _cross, _inter, leaf = _pki()
    chain = [certparse.cert_facts(leaf, "tls")]
    certparse.chain_links(chain, {})
    assert chain[0]["chain_issuer"] == "missing" and chain[0]["chain_top"] is True and chain[0]["chain_extra"] is False


def test_an_issuer_in_the_node_trust_store_is_trusted_not_missing():
    root, _cross, inter, _leaf = _pki()
    chain = [certparse.cert_facts(inter, "tls")]
    certparse.chain_links(chain, certparse.anchor_index([root]))
    assert chain[0]["chain_issuer"] == "trusted"
    selfie = [certparse.cert_facts(root, "tls")]
    certparse.chain_links(selfie, {})
    assert selfie[0]["chain_issuer"] == "self"


def _ctx(kind="kubernetes"):
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind=kind, scrubber=Scrubber(),
                      never_scan=NeverScan([]), deadline=time.monotonic() + 60)


class SecretApi:
    api_url, host, port = "https://k8s.example:6443", "k8s.example", 6443

    def __init__(self, secret):
        self.secret = secret

    def check_scope(self):
        return "10.0.0.1"

    def get(self, path, params=None):
        return 200, {"gitVersion": "v1.31.0"}

    def list_all(self, path, params=None):
        if path == "/api/v1/secrets":
            yield ("item", self.secret)

    def close(self):
        pass


def test_k8s_tls_secret_judges_every_certificate_in_tls_crt_and_ca_crt(monkeypatch):
    root, _cross, inter, leaf = _pki()
    expired_k = _key()
    expired_inter = _cert("Issuing R3", "Root X1", expired_k, expired_k, ca=True, days=(-400, -5))
    secret = {"metadata": {"namespace": "shop", "name": "web-tls"}, "type": "kubernetes.io/tls",
              "data": {"tls.crt": base64.b64encode(_pem(leaf, expired_inter)).decode(),
                       "ca.crt": base64.b64encode(_pem(root)).decode(), "tls.key": "c2VjcmV0"}}
    api = SecretApi(secret)
    monkeypatch.setattr(K, "Api", lambda *a: api)
    monkeypatch.setattr(K.T, "have_openssl", lambda: False)
    ctx = _ctx()
    K.collect(ctx, {"api_url": SecretApi.api_url, "tier": 2}, {}, {})
    ctx.flush()
    rows = [a for a in ctx.collected if a["location"].startswith("shop/secret/web-tls")]
    by_loc = {a["location"]: a for a in rows}
    assert by_loc["shop/secret/web-tls"]["type"] == "k8s_tls_secret"
    assert by_loc["shop/secret/web-tls"]["facts"]["subject"] == "CN=shop.example.com"
    assert by_loc["shop/secret/web-tls"]["facts"]["chain_length"] == 2
    intermediate = by_loc["shop/secret/web-tls#tls.crt[1]"]
    assert intermediate["type"] == "certificate" and intermediate["facts"]["chain_index"] == 1
    assert intermediate["facts"]["not_after"] < NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    anchor = by_loc["shop/secret/web-tls#ca.crt[0]"]
    assert anchor["type"] == "certificate" and anchor["facts"]["subject"] == "CN=Root X1"
    assert not any("tls.key" in str(a) or "c2VjcmV0" in str(a) for a in ctx.collected)


def test_k8s_tls_secret_with_a_misordered_bundle_keeps_the_leaf_as_the_secret_row(monkeypatch):
    _root, _cross, inter, leaf = _pki()
    secret = {"metadata": {"namespace": "shop", "name": "odd"}, "type": "kubernetes.io/tls",
              "data": {"tls.crt": base64.b64encode(_pem(inter, leaf)).decode()}}
    monkeypatch.setattr(K, "Api", lambda *a: SecretApi(secret))
    monkeypatch.setattr(K.T, "have_openssl", lambda: False)
    ctx = _ctx()
    K.collect(ctx, {"api_url": SecretApi.api_url, "tier": 2}, {}, {})
    ctx.flush()
    row = next(a for a in ctx.collected if a["location"] == "shop/secret/odd")
    assert row["facts"]["subject"] == "CN=shop.example.com"
    other = next(a for a in ctx.collected if a["location"] == "shop/secret/odd#tls.crt[0]")
    assert other["facts"]["subject"] == "CN=Issuing R3"


KEYTOOL = ("Keystore type: JKS\nKeystore provider: SUN\n\nYour keystore contains 2 entries\n\n"
           "Alias name: legacy\nCreation date: Jan 1, 2024\nEntry type: trustedCertEntry\n\n"
           "Owner: CN=legacy, O=Example\nIssuer: CN=legacy, O=Example\nSerial number: 1a2b\n"
           "Valid from: Mon Jan 01 00:00:00 UTC 2024 until: Wed Jan 01 00:00:00 UTC 2025\n"
           "Certificate fingerprints:\n\t SHA1: 00:11\n\t SHA256: AA:BB:CC:DD\n"
           "Signature algorithm name: SHA1withRSA\nSubject Public Key Algorithm: 1024-bit RSA key\nVersion: 3\n\n"
           "Alias name: app\nCreation date: Jan 1, 2026\nEntry type: PrivateKeyEntry\nCertificate chain length: 1\n"
           "Certificate[1]:\nOwner: CN=app\nIssuer: CN=Corp CA\nSerial number: ff\n"
           "Valid from: Thu Jan 01 00:00:00 GMT 2026 until: Fri Jan 01 00:00:00 GMT 2027\n"
           "Signature algorithm name: SHA256withRSA\nSubject Public Key Algorithm: 2048-bit RSA key\n"
           "*** WARNING: The integrity of the information stored in your keystore has NOT been verified!\n")


def test_keytool_entries_carry_dates_issuer_and_fingerprint():
    d = P.keytool_list(KEYTOOL)
    legacy, app = d["entry_list"]
    assert legacy["not_before"] == "2024-01-01T00:00:00Z" and legacy["not_after"] == "2025-01-01T00:00:00Z"
    assert legacy["issuer"] == "CN=legacy, O=Example" and legacy["fingerprint_sha256"] == "aabbccdd"
    assert legacy["self_signed"] is True and app["self_signed"] is False
    assert app["not_after"] == "2027-01-01T00:00:00Z" and app["key_size"] == 2048


class KeystoreSession:
    def __init__(self, status, out, err=""):
        self.status, self.out, self.err = status, out, err

    def run(self, command, timeout=None, binary=False):
        return self.status, self.out, self.err, False


def test_a_listed_jks_gives_one_certificate_asset_per_entry():
    ctx = _ctx("linux")
    L._inspect_file(ctx, KeystoreSession(0, KEYTOOL), "host1", "/opt/app/store.jks")
    ctx.flush()
    certs = [a for a in ctx.collected if a["type"] == "certificate"]
    assert {c["location"] for c in certs} == {"/opt/app/store.jks#legacy", "/opt/app/store.jks#app"}
    legacy = next(c for c in certs if c["location"].endswith("#legacy"))
    assert legacy["algorithm"] == "RSA" and legacy["key_size"] == 1024 and legacy["name"] == "CN=legacy, O=Example"
    assert legacy["facts"]["keystore"] == "/opt/app/store.jks" and legacy["facts"]["alias"] == "legacy"
    assert legacy["facts"]["not_after"] == "2025-01-01T00:00:00Z" and legacy["facts"]["sig_alg"] == "SHA1withRSA"
    assert sum(1 for a in ctx.collected if a["type"] == "keystore") == 1


def test_a_password_protected_store_and_a_missing_keytool_are_coverage_rows():
    ctx = _ctx("linux")
    L._inspect_file(ctx, KeystoreSession(1, "", "keytool error: java.io.IOException: keystore password was incorrect"),
                    "host1", "/opt/app/a.p12")
    L._inspect_file(ctx, KeystoreSession(127, "", "bash: keytool: command not found"), "host1", "/opt/app/b.jks")
    ctx.flush()
    cov = [a["facts"] for a in ctx.collected if a["type"] == "coverage"]
    assert any(c["status"] == "incomplete" and c["scope"] == ["/opt/app/a.p12"] and c["incomplete"] is True
               for c in cov)
    assert any(c["status"] == "not_installed" and "keytool" in c["detail"] for c in cov)
    assert sum(1 for a in ctx.collected if a["type"] == "keystore") == 2  # the files stay listed
