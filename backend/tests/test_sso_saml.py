"""SAML response verification (F4 SSO): every check in utilities/sso/saml.py, with real signatures (signxml).

The IdP key and certificate are made per test run (cryptography); nothing secret is stored.  Covered: a response
or an assertion signed by the configured certificate; unsigned; signed by another key (also with that key's
certificate in KeyInfo); XML signature wrapping (an injected assertion next to, or around, the signed one); a
changed NameID; the comment-truncation trick (CVE-2017-11427 class); audience, recipient, destination, issuer,
InResponseTo (unsolicited), NotBefore / NotOnOrAfter with the 120 s skew; DOCTYPE / entities (XXE);
EncryptedAssertion; SHA-1; size and base64 limits; the email attribute fallback.

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. python -m pytest tests/test_sso_saml.py -q -p no:cacheprovider
"""
import base64
import copy
import datetime as dt
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "sso-saml-test-access-secret-0123456789")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "sso-saml-test-refresh-secret-0123456789")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from lxml import etree  # noqa: E402

from backend.utilities.sso import saml  # noqa: E402

IDP = "https://idp.acme.test/realms/acme"
SP = "https://api.devsec.test/sso/7/saml"
ACS = "https://api.devsec.test/sso/7/saml/acs"
REQ = "_req0123456789abcdef"
NOW = dt.datetime(2026, 11, 11, 12, 0, 0)
P, A = saml.SAMLP, saml.SAML


def _key_and_cert(cn: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            .not_valid_after(dt.datetime(2028, 1, 1, tzinfo=dt.timezone.utc))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return key_pem, cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture(scope="module")
def idp():
    return _key_and_cert("idp.acme.test")


@pytest.fixture(scope="module")
def attacker():
    return _key_and_cert("evil.test")


def _iso(moment):
    return moment.replace(microsecond=0).isoformat() + "Z"


def build(email="alice@acme-sso.test", *, audience=SP, recipient=ACS, destination=ACS, issuer=IDP, in_response_to=REQ,
          not_before=NOW - dt.timedelta(minutes=1), not_after=NOW + dt.timedelta(minutes=5), name_format=saml.EMAIL_FORMAT,
          assertion_id="_a1b2c3", status=saml.SUCCESS, attrs=None):
    nsmap = {"samlp": saml.NS["samlp"], "saml": saml.NS["saml"]}
    response = etree.Element(P + "Response", nsmap=nsmap, ID="_resp1", Version="2.0", IssueInstant=_iso(NOW))
    if destination is not None:
        response.set("Destination", destination)
    if in_response_to is not None:
        response.set("InResponseTo", in_response_to)
    etree.SubElement(response, A + "Issuer").text = issuer
    st = etree.SubElement(response, P + "Status")
    etree.SubElement(st, P + "StatusCode", Value=status)
    assertion = etree.SubElement(response, A + "Assertion", ID=assertion_id, Version="2.0", IssueInstant=_iso(NOW))
    etree.SubElement(assertion, A + "Issuer").text = issuer
    subject = etree.SubElement(assertion, A + "Subject")
    nid = etree.SubElement(subject, A + "NameID", Format=name_format)
    nid.text = email
    conf = etree.SubElement(subject, A + "SubjectConfirmation", Method=saml.BEARER)
    data = etree.SubElement(conf, A + "SubjectConfirmationData", NotOnOrAfter=_iso(not_after), Recipient=recipient)
    if in_response_to is not None:
        data.set("InResponseTo", in_response_to)
    cond = etree.SubElement(assertion, A + "Conditions", NotBefore=_iso(not_before), NotOnOrAfter=_iso(not_after))
    etree.SubElement(etree.SubElement(cond, A + "AudienceRestriction"), A + "Audience").text = audience
    etree.SubElement(assertion, A + "AuthnStatement", AuthnInstant=_iso(NOW))
    if attrs:
        stmt = etree.SubElement(assertion, A + "AttributeStatement")
        for name, value in attrs.items():
            attr = etree.SubElement(stmt, A + "Attribute", Name=name)
            etree.SubElement(attr, A + "AttributeValue").text = value
    return response


def sign(response, key_cert, *, what="assertion", digest="sha256"):
    from signxml import XMLSigner

    key, cert = key_cert
    if digest == "sha1":
        class LegacySigner(XMLSigner):  # signxml refuses to make SHA-1 signatures; an old IdP still can
            def check_deprecated_methods(self):
                pass
        signer = LegacySigner(signature_algorithm="rsa-sha1", digest_algorithm="sha1")
    else:
        signer = XMLSigner(signature_algorithm=f"rsa-{digest}", digest_algorithm=digest)
    if what in ("assertion", "both"):
        assertion = response.find(A + "Assertion")
        signed = signer.sign(assertion, key=key, cert=cert, reference_uri=assertion.get("ID"))
        # the signature goes after the Issuer, as the schema wants
        sig = signed.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
        signed.remove(sig)
        signed.insert(1, sig)
        response.replace(assertion, signed)
    if what in ("response", "both"):
        signed = signer.sign(response, key=key, cert=cert, reference_uri=response.get("ID"))
        sig = signed.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
        signed.remove(sig)
        signed.insert(1, sig)
        response = signed
    return response


def b64(element) -> str:
    return base64.b64encode(etree.tostring(element)).decode("ascii")


def check(payload, cert, **kw):
    args = dict(idp_certs=[cert], idp_entity_id=IDP, sp_entity_id=SP, acs_url=ACS, request_id=REQ, now=NOW)
    args.update(kw)
    return saml.parse_response(payload, **args)


# ------------------------------------------------------------------------------------------------ accepted

@pytest.mark.parametrize("what", ["assertion", "response", "both"])
def test_a_signed_response_or_assertion_signs_the_person_in(idp, what):
    identity = check(b64(sign(build(), idp, what=what)), idp[1])
    assert identity.email == "alice@acme-sso.test" and identity.assertion_id == "_a1b2c3"
    assert identity.expires_at >= NOW + dt.timedelta(minutes=5)


def test_the_email_attribute_is_used_when_the_name_id_is_not_an_email(idp):
    response = build(email="opaque-123", name_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                     attrs={"email": "Bob@ACME-sso.test"})
    assert check(b64(sign(response, idp)), idp[1]).email == "bob@acme-sso.test"


def test_clock_skew_of_two_minutes_is_tolerated(idp):
    response = build(not_before=NOW + dt.timedelta(seconds=90))
    assert check(b64(sign(response, idp)), idp[1]).email == "alice@acme-sso.test"


def test_a_rotated_certificate_list_accepts_either(idp, attacker):
    signed = b64(sign(build(), idp))
    assert check(signed, idp[1], idp_certs=[attacker[1], idp[1]]).email == "alice@acme-sso.test"


# ------------------------------------------------------------------------------------------------ signature

def test_unsigned_is_refused(idp):
    with pytest.raises(saml.SamlError, match="not signed"):
        check(b64(build()), idp[1])


def test_signed_by_another_key_is_refused_even_with_its_own_certificate_inside(idp, attacker):
    forged = sign(build(), attacker)  # KeyInfo carries the attacker's certificate
    with pytest.raises(saml.SamlError, match="not signed"):
        check(b64(forged), idp[1])


def test_a_changed_name_id_breaks_the_signature(idp):
    signed = sign(build(), idp)
    signed.find(f"{A}Assertion/{A}Subject/{A}NameID").text = "ceo@acme-sso.test"
    with pytest.raises(saml.SamlError, match="not signed"):
        check(b64(signed), idp[1])


def test_signature_wrapping_an_injected_assertion_next_to_the_signed_one(idp):
    """XSW: the signed assertion stays (signature valid); an evil one is added.  Never read: exactly one assertion."""
    signed = sign(build(), idp)
    evil = copy.deepcopy(signed.find(A + "Assertion"))
    evil.set("ID", "_evil")
    evil.find(f"{A}Subject/{A}NameID").text = "ceo@acme-sso.test"
    for sig in evil.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
        evil.remove(sig)
    signed.insert(2, evil)  # before the signed one: a naive parser reads the first
    with pytest.raises(saml.SamlError, match="exactly one assertion"):
        check(b64(signed), idp[1])


def test_signature_wrapping_the_signed_response_moved_inside_an_evil_one(idp):
    """XSW: an evil unsigned Response wraps the IdP-signed Response (in Extensions)."""
    original = sign(build(), idp, what="response")
    evil = build(email="ceo@acme-sso.test", assertion_id="_evil")
    extensions = etree.SubElement(evil, P + "Extensions")
    extensions.append(original)
    with pytest.raises(saml.SamlError):
        check(b64(evil), idp[1])


def test_signature_wrapping_signed_assertion_hidden_in_an_object_and_an_evil_one_in_its_place(idp):
    signed = sign(build(), idp)
    good = signed.find(A + "Assertion")
    evil = copy.deepcopy(good)
    evil.find(f"{A}Subject/{A}NameID").text = "ceo@acme-sso.test"
    sig = evil.find("{http://www.w3.org/2000/09/xmldsig#}Signature")
    obj = etree.SubElement(sig, "{http://www.w3.org/2000/09/xmldsig#}Object")
    signed.remove(good)
    obj.append(good)  # the referenced (signed) element now hides inside the evil assertion's signature
    signed.append(evil)
    with pytest.raises(saml.SamlError):
        check(b64(signed), idp[1])


def test_comment_inside_the_name_id_cannot_truncate_the_address(idp):
    """CVE-2017-11427 class: alice@acme-sso.test<!---->.evil.test.  Canonicalisation drops the comment (the
    signature covers 'alice@acme-sso.test.evil.test'); reading text before the comment would sign in alice."""
    response = build(email="alice@acme-sso.test")
    nid = response.find(f"{A}Assertion/{A}Subject/{A}NameID")
    nid.text = "alice@acme-sso.test"
    comment = etree.Comment("")
    nid.append(comment)
    comment.tail = ".evil.test"
    identity = check(b64(sign(response, idp)), idp[1])
    assert identity.email == "alice@acme-sso.test.evil.test"


def test_sha1_signatures_are_refused(idp):
    with pytest.raises(saml.SamlError, match="not signed"):
        check(b64(sign(build(), idp, digest="sha1")), idp[1])


# ------------------------------------------------------------------------------------------------ conditions

@pytest.mark.parametrize("change,message", [
    (dict(audience="https://other.test/sp"), "audience"),
    (dict(recipient="https://evil.test/acs"), "not confirmed"),
    (dict(destination="https://evil.test/acs"), "another address"),
    (dict(issuer="https://evil-idp.test"), "another identity provider"),
    (dict(in_response_to="_someone_elses_request"), "another sign-in"),
    (dict(in_response_to=None), "not confirmed"),  # unsolicited (IdP-initiated) responses are refused
    (dict(not_after=NOW - dt.timedelta(minutes=3)), "expired"),
    (dict(not_before=NOW + dt.timedelta(minutes=5)), "not valid yet"),
    (dict(status="urn:oasis:names:tc:SAML:2.0:status:Requester"), "did not sign you in"),
    (dict(email="not-an-email", name_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"), "email"),
])
def test_conditions(idp, change, message):
    with pytest.raises(saml.SamlError, match=message):
        check(b64(sign(build(**change), idp, what="both")), idp[1])


# ------------------------------------------------------------------------------------------------ parsing

def test_doctype_and_entities_are_refused(idp):
    xml = etree.tostring(sign(build(), idp)).decode()
    evil = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + xml
    with pytest.raises(saml.SamlError, match="DOCTYPE"):
        check(base64.b64encode(evil.encode()).decode(), idp[1])


def test_encrypted_assertions_are_refused(idp):
    response = sign(build(), idp)
    etree.SubElement(response, A + "EncryptedAssertion")
    with pytest.raises(saml.SamlError, match="Encrypted"):
        check(b64(response), idp[1])


@pytest.mark.parametrize("payload", ["", "%%%not-base64%%%", base64.b64encode(b"<a>not saml</a>").decode(),
                                     base64.b64encode(b"<unclosed").decode()])
def test_malformed_input(idp, payload):
    with pytest.raises(saml.SamlError):
        check(payload, idp[1])


def test_oversized_input_is_refused_before_parsing(idp):
    with pytest.raises(saml.SamlError, match="too large"):
        check("A" * (saml.MAX_RESPONSE_BYTES * 2), idp[1])


def test_no_certificate_configured(idp):
    with pytest.raises(saml.SamlError, match="No IdP signing certificate"):
        check(b64(sign(build(), idp)), idp[1], idp_certs=[])


def test_the_authn_request_url_round_trips(idp):
    import zlib
    from urllib.parse import parse_qs, urlsplit

    url = saml.authn_request_url(idp_sso_url=IDP + "/protocol/saml", sp_entity_id=SP, acs_url=ACS, request_id=REQ,
                                 relay_state="state-1", now=NOW)
    query = parse_qs(urlsplit(url).query)
    xml = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -15)
    root = etree.fromstring(xml)
    assert root.get("ID") == REQ and root.get("AssertionConsumerServiceURL") == ACS
    assert root.findtext(A + "Issuer") == SP and query["RelayState"] == ["state-1"]
