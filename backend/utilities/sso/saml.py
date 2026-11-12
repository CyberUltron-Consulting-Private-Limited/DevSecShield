"""SAML 2.0 service provider: SP-initiated sign-in, HTTP-Redirect AuthnRequest, HTTP-POST Response (F4 SSO).

The XML signature is verified by ``signxml`` (lxml + cryptography; no hand-written crypto).  Everything this module
trusts is read **only from the element signxml returns as signed** (``VerifyResult.signed_xml``), never from the
document it was handed, so a wrapped or injected assertion next to the signed one is never read (XML signature
wrapping).  On top of the signature:

* the document has no DOCTYPE (no entities, no XXE) and is parsed with entity resolution and network access off;
* exactly one ``Assertion`` and no ``EncryptedAssertion`` in the whole document;
* the signing certificate is one the team configured (the certificate in the message's KeyInfo is never trusted);
  SHA-1 signatures are refused (signxml's default);
* Issuer = the IdP's entity id; Audience = our SP entity id; Recipient (and Destination when present) = our ACS
  URL; InResponseTo = the request we sent for this browser (no unsolicited responses);
* NotBefore / NotOnOrAfter of the Conditions and of the bearer SubjectConfirmationData, with ``CLOCK_SKEW``;
* the assertion ID is returned with its expiry so the caller records it once (replay, ``SsoAssertionSeen``).
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import secrets
import zlib
from dataclasses import dataclass, field
from urllib.parse import urlencode

from lxml import etree

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
SAMLP = "{%s}" % NS["samlp"]
SAML = "{%s}" % NS["saml"]
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
CLOCK_SKEW = dt.timedelta(seconds=120)
MAX_RESPONSE_BYTES = 256 * 1024
EMAIL_ATTRIBUTES = ("email", "mail", "emailaddress", "urn:oid:0.9.2342.19200300.100.1.3",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")


class SamlError(Exception):
    """``str(err)`` is safe to show (no XML, no secrets)."""


@dataclass
class SamlIdentity:
    email: str
    name_id: str
    assertion_id: str
    expires_at: dt.datetime  # naive UTC: keep the assertion id until then (replay)
    attributes: dict[str, list[str]] = field(default_factory=dict)


def new_request_id() -> str:
    return "_" + secrets.token_hex(20)  # an xs:ID must not start with a digit


def _iso(moment: dt.datetime) -> str:
    return moment.replace(microsecond=0, tzinfo=None).isoformat() + "Z"


def authn_request_url(*, idp_sso_url: str, sp_entity_id: str, acs_url: str, request_id: str, relay_state: str,
                      now: dt.datetime) -> str:
    """The IdP URL that starts the sign-in (HTTP-Redirect binding: deflate, base64, query string)."""
    root = etree.Element(SAMLP + "AuthnRequest", nsmap={"samlp": NS["samlp"], "saml": NS["saml"]})
    root.set("ID", request_id)
    root.set("Version", "2.0")
    root.set("IssueInstant", _iso(now))
    root.set("Destination", idp_sso_url)
    root.set("AssertionConsumerServiceURL", acs_url)
    root.set("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    etree.SubElement(root, SAML + "Issuer").text = sp_entity_id
    policy = etree.SubElement(root, SAMLP + "NameIDPolicy")
    policy.set("Format", EMAIL_FORMAT)
    policy.set("AllowCreate", "true")
    xml = etree.tostring(root)
    deflated = zlib.compress(xml)[2:-4]  # raw DEFLATE (RFC 1951), as the binding requires
    query = urlencode({"SAMLRequest": base64.b64encode(deflated).decode("ascii"), "RelayState": relay_state})
    return idp_sso_url + ("&" if "?" in idp_sso_url else "?") + query


def sp_metadata(*, sp_entity_id: str, acs_url: str) -> bytes:
    """SP metadata for the IdP administrator (POST binding, email NameID, signed assertions wanted)."""
    md = "urn:oasis:names:tc:SAML:2.0:metadata"
    root = etree.Element("{%s}EntityDescriptor" % md, nsmap={"md": md})
    root.set("entityID", sp_entity_id)
    sp = etree.SubElement(root, "{%s}SPSSODescriptor" % md)
    sp.set("AuthnRequestsSigned", "false")
    sp.set("WantAssertionsSigned", "true")
    sp.set("protocolSupportEnumeration", NS["samlp"])
    etree.SubElement(sp, "{%s}NameIDFormat" % md).text = EMAIL_FORMAT
    acs = etree.SubElement(sp, "{%s}AssertionConsumerService" % md)
    acs.set("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    acs.set("Location", acs_url)
    acs.set("index", "0")
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _parse(raw: bytes):
    head = raw[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in raw.lower():
        raise SamlError("The SAML response contains a DOCTYPE or an entity, which is never allowed")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_blank_text=False,
                             load_dtd=False, dtd_validation=False)
    try:
        return etree.fromstring(raw, parser)
    except etree.XMLSyntaxError:
        raise SamlError("The SAML response is not well-formed XML") from None


def _text(element) -> str:
    """All of an element's text, comments removed and their tails kept (``.text`` stops at the first comment: the
    CVE-2017-11427 class, where "alice@corp.test<!---->.evil.test" would read as alice@corp.test)."""
    if element is None:
        return ""
    clone = copy.deepcopy(element)
    etree.strip_tags(clone, etree.Comment, etree.ProcessingInstruction)
    return "".join(clone.itertext()).strip()


def _time(value: str | None, what: str) -> dt.datetime | None:
    if value is None:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise SamlError(f"{what} is not a valid time") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).replace(tzinfo=None)


def _verify(raw: bytes, certs: list[str]):
    """The element the IdP signed, verified with one of the team's certificates (signxml)."""
    from signxml import XMLVerifier
    from signxml.exceptions import InvalidInput, InvalidSignature

    last: Exception | None = None
    for cert in certs:
        try:
            # x509_cert: verify with THIS certificate only; any certificate inside the message is ignored
            return XMLVerifier().verify(raw, x509_cert=cert).signed_xml
        except (InvalidSignature, InvalidInput) as exc:
            last = exc
        except Exception as exc:  # malformed signature structures raise other errors in lxml / cryptography
            last = exc
    raise SamlError("The SAML response is not signed by the identity provider's certificate") from last


def parse_response(saml_response_b64: str, *, idp_certs: list[str], idp_entity_id: str, sp_entity_id: str,
                   acs_url: str, request_id: str, now: dt.datetime) -> SamlIdentity:
    """Verify an HTTP-POST ``SAMLResponse`` and return who it signs in.  ``now`` is naive UTC."""
    if not idp_certs:
        raise SamlError("No IdP signing certificate is configured")
    if not saml_response_b64 or len(saml_response_b64) > MAX_RESPONSE_BYTES * 4 // 3 + 4:
        raise SamlError("The SAML response is missing or too large")
    try:
        raw = base64.b64decode(saml_response_b64.strip(), validate=False)
    except (ValueError, TypeError):
        raise SamlError("The SAML response is not base64") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SamlError("The SAML response is too large")
    document = _parse(raw)
    if document.tag != SAMLP + "Response":
        raise SamlError("This is not a SAML Response")
    if document.xpath("count(//saml:EncryptedAssertion)", namespaces=NS):
        raise SamlError("Encrypted assertions are not supported: turn assertion encryption off for this client")
    if int(document.xpath("count(//saml:Assertion)", namespaces=NS)) != 1:
        raise SamlError("The SAML response must carry exactly one assertion")

    signed = _verify(raw, idp_certs)
    if signed.tag == SAMLP + "Response":
        response_signed = True
        assertions = signed.findall(SAML + "Assertion")
        if len(assertions) != 1:
            raise SamlError("The signed response must carry exactly one assertion")
        assertion = assertions[0]
        response = signed
    elif signed.tag == SAML + "Assertion":
        response_signed = False
        assertion = signed
        response = document  # only its Status, Destination and InResponseTo are read, as extra checks
    else:
        raise SamlError("The signature covers neither the response nor the assertion")

    # the Response envelope (checked whether or not it is signed; the signed assertion carries the same facts)
    status = response.find(f"{SAMLP}Status/{SAMLP}StatusCode")
    if status is None or status.get("Value") != SUCCESS:
        raise SamlError("The identity provider did not sign you in")
    destination = response.get("Destination")
    if destination is not None and destination != acs_url:
        raise SamlError("The SAML response was sent to another address")
    in_response_to = response.get("InResponseTo")
    if in_response_to is not None and in_response_to != request_id:
        raise SamlError("The SAML response answers another sign-in")
    if response_signed:
        issuer_el = response.find(SAML + "Issuer")
        if issuer_el is not None and _text(issuer_el) != idp_entity_id:
            raise SamlError("The SAML response comes from another identity provider")

    # the assertion (signed)
    if _text(assertion.find(SAML + "Issuer")) != idp_entity_id:
        raise SamlError("The assertion comes from another identity provider")
    assertion_id = assertion.get("ID") or ""
    if not assertion_id or len(assertion_id) > 256:
        raise SamlError("The assertion has no valid ID")

    conditions = assertion.find(SAML + "Conditions")
    if conditions is None:
        raise SamlError("The assertion has no Conditions")
    not_before = _time(conditions.get("NotBefore"), "NotBefore")
    not_on_or_after = _time(conditions.get("NotOnOrAfter"), "NotOnOrAfter")
    if not_before is not None and now + CLOCK_SKEW < not_before:
        raise SamlError("The assertion is not valid yet (check the clocks)")
    if not_on_or_after is None or now - CLOCK_SKEW >= not_on_or_after:
        raise SamlError("The assertion has expired")
    audiences = [_text(a) for a in conditions.findall(f"{SAML}AudienceRestriction/{SAML}Audience")]
    if sp_entity_id not in audiences:
        raise SamlError("The assertion is meant for another service (audience)")

    subject = assertion.find(SAML + "Subject")
    if subject is None:
        raise SamlError("The assertion has no Subject")
    confirmed = False
    expires = not_on_or_after
    for confirmation in subject.findall(SAML + "SubjectConfirmation"):
        if confirmation.get("Method") != BEARER:
            continue
        data = confirmation.find(SAML + "SubjectConfirmationData")
        if data is None:
            continue
        if data.get("Recipient") != acs_url:
            continue
        if data.get("InResponseTo") != request_id:
            continue
        data_not_on_or_after = _time(data.get("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter")
        if data_not_on_or_after is None or now - CLOCK_SKEW >= data_not_on_or_after:
            continue
        data_not_before = _time(data.get("NotBefore"), "SubjectConfirmationData NotBefore")
        if data_not_before is not None:
            continue  # bearer confirmations must not carry NotBefore (SAML profiles 4.1.4.2)
        confirmed = True
        expires = max(expires, data_not_on_or_after)
        break
    if not confirmed:
        raise SamlError("The assertion is not confirmed for this sign-in (recipient, request or time)")

    name_id_el = subject.find(SAML + "NameID")
    name_id = _text(name_id_el)
    attributes: dict[str, list[str]] = {}
    for attribute in assertion.findall(f"{SAML}AttributeStatement/{SAML}Attribute"):
        values = [_text(v) for v in attribute.findall(SAML + "AttributeValue")]
        attributes[(attribute.get("Name") or "").strip()] = [v for v in values if v]
    email = ""
    if name_id_el is not None and name_id_el.get("Format") == EMAIL_FORMAT:
        email = name_id
    if not email:
        lowered = {k.lower(): v for k, v in attributes.items()}
        for key in EMAIL_ATTRIBUTES:
            if lowered.get(key.lower()):
                email = lowered[key.lower()][0]
                break
    if not email or "@" not in email:
        raise SamlError("The assertion does not say the email address (send it as the NameID or an email attribute)")
    return SamlIdentity(email=email.strip().lower(), name_id=name_id, assertion_id=assertion_id,
                        expires_at=expires + CLOCK_SKEW, attributes=attributes)
