"""OpenID Connect relying party: authorization code flow with PKCE (S256), state and nonce (F4 SSO).

Token signatures are checked by ``python-jose`` (already the app's JWT library; no hand-written crypto) against the
IdP's published JWKS.  The ID token must be signed with an asymmetric algorithm the IdP's key declares (RS*/PS*/ES*;
``none`` and HS* are refused, so a public key can never be used as an HMAC secret), and carry (all required):
``iss`` = the discovery document's issuer, exactly (itself the configured issuer, a trailing "/" aside), ``aud``
containing our client id (and ``azp`` = our client id when present or when there are several audiences), ``exp`` in
the future, ``nbf`` (if any) and ``iat`` not in the future (each with ``CLOCK_SKEW``), ``sub``, ``nonce`` = the one
this browser's sign-in started with, and ``email`` with ``email_verified`` true.

Everything is fetched through ``http.py`` (no proxy, size and time caps, and, unless the operator listed the IdP's
origin, https to public addresses only), so an owner's issuer URL cannot reach the server's own network.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

from backend.utilities.sso import http as sso_http

CLOCK_SKEW = dt.timedelta(seconds=120)
ASYMMETRIC_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")


class OidcError(Exception):
    """``str(err)`` is safe to show."""


@dataclass
class OidcIdentity:
    email: str
    subject: str
    name: str | None = None


def pkce_pair() -> tuple[str, str]:
    """(verifier, S256 challenge) per RFC 7636."""
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def discovery(issuer: str) -> dict:
    issuer = issuer.rstrip("/")
    doc = sso_http.get_json(issuer + "/.well-known/openid-configuration")
    if (doc.get("issuer") or "").rstrip("/") != issuer:
        raise OidcError("The issuer's discovery document names another issuer")
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(doc.get(key), str) or not doc[key]:
            raise OidcError(f"The issuer's discovery document has no {key}")
    if "S256" not in (doc.get("code_challenge_methods_supported") or ["S256"]):
        raise OidcError("The identity provider does not support PKCE (S256)")
    return doc


def authorization_url(doc: dict, *, client_id: str, redirect_uri: str, state: str, nonce: str, challenge: str,
                      scopes: str = "openid email profile", login_hint: str | None = None) -> str:
    params = {
        "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "scope": scopes,
        "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if login_hint:
        params["login_hint"] = login_hint
    endpoint = doc["authorization_endpoint"]
    return endpoint + ("&" if urlsplit(endpoint).query else "?") + urlencode(params)


def exchange_code(doc: dict, *, client_id: str, client_secret: str | None, code: str, redirect_uri: str,
                  verifier: str) -> dict:
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "client_id": client_id,
            "code_verifier": verifier}
    if client_secret:
        form["client_secret"] = client_secret  # client_secret_post (also what Keycloak and Entra accept)
    body = sso_http.post_form(doc["token_endpoint"], form)
    if not isinstance(body.get("id_token"), str):
        raise OidcError("The identity provider returned no ID token")
    return body


def _unverified_header(token: str) -> dict:
    try:
        head = token.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    except (ValueError, IndexError):
        raise OidcError("The ID token is malformed") from None


def verify_id_token(doc: dict, id_token: str, *, issuer: str, client_id: str, nonce: str,
                    now: dt.datetime) -> OidcIdentity:
    from jose import jwk, jwt
    from jose.exceptions import JOSEError

    expected_issuer = doc.get("issuer") or ""
    if not expected_issuer or expected_issuer.rstrip("/") != issuer.rstrip("/"):
        raise OidcError("The issuer's discovery document names another issuer")
    header = _unverified_header(id_token)
    alg = header.get("alg")
    if alg not in ASYMMETRIC_ALGS:
        raise OidcError("The ID token is not signed with an accepted algorithm")
    keys = (sso_http.get_json(doc["jwks_uri"]).get("keys") or [])
    kid = header.get("kid")
    candidates = [k for k in keys if isinstance(k, dict) and (kid is None or k.get("kid") == kid)
                  and k.get("use", "sig") == "sig" and k.get("kty") in ("RSA", "EC")]
    if not candidates:
        raise OidcError("The identity provider's keys do not include the one that signed the ID token")
    claims = None
    for key in candidates:
        if key.get("alg") not in (None, alg):
            continue
        try:
            public = jwk.construct(key, algorithm=alg)
            # iss: exactly the discovery document's issuer (checked equal to the configured one, which may end in
            # "/").  python-jose checks exp / iat / aud / iss / sub only when present unless told to require them.
            claims = jwt.decode(id_token, public.to_dict(), algorithms=[alg], audience=client_id,
                                issuer=expected_issuer,
                                options={"verify_at_hash": False, "leeway": int(CLOCK_SKEW.total_seconds()),
                                         "require_exp": True, "require_iat": True, "require_aud": True,
                                         "require_iss": True, "require_sub": True})
            break
        except JOSEError:
            continue
    if claims is None:
        raise OidcError("The ID token's signature, issuer, audience or time is not valid")
    audiences = claims.get("aud") if isinstance(claims.get("aud"), list) else [claims.get("aud")]
    azp = claims.get("azp")
    if (len(audiences) > 1 or azp is not None) and azp != client_id:
        raise OidcError("The ID token was issued to another client (azp)")
    iat = claims.get("iat")
    if not isinstance(iat, (int, float)) or dt.datetime.fromtimestamp(iat, dt.timezone.utc).replace(tzinfo=None) > now + CLOCK_SKEW:
        raise OidcError("The ID token's issue time is not valid")
    if not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(claims["nonce"], nonce):
        raise OidcError("The ID token belongs to another sign-in (nonce)")
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email:
        raise OidcError("The identity provider did not send an email address (add the email scope)")
    if claims.get("email_verified") is not True:
        raise OidcError("The identity provider has not verified this email address")
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise OidcError("The ID token has no subject")
    name = claims.get("name") if isinstance(claims.get("name"), str) else None
    return OidcIdentity(email=email.strip().lower(), subject=subject, name=name)
