"""Keycloak lab for the F4 SSO tests: two realms, made through Keycloak's admin REST API (nothing secret is stored).

    python e2e/sso/keycloak_lab.py setup  --keycloak http://127.0.0.1:8180 --admin-password-env KC_ADMIN_PW \
        --api http://127.0.0.1:8099 --out lab.json
    python e2e/sso/keycloak_lab.py teardown --keycloak ... --admin-password-env KC_ADMIN_PW

* realm ``zs-oidc``: confidential client ``devsecshield`` (authorization code only, PKCE S256 required, redirect
  URI = our OIDC callback); users with a verified email in ``acme-sso.test``, one in another domain, one whose
  email is NOT verified.
* realm ``zs-saml``: SAML client whose entity id is our SP entity id, ACS = our ACS URL, documents AND assertions
  signed (RSA-SHA256), NameID = email; the same users.

Passwords and the client secret are random per run and written only to ``--out`` (a scratch file the test reads).
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys

import requests

REALM_OIDC = "zs-oidc"
REALM_SAML = "zs-saml"
USERS = [
    ("alice", "alice@acme-sso.test", True),       # verified, in the team's verified domain
    ("bob", "bob@acme-sso.test", True),           # verified, no account yet: JIT
    ("mallory", "mallory@evil-sso.test", True),   # verified, but another domain: refused
    ("unverified", "unverified@acme-sso.test", False),  # email not verified: refused (OIDC)
]


def admin_token(base: str, password: str) -> str:
    r = requests.post(f"{base}/realms/master/protocol/openid-connect/token", timeout=30, data={
        "grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": password})
    r.raise_for_status()
    return r.json()["access_token"]


def call(base: str, token: str, method: str, path: str, **kw):
    r = requests.request(method, f"{base}/admin{path}", headers={"Authorization": f"Bearer {token}"}, timeout=30, **kw)
    if r.status_code >= 400 and not (method == "DELETE" and r.status_code == 404):
        raise RuntimeError(f"{method} {path}: {r.status_code} {r.text[:300]}")
    return r


def make_realm(base: str, token: str, realm: str, users: dict[str, str]) -> None:
    call(base, token, "DELETE", f"/realms/{realm}")
    call(base, token, "POST", "/realms", json={"realm": realm, "enabled": True, "sslRequired": "none",
                                                "loginWithEmailAllowed": True, "duplicateEmailsAllowed": False})
    for username, email, verified in USERS:
        call(base, token, "POST", f"/realms/{realm}/users", json={
            "username": username, "email": email, "emailVerified": verified, "enabled": True,
            "firstName": username.capitalize(), "lastName": "Lab", "requiredActions": [],
            "credentials": [{"type": "password", "value": users[username], "temporary": False}]})


def setup(args) -> int:
    base = args.keycloak.rstrip("/")
    token = admin_token(base, os.environ[args.admin_password_env])
    api = args.api.rstrip("/")
    users = {u: secrets.token_urlsafe(18) for u, _e, _v in USERS}
    secret = secrets.token_urlsafe(32)
    make_realm(base, token, REALM_OIDC, users)
    call(base, token, "POST", f"/realms/{REALM_OIDC}/clients", json={
        "clientId": "devsecshield", "enabled": True, "protocol": "openid-connect", "publicClient": False,
        "secret": secret, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False, "redirectUris": [f"{api}/sso/*"], "webOrigins": [],
        "attributes": {"pkce.code.challenge.method": "S256"}})
    make_realm(base, token, REALM_SAML, users)
    descriptor = call(base, token, "GET", f"/realms/{REALM_SAML}/keys").json()
    cert = next(k["certificate"] for k in descriptor["keys"] if k.get("algorithm") == "RS256" and k.get("certificate"))
    sp_entity = args.sp_entity_id or f"{api}/sso/saml"
    call(base, token, "POST", f"/realms/{REALM_SAML}/clients", json={
        "clientId": sp_entity, "enabled": True, "protocol": "saml", "frontchannelLogout": False,
        "redirectUris": [f"{api}/sso/*"], "adminUrl": "",
        "attributes": {
            "saml.authnstatement": "true", "saml.server.signature": "true", "saml.assertion.signature": "true",
            "saml.client.signature": "false", "saml.encrypt": "false", "saml.signature.algorithm": "RSA_SHA256",
            "saml_force_name_id_format": "true", "saml_name_id_format": "email",
            "saml_assertion_consumer_url_post": f"{api}/sso/{args.team_id}/saml/acs" if args.team_id else "",
            "post.logout.redirect.uris": "",
        }})
    out = {
        "keycloak": base, "users": users, "emails": {u: e for u, e, _v in USERS},
        "oidc": {"issuer": f"{base}/realms/{REALM_OIDC}", "client_id": "devsecshield", "client_secret": secret},
        "saml": {"idp_entity_id": f"{base}/realms/{REALM_SAML}",
                 "idp_sso_url": f"{base}/realms/{REALM_SAML}/protocol/saml",
                 "idp_cert_pem": "-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----\n",
                 "sp_entity_id": sp_entity},
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh)
    os.chmod(args.out, 0o600)
    print(f"realms {REALM_OIDC} and {REALM_SAML} ready; lab file {args.out}")
    return 0


def teardown(args) -> int:
    base = args.keycloak.rstrip("/")
    token = admin_token(base, os.environ[args.admin_password_env])
    for realm in (REALM_OIDC, REALM_SAML):
        call(base, token, "DELETE", f"/realms/{realm}")
    print("realms removed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("setup", "teardown"))
    parser.add_argument("--keycloak", required=True)
    parser.add_argument("--admin-password-env", default="KC_ADMIN_PW")
    parser.add_argument("--api", default="http://127.0.0.1:8099")
    parser.add_argument("--sp-entity-id", default="")
    parser.add_argument("--team-id", default="")
    parser.add_argument("--out", default="keycloak-lab.json")
    args = parser.parse_args()
    return setup(args) if args.action == "setup" else teardown(args)


if __name__ == "__main__":
    sys.exit(main())
