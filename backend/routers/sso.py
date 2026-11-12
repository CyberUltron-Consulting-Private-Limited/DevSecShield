"""Single sign-on (F4 PR 2): per-team OIDC / SAML configuration (owners) and the sign-in round trip (public).

Team routes (``team.sso.manage``, owners):
* GET    /team/{team_id}/sso                         configuration (no secret), domains, what to give the IdP
* PUT    /team/{team_id}/sso                         save it (client secret write-only)
* POST   /team/{team_id}/sso/domains                 claim an email domain (a TXT record proves it)
* POST   /team/{team_id}/sso/domains/{id}/verify     check the TXT record
* DELETE /team/{team_id}/sso/domains/{id}
Platform: POST /admin/sso/domains/{id}/verify (superusers vouch for a domain on an air-gapped install).

Sign-in (public; the round trip is described in utilities/sso/service.py):
* GET  /sso/discover?email=                          does this address sign in with SSO, and where
* GET  /sso/{team_id}/start?redirect=&cn=            to the IdP (sets the browser-binding cookie)
* GET  /sso/{team_id}/oidc/callback                  OIDC code -> verified ID token -> hand-off
* POST /sso/{team_id}/saml/acs                       SAML POST binding -> verified assertion -> hand-off
* GET  /sso/{team_id}/saml/metadata                  SP metadata for the IdP administrator
* POST /sso/exchange                                 the SPA trades the hand-off code (+ its nonce) for tokens
"""
import logging
from typing import Annotated, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from backend.get_db import get_db
from backend.routers.auth import _tokens
from backend.utilities.ratelimit import RateLimiter, ip_key
from backend.utilities.rbac import audit
from backend.utilities.rbac.policy import Access, public, request_meta
from backend.utilities.sso import service as SSO

log = logging.getLogger("backend.sso")

router = APIRouter(tags=["sso"])
access = Access(lambda: get_db())  # route policies (utilities/rbac), bound to this module's get_db (tests replace it)
read_limiter = RateLimiter("sso.config.read", times=60, seconds=60)
write_limiter = RateLimiter("sso.config.write", times=20, seconds=60)
# Per client address, per route.  Sized for a company's sign-ins behind one NAT egress address at 9 a.m. (each sign-in
# is one discover, one start, one callback or ACS and one exchange); a single shared bucket would allow ~10 a minute.
discover_limiter = RateLimiter("sso.discover", times=120, seconds=60, key_func=ip_key)
start_limiter = RateLimiter("sso.start", times=120, seconds=60, key_func=ip_key)
callback_limiter = RateLimiter("sso.callback", times=120, seconds=60, key_func=ip_key)
metadata_limiter = RateLimiter("sso.metadata", times=30, seconds=60, key_func=ip_key)
exchange_limiter = RateLimiter("sso.exchange", times=120, seconds=60, key_func=ip_key)
PRIVATE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}


def _principal(request: Request):
    return request.state.access.principal


class SsoConfigBody(BaseModel):
    protocol: str = Field(pattern="^(oidc|saml)$")
    enabled: bool = False
    enforced: bool = False
    jit: bool = True
    default_role: str = Field(default="member", pattern="^(viewer|member)$")
    oidc_issuer: Optional[str] = Field(default=None, max_length=512)
    oidc_client_id: Optional[str] = Field(default=None, max_length=256)
    oidc_client_secret: Optional[str] = Field(default=None, max_length=512)
    oidc_scopes: Optional[str] = Field(default=None, max_length=256)
    saml_idp_entity_id: Optional[str] = Field(default=None, max_length=512)
    saml_idp_sso_url: Optional[str] = Field(default=None, max_length=1024)
    saml_idp_certs: Optional[list[str]] = Field(default=None, max_length=4)
    expected_version: Optional[int] = None


class DomainBody(BaseModel):
    domain: str = Field(max_length=260)


class ExchangeBody(BaseModel):
    code: str = Field(min_length=20, max_length=128)
    client_nonce: str = Field(min_length=20, max_length=128)


def _unavailable(exc: Exception) -> HTTPException:
    return HTTPException(status_code=503, detail=str(exc))


# ------------------------------------------------------------------------------------------- configuration

@router.get("/team/{team_id}/sso", summary="Single sign-on configuration (owners)",
            dependencies=[Depends(read_limiter), access.team("team.sso.manage")])
async def get_sso(team_id: int):
    def run():
        from sqlmodel import Session
        with Session(get_db()) as session:
            return SSO.public_config(session, team_id)
    return await run_in_threadpool(run)


@router.put("/team/{team_id}/sso", summary="Save the single sign-on configuration (owners)",
            dependencies=[Depends(write_limiter), access.team("team.sso.manage")])
async def put_sso(team_id: int, body: SsoConfigBody, request: Request):
    data = SSO.ConfigInput(**body.model_dump())
    result = await run_in_threadpool(SSO.save_config, get_db(), team_id, data, _principal(request), request_meta(request))
    audit.mark_written(request)
    return result


@router.post("/team/{team_id}/sso/domains", summary="Claim an email domain for single sign-on (owners)",
             dependencies=[Depends(write_limiter), access.team("team.sso.manage")])
async def add_sso_domain(team_id: int, body: DomainBody, request: Request):
    result = await run_in_threadpool(SSO.add_domain, get_db(), team_id, body.domain, _principal(request),
                                     request_meta(request))
    audit.mark_written(request)
    return result


@router.post("/team/{team_id}/sso/domains/{domain_id}/verify", summary="Check a domain's TXT record (owners)",
             dependencies=[Depends(write_limiter), access.team("team.sso.manage")])
async def verify_sso_domain(team_id: int, domain_id: int, request: Request):
    result = await run_in_threadpool(SSO.verify_domain, get_db(), team_id, domain_id, _principal(request),
                                     request_meta(request))
    audit.mark_written(request)
    return result


@router.delete("/team/{team_id}/sso/domains/{domain_id}", summary="Remove a claimed domain (owners)",
               dependencies=[Depends(write_limiter), access.team("team.sso.manage")])
async def delete_sso_domain(team_id: int, domain_id: int, request: Request):
    result = await run_in_threadpool(SSO.delete_domain, get_db(), team_id, domain_id, _principal(request),
                                     request_meta(request))
    audit.mark_written(request)
    return result


@router.post("/admin/sso/domains/{domain_id}/verify",
             summary="Vouch for a team's domain without DNS (superusers; air-gapped installs)",
             dependencies=[Depends(write_limiter), access.platform_admin(audited=True)])
async def superuser_verify_sso_domain(domain_id: int, request: Request):
    def run():
        from sqlmodel import Session

        from backend.access_models import TeamSsoDomain
        with Session(get_db()) as session:
            row = session.get(TeamSsoDomain, domain_id)
            if row is None:
                raise HTTPException(status_code=404, detail="Domain not found")
            team_id = row.team_id
        return SSO.verify_domain(get_db(), team_id, domain_id, _principal(request), request_meta(request),
                                 method="superuser")
    result = await run_in_threadpool(run)
    audit.mark_written(request)
    return result


# ------------------------------------------------------------------------------------------- sign-in

@router.get("/sso/discover", summary="Does this address sign in with single sign-on?",
            dependencies=[Depends(discover_limiter), public("tells the sign-in page whether an address uses SSO")])
async def discover(email: Annotated[str, Query(max_length=254)]):
    return await run_in_threadpool(SSO.discover, get_db(), email)


def _cookie_attributes() -> dict:
    """The binding cookie's attributes; a delete must repeat them (a SameSite=None; Secure cookie is not replaced by
    a Set-Cookie without Secure).  SameSite=None: the SAML IdP comes back with a cross-site POST, which a Lax cookie
    would not join.  The cookie is only a random value checked against the server-side state; it grants nothing."""
    try:
        secure = SSO.cookie_secure()
    except SSO.SsoUnavailable:
        secure = True
    return {"path": "/sso/", "httponly": True, "secure": secure, "samesite": "none" if secure else "lax"}


def _back_to_app(fragment: str) -> RedirectResponse:
    response = RedirectResponse(f"{SSO.app_url()}/sso/complete#{fragment}", status_code=303, headers=PRIVATE)
    response.delete_cookie(SSO.COOKIE, **_cookie_attributes())
    return response


def _refused(team_id: int, protocol: str, message: str, request: Request) -> RedirectResponse:
    SSO.refused_event(get_db(), team_id, protocol, message, request_meta(request))
    return _back_to_app("error=" + quote(message[:300], safe=""))


@router.get("/sso/{team}/start", summary="Start single sign-on: to the identity provider",
            dependencies=[Depends(start_limiter), public("starts a sign-in; the IdP authenticates")])
async def start(team: int, cn: Annotated[str, Query(max_length=64)] = "",
                redirect: Annotated[str, Query(max_length=512)] = "/home",
                login_hint: Annotated[str | None, Query(max_length=254)] = None):
    try:
        url, cookie = await run_in_threadpool(SSO.start, get_db(), team, redirect=redirect, client_nonce_hash=cn,
                                              login_hint=login_hint)
    except SSO.SsoUnavailable as exc:
        raise _unavailable(exc) from None
    except SSO.SsoRefused as exc:
        return _back_to_app("error=" + quote(str(exc)[:300], safe=""))
    response = RedirectResponse(url, status_code=303, headers=PRIVATE)
    response.set_cookie(SSO.COOKIE, cookie, max_age=int(SSO.STATE_TTL.total_seconds()), **_cookie_attributes())
    return response


@router.get("/sso/{team}/oidc/callback", summary="OIDC: the identity provider returns here",
            dependencies=[Depends(callback_limiter), public("the IdP's answer; checked against the browser's state")])
async def oidc_callback(team: int, request: Request, state: Annotated[str, Query(max_length=64)] = "",
                        code: Annotated[str, Query(max_length=2048)] = "",
                        error: Annotated[str | None, Query(max_length=200)] = None):
    if error:
        return _refused(team, "oidc", f"The identity provider did not sign you in ({error[:60]})", request)
    try:
        handoff = await run_in_threadpool(SSO.finish_oidc, get_db(), team, state_id=state,
                                          cookie=request.cookies.get(SSO.COOKIE), code=code, meta=request_meta(request))
    except SSO.SsoUnavailable as exc:
        raise _unavailable(exc) from None
    except SSO.SsoRefused as exc:
        return await run_in_threadpool(_refused, team, "oidc", str(exc), request)
    return _back_to_app("code=" + handoff)


@router.post("/sso/{team}/saml/acs", summary="SAML: the identity provider posts the response here",
             dependencies=[Depends(callback_limiter), public("the IdP's signed response; checked against the browser's state")])
async def saml_acs(team: int, request: Request, SAMLResponse: Annotated[str, Form(max_length=400_000)] = "",
                   RelayState: Annotated[str, Form(max_length=64)] = ""):
    try:
        handoff = await run_in_threadpool(SSO.finish_saml, get_db(), team, relay_state=RelayState,
                                          cookie=request.cookies.get(SSO.COOKIE), saml_response=SAMLResponse,
                                          meta=request_meta(request))
    except SSO.SsoUnavailable as exc:
        raise _unavailable(exc) from None
    except SSO.SsoRefused as exc:
        return await run_in_threadpool(_refused, team, "saml", str(exc), request)
    return _back_to_app("code=" + handoff)


@router.get("/sso/{team}/saml/metadata", summary="SAML service provider metadata",
            dependencies=[Depends(metadata_limiter), public("public SP metadata for the IdP administrator")])
async def saml_metadata(team: int):
    from backend.utilities.sso import saml
    try:
        xml = saml.sp_metadata(sp_entity_id=SSO.saml_sp_entity_id(team), acs_url=SSO.saml_acs_url(team))
    except SSO.SsoUnavailable as exc:
        raise _unavailable(exc) from None
    return Response(xml, media_type="application/samlmetadata+xml")


@router.post("/sso/exchange", summary="Trade a single sign-on hand-off code for tokens",
             dependencies=[Depends(exchange_limiter), public("the one-time hand-off code and the SPA's nonce")])
async def exchange(body: ExchangeBody, request: Request):
    try:
        user, redirect, team_id = await run_in_threadpool(SSO.exchange, get_db(), body.code, body.client_nonce)
    except SSO.SsoRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    return {**_tokens(user), "redirect": redirect, "team_id": team_id}
