"""Google Cloud control-plane TLS and certificate stores, and Cloud Storage encryption (cloud worker; REST, metadata only).

* Compute Engine (load balancing): ``aggregated/sslPolicies``, ``aggregated/sslCertificates``,
  ``aggregated/targetHttpsProxies``, ``global/targetSslProxies`` and ``aggregated/forwardingRules``
  (https://cloud.google.com/compute/docs/reference/rest/v1).  One ``load_balancer_tls`` row per target HTTPS / SSL
  proxy with the SSL policy it serves: a proxy with no policy gets the documented default, the COMPATIBLE profile with
  TLS 1.0 as the minimum (https://cloud.google.com/load-balancing/docs/ssl-policies-concepts).  The cipher suites are
  the policy's server-populated ``enabledFeatures``; for the default policy none are listed (Google publishes no list
  in the API), so only the protocol versions are reported.  Exposure comes from the forwarding rules that point at the
  proxy (``loadBalancingScheme`` EXTERNAL / EXTERNAL_MANAGED is internet-facing, INTERNAL_* is not).
  One ``certificate`` row per SSL certificate (the public PEM chain; the private key is write-only in the API), with
  ``in_use`` when a proxy references it.
* Certificate Manager: ``projects/{p}/locations`` then ``locations/{l}/certificates`` (``pemCertificate`` is the public
  certificate); a location named in ``unreachable`` is a coverage row over that location.
* Cloud Storage: ``storage/v1/b?project=`` -- every bucket is encrypted at rest; ``encryption.defaultKmsKeyName`` says
  whether a customer-managed key is the default.

Locations are the provider's own names so a coverage row can name exactly what it left out: Compute ``selfLink``
(``https://www.googleapis.com/compute/v1/projects/{p}/...``), and full resource names for Certificate Manager
(``//certificatemanager.googleapis.com/projects/...``) and buckets (``//storage.googleapis.com/projects/_/buckets/...``).
"""
from __future__ import annotations

from typing import Any, Callable

from backend.utilities.cbom_sources.cloud_http import CloudHttp, CloudHttpError

COMPUTE = "https://compute.googleapis.com/compute/v1"
CERTMGR = "https://certificatemanager.googleapis.com/v1"
STORAGE = "https://storage.googleapis.com/storage/v1"
ITEM_CAP = 1000
LOCATION_CAP = 100

Emit = Callable[[dict[str, Any]], None]

_TLS = {"TLS_1_0": "TLSv1.0", "TLS_1_1": "TLSv1.1", "TLS_1_2": "TLSv1.2", "TLS_1_3": "TLSv1.3"}
_ORDER = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
# https://cloud.google.com/load-balancing/docs/ssl-policies-concepts: "If no SSL policy is attached, the load balancer
# behaves as if it had the COMPATIBLE profile with a minimum TLS version of 1.0"; every profile also offers TLS 1.3.
DEFAULT_POLICY = {"profile": "COMPATIBLE", "minTlsVersion": "TLS_1_0"}


def compute_scope(project: str) -> str:
    return f"https://www.googleapis.com/compute/v1/projects/{project}/"


def certmgr_scope(project: str) -> str:
    return f"//certificatemanager.googleapis.com/projects/{project}/"


STORAGE_SCOPE = "//storage.googleapis.com/projects/_/buckets/"


def _short(url: Any) -> str:
    return str(url or "").rstrip("/").rsplit("/", 1)[-1]


def _protocols(min_tls: Any) -> list[str]:
    start = _TLS.get(str(min_tls or ""), None)
    return _ORDER[_ORDER.index(start):] if start else []


def _cert_rows(pem: Any) -> tuple[str | None, int | None, dict[str, Any]]:
    """The first certificate of a PEM chain (the leaf) as (algorithm, bits, facts).  Raises ValueError when unreadable."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from backend.utilities.cbom_sources.idp_collect import cert_facts

    if not isinstance(pem, str) or "BEGIN CERTIFICATE" not in pem:
        return None, None, {}
    der = x509.load_pem_x509_certificates(pem.encode())[0].public_bytes(serialization.Encoding.DER)
    return cert_facts(der, "gcp")


def compute(http: CloudHttp, access: str, project: str, label: str, emit: Emit) -> str:
    """Load-balancer TLS policies and SSL certificates of one project.  Raises CloudHttpError when a list fails."""
    base = f"{COMPUTE}/projects/{project}"
    gaps: list[str] = []

    def aggregated(kind: str) -> list[dict[str, Any]]:
        items, cut, unreachable = http.google_aggregated(f"{base}/aggregated/{kind}", access, kind, cap=ITEM_CAP)
        for scope in unreachable:
            gaps.append(scope)
            emit({"type": "coverage", "target": label, "location": f"projects/{project}#compute-{kind}-{scope}",
                  "facts": {"check": f"compute {kind} in {scope}", "status": "unreachable",
                            "detail": f"Compute Engine could not answer for {scope}", "scope": [f"{compute_scope(project)}{scope}/"]}})
        if cut:
            gaps.append(kind)
            emit({"type": "coverage", "target": label, "location": f"projects/{project}#compute-{kind}-cap",
                  "facts": {"check": f"compute {kind} in project {project}", "status": "truncated",
                            "detail": f"More than {ITEM_CAP} {kind}; the first {ITEM_CAP} were read", "scope": [compute_scope(project)]}})
        return items

    policies = {str(p.get("selfLink")): p for p in aggregated("sslPolicies") if p.get("selfLink")}
    certificates = aggregated("sslCertificates")
    https_proxies = aggregated("targetHttpsProxies")
    ssl_proxies, ssl_cut = http.google_pages(f"{base}/global/targetSslProxies", access, "items", cap=ITEM_CAP)
    if ssl_cut:
        gaps.append("targetSslProxies")
        emit({"type": "coverage", "target": label, "location": f"projects/{project}#compute-targetSslProxies-cap",
              "facts": {"check": f"compute targetSslProxies in project {project}", "status": "truncated",
                        "detail": f"More than {ITEM_CAP} target SSL proxies; the first {ITEM_CAP} were read",
                        "scope": [compute_scope(project)]}})
    rules: dict[str, list[dict[str, Any]]] = {}
    for rule in aggregated("forwardingRules"):
        if rule.get("target"):
            rules.setdefault(str(rule["target"]), []).append(rule)

    used: set[str] = set()
    for proxy, proto in [(p, "HTTPS") for p in https_proxies] + [(p, "SSL") for p in ssl_proxies]:
        link = str(proxy.get("selfLink") or "")
        if not link:
            continue
        policy_link = proxy.get("sslPolicy")
        policy = policies.get(str(policy_link)) if policy_link else DEFAULT_POLICY
        certs = [str(c) for c in proxy.get("sslCertificates") or [] if isinstance(c, str)]
        used.update(certs)
        fronts = rules.get(link, [])
        schemes = {str(r.get("loadBalancingScheme") or "") for r in fronts}
        external = {s for s in schemes if s.startswith("EXTERNAL")}
        internet = True if external else (False if schemes and not external else None)
        basis = (f"forwarding rule scheme {', '.join(sorted(schemes))}" if schemes
                 else "no forwarding rule points at this proxy")
        ciphers = [str(c) for c in (policy or {}).get("enabledFeatures") or [] if isinstance(c, str)]
        emit({"type": "load_balancer_tls", "target": label, "location": link, "name": proxy.get("name") or _short(link),
              "protocol": proto,
              "facts": {"provider": "gcp", "ssl_policy": _short(policy_link) if policy_link else None,
                        "default_policy": not policy_link, "policy_found": policy is not None,
                        "profile": (policy or {}).get("profile"), "min_tls_version": (policy or {}).get("minTlsVersion"),
                        "protocols": _protocols((policy or {}).get("minTlsVersion")), "ciphers": ciphers[:100],
                        "static_rsa_kex": any(c.startswith("TLS_RSA_") for c in ciphers),
                        "certificates": [_short(c) for c in certs][:20], "certificate_map": proxy.get("certificateMap"),
                        "quic_override": proxy.get("quicOverride"), "forwarding_rules": [str(r.get("name")) for r in fronts][:20],
                        "internet_facing": internet, "exposure_basis": basis[:200], "identity": link}})

    unparsed = 0
    for cert in certificates:
        link = str(cert.get("selfLink") or "")
        if not link:
            continue
        pem = cert.get("certificate") or (cert.get("selfManaged") or {}).get("certificate")
        try:
            alg, bits, facts = _cert_rows(pem)
        except ValueError:
            unparsed += 1
            emit({"type": "coverage", "target": label, "location": f"{link}#parse",
                  "facts": {"check": f"compute ssl certificate {_short(link)}", "status": "error",
                            "detail": "the certificate could not be parsed", "scope": [link]}})
            continue
        managed = cert.get("managed") or {}
        facts.update({"provider": "gcp", "service": "load_balancing", "certificate_type": cert.get("type"),
                      "managed_status": managed.get("status"), "managed_domains": list(managed.get("domains") or [])[:50],
                      "san_names": list(cert.get("subjectAlternativeNames") or [])[:50],
                      "not_after": facts.get("not_after") or cert.get("expireTime"),
                      "in_use": link in used, "identity": link})
        emit({"type": "certificate", "target": label, "location": link,
              "name": facts.get("subject") or cert.get("name") or _short(link), "algorithm": alg, "key_size": bits, "facts": facts})
    return "partial" if gaps or unparsed else "ok"


def certificate_manager(http: CloudHttp, access: str, project: str, label: str, emit: Emit) -> str:
    locations, _t = http.google_pages(f"{CERTMGR}/projects/{project}/locations", access, "locations", cap=LOCATION_CAP)
    gaps = 0
    count = 0
    for loc in locations:
        if not loc.get("name"):
            continue
        certs: list[dict[str, Any]] = []
        query: dict[str, Any] = {}
        unreachable: list[str] = []
        for _ in range(50):
            page = http.get(f"{CERTMGR}/{loc['name']}/certificates", access, params=query)
            certs.extend(c for c in page.get("certificates") or [] if isinstance(c, dict))
            unreachable.extend(str(u) for u in page.get("unreachable") or [] if isinstance(u, str))
            if not page.get("nextPageToken") or len(certs) >= ITEM_CAP:
                break
            query["pageToken"] = page["nextPageToken"]
        for where in unreachable:
            gaps += 1
            emit({"type": "coverage", "target": label, "location": f"projects/{project}#certificatemanager-{where}",
                  "facts": {"check": f"certificatemanager certificates in {where}", "status": "unreachable",
                            "detail": f"Certificate Manager could not answer for location {where}",
                            "scope": [f"{certmgr_scope(project)}locations/{where}/"]}})
        for cert in certs:
            name = str(cert.get("name") or "")
            if not name:
                continue
            where = f"//certificatemanager.googleapis.com/{name}"
            try:
                alg, bits, facts = _cert_rows(cert.get("pemCertificate"))
            except ValueError:
                gaps += 1
                emit({"type": "coverage", "target": label, "location": f"{where}#parse",
                      "facts": {"check": f"certificatemanager certificate {_short(name)}", "status": "error",
                                "detail": "the certificate could not be parsed", "scope": [where]}})
                continue
            managed = cert.get("managed") or {}
            facts.update({"provider": "gcp", "service": "certificate_manager", "scope": cert.get("scope"),
                          "managed": bool(managed), "managed_state": managed.get("state"),
                          "san_names": list(cert.get("sanDnsnames") or [])[:50],
                          "used_by": len(cert.get("usedBy") or []), "not_after": facts.get("not_after") or cert.get("expireTime"),
                          "identity": where})
            emit({"type": "certificate", "target": label, "location": where, "name": facts.get("subject") or _short(name),
                  "algorithm": alg, "key_size": bits, "facts": facts})
            count += 1
            if count >= ITEM_CAP:
                emit({"type": "coverage", "target": label, "location": f"projects/{project}#certificatemanager-cap",
                      "facts": {"check": f"certificatemanager in project {project}", "status": "truncated",
                                "detail": f"More than {ITEM_CAP} certificates; the first {ITEM_CAP} were read",
                                "scope": [certmgr_scope(project)]}})
                return "truncated"
    return "partial" if gaps else "ok"


def storage(http: CloudHttp, access: str, project: str, label: str, emit: Emit) -> str:
    buckets, cut = http.google_pages(f"{STORAGE}/b", access, "items", cap=ITEM_CAP, params={"project": project})
    for bucket in buckets:
        name = str(bucket.get("name") or "")
        if not name:
            continue
        kms_key = (bucket.get("encryption") or {}).get("defaultKmsKeyName") if isinstance(bucket.get("encryption"), dict) else None
        where = f"{STORAGE_SCOPE}{name}"
        emit({"type": "storage_encryption", "target": label, "location": where, "name": name,
              "facts": {"provider": "gcp", "resource": f"Cloud Storage bucket {name}", "encrypted": True,
                        "kms_key_id": kms_key or "google-managed", "location": bucket.get("location"), "identity": where}})
    if cut:
        emit({"type": "coverage", "target": label, "location": f"projects/{project}#storage-cap",
              "facts": {"check": f"storage in project {project}", "status": "truncated",
                        "detail": f"More than {ITEM_CAP} buckets; the first {ITEM_CAP} were read", "scope": [STORAGE_SCOPE]}})
        return "truncated"
    return "ok"


# what the reader script grants for each service (named in a denied coverage row and in validation warnings)
PERMISSIONS = {
    "certificatemanager": "roles/certificatemanager.viewer",
    "compute": "compute.sslPolicies.list, compute.sslCertificates.list, compute.targetHttpsProxies.list, "
               "compute.targetSslProxies.list, compute.forwardingRules.list",
    "storage": "storage.buckets.list",
}


# service -> (reader, coverage scope of a failure); a disabled API holds nothing to read, so it never fails the target
SERVICES: dict[str, tuple[Callable[[CloudHttp, str, str, str, Emit], str], Callable[[str], str]]] = {
    "certificatemanager": (certificate_manager, certmgr_scope),
    "compute": (compute, compute_scope),
    "storage": (storage, lambda _p: STORAGE_SCOPE),
}


def read(service: str, http: CloudHttp, access: str, project: str, label: str, emit: Emit,
         status_of: Callable[[CloudHttpError], str]) -> str:
    reader, scope = SERVICES[service]
    try:
        return reader(http, access, project, label, emit)
    except (AttributeError, TypeError, ValueError, KeyError) as exc:  # a valid-JSON answer of an unexpected shape
        emit({"type": "coverage", "target": label, "location": f"projects/{project}#{service}-shape",
              "facts": {"check": f"{service} in project {project}", "status": "error",
                        "detail": f"unexpected answer shape from {service} ({type(exc).__name__})", "scope": [scope(project)]}})
        return "error"
    except CloudHttpError as exc:
        status = status_of(exc)
        detail = str(exc)
        if status == "denied":
            detail = f"{PERMISSIONS[service]} needed (re-run the ZeroShield reader script): {exc}"
        facts: dict[str, Any] = {"check": f"{service} in project {project}", "status": status, "detail": detail[:200],
                                 "scope": [scope(project)]}
        if status == "not_enabled":
            facts["by_choice"] = True  # the project does not use this API: nothing of it exists to read
        emit({"type": "coverage", "target": label, "location": f"projects/{project}#{service}", "facts": facts})
        return status
