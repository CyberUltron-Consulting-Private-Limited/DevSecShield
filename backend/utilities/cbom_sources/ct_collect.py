"""Certificate Transparency discovery: every publicly logged certificate for a team's domains, as CBOM assets.

Run by the cloud worker for a ``ct_logs`` source (``kinds.CtLogsConfig``).  For each name of the query set
(``ct_domains.query_set``) the provider chain is asked in order (``ct_providers``): the first provider that answers
is used; one that is unavailable, out of quota or refuses the key hands the name to the next.  A provider that
refuses the QUERY (a malformed name) is not retried elsewhere.

Assets (SPEC section 4):
* one ``certificate`` per issuance across all names (a precertificate and its certificate are one issuance; the
  identity is serial + issuer CN, which every provider, the scan node and ACM agree on);
* ``target`` = the first listed name (sorted) whose search returned it; ``location`` = ``ct:<serial>@<issuer cn>``,
  so each certificate is its own asset and a new certificate is a ``new_asset`` drift event;
* facts read from the DER with the ``cryptography`` package when the provider gives it (``ct_detail=full``); crt.sh
  rows have no key, signature or fingerprint (``ct_detail=summary``) and a coverage row says which checks were not run;
* ``fingerprint_sha256`` only for a final certificate: a precertificate's hash never matches what a server presents
  (``precert_sha256`` then), and ``serial`` + ``not_after`` still correlate it (collections_view link keys);
* ``coverage`` rows for names that could not be read, so drift never reads them as removed certificates.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from backend.utilities.cbom_sources import ct_domains as D
from backend.utilities.cbom_sources import ct_providers as P

POISON_OID = "1.3.6.1.4.1.11129.2.4.3"  # RFC 6962 precertificate poison extension
WILDCARD_SPRAWL_THRESHOLD = 3  # more live wildcard certificates than this for one name is sprawl
DEADLINE_MARGIN_S = 120.0  # stop starting new searches this close to the job's deadline
CHECK = "Certificate Transparency search"
_CN = re.compile(r"(?:^|[,/])\s*CN\s*=\s*([^,/+]+)", re.IGNORECASE)
_O = re.compile(r"(?:^|[,/])\s*O\s*=\s*([^,/+]+)", re.IGNORECASE)
_FALLBACK_KINDS = frozenset({"unavailable", "rate_limited", "auth", "malformed"})


def _iso(value: Any) -> str | None:
    """RFC 3339 / crt.sh time -> ``YYYY-MM-DDTHH:MM:SSZ`` (the node's form), or None."""
    if not value:
        return None
    text = str(value).strip().replace(" ", "T")
    try:
        moment = _dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _naive(value: str | None) -> _dt.datetime | None:
    try:
        return _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ") if value else None
    except ValueError:
        return None


def cn_of(dn: Any) -> str:
    match = _CN.search(" ".join(str(dn or "").split()))
    return match.group(1).strip() if match else ""


def norm_serial(value: Any) -> str | None:
    text = re.sub(r"[^0-9a-f]", "", str(value or "").lower()).lstrip("0")
    return text or None


@dataclass
class Cert:
    """One issuance being assembled from one or more provider rows (a name can return it more than once)."""

    key: str
    issuance: P.Issuance
    facts: dict[str, Any]
    algorithm: str | None
    key_size: int | None
    matched: set[str] = field(default_factory=set)

    @property
    def wildcards(self) -> list[str]:
        return sorted({n for n in self.facts.get("san") or [] if isinstance(n, str) and n.startswith("*.")})


def _pubkey(pubkey: dict[str, Any] | None) -> tuple[str | None, int | None, str | None]:
    if not isinstance(pubkey, dict):
        return None, None, None
    kind = str(pubkey.get("type") or "").lower()
    curve = pubkey.get("curve") if isinstance(pubkey.get("curve"), str) else None
    if kind == "rsa":
        bits = pubkey.get("bit_length")
        return "RSA", bits if isinstance(bits, int) else None, None
    if kind == "ecdsa":
        return "ECDSA", {"P-256": 256, "P-384": 384, "P-521": 521}.get(curve or ""), curve
    return None, None, None


def details(iss: P.Issuance) -> tuple[dict[str, Any], str | None, int | None]:
    """(facts, algorithm, key size) of one issuance."""
    facts: dict[str, Any] = {"source": "ct", "ct_provider": iss.provider, "ct_provider_id": iss.provider_id,
                             "self_signed": False, "is_ca": False}
    algorithm = key_size = None
    der_facts: dict[str, Any] | None = None
    precert = None
    if iss.der:
        try:
            from cryptography import x509

            from backend.utilities.cbom_sources.idp_collect import cert_facts

            algorithm, key_size, der_facts = cert_facts(iss.der, "ct")
            cert = x509.load_der_x509_certificate(iss.der)
            precert = any(ext.oid.dotted_string == POISON_OID for ext in cert.extensions)
        except Exception:  # an unparseable DER: keep the provider's summary, say so
            der_facts = None
            facts["der_unreadable"] = True
    if der_facts is not None:
        facts.update({k: der_facts[k] for k in ("subject", "issuer", "serial", "not_before", "not_after", "sig_alg",
                                                "key_alg", "key_size", "curve", "san") if der_facts.get(k) is not None})
        facts["source"] = "ct"
        digest = hashlib.sha256(iss.der).hexdigest()  # type: ignore[arg-type]
        facts["fingerprint_sha256" if not precert else "precert_sha256"] = digest
        facts["precertificate_only"] = bool(precert)
        facts["ct_detail"] = "full"
        facts["format"] = "der"  # read from the log entry, not a file
    else:
        alg, bits, curve = _pubkey(iss.pubkey)
        algorithm, key_size = alg, bits
        facts.update({k: v for k, v in (("subject", f"CN={iss.subject_cn}" if iss.subject_cn else None),
                                        ("issuer", iss.issuer_dn), ("serial", norm_serial(iss.serial)),
                                        ("not_before", _iso(iss.not_before)), ("not_after", _iso(iss.not_after)),
                                        ("key_alg", alg), ("key_size", bits), ("curve", curve)) if v is not None})
        facts["san"] = [n for n in iss.dns_names][:50]
        facts["ct_detail"] = "summary"
    # the provider's own fields win only where the DER said nothing
    if iss.dns_names and not facts.get("san"):
        facts["san"] = iss.dns_names[:50]
    facts["san_count"] = max(len(iss.dns_names), len(facts.get("san") or []))
    facts["serial"] = norm_serial(facts.get("serial") or iss.serial)
    if iss.issuer_name:
        facts["issuer_name"] = iss.issuer_name
    if iss.tbs_sha256:
        facts["tbs_sha256"] = iss.tbs_sha256
    if iss.revoked is not None:
        facts["revoked"] = iss.revoked
    if iss.revoked:
        facts["revocation_time"] = _iso(iss.revocation_time)
        facts["revocation_reason"] = iss.revocation_reason if isinstance(iss.revocation_reason, (int, str)) else None
    facts["wildcard"] = any(isinstance(n, str) and n.startswith("*.") for n in facts.get("san") or [])
    if algorithm is None and facts.get("key_alg"):
        algorithm = str(facts["key_alg"])
    if key_size is None and isinstance(facts.get("key_size"), int):
        key_size = facts["key_size"]
    return facts, algorithm, key_size


def issuer_matches(facts: dict[str, Any], expected: list[str]) -> bool:
    """True when any expected issuer text is in the issuer's name, organisation, CN or DN (case-insensitive)."""
    dn = str(facts.get("issuer") or "")
    haystack = " | ".join(x for x in (str(facts.get("issuer_name") or ""), dn, cn_of(dn),
                                      (_O.search(dn).group(1) if _O.search(dn) else "")) if x).casefold()
    return any(e.strip().casefold() in haystack for e in expected if e and e.strip())


def _better(old: Cert, new_facts: dict[str, Any]) -> bool:
    """A final certificate beats a precertificate; full detail beats a summary row."""
    rank = lambda f: (f.get("ct_detail") == "full", not f.get("precertificate_only", False))  # noqa: E731
    return rank(new_facts) > rank(old.facts)


def collect_ct(cfg: dict[str, Any], label: str, emit: Callable[[dict[str, Any]], None],
               should_stop: Callable[[], str | None], *, deadline: float | None = None,
               chain: list[Any] | None = None, http: P.CtHttp | None = None, clock: P.Clock | None = None,
               now: _dt.datetime | None = None, cache: P.AnswerCache | None = None) -> dict[str, Any]:
    """Search every name, emit the assets, return the job result (targets, counts, summary, provider use)."""
    clock = clock or (http.clock if http is not None else P.Clock())
    own_http = http is None and chain is None
    http = http or P.CtHttp(clock=clock)
    chain = chain if chain is not None else P.build_chain(http)
    now = now or _dt.datetime.utcnow()
    started = clock.monotonic()
    include_sub = bool(cfg.get("include_subdomains", True))
    expected = [str(e) for e in cfg.get("expected_issuers") or [] if isinstance(e, str) and e.strip()]
    names = D.query_set(list(cfg.get("domains") or []), include_sub)
    certs: dict[str, Cert] = {}
    targets: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    summary_rows = 0
    calls: dict[str, int] = {}
    stop_left: str | None = None
    try:
        for name in names:
            t0 = clock.monotonic()
            if stop_left is None:
                reason = should_stop()
                if reason:
                    stop_left = reason
                elif deadline is not None and clock.monotonic() > deadline - DEADLINE_MARGIN_S:
                    stop_left = "the run reached its maximum time"
            if stop_left is not None:
                targets.append({"target": name, "status": "skipped", "error": f"Not searched: {stop_left}", "assets": 0,
                                "duration_ms": 0})
                coverage.append(_gap(label, name, "skipped", f"Not searched: {stop_left}"))
                continue
            result, used, errors = None, None, []
            for provider in chain:
                if getattr(provider, "throttled_until", 0) > clock.monotonic():
                    errors.append(f"{provider.label}: rate limit reached")
                    continue
                try:
                    result = P.search_cached(provider, name, include_sub, clock, deadline=deadline, cache=cache)
                    calls[provider.name] = calls.get(provider.name, 0) + result.requests
                    used = provider
                    break
                except P.CtError as exc:
                    calls[provider.name] = calls.get(provider.name, 0) + 1
                    errors.append(str(exc))
                    if exc.kind == "rate_limited":  # do not ask it again for the other names of this job
                        provider.throttled_until = clock.monotonic() + (exc.retry_after or P.MAX_WAIT_S)
                    elif exc.kind == "auth":
                        provider.throttled_until = float("inf")
                    if exc.kind not in _FALLBACK_KINDS:
                        break
            ms = int((clock.monotonic() - t0) * 1000)
            if result is None:
                status = "skipped" if all("rate limit" in e for e in errors) else "error"
                detail = "; ".join(errors)[:256] or "No provider is configured"
                targets.append({"target": name, "status": status, "error": detail, "assets": 0, "duration_ms": ms})
                coverage.append(_gap(label, name, status, detail))
                continue
            found = 0
            for iss in result.issuances:
                facts, algorithm, key_size = details(iss)
                key = f"{facts.get('serial') or 'tbs:' + str(iss.tbs_sha256 or iss.provider_id)}@{cn_of(facts.get('issuer')).casefold()}"
                held = certs.get(key)
                if held is None:
                    certs[key] = Cert(key, iss, facts, algorithm, key_size, {name})
                    found += 1
                else:
                    held.matched.add(name)
                    if _better(held, facts):
                        held.issuance, held.facts, held.algorithm, held.key_size = iss, facts, algorithm, key_size
            if used.name == "crtsh":
                summary_rows += len(result.issuances)
            row = {"target": name, "status": "ok", "error": None, "assets": len(result.issuances), "new": found,
                   "provider": used.name, "pages": result.pages, "cached": result.cached, "duration_ms": ms}
            if result.truncated:
                row["status"] = "partial"
                row["error"] = f"More than {P.MAX_RESULTS} certificates; the first {len(result.issuances)} are listed"
                coverage.append(_gap(label, name, "partial", row["error"]))
            elif errors:
                row["note"] = f"answered by {used.label} after: {'; '.join(errors)[:200]}"
            targets.append(row)
    finally:
        if own_http:
            http.close()
    # wildcard sprawl: live (unexpired, not revoked) certificates naming the same wildcard
    live_wild: dict[str, set[str]] = {}
    for cert in certs.values():
        after = _naive(cert.facts.get("not_after"))
        if cert.facts.get("revoked") or (after is not None and after < now):
            continue
        for wildcard in cert.wildcards:
            live_wild.setdefault(wildcard, set()).add(cert.key)
    for cert in sorted(certs.values(), key=lambda c: c.key):
        facts = dict(cert.facts)
        facts["matched_domains"] = sorted(cert.matched)[:20]
        after = _naive(facts.get("not_after"))
        facts["expired"] = bool(after is not None and after < now)
        if expected:
            facts["issuer_expected"] = issuer_matches(facts, expected)
        sprawl = [(w, len(live_wild.get(w, ()))) for w in cert.wildcards if len(live_wild.get(w, ())) > WILDCARD_SPRAWL_THRESHOLD]
        if sprawl:
            name, count = max(sprawl, key=lambda x: x[1])
            facts["wildcard_sprawl"] = {"name": name, "certificates": count, "threshold": WILDCARD_SPRAWL_THRESHOLD}
        facts["identity"] = cert.key
        issuer_cn = cn_of(facts.get("issuer")) or "unknown issuer"
        emit({"type": "certificate", "target": min(cert.matched), "location": f"ct:{facts.get('serial') or cert.key}@{issuer_cn}",
              "name": cn_of(facts.get("subject")) or next(iter(facts.get("san") or []), None) or facts.get("serial"),
              "algorithm": cert.algorithm, "key_size": cert.key_size, "facts": facts})
    if summary_rows:
        coverage.append({"type": "coverage", "target": label, "location": "ct:crtsh",
                         "facts": {"check": "CT certificate details", "status": "incomplete",
                                   "detail": (f"{summary_rows} certificates came from crt.sh, which gives no public key, "
                                              "signature algorithm or fingerprint: weak-key and SHA-1 checks were not run "
                                              "for them")}})
    for gap in coverage:
        emit(gap)
    ok = sum(1 for t in targets if t["status"] == "ok")
    failed = sum(1 for t in targets if t["status"] == "error")
    skipped = sum(1 for t in targets if t["status"] == "skipped")
    partial = sum(1 for t in targets if t["status"] == "partial")
    summary = f"{len(certs)} certificates from {ok + partial} of {len(targets)} domains"
    if failed or skipped:
        summary += f" ({failed} failed, {skipped} not searched)"
    return {"targets": targets, "counts": {"total": len(targets), "ok": ok, "failed": failed, "skipped": skipped,
                                           "partial": partial},
            "summary": summary, "certificates": len(certs), "provider_calls": calls,
            "providers": [p.name for p in chain], "rate_limited": http.rate_limited,
            "waited_s": round(http.waited_s, 1), "duration_s": int(clock.monotonic() - started)}


def _gap(label: str, name: str, status: str, detail: str) -> dict[str, Any]:
    return {"type": "coverage", "target": name, "location": f"ct:{name}",
            "facts": {"check": CHECK, "status": status, "detail": detail[:200], "source_label": label}}


__all__ = ["CHECK", "WILDCARD_SPRAWL_THRESHOLD", "collect_ct", "details", "issuer_matches", "norm_serial"]
