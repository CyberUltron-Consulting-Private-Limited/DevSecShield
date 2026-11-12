#!/usr/bin/env python3
"""Record live Certificate Transparency provider responses (CT discovery fixtures and provider evidence).

Runs on a GitHub Actions runner (the development box has no outbound internet).  Standard library only, and it
imports nothing from backend/, aibom/, scan_node/ or frontend/: these recordings are the independent side of the
fixtures and of the live proof (DEVILS-ADVOCATE section 3, O-1).

For every case it writes, under OUT/<case>/:
  request.json   URL (no credential), method, start time (UTC), duration in ms
  status         the HTTP status code (or "error: <exception>" when no response arrived)
  headers.json   response headers (lower-case names)
  body           the raw response body, byte for byte
and OUT/MANIFEST.json lists every case with its sha256, size and status.

    python3 bench/ct/capture.py OUT [--cases all|fixtures|reliability|logs]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "zeroshield-ct-capture/1 (+https://zeroshield.ai)"
CS = "https://api.certspotter.com/v1/issuances"
CS_EXPAND = ["dns_names", "issuer", "revocation", "cert_der", "pubkey"]
CRTSH = "https://crt.sh/"
TIMEOUT = 90


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def cs_url(domain: str, *, subdomains: bool = True, wildcards: bool = True, after: str | None = None,
           extra: list[tuple[str, str]] | None = None) -> str:
    params: list[tuple[str, str]] = [("domain", domain)]
    if subdomains:
        params.append(("include_subdomains", "true"))
    if wildcards:
        params.append(("match_wildcards", "true"))
    params += [("expand", e) for e in CS_EXPAND]
    if after:
        params.append(("after", after))
    params += extra or []
    return CS + "?" + urllib.parse.urlencode(params)


def crtsh_url(query: str, **extra: str) -> str:
    return CRTSH + "?" + urllib.parse.urlencode({"q": query, "output": "json", **extra})


def fetch(url: str, timeout: float = TIMEOUT) -> tuple[str, dict[str, str], bytes, int, str]:
    started = _now()
    t0 = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https hosts
            body = resp.read()
            status, headers = str(resp.status), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        status, headers = str(exc.code), {k.lower(): v for k, v in (exc.headers or {}).items()}
    except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        body, status, headers = b"", f"error: {type(exc).__name__}: {str(exc)[:200]}", {}
    return status, headers, body, int((time.monotonic() - t0) * 1000), started


class Recorder:
    def __init__(self, out: pathlib.Path):
        self.out = out
        self.cases: list[dict] = []
        out.mkdir(parents=True, exist_ok=True)

    def record(self, case: str, url: str, timeout: float = TIMEOUT) -> tuple[str, bytes]:
        status, headers, body, ms, started = fetch(url, timeout)
        folder = self.out / case
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "request.json").write_text(json.dumps({"url": url, "method": "GET", "started": started,
                                                          "duration_ms": ms, "user_agent": UA}, indent=1) + "\n")
        (folder / "status").write_text(status + "\n")
        (folder / "headers.json").write_text(json.dumps(headers, indent=1, sort_keys=True) + "\n")
        (folder / "body").write_bytes(body)
        entry = {"case": case, "url": url, "status": status, "duration_ms": ms, "started": started,
                 "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        self.cases.append(entry)
        print(f"{case:40s} {status:>6s} {ms:>7d} ms {len(body):>9d} B", flush=True)
        return status, body

    def write_manifest(self, extra: dict | None = None) -> None:
        manifest = {"captured_by": "bench/ct/capture.py", "runner": os.environ.get("RUNNER_NAME"),
                    "github_run_id": os.environ.get("GITHUB_RUN_ID"), "github_sha": os.environ.get("GITHUB_SHA"),
                    "finished": _now(), "cases": self.cases, **(extra or {})}
        (self.out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n")


def _last_id(body: bytes) -> str | None:
    try:
        rows = json.loads(body)
    except ValueError:
        return None
    return rows[-1]["id"] if isinstance(rows, list) and rows and isinstance(rows[-1], dict) else None


def fixtures(rec: Recorder) -> None:
    # SSLMate Cert Spotter (unauthenticated: the box has no key; production uses CBOM_CT_CERTSPOTTER_KEY)
    for name, domain in (("zeroshield", "zeroshield.ai"), ("example", "example.com"),
                         ("idn_buecher", "xn--bcher-kva.de"), ("idn_muenchen", "xn--mnchen-3ya.de")):
        status, body = rec.record(f"certspotter_{name}", cs_url(domain))
        after = _last_id(body) if status == "200" else None
        if after:  # the next page (empty when one page held everything)
            rec.record(f"certspotter_{name}_after", cs_url(domain, after=after))
        time.sleep(1)
    rec.record("certspotter_wildcard_host", cs_url("ct-proof-host.zeroshield.ai", subdomains=False, wildcards=True))
    rec.record("certspotter_no_wildcards_host", cs_url("ct-proof-host.zeroshield.ai", subdomains=False, wildcards=False))
    rec.record("certspotter_empty", cs_url("zs-ct-empty-proof.example.com", subdomains=False, wildcards=False))
    rec.record("certspotter_error_public_suffix", cs_url("com", subdomains=False, wildcards=False))
    rec.record("certspotter_error_bad_value", cs_url("example.com", subdomains=False, wildcards=False,
                                                     extra=[("include_subdomains", "maybe")]))
    # an invalid API key: the error the provider returns for bad credentials (no real key is ever used here)
    req_url = cs_url("example.com", subdomains=False, wildcards=False)
    started = _now()
    t0 = time.monotonic()
    req = urllib.request.Request(req_url, headers={"User-Agent": UA, "Accept": "application/json",
                                                   "Authorization": "Bearer zs-invalid-key-for-error-capture"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310
            body, status, headers = resp.read(), str(resp.status), {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as exc:
        body, status, headers = (exc.read() if exc.fp else b""), str(exc.code), {k.lower(): v for k, v in (exc.headers or {}).items()}
    except OSError as exc:
        body, status, headers = b"", f"error: {type(exc).__name__}", {}
    folder = rec.out / "certspotter_error_bad_credentials"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "request.json").write_text(json.dumps({"url": req_url, "method": "GET", "started": started,
                                                      "duration_ms": int((time.monotonic() - t0) * 1000),
                                                      "authorization": "Bearer <invalid placeholder>"}, indent=1) + "\n")
    (folder / "status").write_text(status + "\n")
    (folder / "headers.json").write_text(json.dumps(headers, indent=1, sort_keys=True) + "\n")
    (folder / "body").write_bytes(body)
    rec.cases.append({"case": "certspotter_error_bad_credentials", "url": req_url, "status": status,
                      "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "started": started})
    print(f"{'certspotter_error_bad_credentials':40s} {status:>6s}", flush=True)

    # crt.sh JSON (no key; documented as best effort)
    for name, query, extra in (("zeroshield", "zeroshield.ai", {}), ("zeroshield_subdomains", "%.zeroshield.ai", {}),
                               ("zeroshield_dedup", "%.zeroshield.ai", {"deduplicate": "Y"}),
                               ("zeroshield_unexpired", "%.zeroshield.ai", {"exclude": "expired"}),
                               ("example", "example.com", {"exclude": "expired"}),
                               ("idn_buecher", "xn--bcher-kva.de", {"exclude": "expired"}),
                               ("empty", "zs-ct-empty-proof.example.com", {})):
        rec.record(f"crtsh_{name}", crtsh_url(query, **extra))
        time.sleep(3)
    # one certificate's DER from crt.sh (crt.sh JSON has no key, signature or fingerprint fields)
    try:
        rows = json.loads((rec.out / "crtsh_zeroshield_subdomains" / "body").read_bytes())
        first = rows[0]["id"] if isinstance(rows, list) and rows else None
    except (OSError, ValueError, KeyError, TypeError):
        first = None
    if first:
        rec.record("crtsh_cert_der", f"{CRTSH}?d={first}")


def rate_limit(rec: Recorder, tries: int = 40) -> None:
    """Unauthenticated Cert Spotter until it refuses (or ``tries`` requests): the real rate-limit response."""
    for n in range(tries):
        status, _body = rec.record(f"certspotter_ratelimit_{n:02d}", cs_url("example.com", subdomains=False,
                                                                            wildcards=False))
        if status != "200":
            break


def live(rec: Recorder, domains: list[str], provider: str, tag: str) -> None:
    """The oracle side of the live proof: each domain's full listing, as the provider answers it (pages followed)."""
    for domain in domains:
        if provider == "crtsh":
            rec.record(f"{tag}_crtsh_{domain}", crtsh_url(domain, exclude="expired", deduplicate="Y"), timeout=90)
            continue
        after, page = None, 0
        while page < 40:
            status, body = rec.record(f"{tag}_certspotter_{domain}_p{page}", cs_url(domain, after=after))
            rows = json.loads(body) if status == "200" else []
            if status != "200" or not rows or len(rows) < 100:
                break
            after, page = rows[-1]["id"], page + 1


def round2(rec: Recorder) -> None:
    """Paging, the full-domain rate limit (unauthenticated: 10 per hour, x-ratelimit-limit) and a crt.sh burst."""
    status, body = rec.record("certspotter_paging_p1", cs_url("google.com", wildcards=False))
    after = _last_id(body) if status == "200" else None
    if after:
        rec.record("certspotter_paging_p2", cs_url("google.com", wildcards=False, after=after))
    for n, domain in enumerate(["example.org", "example.net", "iana.org", "ietf.org", "w3.org", "mozilla.org",
                                "python.org", "debian.org", "kernel.org", "gnu.org", "apache.org", "openssl.org",
                                "letsencrypt.org", "github.io", "wikipedia.org"]):
        status, _body = rec.record(f"certspotter_fullquota_{n:02d}", cs_url(domain))
        if status != "200":
            break
    for n in range(8):  # back to back: crt.sh allows 5 requests per minute per address
        rec.record(f"crtsh_burst_{n:02d}", crtsh_url("example.org", exclude="expired"), timeout=60)


def reliability(rec: Recorder, rounds: int = 12) -> None:
    """crt.sh under ordinary use: the same small query, spaced out, timed (status and latency per try)."""
    for n in range(rounds):
        rec.record(f"crtsh_reliability_{n:02d}", crtsh_url("%.zeroshield.ai", exclude="expired"), timeout=60)
        time.sleep(5)
    for n in range(4):  # a large domain (the usual failure: a timeout or a 502/503 after tens of seconds)
        rec.record(f"crtsh_reliability_large_{n:02d}", crtsh_url("%.google.com", exclude="expired"), timeout=90)
        time.sleep(5)


def postgres(rec: Recorder) -> None:
    """crt.sh's public PostgreSQL interface (guest@crt.sh:5432/certwatch), with psql when the runner has it."""
    folder = rec.out / "crtsh_postgres"
    folder.mkdir(parents=True, exist_ok=True)
    sql = ("SELECT c.id, x509_notAfter(c.certificate) FROM certificate_and_identities cai JOIN certificate c "
           "ON c.id = cai.certificate_id WHERE plainto_tsquery('certwatch', 'zeroshield.ai') @@ "
           "identities(c.certificate) AND cai.name_value ILIKE '%zeroshield.ai' LIMIT 50;")
    results = []
    for n in range(3):
        t0 = time.monotonic()
        try:
            proc = subprocess.run(["psql", "-h", "crt.sh", "-p", "5432", "-U", "guest", "-d", "certwatch",
                                   "-A", "-F", "\t", "-c", sql], capture_output=True, timeout=120, text=True,
                                  env={**os.environ, "PGCONNECT_TIMEOUT": "20"})
            results.append({"try": n, "rc": proc.returncode, "ms": int((time.monotonic() - t0) * 1000),
                            "stdout_lines": len(proc.stdout.splitlines()), "stderr": proc.stderr[:400]})
            (folder / f"stdout_{n}.tsv").write_text(proc.stdout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({"try": n, "rc": None, "ms": int((time.monotonic() - t0) * 1000),
                            "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
        time.sleep(5)
    (folder / "results.json").write_text(json.dumps({"sql": sql, "results": results}, indent=1) + "\n")
    print("crtsh_postgres", json.dumps(results)[:600], flush=True)


def logs(rec: Recorder) -> None:
    """RFC 6962 logs: the log list and each usable Google / Cloudflare log's tree head (size of a full scan)."""
    status, body = rec.record("loglist_v3", "https://www.gstatic.com/ct/log_list/v3/log_list.json")
    if status != "200":
        return
    picked = []
    try:
        for op in json.loads(body).get("operators") or []:
            if op.get("name") not in ("Google", "Cloudflare"):
                continue
            for log in op.get("logs") or []:
                if "usable" in (log.get("state") or {}):
                    picked.append((op["name"], log.get("description"), log.get("url")))
    except (ValueError, AttributeError):
        return
    for n, (operator, description, url) in enumerate(picked[:6]):
        if not url:
            continue
        rec.record(f"rfc6962_sth_{n}_{operator.lower()}", url.rstrip("/") + "/ct/v1/get-sth")
        if n == 0:
            rec.record(f"rfc6962_entries_{n}_{operator.lower()}", url.rstrip("/") + "/ct/v1/get-entries?start=0&end=1")
        print(f"  log {n}: {operator} {description}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out", type=pathlib.Path)
    parser.add_argument("--cases", default="all", choices=["all", "fixtures", "reliability", "logs", "ratelimit", "round2",
                                                            "live"])
    parser.add_argument("--domains", default="zeroshield.ai,example.com")
    parser.add_argument("--provider", default="certspotter", choices=["certspotter", "crtsh"])
    parser.add_argument("--tag", default="oracle")
    args = parser.parse_args()
    rec = Recorder(args.out)
    if args.cases == "live":
        live(rec, [d.strip() for d in args.domains.split(",") if d.strip()], args.provider, args.tag)
        rec.write_manifest({"tag": args.tag, "provider": args.provider})
        return 0
    if args.cases in ("all", "fixtures"):
        fixtures(rec)
    if args.cases in ("all", "logs"):
        logs(rec)
    if args.cases in ("all", "reliability"):
        reliability(rec)
        postgres(rec)
    if args.cases == "round2":
        round2(rec)
    if args.cases in ("all", "ratelimit"):  # last: it spends the runner's unauthenticated quota
        rate_limit(rec)
    rec.write_manifest()
    return 0


if __name__ == "__main__":
    sys.exit(main())
