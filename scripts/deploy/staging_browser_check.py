#!/usr/bin/env python3
"""Real-browser check of a deployed frontend: the login page is a hydrated production build.

Passes only when, in Chromium:
  * /login is served by a production build: it references /_next/static/chunks/ and carries none of the `next dev`
    markers (HMR client chunk, "development" build id, webpack-hmr, react-refresh);
  * React has hydrated: typing an e-mail and pressing "Send Verification Code" makes the page POST /send_code to
    the API URL baked into the bundle (any HTTP status counts: the click handler ran);
  * no request goes to a dev endpoint or to an API host other than --api-url.

    python3 scripts/deploy/staging_browser_check.py \
        --frontend-url https://devsec-staging.zeroshield.ai --api-url https://devsec-staging-api.zeroshield.ai

Local proof against a stack on this machine: add --resolve 127.0.0.1 (both host names go to that address) and
--ignore-https-errors for a self-signed certificate. Needs the Python `playwright` package and its Chromium.
Writes login.png, after-click.png and result.json to --out.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from urllib.parse import urlsplit

DEV_MARKERS = (
    "hmr-client",  # Turbopack dev: /_next/static/chunks/[turbopack]_browser_dev_hmr-client_...
    "_browser_dev_",
    "webpack-hmr",  # webpack dev: /_next/webpack-hmr
    "react-refresh",
    '\\"b\\":\\"development\\"',  # `next dev` always uses the build id "development"
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--frontend-url", required=True)
    ap.add_argument("--api-url", required=True)
    ap.add_argument("--email", default="staging-check@example.com")
    ap.add_argument("--resolve", help="send both host names to this IP (local proof)")
    ap.add_argument("--ignore-https-errors", action="store_true")
    ap.add_argument("--out", default="staging-browser-check")
    args = ap.parse_args()

    from playwright.sync_api import sync_playwright

    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    front, api = urlsplit(args.frontend_url), urlsplit(args.api_url)
    launch: dict = {"args": []}
    if args.resolve:
        hosts = sorted({front.hostname, api.hostname})
        launch["args"].append("--host-resolver-rules=" + ",".join(f"MAP {h} {args.resolve}" for h in hosts))
        # A machine-wide HTTPS proxy would receive the request instead of the mapped address: bypass it for the two
        # host names only.
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if proxy:
            launch["proxy"] = {"server": proxy, "bypass": ",".join(hosts)}

    result: dict = {"frontend_url": args.frontend_url, "api_url": args.api_url, "checks": {}}
    requests: list[dict] = []
    console_errors: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch)
        context = browser.new_context(ignore_https_errors=args.ignore_https_errors)
        page = context.new_page()
        page.on("request", lambda r: requests.append({"method": r.method, "url": r.url}))
        page.on("console", lambda m: console_errors.append(m.text) if m.type == "error" else None)

        resp = page.goto(args.frontend_url.rstrip("/") + "/login", wait_until="networkidle")
        html = resp.text() if resp else ""
        (out / "login.html").write_text(html)
        page.screenshot(path=str(out / "login.png"), full_page=True)
        chunks = sorted(set(re.findall(r"/_next/static/chunks/[^\"'\\\s]+", html)))
        found_markers = [m for m in DEV_MARKERS if m in html]
        result["checks"]["login_status"] = resp.status if resp else None
        result["checks"]["production_chunks"] = len(chunks)
        result["checks"]["dev_markers"] = found_markers
        result["chunk_sample"] = chunks[:8]

        page.fill("#email", args.email)
        with page.expect_request(lambda r: r.url.rstrip("/") == args.api_url.rstrip("/") + "/send_code"
                                 and r.method == "POST", timeout=15000) as req_info:
            page.get_by_text("Send Verification Code").click()
        send = req_info.value
        send_resp = send.response()
        result["checks"]["send_code_request"] = {"url": send.url, "method": send.method,
                                                 "status": send_resp.status if send_resp else None,
                                                 "body": send.post_data}
        page.wait_for_timeout(1500)
        page.screenshot(path=str(out / "after-click.png"), full_page=True)
        browser.close()

    other_hosts = sorted({urlsplit(r["url"]).netloc for r in requests} - {front.netloc, api.netloc})
    dev_requests = [r["url"] for r in requests if any(m in r["url"] for m in ("hmr", "webpack-hmr", "_browser_dev_"))]
    result["checks"]["other_hosts_contacted"] = other_hosts
    result["checks"]["dev_requests"] = dev_requests
    result["requests"] = requests
    result["console_errors"] = console_errors[:20]
    ok = (result["checks"]["login_status"] == 200 and result["checks"]["production_chunks"] > 0
          and not found_markers and not dev_requests and not other_hosts
          and result["checks"]["send_code_request"]["status"] is not None)
    result["passed"] = ok
    (out / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps({k: result[k] for k in ("passed", "checks")}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
