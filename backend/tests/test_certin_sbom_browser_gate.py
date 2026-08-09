"""Optional pytest wrapper for CERT-In Phase 3 Playwright browser gate."""
from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request

import pytest

FRONTEND = os.getenv("FRONTEND_BASE", "http://localhost:3000")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "e2e", "certin_phase3_browser.cjs")
TOKENS = os.getenv("CERTIN_TOKENS_FILE", "/tmp/certin_phase3_tokens.json")


def _frontend_up() -> bool:
    try:
        with urllib.request.urlopen(FRONTEND + "/login", timeout=5) as r:
            return r.status < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


@pytest.mark.skipif(not os.path.isfile(SCRIPT), reason="browser script missing")
def test_certin_phase3_browser_gate():
    if not _frontend_up():
        pytest.skip(f"frontend not reachable on {FRONTEND}")
    if not os.path.isfile(TOKENS):
        pytest.skip(f"tokens file missing: {TOKENS}")
    data = json.loads(open(TOKENS).read())
    if not (data.get("access") or data.get("access_token")) or not data.get("scan_id"):
        pytest.skip("tokens file missing access/scan_id")

    proc = subprocess.run(
        ["node", SCRIPT],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        env={**os.environ, "CERTIN_TOKENS_FILE": TOKENS, "FRONTEND_BASE": FRONTEND},
    )
    if proc.returncode != 0:
        pytest.fail(
            f"browser gate failed (rc={proc.returncode}):\n"
            f"stdout:\n{proc.stdout[-2000:]}\nstderr:\n{proc.stderr[-2000:]}"
        )
