#!/usr/bin/env python3
"""Regenerate the CBOM team roll-up fixtures (plan ``cbom-medium-renderers-plan.md`` 6.2 / App. B).

Outputs (next to this script; deterministic, compact JSON with sorted keys):

* ``cbom_team_rollup_scans.json``   the Appendix-B seed: REAL ``aibom`` run-objects for 8 usable
  scans (7 sources) plus a failed, a queued, a started, a success-but-empty, an ``sbom_sca`` and
  an other-team scan.  Consumed by the WP1b / WP2 / WP3 / WP4 tests.
* ``cbom_scanner_registry.json``    ``ordered_cbom_scanners()`` names + orders, ``CBOM_FRAMEWORKS``
  and the two PQC timeline strings (drift locks T-CON-5 / T-CON-6, plan 6.3).

RUN IT WITH THE AIBOM VENV (py3.13), NOT the backend venv, pinning ``aibom`` to THIS checkout::

    WT=/home/contact_cyberultron_com/DevSecShield/.worktrees/cbom-team-deliverables
    cd "$WT"
    PYTHONPATH="$WT/aibom/src" /home/contact_cyberultron_com/DevSecShield/aibom/.venv/bin/python \\
        backend/tests/fixtures/make_cbom_team_rollup_fixture.py
    sha256sum backend/tests/fixtures/cbom_team_rollup_scans.json \\
              backend/tests/fixtures/cbom_scanner_registry.json
    # drift check (exit 1 when the committed files differ from a fresh regeneration): add --check

The venv's ``aibom`` is an editable install of the MAIN checkout; ``PYTHONPATH`` shadows it.  The
script asserts ``aibom.__file__`` resolves under ``<this checkout>/aibom/src`` (exactly the
worktree above when the script lives there) and, unless ``--allow-dirty``, that ``aibom/`` and
the legacy input file have no uncommitted tracked change - so the fixture is a function of the
clean base commit.  It reads no network, calls no LLM and needs no ``openssl`` at run time.

Determinism (two runs => identical sha256):

* the scanner's only clock read (the weak flagger's ``date.today()``) is frozen to ``AS_OF``
  while scanning, so ``EXPIRED_CERTIFICATE`` flags, scores and compliance never drift with the
  wall clock; ``duration_of_scan`` is pinned to ``FIXED_DURATION_S``;
* the three authored certificates are embedded as PEM constants (below), not generated;
* every scan runs twice in-process and must be byte-identical; an absolute-path leak into the
  output aborts generation; ``json.dumps(sort_keys=True, separators=(",", ":"))``.

Fixture schema (``schema_version`` 1)::

    {as_of, now, team, other_teams, refs_stripped, scans: [
        {id, team_id, scan_type, title, status, age_days, created_at, last_updated,
         scan_metadata, scan_data}, ...]}

``status`` is the raw DB value; ``created_at = now - age_days``; ``last_updated`` is +2 min for
success / failure, +1 min for ``started``, +0 for ``NOT_STARTED``.  ``scan_metadata`` has the
shape of ``backend/utilities/db/metadata.py`` (cbom).  Canary payloads (``FAILED-SCAN-CANARY``,
``QUEUED-SCAN-CANARY``, ``RUNNING-SCAN-CANARY``, ``SBOM-TYPE-CANARY``, cert CN
``other-team-canary.test``) live ONLY in ``scan_data`` - titles and URLs of excluded scans are
plain - so a canary in a PDF proves a blob was wrongly read.  A real queued / started scan has
``scan_data == {}``; the canary row there is a test device only.  Repo URLs use hostile
spellings (``.git`` suffix with mixed case, trailing ``/``, and a ``user:token@`` userinfo) that
must collapse / sanitise to the Appendix-B source keys.

Scan trees (assembled in a temp dir from the frozen ``aibom/tests/fixtures``; nothing there is
edited) and the scan each one feeds::

    1  payments-service-v1    synthetic-crypto-app
    2  payments-service-v2    synthetic-crypto-app + deploy/tls/server.crt (= chain-leaf.crt)
    3  identity-gateway       synthetic-crypto-certs + certs/imported/payments-ca.pem (= app cert)
    4  crypto-misuse-lab      synthetic-crypto-misuse
    5  pqc-pilot              synthetic-crypto-pqc
    6  cert-lifecycle-lab     expired.crt (-35 d) + expiring-soon.crt (+20 d)       [authored]
    7  vendor-sdk-manifests   synthetic-crypto-manifests           (0 rows, 18 libraries)
    8  legacy-billing         backend/tests/fixtures/cbom_export_scandata.json (Tier B, verbatim)
    14 other-team-app         other-team-canary.crt                                 [authored]

(``vendor/`` is skipped by the certificate scanner - plan R-07 - so no tree uses it.)

Authored certificates (embedded below; an authoring-time tool, never a product dependency):
subject ``O=DevSecShield-E2E, CN=<cn>``, RSA-2048, sha256WithRSAEncryption, CA:FALSE,
self-signed, fixed validity relative to ``AS_OF`` = 2026-10-19 (expired = AS_OF - 35 d,
soon = AS_OF + 20 d), authored once with OpenSSL 3.5.5::

    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -keyout /tmp/k.pem \\
      -subj "/O=DevSecShield-E2E/CN=expired-api.e2e.test" \\
      -addext "basicConstraints=critical,CA:FALSE" \\
      -not_before 20250914000000Z -not_after 20260914000000Z -out expired.crt
    # expiring-soon.e2e.test : -not_before 20251108000000Z -not_after 20261108000000Z
    # other-team-canary.test : -not_before 20260101000000Z -not_after 20280101000000Z

Independent oracle: after generation the script re-derives every Appendix-B quantity with plain
stdlib code that shares nothing with the future product aggregator - DER SHA-256 fingerprints of
the certificate FILES (the ``openssl x509 -fingerprint -sha256`` equivalent) cross-checked
against the ``crypto:*`` tuple identity, plus counts, bands, finding codes, readiness, libraries
and pooled compliance - and aborts when a number differs.  Changing the scanner legitimately
changes those numbers: update Appendix B / ``APPENDIX_B`` here and the tests together (the pin).

Size guard: the compact scans file is expected around 0.5-1 MB.  If it exceeds
``MAX_FIXTURE_BYTES`` the ``refs`` arrays of ``cbom_compliance`` requirements (no renderer reads
them) are dropped and ``refs_stripped`` is set to ``true`` in the file header.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple
from urllib.parse import urlsplit

sys.dont_write_bytecode = True  # keep the aibom tree free of *.pyc so the cleanliness check holds

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]  # <checkout>/backend/tests/fixtures -> <checkout>
AIBOM_SRC = ROOT / "aibom" / "src"
AIBOM_FIXTURES = ROOT / "aibom" / "tests" / "fixtures"
LEGACY_TIER_B = HERE / "cbom_export_scandata.json"
SCANS_NAME = "cbom_team_rollup_scans.json"
REGISTRY_NAME = "cbom_scanner_registry.json"

AS_OF = date(2026, 10, 19)
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=timezone.utc)  # 12:28 UTC == 17:58 IST (plan 5.2)
FIXED_DURATION_S = 0.25
MAX_FIXTURE_BYTES = 1_000_000
REPO = "https://github.com/e2e-demo/"

# Authored certificates: file name -> (pinned DER sha256, PEM).  The pin makes an accidental edit
# of a PEM fail loudly instead of silently changing the fixture.
CERT_FILES: dict[str, tuple[str, str]] = {
    "expired.crt": (
        "a1a0a888f82264d856801316ca7f92272dbac29f29ff266ee56cc8b19d00d085",
        """-----BEGIN CERTIFICATE-----
MIIDUjCCAjqgAwIBAgIUK7GAUvvng5J5a+bIlE59hIkeXsEwDQYJKoZIhvcNAQEL
BQAwOjEZMBcGA1UECgwQRGV2U2VjU2hpZWxkLUUyRTEdMBsGA1UEAwwUZXhwaXJl
ZC1hcGkuZTJlLnRlc3QwHhcNMjUwOTE0MDAwMDAwWhcNMjYwOTE0MDAwMDAwWjA6
MRkwFwYDVQQKDBBEZXZTZWNTaGllbGQtRTJFMR0wGwYDVQQDDBRleHBpcmVkLWFw
aS5lMmUudGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALuRI1BM
Z0PG/u664457Qlj0pVjiVYgk+McV5SKFDs4+GG9+3zhyPse9EcqyawGbARRQYZ+f
u1jsAhVDP8UPnPNjnXSjt8H54PKg/A6tg9edjC2rJvyAhWdcDdyz+FiYh1hSigfQ
Z2uOLJn58p2xP1Y1/w573n7q2La0r3NsKVAveAntObxzfct1Go19iYy2zbkee+bC
N0RPMup6JpZvZqLAaZZ9vpTJdX+vSKpJnxszsdBSgboBr5h/egtu+qq+wmfzCz4h
ub5ydi+Zn6lvlfERinFhEHnZQM8/VtEowA6y9NnvGKbL6tCWw6nWqf+vF8mnWoJ1
gHQJAN+UzNxkrZkCAwEAAaNQME4wHQYDVR0OBBYEFE0bUuff9oQVJ49I5B2Je4kn
yty2MB8GA1UdIwQYMBaAFE0bUuff9oQVJ49I5B2Je4knyty2MAwGA1UdEwEB/wQC
MAAwDQYJKoZIhvcNAQELBQADggEBABooY5/9FzCLtaCmnvFQR1L8YJN+mD06+1cE
4ESG1JMvk1d93aBGHmyqo+AFcIp2bu/aXhmcen9+M5mMRoOGMOSSFNOcFwJ6vqJI
m/p7cry6YshXUl+KbUdDRVaiTtihfC/+rzPHAWSGTtKKgZFi8MHbnPldfAva7DXb
LUCyjD3FnWjaeA6rVBNvHMhs0r6/1IFaMaM4Z5BFaTsCda0xLu3Czw03ihX3Oye6
0zl0ktECDvRS2k01Es+UB/js9PHUZKJHa+oVPSFS31i/f8eujdpTJF2cmzDFHUCa
+0R6PdroC+sMs+B+sJF9w6tHL5mKMyq+p0Q4lRcbba1XWtT+3mw=
-----END CERTIFICATE-----
""",
    ),
    "expiring-soon.crt": (
        "b7b0bc6a4797ee925b99df425c3d865253fa483b7754464fe27f185f7527ddcb",
        """-----BEGIN CERTIFICATE-----
MIIDVjCCAj6gAwIBAgIUabJQhDszpxGpINM3AHc2hfJy868wDQYJKoZIhvcNAQEL
BQAwPDEZMBcGA1UECgwQRGV2U2VjU2hpZWxkLUUyRTEfMB0GA1UEAwwWZXhwaXJp
bmctc29vbi5lMmUudGVzdDAeFw0yNTExMDgwMDAwMDBaFw0yNjExMDgwMDAwMDBa
MDwxGTAXBgNVBAoMEERldlNlY1NoaWVsZC1FMkUxHzAdBgNVBAMMFmV4cGlyaW5n
LXNvb24uZTJlLnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCy
+/fv9T2hf9QVHoKdwYWmul7WiuX2kNYunDVNTEk0uYWnuFEvUl96DqiyVoNxziAr
RZphP9QXfuA18grDH/3ZaapRrrDLA2B/pi7sK2yG8J3qiWfZXtl2NEzhbAyHrl1k
FfJ9EMENQceZuAKinW6JA7NPkISfxywfc4vzOIelR0VJIE+2ON+TfUu8iCBr8Mim
DOeB1MGWnH3lahhNR/4l9v3iby/cMGIu1DYuGSkE8xxwHHRRQQv4yBNY6IG7NKWX
XCJ7XwIRN7rsviFKb4b5QTR7n+phSL4jPVZNhDvarw0kzNVya5kBK8+8gL8KE8Fj
3xQh1gj33JP5vo1Ti+8xAgMBAAGjUDBOMB0GA1UdDgQWBBRDSiCGv+bbGdoVVjYC
gE/SWDCmSzAfBgNVHSMEGDAWgBRDSiCGv+bbGdoVVjYCgE/SWDCmSzAMBgNVHRMB
Af8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQA65hcisXZhMgEBipBN1f8UQh+BP0vy
6gtkfLE0K8MgtrGiCzIcjie1AUpTMDAKIEYqIfoLVO9NMl9Sk/R2MfWPjggM1uHJ
NC9dxFZCgTfVBIyPUxe4NT2Lvyq/jAMzhQx0QwUWu0eqDRMQd7IVdATHRz0mZLKk
/2n+HqQ54H34jjSvIHwn6pzeeQPy5Fst/RCJqLQfe7vhXkeiUK960zRBXciUBaqt
2RsoBKKlKcIeJjCy0ju6sQK7qAfkV+Jhm0dqfMV0THBjOhY53X9lxL7ob17HyYxD
M2nbO+8SFKcE3pJQ6lyq98rXhaitET1itk9V5jbrh41TPOYLGCk0RGM5
-----END CERTIFICATE-----
""",
    ),
    "other-team-canary.crt": (
        "fd3c62c876bb79d644d4eb3cad8395fc6e0105fc568deb9ca51ec71274f983f2",
        """-----BEGIN CERTIFICATE-----
MIIDVjCCAj6gAwIBAgIUeB3bPnc2T6j8ObA0tU/46RMfhiAwDQYJKoZIhvcNAQEL
BQAwPDEZMBcGA1UECgwQRGV2U2VjU2hpZWxkLUUyRTEfMB0GA1UEAwwWb3RoZXIt
dGVhbS1jYW5hcnkudGVzdDAeFw0yNjAxMDEwMDAwMDBaFw0yODAxMDEwMDAwMDBa
MDwxGTAXBgNVBAoMEERldlNlY1NoaWVsZC1FMkUxHzAdBgNVBAMMFm90aGVyLXRl
YW0tY2FuYXJ5LnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
ljE5fyinDQdeXUE9DNny8e43+irVKpud74X5zZWHhDoT1rdRf4BZ+Vvpra90ZKLL
g4RtJCoLRaUKLuCp3H857lt1R5hJusFcnw1jP/xZprCAnkaj0czddz+7VZJ8zmds
O9aj1SgQHtMJ7olUx9q9jWT718DIrv/tKBWNXVmXEUUnqdY1XDbhYQR226cN9lyg
yyggY9fhRMi54mU5Eqrv1e21GQy4tG8VyDwrvkgNsaFeYOh0Yci3KwVbyUUWHdNf
CtxjVHFMGoZEy/bs6VkMiY7aiEzlgIIQmJPkfb2eX5BX57COZvAH3cNVTy0tFcnh
iwjkcXU3djQd9FfQSeNpAgMBAAGjUDBOMB0GA1UdDgQWBBQncaZdujAfwQKk4skd
sCmq64tQIzAfBgNVHSMEGDAWgBQncaZdujAfwQKk4skdsCmq64tQIzAMBgNVHRMB
Af8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAi0Vkfrf3x4aEGRp6mlcvyL1opOwxU
Yi9IRTkJPoLGK9m2iCILXtE9/TiHzR2MF/jbv1h7CingKSeCKFG7TBcCT6YFy0aA
stx+fkGAVM9mdP9XBAl1Lr5ebo2xI2dJQx4wHvKQuISx0AQMh/VCNtW9MAPRpIgo
+0iYfQ1OEoGPpea4N8Eg1mne6OQFXpBO4yEtolxVV+W4Kbe8wHR//nAXqA+ymFY9
DoqJ0c6blacrlAVQiG9bieuaTUZK/0uYmerlqrQz23hOYJz+lwx/HKQFWfYmi7Mz
Bc0nkXlp3O7Tvhczwq23oPceuycB2F/6ZsEE5tCj+rbD8wFM347O9Zjb
-----END CERTIFICATE-----
""",
    ),
}

# Appendix B "Expected values" - the independent oracle the generated fixture must reproduce.
APPENDIX_B: dict[str, Any] = {
    "scans_total": 12,
    "eligible": 9,
    "included": 8,
    "excluded": {"failure": 1, "not_completed": 2, "no_data": 1},
    "sources": 7,
    "cert_files": 17,
    "cert_raw": 18,
    "cert_unique": 14,
    "bands": {"EXPIRED": 1, "LE_30": 1, "VALID": 12},
    "occurrences": 68,
    "impact": {"Critical": 1, "High": 23, "Medium": 5, "Low": 39},
    "issue": {"Critical": 1, "High": 23, "Medium": 5},
    "risk": (100, "F"),
    "codes": {
        "EXPIRED_CERTIFICATE": 1,
        "HARDCODED_KEY": 1,
        "QUANTUM_VULNERABLE": 5,
        "REUSED_NONCE": 1,
        "SELF_SIGNED_LEAF": 3,
        "STATIC_IV": 1,
        "WEAK_ALGORITHM": 8,
        "WEAK_CERTIFICATE_KEY": 3,
        "WEAK_CERTIFICATE_SIGNATURE": 3,
        "WEAK_CIPHER_MODE": 2,
        "WEAK_PROTOCOL": 2,
        "WEAK_RNG": 3,
    },
    "top_critical": "rsa1024_sha1.pem",
    "qv": 5,
    "safe": 32,
    "readiness": 86.5,
    "libs": 23,
    "libs_multi": ["hashlib (stdlib)", "pyca/cryptography", "pyopenssl", "ssl (stdlib)"],
    "pooled": 6,
    "legacy": 1,
    # framework -> (pass, fail, not_bom_evidenceable, out_of_scope, coverage)
    "compliance": {
        "bsi_tr_02102": (10, 5, 5, 4, 0.667),
        "cert_in_cbom": (114, 4, 97, 43, 0.966),
        "cnsa_2_0": (13, 2, 5, 4, 0.867),
        "eu_cra": (7, 3, 5, 3, 0.700),
        "eu_dora": (8, 2, 5, 3, 0.800),
        "fips_140_3": (11, 4, 5, 4, 0.733),
        "nist_1800_38b": (13, 2, 5, 4, 0.867),
        "nist_1800_38c": (12, 3, 5, 4, 0.800),
        "nist_800_57": (22, 8, 5, 7, 0.733),
        "omb_m_23_02": (8, 2, 5, 3, 0.800),
        "pci_dss_4": (11, 4, 5, 4, 0.733),
        "rbi_free_ai_protection": (24, 6, 10, 8, 0.800),
        "sebi_cscrf_cbom": (36, 4, 50, 18, 0.900),
    },
}


# ---------------------------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------------------------
def _die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def _import_aibom() -> Path:
    """Import ``aibom`` and prove it is THIS checkout's source (never the editable main install)."""
    import aibom

    location = Path(aibom.__file__).resolve()
    if AIBOM_SRC.resolve() not in location.parents:
        _die(
            f"aibom resolved to {location}, expected under {AIBOM_SRC}.\n"
            f"Re-run with: PYTHONPATH={AIBOM_SRC} <aibom-venv>/bin/python {Path(__file__).name}"
        )
    return location


def _assert_inputs_clean(allow_dirty: bool) -> None:
    """The fixture must be a function of committed code: no tracked change under the inputs."""
    paths = ["aibom", str(LEGACY_TIER_B.relative_to(ROOT))]
    command = [
        "git",
        "--no-optional-locks",
        "-C",
        str(ROOT),
        "status",
        "--porcelain",
        "--untracked-files=no",
        "--",
        *paths,
    ]
    try:
        out = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=120
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"warning: git unavailable ({exc}); input cleanliness NOT verified", file=sys.stderr)
        return
    if out and not allow_dirty:
        _die(f"uncommitted tracked changes in generator inputs (use --allow-dirty):\n{out}")


@contextlib.contextmanager
def _frozen_scanner_clock(as_of: date) -> Iterator[None]:
    """Freeze the only wall-clock read in the CBOM lane (``date.today()`` in the weak flagger)."""
    from aibom.cbom.scanners import weak_algorithm_scan as flagger

    real = flagger.date

    class FrozenDate(real):  # type: ignore[valid-type, misc]
        @classmethod
        def today(cls) -> date:
            return as_of

    flagger.date = FrozenDate
    try:
        yield
    finally:
        flagger.date = real


# ---------------------------------------------------------------------------------------------
# Trees
# ---------------------------------------------------------------------------------------------
def _copy_tree(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return dst


def _der_sha256(pem: str) -> str:
    body = "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def build_trees(base: Path) -> dict[str, Path]:
    for name, (pinned, pem) in CERT_FILES.items():
        if _der_sha256(pem) != pinned:
            _die(f"embedded certificate {name} does not match its pinned SHA-256")
    certs = AIBOM_FIXTURES / "synthetic-crypto-certs"
    app = AIBOM_FIXTURES / "synthetic-crypto-app"
    copies = {  # tree name -> frozen aibom fixture it starts from
        "payments-service-v1": app,
        "payments-service-v2": app,
        "identity-gateway": certs,
        "crypto-misuse-lab": AIBOM_FIXTURES / "synthetic-crypto-misuse",
        "pqc-pilot": AIBOM_FIXTURES / "synthetic-crypto-pqc",
        "vendor-sdk-manifests": AIBOM_FIXTURES / "synthetic-crypto-manifests",
    }
    trees = {name: _copy_tree(src, base / name) for name, src in copies.items()}
    server = trees["payments-service-v2"] / "deploy" / "tls"
    server.mkdir(parents=True)
    shutil.copyfile(certs / "chain-leaf.crt", server / "server.crt")
    imported = trees["identity-gateway"] / "certs" / "imported"
    imported.mkdir(parents=True)
    shutil.copyfile(app / "cert.pem", imported / "payments-ca.pem")
    authored = {  # tree name -> authored certificate files placed in it
        "cert-lifecycle-lab": ("expired.crt", "expiring-soon.crt"),
        "other-team-app": ("other-team-canary.crt",),
    }
    for name, files in authored.items():
        trees[name] = base / name
        trees[name].mkdir()
        for filename in files:
            (trees[name] / filename).write_text(CERT_FILES[filename][1], encoding="ascii")
    return trees


def tree_cert_fingerprints(tree: Path) -> dict[str, str]:
    """``{repo-relative path: DER sha256}`` of every certificate FILE in ``tree``."""
    found: dict[str, str] = {}
    for path in sorted(tree.rglob("*")):
        if path.is_file() and path.suffix in {".pem", ".crt"}:
            text = path.read_text(encoding="ascii", errors="replace")
            if "BEGIN CERTIFICATE" in text:
                found[path.relative_to(tree).as_posix()] = _der_sha256(text)
    return found


# ---------------------------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------------------------
def _dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def scan_tree(tree: Path, base: Path) -> dict[str, Any]:
    """The exact function the worker calls (``scan_worker.cbom``), run twice as a self-check."""
    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

    renders = []
    for _ in range(2):
        run = scan_crypto_to_devsecshield(str(tree), level=4)
        run["duration_of_scan"] = FIXED_DURATION_S
        renders.append(_dumps(run))
    if renders[0] != renders[1]:
        _die(f"scan of {tree.name} is not deterministic within one process")
    if str(base) in renders[0]:
        _die(f"scan of {tree.name} leaked an absolute path ({base}) into the run-object")
    return json.loads(renders[0])


# ---------------------------------------------------------------------------------------------
# Seed (plan Appendix B)
# ---------------------------------------------------------------------------------------------
class SeedScan(NamedTuple):
    id: int
    team_id: int
    scan_type: str
    title: str
    status: str  # raw DB value
    age_days: int
    meta: dict[str, Any]  # scan_metadata, shaped like backend/utilities/db/metadata.py (cbom)
    payload: tuple[Any, ...]  # ("tree", name) | ("legacy",) | ("raw", scan_data)


def _repo_meta(url: str, branch: str = "main") -> dict[str, Any]:
    return {
        "zip_file_used": False,
        "repo_url": url,
        "repo_type": "github",
        "branch": branch,
        "cbom_file_used": False,
        "scan_binaries": False,
    }


def _zip_meta() -> dict[str, Any]:
    return {
        "zip_file_used": True,
        "repo_url": None,
        "repo_type": None,
        "branch": None,
        "cbom_file_used": False,
        "scan_binaries": False,
    }


def _canary(title: str) -> tuple[str, dict[str, Any]]:
    return "raw", {"results": [{"title": title}]}


LEGACY_URL = (  # userinfo that sanitisation must remove from every view and PDF
    "https://x-access-token:NOT-A-REAL-TOKEN-CANARY@github.com/e2e-demo/legacy-billing.git"
)
SBOM_NOISE = {
    "results": [{"title": "SBOM-TYPE-CANARY", "asset_type": "algorithm", "impact": "Critical"}]
}

SEED: list[SeedScan] = [
    SeedScan(1, 1, "cbom", "payments-service #1", "success", 21,
             _repo_meta("https://github.com/E2E-Demo/payments-service.git"),
             ("tree", "payments-service-v1")),
    SeedScan(2, 1, "cbom", "payments-service #2", "success", 7,
             _repo_meta(REPO + "payments-service"), ("tree", "payments-service-v2")),
    SeedScan(3, 1, "cbom", "identity-gateway", "success", 14,
             _repo_meta(REPO + "identity-gateway"), ("tree", "identity-gateway")),
    SeedScan(4, 1, "cbom", "crypto-misuse-lab", "success", 10,
             _repo_meta(REPO + "crypto-misuse-lab"), ("tree", "crypto-misuse-lab")),
    SeedScan(5, 1, "cbom", "pqc-pilot", "success", 5,
             _repo_meta(REPO + "pqc-pilot", "release"), ("tree", "pqc-pilot")),
    SeedScan(6, 1, "cbom", "cert-lifecycle-lab", "success", 3,
             _zip_meta(), ("tree", "cert-lifecycle-lab")),
    SeedScan(7, 1, "cbom", "vendor-sdk-manifests", "success", 2,
             _repo_meta(REPO + "vendor-sdk-manifests"), ("tree", "vendor-sdk-manifests")),
    SeedScan(8, 1, "cbom", "legacy-billing", "success", 60,
             _repo_meta(LEGACY_URL), ("legacy",)),
    SeedScan(9, 1, "cbom", "payments-service (FAILED)", "failure", 1,
             _repo_meta(REPO + "payments-service/"), _canary("FAILED-SCAN-CANARY")),
    SeedScan(10, 1, "cbom", "queued", "NOT_STARTED", 0,
             _repo_meta(REPO + "queued"), _canary("QUEUED-SCAN-CANARY")),
    SeedScan(11, 1, "cbom", "running", "started", 0,
             _repo_meta(REPO + "running"), _canary("RUNNING-SCAN-CANARY")),
    SeedScan(12, 1, "sbom_sca", "sbom noise", "success", 4,
             _repo_meta(REPO + "sbom-noise"), ("raw", SBOM_NOISE)),
    SeedScan(13, 1, "cbom", "success-but-empty", "success", 4,
             _repo_meta(REPO + "empty"), ("raw", {})),
    SeedScan(14, 2, "cbom", "other-team scan", "success", 3,
             _repo_meta("https://github.com/other-org/other-team-canary-repo"),
             ("tree", "other-team-app")),
]  # fmt: skip

_LAG_MINUTES = {"success": 2, "failure": 2, "started": 1, "NOT_STARTED": 0}


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_scans(runs: dict[str, dict[str, Any]], legacy: dict[str, Any]) -> list[dict[str, Any]]:
    scans = []
    for seed in SEED:
        if seed.payload[0] == "tree":
            scan_data: Any = runs[seed.payload[1]]
        elif seed.payload[0] == "legacy":
            scan_data = legacy
        else:
            scan_data = seed.payload[1]
        created = NOW - timedelta(days=seed.age_days)
        scans.append(
            {
                "id": seed.id,
                "team_id": seed.team_id,
                "scan_type": seed.scan_type,
                "title": seed.title,
                "status": seed.status,
                "age_days": seed.age_days,
                "created_at": _iso(created),
                "last_updated": _iso(created + timedelta(minutes=_LAG_MINUTES[seed.status])),
                "scan_metadata": seed.meta,
                "scan_data": scan_data,
            }
        )
    return scans


def _strip_refs(scans: list[dict[str, Any]]) -> None:
    for scan in scans:
        data = scan["scan_data"]
        compliance = data.get("cbom_compliance") if isinstance(data, dict) else None
        if isinstance(compliance, dict):
            for block in compliance.values():
                if isinstance(block, dict):
                    for requirement in block.get("requirements", []):
                        requirement.pop("refs", None)


# ---------------------------------------------------------------------------------------------
# Independent oracle (shares no code with the future product aggregator)
# ---------------------------------------------------------------------------------------------
class _Checker:
    def __init__(self) -> None:
        self.problems: list[str] = []

    def eq(self, label: str, actual: Any, wanted: Any) -> None:
        if actual != wanted:
            self.problems.append(f"{label}: got {actual!r}, expected {wanted!r}")

    def fail(self, message: str) -> None:
        self.problems.append(message)


class _CertOcc(NamedTuple):
    scan_id: int
    source: str
    path: str | None
    key: str
    props: dict[str, str]


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _source_of(scan: dict[str, Any]) -> str:
    """Plan 4.3 source key, re-implemented here as part of the independent oracle."""
    meta, title = scan["scan_metadata"], scan["title"]
    if meta.get("repo_url"):
        parts = urlsplit(meta["repo_url"].strip())
        path = parts.path.rstrip("/")
        path = path.removesuffix(".git")
        return f"repo:{parts.hostname or ''}{path}@{meta.get('branch') or 'default'}".lower()
    if meta.get("zip_file_used"):
        return f"zip:{_slug(title)}"
    return f"scan:{scan['id']}"


def _props(component: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def _tuple_key(props: dict[str, str]) -> str:
    parts = [
        (props.get("crypto:subjectName") or "").strip().casefold(),
        (props.get("crypto:issuerName") or "").strip().casefold(),
        props.get("crypto:notValidBefore", ""),
        props.get("crypto:notValidAfter", ""),
        (props.get("crypto:signatureAlgorithm") or "").casefold(),
        (props.get("crypto:publicKeyAlgorithm") or "").casefold(),
        str(props.get("crypto:keySize", "")),
        (props.get("crypto:curve") or "").casefold(),
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def _usable(scan: dict[str, Any]) -> bool:
    data = scan["scan_data"]
    return isinstance(data, dict) and (
        isinstance(data.get("results"), list) or isinstance(data.get("cbom_json"), dict)
    )


def _components(scan: dict[str, Any]) -> list[dict[str, Any]]:
    return (scan["scan_data"].get("cbom_json") or {}).get("components", [])


def _check_selection(chk: _Checker, scans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    team1 = [s for s in scans if s["team_id"] == 1 and s["scan_type"] == "cbom"]
    status = {s["id"]: s["status"].strip().lower() for s in team1}
    eligible = [s for s in team1 if status[s["id"]] == "success"]
    included = [s for s in eligible if _usable(s)]
    not_completed = {"pending", "started", "retry", "not_started"}
    chk.eq("scans_total", len(team1), APPENDIX_B["scans_total"])
    chk.eq("eligible", len(eligible), APPENDIX_B["eligible"])
    chk.eq("included", len(included), APPENDIX_B["included"])
    chk.eq(
        "excluded",
        {
            "failure": sum(v == "failure" for v in status.values()),
            "not_completed": sum(v in not_completed for v in status.values()),
            "no_data": len(eligible) - len(included),
        },
        APPENDIX_B["excluded"],
    )
    return included


def _check_sources(chk: _Checker, included: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for scan in included:
        by_source[_source_of(scan)].append(scan)
    chk.eq("sources", len(by_source), APPENDIX_B["sources"])
    newest = {
        key: max(group, key=lambda s: (s["created_at"], s["id"]))
        for key, group in by_source.items()
    }
    current = newest.get("repo:github.com/e2e-demo/payments-service@main", {}).get("id")
    chk.eq("payments current scan", current, 2)
    return newest


def _cert_occurrences(included: list[dict[str, Any]]) -> list[_CertOcc]:
    found = []
    for scan in included:
        for comp in _components(scan):
            if (comp.get("cryptoProperties") or {}).get("assetType") == "certificate":
                props = _props(comp)
                found.append(
                    _CertOcc(
                        scan["id"], _source_of(scan), props.get("discovery:source"),
                        _tuple_key(props), props,
                    )
                )  # fmt: skip
    return found


def _check_certificates(
    chk: _Checker,
    included: list[dict[str, Any]],
    file_fps: dict[int, dict[str, str]],
) -> None:
    ids = {s["id"] for s in included}
    files = {sid: paths for sid, paths in file_fps.items() if sid in ids}
    occurrences = _cert_occurrences(included)
    chk.eq("cert_files", sum(len(p) for p in files.values()), APPENDIX_B["cert_files"])
    chk.eq("cert_raw", len(occurrences), APPENDIX_B["cert_raw"])
    chk.eq(
        "cert_unique (crypto:* tuple identity)",
        len({o.key for o in occurrences}),
        APPENDIX_B["cert_unique"],
    )
    chk.eq(
        "cert_unique (DER fingerprints of the files)",
        len({fp for paths in files.values() for fp in paths.values()}),
        APPENDIX_B["cert_unique"],
    )
    fp_to_keys: dict[str, set[str]] = defaultdict(set)
    key_to_fps: dict[str, set[str]] = defaultdict(set)
    for occ in occurrences:
        fingerprint = files.get(occ.scan_id, {}).get(occ.path or "")
        if fingerprint is not None:  # the legacy scan has no files; tuple identity only
            fp_to_keys[fingerprint].add(occ.key)
            key_to_fps[occ.key].add(fingerprint)
    partitions_agree = all(len(v) == 1 for v in fp_to_keys.values()) and all(
        len(v) == 1 for v in key_to_fps.values()
    )
    if not partitions_agree:
        chk.fail("crypto:* tuple identity and DER-fingerprint partitions disagree")

    created = {s["id"]: s["created_at"] for s in included}
    groups: dict[str, list[_CertOcc]] = defaultdict(list)
    for occ in occurrences:
        groups[occ.key].append(occ)

    def group_of(cn: str) -> list[_CertOcc]:
        return next((g for g in groups.values() if g[0].props.get("crypto:subjectName") == cn), [])

    app = group_of("synthetic-crypto-app.test")
    chk.eq("app cert scans", sorted({o.scan_id for o in app}), [1, 2, 3, 8])
    chk.eq("app cert sources", len({o.source for o in app}), 3)
    chk.eq("app cert locations", len({(o.source, o.path) for o in app}), 3)
    chk.eq("app cert first seen", min(app, key=lambda o: created[o.scan_id]).scan_id, 8)
    chk.eq("app cert last seen", max(app, key=lambda o: created[o.scan_id]).scan_id, 2)
    leaf = group_of("chain.leaf.test")
    chk.eq("leaf cert scans", sorted({o.scan_id for o in leaf}), [2, 3])
    chk.eq("leaf cert sources", len({o.source for o in leaf}), 2)

    bands: Counter[str] = Counter()
    for group in groups.values():
        days = (date.fromisoformat(group[0].props["crypto:notValidAfter"][:10]) - AS_OF).days
        if days < 0:
            bands["EXPIRED"] += 1
        elif days <= 30:
            bands["LE_30"] += 1
        elif days <= 90:
            bands["LE_90"] += 1
        else:
            bands["VALID"] += 1
    chk.eq("expiry bands", dict(bands), APPENDIX_B["bands"])


def _check_current_state(chk: _Checker, newest: dict[str, dict[str, Any]]) -> None:
    rows = [row for scan in newest.values() for row in scan["scan_data"].get("results", [])]
    chk.eq("occurrences", len(rows), APPENDIX_B["occurrences"])
    chk.eq("impact", dict(Counter(r.get("impact") for r in rows)), APPENDIX_B["impact"])
    issues = [r for r in rows if r.get("finding_codes")]
    chk.eq("issue assets", dict(Counter(r.get("impact") for r in issues)), APPENDIX_B["issue"])
    weighted = sum({"Critical": 10, "High": 5, "Medium": 2, "Low": 1}[r["impact"]] for r in issues)
    score = min(100, weighted * 4)  # report_branding.compute_risk_score formula
    grades = ((70, "F"), (50, "D"), (30, "C"), (15, "B"), (0, "A"))
    chk.eq("risk", (score, next(g for floor, g in grades if score >= floor)), APPENDIX_B["risk"])
    codes: Counter[str] = Counter()
    for row in rows:
        codes.update(row.get("finding_codes") or [])
    chk.eq("finding codes", dict(codes), APPENDIX_B["codes"])
    critical = [r.get("title") for r in rows if r.get("impact") == "Critical"]
    chk.eq("critical asset", critical, [APPENDIX_B["top_critical"]])
    algorithms = [r for r in rows if r.get("asset_type") == "algorithm"]
    vulnerable = sum(1 for r in algorithms if r.get("quantum_vulnerable"))
    safe = len(algorithms) - vulnerable
    chk.eq("quantum vulnerable", vulnerable, APPENDIX_B["qv"])
    chk.eq("quantum safe", safe, APPENDIX_B["safe"])
    chk.eq("readiness %", round(100 * safe / (safe + vulnerable), 1), APPENDIX_B["readiness"])


def _check_libraries(chk: _Checker, included: list[dict[str, Any]]) -> None:
    libs: dict[str, set[str]] = defaultdict(set)
    for scan in included:
        for comp in _components(scan):
            if comp.get("type") == "library":
                libs[comp["name"].casefold()].add(_source_of(scan))
    chk.eq("libraries", len(libs), APPENDIX_B["libs"])
    multi = sorted(name for name, sources in libs.items() if len(sources) > 1)
    chk.eq("libraries in >1 source", multi, APPENDIX_B["libs_multi"])


def _check_compliance(chk: _Checker, newest: dict[str, dict[str, Any]]) -> None:
    states = ("pass", "pass_with_evidence", "fail", "not_bom_evidenceable", "out_of_scope")
    pool: dict[str, Counter[str]] = defaultdict(Counter)
    pooled = 0
    for scan in newest.values():
        compliance = scan["scan_data"].get("cbom_compliance")
        if not compliance:
            continue
        pooled += 1
        for framework, block in compliance.items():
            if isinstance(block, dict):
                for state in states:
                    pool[framework][state] += block.get(state, 0)
    chk.eq("pooled sources", pooled, APPENDIX_B["pooled"])
    chk.eq("legacy sources excluded", len(newest) - pooled, APPENDIX_B["legacy"])
    actual = {}
    for framework, c in sorted(pool.items()):
        denominator = c["pass"] + c["pass_with_evidence"] + c["fail"]
        coverage = round((c["pass"] + c["pass_with_evidence"]) / denominator, 3)
        actual[framework] = (
            c["pass"], c["fail"], c["not_bom_evidenceable"], c["out_of_scope"], coverage,
        )  # fmt: skip
    wanted = {k: tuple(v) for k, v in sorted(APPENDIX_B["compliance"].items())}
    chk.eq("pooled compliance", actual, wanted)


def _check_canaries_and_timeline(
    chk: _Checker,
    scans: list[dict[str, Any]],
    included: list[dict[str, Any]],
    timeline: dict[str, str],
) -> None:
    blobs = {s["id"]: _dumps(s["scan_data"]) for s in scans}
    owners = (
        (9, "FAILED-SCAN-CANARY"),
        (10, "QUEUED-SCAN-CANARY"),
        (11, "RUNNING-SCAN-CANARY"),
        (12, "SBOM-TYPE-CANARY"),
        (14, "other-team-canary.test"),
    )
    for owner, token in owners:
        seen_in = sorted(sid for sid, blob in blobs.items() if token in blob)
        chk.eq(f"canary {token} confined to its scan", seen_in, [owner])
    descriptions = " ".join(
        m.get("description", "")
        for scan in included
        for m in ((scan["scan_data"].get("cbom_distributions") or {}).get("pqc") or {}).get(
            "migration", []
        )
    )
    for label, text in timeline.items():
        if text not in descriptions:
            chk.fail(f"PQC timeline {label!r} not found verbatim in migration[].description")


def verify_appendix_b(
    scans: list[dict[str, Any]],
    file_fps: dict[int, dict[str, str]],
    timeline: dict[str, str],
) -> list[str]:
    """Mismatch descriptions between the fixture and plan Appendix B (empty == reproduced)."""
    chk = _Checker()
    included = _check_selection(chk, scans)
    newest = _check_sources(chk, included)
    _check_certificates(chk, included, file_fps)
    _check_current_state(chk, newest)
    _check_libraries(chk, included)
    _check_compliance(chk, newest)
    _check_canaries_and_timeline(chk, scans, included, timeline)
    return chk.problems


# ---------------------------------------------------------------------------------------------
# Registry fixture
# ---------------------------------------------------------------------------------------------
def build_registry() -> dict[str, Any]:
    import aibom.cbom.pipeline  # noqa: F401  (imports the scanners package => registers them)
    from aibom.cbom import pqc
    from aibom.cbom.compliance import CBOM_FRAMEWORKS
    from aibom.cbom.registry import ordered_cbom_scanners

    scanners = ordered_cbom_scanners()
    registered = {type(s).__module__.rsplit(".", 1)[-1] for s in scanners}
    package = AIBOM_SRC / "aibom" / "cbom" / "scanners"
    on_disk = {p.stem for p in package.glob("*.py") if p.stem != "__init__"}
    return {
        "scanners": [{"name": s.name, "order": s.order} for s in scanners],
        # modules that exist but are NOT imported => never describe them as active (plan 3.2)
        "unregistered_scanner_modules": sorted(on_disk - registered),
        "frameworks": list(CBOM_FRAMEWORKS),
        "pqc_timeline": {"nist": pqc._TIMELINE, "cnsa": pqc._CNSA_TIMELINE},
    }


# ---------------------------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------------------------
def generate() -> tuple[str, str]:
    """Return ``(scans_json, registry_json)`` texts, each ending in a newline."""
    registry = build_registry()
    legacy = json.loads(LEGACY_TIER_B.read_text(encoding="utf-8"))
    tree_of = {s.id: s.payload[1] for s in SEED if s.payload[0] == "tree"}
    with tempfile.TemporaryDirectory(prefix="cbom-rollup-fixture-") as raw_base:
        base = Path(raw_base)
        trees = build_trees(base)
        with _frozen_scanner_clock(AS_OF):
            runs = {name: scan_tree(path, base) for name, path in trees.items()}
        file_fps = {sid: tree_cert_fingerprints(trees[name]) for sid, name in tree_of.items()}
    scans = build_scans(runs, legacy)
    problems = verify_appendix_b(scans, file_fps, registry["pqc_timeline"])
    if problems:
        _die("fixture does not reproduce plan Appendix B:\n  - " + "\n  - ".join(problems))
    header: dict[str, Any] = {
        "schema_version": 1,
        "as_of": AS_OF.isoformat(),
        "now": _iso(NOW),
        "team": {"id": 1, "name": "E2E Demo Team"},
        "other_teams": [{"id": 2, "name": "Other Team"}, {"id": 3, "name": "Empty Team"}],
        "refs_stripped": False,
        "scans": scans,
    }
    text = _dumps(header) + "\n"
    if len(text.encode("utf-8")) > MAX_FIXTURE_BYTES:
        _strip_refs(scans)
        header["refs_stripped"] = True
        text = _dumps(header) + "\n"
    return text, _dumps(registry) + "\n"


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def _differs(path: Path, text: str) -> bool:
    return not path.is_file() or path.read_text(encoding="utf-8") != text


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out-dir", type=Path, default=HERE, help="where the two files live")
    parser.add_argument("--check", action="store_true", help="exit 1 if --out-dir files differ")
    parser.add_argument("--allow-dirty", action="store_true", help="skip the git cleanliness check")
    args = parser.parse_args()

    location = _import_aibom()
    _assert_inputs_clean(args.allow_dirty)
    outputs = dict(zip((SCANS_NAME, REGISTRY_NAME), generate(), strict=True))
    print(f"aibom: {location}")
    for name, text in outputs.items():
        print(f"{hashlib.sha256(text.encode('utf-8')).hexdigest()}  {name}  ({len(text)} bytes)")
    if args.check:
        stale = [name for name, text in outputs.items() if _differs(args.out_dir / name, text)]
        if stale:
            print(f"DRIFT: {', '.join(stale)} differ from a fresh regeneration", file=sys.stderr)
            return 1
        print("OK: committed fixtures are byte-identical to a fresh regeneration")
        return 0
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, text in outputs.items():
        _write_atomic(args.out_dir / name, text)
    print("Appendix-B oracle: every quantity reproduced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
