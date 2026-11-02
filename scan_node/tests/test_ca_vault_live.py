"""Vault PKI + transit collector against a real Vault (dev server with -dev-tls; skipped unless configured).

ZS_TEST_VAULT_ADDR (https://127.0.0.1:<port>), ZS_TEST_VAULT_ROOT_TOKEN and ZS_TEST_VAULT_CA (the dev CA file) point
at a throw-away Vault.  The test seeds a PKI root with roles and transit keys with the root token, installs the
read-only policy shipped to customers (templates.VAULT_POLICY), and collects with a token that has only that policy.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

ADDR = os.environ.get("ZS_TEST_VAULT_ADDR")
ROOT = os.environ.get("ZS_TEST_VAULT_ROOT_TOKEN")
CA = os.environ.get("ZS_TEST_VAULT_CA")
pytestmark = pytest.mark.skipif(not (ADDR and ROOT and CA), reason="ZS_TEST_VAULT_* not set")
REPO = Path(__file__).resolve().parents[2]


def _vault(method, path, token, body=None):
    import httpx

    r = httpx.request(method, f"{ADDR}/v1/{path}", headers={"X-Vault-Token": token}, json=body, verify=CA, timeout=20,
                      trust_env=False)
    assert r.status_code < 300, (path, r.status_code, r.text[:300])
    return r.json() if r.content else {}


@pytest.fixture(scope="module")
def reader_token():
    sys.path.insert(0, str(REPO))
    from backend.utilities.cbom_sources import templates

    _vault("POST", "sys/mounts/pki", ROOT, {"type": "pki", "config": {"max_lease_ttl": "87600h"}})
    _vault("POST", "pki/root/generate/internal", ROOT, {"common_name": "wp6 root", "key_type": "rsa", "key_bits": 2048,
                                                       "ttl": "87600h", "issuer_name": "wp6-root"})
    _vault("POST", "pki/roles/any-name", ROOT, {"allow_any_name": True, "max_ttl": "17520h", "key_type": "rsa",
                                               "key_bits": 2048})
    _vault("POST", "pki/roles/web", ROOT, {"allowed_domains": "corp.example", "allow_subdomains": True,
                                          "max_ttl": "2160h", "key_type": "ec", "key_bits": 256})
    _vault("POST", "pki/config/urls", ROOT, {"issuing_certificates": f"{ADDR}/v1/pki/ca",
                                            "crl_distribution_points": f"{ADDR}/v1/pki/crl"})
    _vault("POST", "sys/mounts/transit", ROOT, {"type": "transit"})
    _vault("POST", "transit/keys/app-aes", ROOT, {"type": "aes256-gcm96", "auto_rotate_period": "720h"})
    _vault("POST", "transit/keys/legacy-export", ROOT, {"type": "rsa-2048", "exportable": True,
                                                       "allow_plaintext_backup": True})
    _vault("POST", "transit/keys/no-rotation", ROOT, {"type": "aes128-gcm96"})
    _vault("PUT", "sys/policies/acl/zs-cbom", ROOT, {"policy": templates.VAULT_POLICY})
    token = _vault("POST", "auth/token/create", ROOT, {"policies": ["zs-cbom"], "no_default_policy": True,
                                                      "ttl": "1h"})["auth"]["client_token"]
    return token


def _ctx(kind="collect", secrets=()):
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="ca_connector",
                      scrubber=Scrubber(list(secrets)), never_scan=NeverScan(), deadline=time.monotonic() + 120)


def test_vault_pki_and_transit_with_the_read_only_policy(reader_token):
    from zs_scan_node.collectors import ca

    ctx = _ctx(secrets=[reader_token])
    cfg = {"provider": "vault", "api_url": ADDR, "ca_pem": Path(CA).read_text()}
    ca.collect(ctx, cfg, {"token": reader_token}, {})
    ctx.flush()
    assert [o.status for o in ctx.outcomes] == ["ok"], ctx.outcomes
    by_type: dict[str, list] = {}
    for a in ctx.collected:
        by_type.setdefault(a["type"], []).append(a)
    issuer = by_type["ca_authority"][0]["facts"]
    assert issuer["mount"] == "pki" and issuer["issuer"] == "wp6-root" and issuer["key_type"] == "RSA"
    assert any(c["facts"].get("role") == "ca" and "wp6 root" in c["name"] for c in by_type["certificate"])
    roles = {a["name"]: a for a in by_type["ca_template"]}
    assert roles["pki/any-name"]["facts"]["allow_any_name"] is True
    assert roles["pki/any-name"]["facts"]["max_ttl_s"] == 17520 * 3600
    assert roles["pki/web"]["facts"]["key_type"] == "EC" and roles["pki/web"]["key_size"] == 256
    keys = {a["name"]: a for a in by_type["managed_key"]}
    assert keys["app-aes"]["algorithm"] == "AES" and keys["app-aes"]["key_size"] == 256
    assert keys["app-aes"]["facts"]["auto_rotate_period_s"] == 720 * 3600
    assert keys["legacy-export"]["facts"]["exportable"] is True and keys["legacy-export"]["key_size"] == 2048
    assert keys["no-rotation"]["facts"]["auto_rotate_period_s"] == 0
    blob = json.dumps(ctx.collected)
    assert reader_token not in blob and ROOT not in blob
    assert "PRIVATE KEY" not in blob
    # findings from the server-side rules
    sys.path.insert(0, str(REPO))
    from backend.utilities.cbom_sources import classify

    def codes(a):
        return set(classify.classify(a["type"], a["algorithm"], a["key_size"], a["protocol"], a["facts"])["finding_codes"])

    assert {"CA_ALLOWS_ANY_NAME", "CA_LONG_VALIDITY"} <= codes(roles["pki/any-name"])
    assert not codes(roles["pki/web"]) - {"QUANTUM_VULNERABLE"}
    assert "KEY_PLAINTEXT_EXPORT" in codes(keys["legacy-export"]) and "QUANTUM_VULNERABLE" in codes(keys["legacy-export"])
    assert codes(keys["no-rotation"]) == {"KEY_NO_ROTATION"}
    assert codes(keys["app-aes"]) == set()


def test_vault_wrong_token_and_untrusted_certificate(reader_token):
    from zs_scan_node.collectors import ca

    ctx = _ctx()
    ca.collect(ctx, {"provider": "vault", "api_url": ADDR, "ca_pem": Path(CA).read_text()}, {"token": "hvs.not-a-token"}, {})
    assert [o.status for o in ctx.outcomes] == ["auth_failed"]
    ctx = _ctx()
    ca.collect(ctx, {"provider": "vault", "api_url": ADDR}, {"token": reader_token}, {})  # dev CA not uploaded
    assert [o.status for o in ctx.outcomes] == ["identity_unverified"]
    ctx = _ctx("test_connection")
    ca.test(ctx, {"provider": "vault", "api_url": ADDR, "ca_pem": Path(CA).read_text()}, {"token": reader_token}, {})
    assert ctx.samples[0]["status"] == "ready"
