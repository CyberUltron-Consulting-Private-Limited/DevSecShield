"""Classifier follow-ups from issue #126: AWS post-quantum listener policies, SSH key-exchange verdicts from algid, and
malformed stored facts treated as unread (never an HTTP 500).

Uses the same SQLite + real-router harness as test_cbom_sources_api.py for the route tests.
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest
from sqlalchemy import text

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_sources_api import _collect_job, api, world  # noqa: E402,F401  (shared fixtures)

from backend.utilities.cbom_sources import algid, qgrade  # noqa: E402
from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

NOW = dt.datetime(2026, 11, 14)

# ----------------------------------------------------------------------------- 1. AWS ALB / NLB post-quantum policies
# The 13 ELBSecurityPolicy-*-PQ-* names AWS lists for ALB and NLB (docs.aws.amazon.com/elasticloadbalancing/latest/
# application/describe-ssl-policies.html and .../network/describe-ssl-policies.html, read 2026-11-14): algid's elbv2
# table (scripts/algid/sources/aws-elb-pq-policies.json) holds exactly these.
ELB_PQ = sorted(algid._AWS_TLS_POLICY["elbv2"])
# what aws_collect.elbv2() stores for a listener: the policy name, its protocols and ciphers (no negotiated group)
LISTENER = {"protocols": ["TLSv1.2", "TLSv1.3"],
            "ciphers": ["TLS_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256"],
            "static_rsa_kex": False, "certificates": [], "exposure": "internet"}


def test_algid_elb_table_is_the_thirteen_documented_pq_policies():
    assert len(ELB_PQ) == 13 and all(n.startswith("ELBSecurityPolicy-TLS13-") and "-PQ-2025-09" in n for n in ELB_PQ)
    assert set(algid.aws_tls_policy("elbv2", ELB_PQ[0])) == {"SecP256r1MLKEM768", "SecP384r1MLKEM1024",
                                                               "X25519MLKEM768"}


@pytest.mark.parametrize("policy", ELB_PQ)
def test_an_alb_or_nlb_listener_on_a_pq_policy_is_not_quantum_vulnerable(policy):
    from backend.utilities.cbom_sources.posture import pqc_class

    facts = {**LISTENER, "ssl_policy": policy}
    v = classify("load_balancer_tls", None, None, "HTTPS", facts, NOW)
    assert v["quantum_vulnerable"] is False
    assert "QUANTUM_VULNERABLE" not in v["finding_codes"] and "NO_PQ_KEX" not in v["finding_codes"]
    # a hybrid key exchange (classical + ML-KEM), not a pure post-quantum one: the posture class says so
    assert pqc_class("load_balancer_tls", False, v["finding_codes"], facts) == "hybrid"


@pytest.mark.parametrize("policy", ["ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-2016-08",
                                    "ELBSecurityPolicy-TLS13-1-2-PQ-2099-01", "elbsecuritypolicy-tls13-1-2-pq-2025-09",
                                    None, 7, ["ELBSecurityPolicy-TLS13-1-2-PQ-2025-09"]])
def test_a_listener_on_any_other_policy_keeps_its_classical_verdict(policy):
    """Only a name AWS documents as post-quantum is credited: an unknown future name, a different spelling or a
    malformed value proves nothing, so the listener stays quantum vulnerable as before."""
    v = classify("load_balancer_tls", None, None, "HTTPS", {**LISTENER, "ssl_policy": policy}, NOW)
    assert v["quantum_vulnerable"] is True and "QUANTUM_VULNERABLE" in v["finding_codes"]


def test_a_classic_load_balancer_is_never_credited_with_an_elbv2_policy():
    """Classic Load Balancers have no post-quantum policies; a reference policy name there is not elbv2's."""
    facts = {**LISTENER, "ssl_policy": ELB_PQ[0], "classic": True}
    assert classify("load_balancer_tls", None, None, "HTTPS", facts, NOW)["quantum_vulnerable"] is True


def test_an_explicit_pq_group_fact_still_wins_over_the_policy_name():
    facts = {**LISTENER, "ssl_policy": ELB_PQ[0], "pq_group_supported": False}
    v = classify("load_balancer_tls", None, None, "HTTPS", facts, NOW)
    assert v["quantum_vulnerable"] is True and "NO_PQ_KEX" in v["finding_codes"]


# The 3 API Gateway PQ policies on the AWS policy list page (scripts/algid/sources/aws-apigw-pq-policies.json) plus the
# botocore SecurityPolicy enum's SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09 (botocore-enums.json): algid's table, 4 names.
APIGW_PQ = sorted(algid._AWS_TLS_POLICY["apigateway"])


def test_algid_api_gateway_table_is_the_documented_pq_policies_and_the_sdk_enum():
    assert APIGW_PQ == ["SecurityPolicy_TLS13_1_2_FIPS_PFS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_FIPS_PQ_2025_09",
                        "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09", "SecurityPolicy_TLS13_1_2_PQ_2025_09"]


@pytest.mark.parametrize("pq", APIGW_PQ)
def test_an_api_gateway_domain_on_a_pq_policy_is_judged_by_the_same_table(pq):
    v = classify("api_tls", None, None, "TLS", {"security_policy": pq, "min_version": "TLSv1.2"}, NOW)
    assert v["quantum_vulnerable"] is False and "QUANTUM_VULNERABLE" not in v["finding_codes"]
    old = classify("api_tls", None, None, "TLS", {"security_policy": "TLS_1_2", "min_version": "TLSv1.2"}, NOW)
    assert old["quantum_vulnerable"] is None  # unchanged: no protocol list, so no verdict either way


# The owner default (CB-19): a hybrid is graded on the weakest configuration it accepts.  AWS documents every PQ policy
# as also accepting classical key exchange, so each is a classical fallback whatever protocols the facts list.
AWS_PQ_ROWS = ([("load_balancer_tls", {**LISTENER, "protocols": ["TLSv1.3"], "ssl_policy": p}) for p in ELB_PQ]
               + [("api_tls", {"security_policy": p, "min_version": "TLSv1.2"}) for p in APIGW_PQ])


@pytest.mark.parametrize("asset_type, facts", AWS_PQ_ROWS, ids=[f["ssl_policy" if "ssl_policy" in f else "security_policy"]
                                                                for _t, f in AWS_PQ_ROWS])
def test_every_aws_pq_policy_is_graded_on_its_classical_fallback(asset_type, facts):
    from backend.utilities.cbom_sources.posture import pqc_class

    v = classify(asset_type, None, None, "TLS", facts, NOW)
    cls = pqc_class(asset_type, v["quantum_vulnerable"], v["finding_codes"], facts)
    fallback, why = qgrade.classical_fallback(asset_type, facts, v["finding_codes"])
    assert cls == "hybrid" and fallback is True and "also accepts classical key exchange" in why
    assert qgrade.graded_class(cls, fallback) == "quantum-vulnerable"


def test_a_classic_or_non_pq_aws_policy_gets_no_aws_fallback_reason():
    for facts in ({**LISTENER, "protocols": ["TLSv1.3"], "ssl_policy": ELB_PQ[0], "classic": True},
                  {**LISTENER, "protocols": ["TLSv1.3"], "ssl_policy": "ELBSecurityPolicy-TLS13-1-3-2021-06"}):
        _on, why = qgrade.classical_fallback("load_balancer_tls", facts, [])
        assert "AWS post-quantum policy" not in (why or "")


# ----------------------------------------------------------------------------- 2. SSH key exchange through algid
SSH_KEX_CLASSICAL = ["curve25519-sha256", "curve25519-sha256@libssh.org", "curve448-sha512", "gss-curve25519-sha256-toWM5Slw5Ew8Mqkay+al2g==", "gss-curve448-sha512-x",
                     "gss-nistp256-sha256-toWM5Slw5Ew8Mqkay+al2g==", "gss-group14-sha256-x", "gss-gex-sha1-x",
                     "ecdh-sha2-nistp256", "ecdh-sha2-1.3.132.0.10", "diffie-hellman-group14-sha256"]


@pytest.mark.parametrize("method", SSH_KEX_CLASSICAL)
def test_classify_judges_every_classical_ssh_kex_method_as_algid_does(method):
    assert algid.ssh_kex(method) is not None and algid.ssh_kex(method).quantum == "vulnerable"
    assert C.quantum_vulnerable(method) is True


@pytest.mark.parametrize("method", ["mlkem768x25519-sha256", "sntrup761x25519-sha512",
                                    "sntrup761x25519-sha512@openssh.com"])
def test_classify_judges_post_quantum_ssh_kex_methods_as_algid_does(method):
    assert C.quantum_vulnerable(method) is False


def test_every_ssh_kex_row_algid_knows_gets_the_same_verdict_from_classify():
    from backend.utilities.cbom_sources import algid_tables

    for pattern in algid_tables.SSH_KEX:
        method = pattern[:-1] + "x" if pattern.endswith("*") else pattern
        want = {"vulnerable": True, "safe": False, "hybrid": False}.get(algid.ssh_kex(method).quantum or "")
        assert C.quantum_vulnerable(method) is want, method


def test_names_that_are_no_ssh_kex_method_keep_their_verdict():
    assert C.quantum_vulnerable("ext-info-c") is None and C.quantum_vulnerable("kex-strict-s-v00@openssh.com") is None
    assert C.quantum_vulnerable("AES") is None and C.quantum_vulnerable("RSA") is True
    assert C.quantum_vulnerable(None) is None and C.quantum_vulnerable(7) is None


def test_qgrade_has_no_ssh_kex_table_of_its_own():
    """CB-19 kept a local SSH kex helper; the classifier's verdict is the one source now."""
    assert not hasattr(qgrade, "_classical_ssh_kex")
    on, why = qgrade.classical_fallback("ssh_endpoint", {"kex": ["mlkem768x25519-sha256", "gss-curve25519-sha256-x"]}, [])
    assert on and "gss-curve25519-sha256-x" in why
    on, why = qgrade.classical_fallback("ssh_endpoint", {"kex": ["mlkem768x25519-sha256", "ext-info-s"]}, [])
    assert not on and why is None


# ----------------------------------------------------------------------------- 3. malformed facts are unread, never a 500
def test_ssh_kexalgorithms_that_is_no_list_is_unread():
    for value in (7, 7.5, True, {"a": 1}):
        v = classify("ssh_server_config", None, None, None, {"kexalgorithms": value}, NOW)
        assert v["quantum_vulnerable"] is None and "SSH_NO_PQ_KEX" not in v["finding_codes"]
    # the comma-separated string form sshd -T prints is still read
    v = classify("ssh_server_config", None, None, None, {"kexalgorithms": "curve25519-sha256,ext-info-s"}, NOW)
    assert v["quantum_vulnerable"] is True and "SSH_NO_PQ_KEX" in v["finding_codes"]


@pytest.mark.parametrize("facts", [[1, 2], [{"kex": ["curve25519-sha256"]}], "text", 7, None])
def test_facts_that_are_no_object_are_unread(facts):
    for asset_type in sorted(C.ASSET_TYPES):
        assert classify(asset_type, None, None, None, facts, NOW) == classify(asset_type, None, None, None, {}, NOW)


# Every (asset type, fact) whose malformed value raised before this change, found by feeding each fact name a rule
# reads a value of every JSON shape (the sweep listed in the PR).
SWEEP = [
    ("os_crypto_policy", {"schannel_algorithms": {"k": 7}}),
    ("os_crypto_policy", {"schannel_algorithms": {"k": [7]}}),
    ("crypto_config", {"kind": "openssl_conf", "directives": {"minprotocol": 7, "cipherstring": [1]}}),
    ("crypto_config", {"kind": "openssl_conf", "directives": 7}),
    ("crypto_config", {"kind": "java_security", "directives": {"jdk.tls.disabledalgorithms": 7}}),
    ("crypto_config", {"kind": "nginx", "used_by": 7}),
    ("crypto_config", {"kind": "nginx", "used_by": [7, None]}),
    ("crypto_config", {"kind": "nginx", "protocols": 7}),
    ("crypto_config", {"kind": "openssl_cli", "md": 7}),
    ("tls_endpoint", {"protocols": 7}),
    ("load_balancer_tls", {"protocols": 7.5}),
    ("database_config", {"protocols": 7}),
    ("tls_endpoint", {"weak_ciphers": 7}),
    ("tls_endpoint", {"ciphers": 7}),
    ("ssh_endpoint", {"kex": 7}),
    ("ssh_endpoint", {"ciphers_c2s": 7, "macs_s2c": "hmac-md5"}),
    ("database_user_auth", {"iam_auth_roles": 7}),
    ("db_login_policy", {"logins": 7}),
    ("db_crypto_policy", {"sessions_nne_algorithms": 7}),
    ("k8s_mesh_server", {"unauthenticated_by": 7}),
    ("appliance_config", {"kind": "ike_policy", "encryption": 7, "integrity": 7, "prf": 7, "groups": 7}),
]


@pytest.mark.parametrize("asset_type, facts", SWEEP)
def test_a_malformed_fact_value_never_raises(asset_type, facts):
    v = classify(asset_type, None, None, None, facts, NOW)
    assert isinstance(v["finding_codes"], list)


def test_a_malformed_fact_value_is_unread_not_misread():
    """A protocol list that is a bare string is not read letter by letter (it used to give NO_TLS12)."""
    v = classify("tls_endpoint", None, None, None, {"protocols": "TLSv1.3"}, NOW)
    assert "NO_TLS12" not in v["finding_codes"]


# Each fact name a rule reads (classify.py and classify_ext/), fed every JSON shape: nothing raises.
SHAPES = [7, 7.5, True, "x", {"a": 1}, [7], [None], [{"a": 1}], ["x"], {"k": 7}, {"k": [7]}, -1, None]


def _rule_sources() -> list[str]:
    folder = Path(C.__file__).parent
    return [p.read_text() for p in [folder / "classify.py", *sorted((folder / "classify_ext").glob("*.py"))]]


def _fact_names() -> list[str]:
    import re

    names: set[str] = set()
    for src in _rule_sources():
        names |= set(re.findall(r'(?:facts|f)\.get\(\s*"([^"]+)"', src)) | set(re.findall(r'facts\[\s*"([^"]+)"', src))
    return sorted(names)


def _discriminators() -> list[dict]:
    """Facts a rule branches on (kind == "nginx", engine == "oracle", ...), so every branch is reached."""
    import re

    found: set[tuple[str, str]] = set()
    for src in _rule_sources():
        found |= set(re.findall(r'(?:facts\.get\(\s*)?"?(\w+)"?\)?\s*==\s*"([\w.-]+)"', src))
        for group in re.findall(r'\bkind in \(([^)]*)\)', src):
            found |= {("kind", k) for k in re.findall(r'"([\w-]+)"', group)}
    return [{}] + [{k: v} for k, v in sorted(found) if k in ("kind", "source", "engine", "store", "service", "scope")]


def test_no_fact_of_any_shape_makes_any_rule_raise():
    failures = []
    bases = _discriminators()
    assert {"kind": "ipsec_policy"} in bases and {"engine": "oracle"} in bases and {"source": "bitlocker"} in bases
    for asset_type in sorted(C.ASSET_TYPES | {"managed_key", "appliance_config"}):
        for name in _fact_names():
            for shape in SHAPES:
                for base in bases:
                    try:
                        classify(asset_type, "RSA", 2048, "TLS", {**base, name: shape}, NOW)
                    except Exception as exc:  # noqa: BLE001 - collect them all
                        failures.append(f"{asset_type} {name}={shape!r} {base}: {type(exc).__name__}: {exc}")
    assert failures == [], "\n".join(failures[:30])


def _store(api, engine, assets):  # noqa: F811  (the shared fixtures)
    src, run, claim, hdr = _collect_job(api, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": lease, "batch_id": "f1", "assets": assets})
    assert r.status_code == 200, r.text
    items = {a["location"]: a for a in api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]}
    return run, items


def test_api_an_ssh_config_with_a_scalar_kexalgorithms_is_stored_and_explained(api, world):  # noqa: F811  (the shared fixtures)
    """Was an HTTP 500 at ingest (classify raised on ``kexalgorithms: 7``)."""
    engine, _ = world
    run, items = _store(api, engine, [
        {"type": "ssh_server_config", "target": "10.20.0.1", "location": "/etc/ssh/sshd_config",
         "facts": {"kexalgorithms": 7, "ciphers": "aes128-cbc"}}])
    row = items["/etc/ssh/sshd_config"]
    detail = api("GET", f"/1/cbom/sources/assets/{row['id']}")
    assert detail.status_code == 200, detail.text
    codes = {d["code"] for d in detail.json()["asset"]["details"]}
    assert "SSH_CBC_CIPHER" in codes and "SSH_NO_PQ_KEX" not in codes  # the readable facts are still judged


@pytest.mark.parametrize("stored", ["[1, 2]", '[{"kex": ["curve25519-sha256"]}]', '"text"', "7"])
def test_api_an_asset_whose_stored_facts_are_no_object_is_shown_as_unread(api, world, stored):  # noqa: F811  (the shared fixtures)
    """A row written before facts were validated as an object (or by hand) used to make asset detail an HTTP 500."""
    engine, _ = world
    run, items = _store(api, engine, [
        {"type": "ssh_endpoint", "target": "10.20.0.1", "location": "10.20.0.1:22",
         "facts": {"kex": ["curve25519-sha256"]}},
        {"type": "tls_endpoint", "target": "10.20.0.2", "location": "10.20.0.2:443",
         "facts": {"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519"}},
    ])
    with engine.begin() as conn:
        conn.execute(text("UPDATE cbomcollectedasset SET facts = :f WHERE id IN (:a, :b)"),
                     {"f": stored, "a": items["10.20.0.1:22"]["id"], "b": items["10.20.0.2:443"]["id"]})
    for location in ("10.20.0.1:22", "10.20.0.2:443"):
        r = api("GET", f"/1/cbom/sources/assets/{items[location]['id']}")
        assert r.status_code == 200, r.text
        asset = r.json()["asset"]
        assert asset["facts"] == {}  # unread: nothing invented from a list or a scalar
    for path in (f"/1/cbom/sources/runs/{run['id']}/assets", f"/1/cbom/sources/runs/{run['id']}/posture"):
        r = api("GET", path)
        assert r.status_code == 200, (path, r.text)
    listed = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets").json()["items"]
    assert {a["location"] for a in listed} == {"10.20.0.1:22", "10.20.0.2:443"}
    assert all(a["facts"] == {} for a in listed)
