"""WP5 classifier and template fixes: PostgreSQL role hash types, Istio mesh mode (field name and UNSET), coverage
rows that name their fix, and the Kubernetes ClusterRole granting exactly what the collector reads."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import templates  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402


def _c(asset_type, facts):
    return classify(asset_type, None, None, None, facts)


# ----------------------------------------------------------------------------- PostgreSQL role hash types
def test_role_hash_types_md5_plaintext_and_no_password():
    out = _c("database_user_auth", {"engine": "postgres", "hba_methods": {"scram-sha-256": 3},
                                    "role_hash_types": {"app": "md5", "legacy": "other", "nologin_pw": "none",
                                                        "svc": "scram-sha-256", "iam_user": "md5"},
                                    "iam_auth_roles": ["iam_user"], "role_hash_source": "zs_role_password_types"})
    assert set(out["finding_codes"]) == {"DB_PLAINTEXT_PW", "DB_WEAK_HASH"}
    assert out["impact"] == "High"
    assert "legacy" in out["texts"]["DB_PLAINTEXT_PW"] and "app" not in out["texts"]["DB_PLAINTEXT_PW"]
    weak = out["texts"]["DB_WEAK_HASH"]
    assert "2 login role(s) have MD5 password hashes: app, iam_user (rds_iam)" in weak
    assert "nologin_pw" not in out["finding"] and "svc" not in out["finding"]  # no password / SCRAM: nothing to say


def test_md5_hba_rules_and_md5_roles_share_one_finding():
    out = _c("database_user_auth", {"hba_methods": {"md5": 2}, "role_hash_types": {"app": "md5"}})
    assert out["finding_codes"] == ["DB_WEAK_HASH"]
    assert out["texts"]["DB_WEAK_HASH"] == "2 HBA rule(s) use md5 authentication; 1 login role(s) have MD5 password hashes: app"


def test_scram_only_roles_and_unread_types_are_clean():
    assert _c("database_user_auth", {"role_hash_types": {"a": "scram-sha-256", "b": "none"}})["finding_codes"] == []
    assert _c("database_user_auth", {"role_hash_types": None})["finding_codes"] == []  # gap row says why


def test_md5_hba_rules_are_not_weak_when_every_role_hash_is_scram():
    """Review round 5, L1: PostgreSQL authenticates an md5 HBA rule with SCRAM when the role's password is stored as
    SCRAM, so md5 rules on a server with password_encryption = scram-sha-256 and only SCRAM role hashes are clean."""
    scram = {"app": "scram-sha-256", "svc": "scram-sha-256", "nologin_pw": "none"}
    clean = _c("database_user_auth", {"engine": "postgres", "password_encryption": "scram-sha-256",
                                      "hba_methods": {"md5": 3, "scram-sha-256": 1}, "role_hash_types": scram})
    assert clean["finding_codes"] == []
    # still weak: an MD5 role (the md5 rule really negotiates MD5 for it), password_encryption md5 (the next password
    # change stores MD5), or role hashes that were not read (nothing proves the rule harmless)
    md5_role = _c("database_user_auth", {"password_encryption": "scram-sha-256", "hba_methods": {"md5": 3},
                                         "role_hash_types": {**scram, "old": "md5"}})
    assert "3 HBA rule(s) use md5 authentication" in md5_role["texts"]["DB_WEAK_HASH"]
    md5_default = _c("database_user_auth", {"password_encryption": "md5", "hba_methods": {"md5": 3},
                                            "role_hash_types": scram})
    assert {"DB_WEAK_HASH", "DB_MD5_DEFAULT"} <= set(md5_default["finding_codes"])
    for unread in (None, {}):
        out = _c("database_user_auth", {"password_encryption": "scram-sha-256", "hba_methods": {"md5": 3},
                                        "role_hash_types": unread})
        assert out["finding_codes"] == ["DB_WEAK_HASH"], unread


def test_eddsa_without_a_curve_is_not_dsa():
    """Review round 5, L4: a JWK of kty OKP without crv is labelled EdDSA (idp_collect); 'EDDSA' contains 'DSA' and was
    classified as the deprecated DSA family (High)."""
    from backend.utilities.cbom_sources.classify import family, quantum_vulnerable

    assert family("EdDSA") == "EDDSA" and quantum_vulnerable("EdDSA") is True
    assert family("DSA") == "DSA" and family("SHA256withDSA") == "DSA" and family("ECDSA") == "ECDSA"
    assert family("Ed25519") == "ED25519" and family("ML-DSA-65") == "PQ"
    out = classify("signing_key", "EdDSA", None, None, {"kty": "OKP", "alg": "EdDSA"})
    assert out["finding_codes"] == ["QUANTUM_VULNERABLE"] and out["impact"] is None


def test_coverage_row_keeps_the_whole_fix():
    fix = ("password hash types of login roles are readable only by a superuser; fix: as a superuser in database "
           '"postgres", run the public.zs_role_password_types() section of zs-cbom-grant-postgres.sql (Privilege tab): '
           "a SECURITY DEFINER function that returns role names and hash types only")
    assert len(fix) > 200
    out = _c("coverage", {"check": "postgres role password hash types", "status": "denied", "detail": fix})
    assert out["finding_codes"] == ["COVERAGE_DENIED"] and out["finding"] == f"Not collected: {fix}"


# ----------------------------------------------------------------------------- Istio PeerAuthentication
def test_mesh_mode_is_read_from_the_collector_field_and_the_old_one():
    assert _c("k8s_mesh_policy", {"mtls_mode": "DISABLE"})["finding_codes"] == ["MESH_MTLS_OFF"]
    assert _c("k8s_mesh_policy", {"mtls_mode": "PERMISSIVE"})["finding_codes"] == ["MESH_MTLS_PERMISSIVE"]
    assert _c("k8s_mesh_policy", {"mode": "permissive"})["finding_codes"] == ["MESH_MTLS_PERMISSIVE"]
    assert _c("k8s_mesh_policy", {"mtls_mode": "STRICT"})["finding_codes"] == []


def test_unset_inherits_except_on_the_mesh_wide_policy():
    assert _c("k8s_mesh_policy", {"mtls_mode": "UNSET", "scope": "namespace"})["finding_codes"] == []
    assert _c("k8s_mesh_policy", {"mtls_mode": "UNSET", "scope": "workload"})["finding_codes"] == []
    assert _c("k8s_mesh_policy", {"mtls_mode": "UNSET"})["finding_codes"] == []  # rows from before the scope fact
    mesh = _c("k8s_mesh_policy", {"mtls_mode": "UNSET", "scope": "mesh"})
    assert mesh["finding_codes"] == ["MESH_MTLS_PERMISSIVE"] and "Istio applies PERMISSIVE" in mesh["finding"]


def test_port_level_modes():
    out = _c("k8s_mesh_policy", {"mtls_mode": "STRICT", "scope": "workload", "port_modes": {"8080": "DISABLE", "9090": "PERMISSIVE"}})
    assert set(out["finding_codes"]) == {"MESH_MTLS_OFF", "MESH_MTLS_PERMISSIVE"}
    assert "8080" in out["texts"]["MESH_MTLS_OFF"] and "9090" in out["texts"]["MESH_MTLS_PERMISSIVE"]


# ----------------------------------------------------------------------------- templates
def _grants(text: str) -> set[tuple[str, str]]:
    role = next(d for d in yaml.safe_load_all(text) if d["kind"] == "ClusterRole")
    out = set()
    for rule in role["rules"]:
        assert set(rule["verbs"]) == {"get", "list"}  # read-only
        for group in rule["apiGroups"]:
            for resource in rule["resources"]:
                out.add((group, resource))
    return out


def _collector_reads() -> set[tuple[str, str]]:
    src = (ROOT / "scan_node/zs_scan_node/collectors/kubernetes.py").read_text()
    reads = {("", m) for m in re.findall(r'"/api/v1/([a-z]+)"', src)}
    reads |= {(g, r) for g, r in re.findall(r'"/apis/([a-z0-9.\-]+)/v[0-9a-z]+/([a-z]+)"', src)}
    return {r for r in reads if r != ("authorization.k8s.io", "selfsubjectaccessreviews")}  # allowed to everyone


def test_cluster_roles_grant_exactly_what_the_collector_reads():
    reads = _collector_reads()
    tier1, tier2 = _grants(templates.K8S_TIER1), _grants(templates.K8S_TIER2)
    # DestinationRules live in networking.istio.io (not security.istio.io); the mesh collector reads them (C16)
    planned = {("networking.istio.io", "destinationrules")}
    assert tier1 == (reads - {("", "secrets")}) | planned
    assert tier2 == tier1 | {("", "secrets")}
    assert ("security.istio.io", "destinationrules") not in tier1
    for gone in ("pods", "services", "serviceaccounts", "ingressclasses", "issuers", "deployments"):
        assert not any(r == gone for _g, r in tier1)



# CB36-BUG-04: the cluster form's tier text said Tier 1 reads "issuers" and "images in use"; the ClusterRole grants
# neither (no pods, no cert-manager Issuers) and the collector reads neither. Each phrase of the text names the
# resources it needs; together (plus namespaces, used by the connection test) they are exactly the tier's grants.
TIER_TEXT = {
    1: ("Cluster and node versions, API server TLS, ingress TLS, cert-manager Certificates, certificates and private "
        "keys in ConfigMaps, Istio and Linkerd mTLS policy"),
    2: "Adds the certificates of TLS Secrets (kubernetes.io/tls); their private keys are never read",
}
TIER1_CLAIMS = {
    "Cluster and node versions": {("", "nodes")},  # plus /version, open to every authenticated client
    "API server TLS": set(),  # a TLS handshake with the API server, no RBAC resource
    "ingress TLS": {("networking.k8s.io", "ingresses")},
    "cert-manager Certificates": {("cert-manager.io", "certificates")},
    "certificates and private keys in ConfigMaps": {("", "configmaps")},
    "Istio and Linkerd mTLS policy": {("security.istio.io", "peerauthentications"),
                                      ("networking.istio.io", "destinationrules"),
                                      *{("policy.linkerd.io", r) for r in ("servers", "serverauthorizations",
                                                                          "authorizationpolicies",
                                                                          "meshtlsauthentications",
                                                                          "networkauthentications")}},
}


def test_k8s_tier_text_says_exactly_what_the_cluster_role_grants():
    tsx = (ROOT / "frontend/components/cbom/sources/ClustersDatabasesTab.tsx").read_text()
    for tier, text in TIER_TEXT.items():
        assert f'description: "{text}"' in tsx, f"Tier {tier} text changed: update TIER_TEXT and its claims"
    assert TIER_TEXT[1] == ", ".join(TIER1_CLAIMS)
    claimed = set().union(*TIER1_CLAIMS.values())
    assert claimed | {("", "namespaces")} == _grants(templates.K8S_TIER1)
    assert _grants(templates.K8S_TIER2) - _grants(templates.K8S_TIER1) == {("", "secrets")}
    tier_block = tsx[tsx.index('name="k8s-tier"'):tsx.index('data-testid="k8s-tier2-warning"')]
    shown = " ".join(re.findall(r'(?:title|description): "([^"]*)"', tier_block)).lower()
    assert "tier 1" in shown and "tier 2" in shown
    for word in ("image", "issuer", "pod"):
        assert word not in shown, f"the tier choice claims {word}s, which no tier reads"

def test_postgres_grant_installs_a_locked_down_hash_type_function():
    sql = templates.template_text("grant-postgres")
    assert "SECURITY DEFINER" in sql and "SET search_path = pg_catalog, pg_temp" in sql
    assert "REVOKE EXECUTE ON FUNCTION public.zs_role_password_types() FROM PUBLIC;" in sql
    assert "GRANT EXECUTE ON FUNCTION public.zs_role_password_types() TO zs_cbom;" in sql
    assert "RETURNS TABLE (rolname name, password_type text)" in sql
    body = sql.split("AS $$", 1)[1].split("$$;", 1)[0]
    assert "rolpassword" in body and not re.search(r"SELECT[^;]*\brolpassword\b\s*(,|FROM)", body)  # types only
    assert "rds_tools" in sql
    # on RDS the extension alone is not enough: its function is executable only by rds_superuser (AWS lab, round 5)
    assert "GRANT EXECUTE ON FUNCTION rds_tools.role_password_encryption_type() TO zs_cbom;" in sql
