"""CB-08: what the CBOM Sources pages, templates and API say is what the code does.

Each test pins customer-facing text to the code that makes it true, so a sentence cannot outlive its behaviour:
* every key the backend puts in a job ``scope`` is read by the scan node (the Zeek option was sent and never read);
* every "what ZeroShield reads" line (database reads, the Linux command list, the Kubernetes tiers) has a reviewed
  piece of collector evidence, and a line without one fails ("pgcrypto use" was promised, only presence is read);
* certificate domains are stated as not read, because nothing reads them;
* identity providers are read from public metadata only, and the copy no longer asks for an API permission;
* an AWS Private CA connector is read by its AWS account source, not "not available".

The evidence tables below are written from the collectors' queries and API paths, reviewed by hand; they are the
contract. Changing a promise means changing its row here, which means showing the code that keeps it.
"""
from __future__ import annotations

import ast
import datetime as dt
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_NODE = _REPO / "scan_node" / "zs_scan_node"
_UI = _REPO / "frontend" / "components" / "cbom" / "sources"


# ----------------------------------------------------------------------------- scope keys -> node consumers
def _key_reads(tree: ast.AST):
    """(key, receiver) for every ``x.get("k", ...)`` and ``x["k"]`` read in a module."""
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get" and n.args
                and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)):
            yield n.args[0].value, n.func.value
        elif (isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Load) and isinstance(n.slice, ast.Constant)
              and isinstance(n.slice.value, str)):
            yield n.slice.value, n.value


def _node_reads() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(top-level scope key -> node files that read ``scope[key]``, node file -> every string key it reads)."""
    top: dict[str, set[str]] = {}
    per_file: dict[str, set[str]] = {}
    for path in sorted(_NODE.rglob("*.py")):
        rel = str(path.relative_to(_NODE))
        keys = per_file.setdefault(rel, set())
        for key, receiver in _key_reads(ast.parse(path.read_text(encoding="utf-8"))):
            keys.add(key)
            if isinstance(receiver, ast.Name) and receiver.id == "scope":
                top.setdefault(key, set()).add(rel)
    return top, per_file


def _scopes() -> list[tuple[str, dict]]:
    """The scope of every job kind the backend sends, for every source kind, with every network setting set."""
    from backend.new_models import CbomCollectionJob, CbomCollectionSettings, CbomCollectionSource
    from backend.utilities.cbom_sources import jobs as J
    from backend.utilities.cbom_sources.kinds import KIND_NAMES

    settings = CbomCollectionSettings(
        team_id=1, aws_external_id="ZS-CB08", zeek_span=True, ports=[{"port": 443, "protocol": "tls", "label": "web"}],
        sni_hostnames=["pay.example"], network_exclusions=[{"cidr": "10.20.0.9/32", "reason": "core"}], scan_window=[],
        rate_conn_per_s=7, rate_parallel_per_server=3, rate_handshakes_per_endpoint=5)
    now = dt.datetime(2026, 11, 12, 12, 0)
    config = {"linux_servers": {"targets": ["10.20.0.5"], "exclusions": ["10.20.0.6"]},
              "windows_servers": {"targets": ["10.20.0.7"]},
              "appliance": {"targets": ["10.20.0.8"]},
              "network_range": {"cidr": "10.20.0.0/28", "mode": "fragile"}}
    out = []
    for kind in KIND_NAMES:
        source = CbomCollectionSource(id=7, team_id=1, kind=kind, name=f"cb08-{kind}", config=config.get(kind, {}))
        for job_kind in ("collect", "test_connection"):
            job = CbomCollectionJob(id=1, team_id=1, source_id=7, kind=job_kind, params={"samples": ["10.20.0.5"]})
            out.append((f"{kind}/{job_kind}", J._scope_for(job, source, settings, now)))
    sweep = CbomCollectionJob(id=2, team_id=1, kind="discovery", params={
        "ranges": [{"source_id": 7, "cidr": "10.20.0.0/28", "mode": "full"}], "exclusions": ["10.20.0.9/32"]})
    out.append(("discovery", J._scope_for(sweep, None, settings, now)))
    return out


# Keys inside a scope value that are the server's own bookkeeping, not a customer setting (reviewed one by one).
_BOOKKEEPING = {("ranges", "source_id"): "the discovery job's range -> source link; the server keys sweep results by "
                                         "the job, not by this id"}


def test_every_scope_key_has_consumer():
    top, per_file = _node_reads()
    scopes = _scopes()
    assert any("ranges" in s for _, s in scopes) and any("targets" in s for _, s in scopes)  # the cases ran
    unread = []
    for name, scope in scopes:
        for key, value in scope.items():
            readers = top.get(key)
            if not readers:
                unread.append(f"{name}: scope[{key!r}] is sent to scan nodes but no node code reads it")
                continue
            items = value if isinstance(value, list) else [value]
            for item in items:
                if not isinstance(item, dict):
                    continue
                for sub in item:
                    if (key, sub) in _BOOKKEEPING:
                        continue
                    if not any(sub in per_file[f] for f in readers):
                        unread.append(f"{name}: scope[{key!r}][{sub!r}] is sent but {sorted(readers)} never read it")
    assert not unread, "\n".join(sorted(set(unread)))


def test_zeek_setting_is_described_as_ignored():
    """No Zeek reader exists: the setting stays accepted (old clients send it) but says it is ignored."""
    from backend.utilities.cbom_sources.schemas import SettingsUpdate

    text = (SettingsUpdate.model_fields["zeek_span"].description or "").lower()
    assert "ignored" in text and "zeek" in text


# ----------------------------------------------------------------------------- "what ZeroShield reads" -> collectors
# engine -> {DB_READS line: (collector file, tokens that must be in it, tokens that must NOT be in it)}
_DB = "collectors/database.py"
DB_EVIDENCE: dict[str, dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]]] = {
    "postgres": {
        "TLS on or off, minimum TLS version and ciphers":
            (_DB, ('"ssl"', '"ssl_min_protocol_version"', '"ssl_ciphers"', "FROM pg_settings"), ()),
        "Password hashing setting and the method of each HBA rule":
            (_DB, ('"password_encryption"', "FROM pg_hba_file_rules", '"hba_methods"'), ()),
        "Password hash type of each login role (md5 or SCRAM; never the hash itself)":
            (_DB, ("THEN 'md5'", "THEN 'scram-sha-256'", '"role_hash_types"'), ("SELECT rolpassword",)),
        "TLS used by live client connections":
            (_DB, ("FROM pg_stat_ssl s JOIN pg_stat_activity", '"live_connections"'), ()),
        # presence and version only: nothing reads functions, dependencies or statements that would show USE
        "Installed extensions and their versions (for example pgcrypto); not where they are used":
            (_DB, ("SELECT extname, extversion FROM pg_extension", '"extensions"'),
             ("pg_proc", "pg_depend", "prosrc", "pg_stat_statements")),
    },
    "mysql": {
        "require_secure_transport and TLS versions": (_DB, ('"require_secure_transport"', '"tls_version"'), ()),
        "Authentication plugin per user": (_DB, ("SELECT user, host, plugin, ssl_type FROM mysql.user", '"plugins"'), ()),
        "TLS used by live client connections": (_DB, ("performance_schema.status_by_thread", '"live_connections"'), ()),
        "Table encryption (InnoDB) and keyring":
            (_DB, ('"default_table_encryption"', "PLUGIN_NAME LIKE 'keyring%'", '"encrypted_tables"'), ()),
    },
    "mssql": {
        "Force encryption, TLS versions and the server certificate (read before logging in)":
            ("collectors/mssql.py", ("PRELOGIN", "force_encryption", "#chain["), ()),
        "Transparent Data Encryption per database (algorithm, key length, state)":
            ("collectors/mssql.py", ("dm_database_encryption_keys", "key_length", "tde_state"), ()),
        "Symmetric and asymmetric keys, certificates and Always Encrypted keys per database (metadata only)":
            ("collectors/mssql.py", ("sys.symmetric_keys", "sys.asymmetric_keys", "sys.certificates",
                                     "column_master_keys", "column_encryption_keys"), ()),
        "Encryption of live connections": ("collectors/mssql.py", ("dm_exec_connections", "live_connections"), ()),
        "Password policy and hash version of each SQL login (never the hash)":
            ("collectors/mssql.py", ("sql_logins", "policy_checked", "hash_version"), ()),
    },
    "oracle": {
        "TLS on the listener and native network encryption in use":
            ("collectors/oracle.py", ("v$session_connect_info", "network_service_banner"), ()),
        "TDE keystore state, encrypted tablespaces and columns (algorithms)":
            ("collectors/oracle.py", ("v$encryption_wallet", "v$encrypted_tablespaces", "dba_encrypted_columns"), ()),
        "Password verifier versions per user (10G, 11G, 12C; never the verifier)":
            ("collectors/oracle.py", ("password_versions", "FROM dba_users"), ("USER$", "spare4")),
    },
    "mongodb": {
        "TLS mode and allowed protocols": (_DB, ('("net", "tls", "mode")', '("net", "tls", "disabledProtocols")'), ()),
        "OpenSSL version and whether authorization is on": (_DB, ('build.get("openssl")', '"auth_required"'), ()),
        "Encryption at rest setting": (_DB, ('("security", "enableEncryption")',), ()),
    },
    "redis": {
        "TLS port, protocols and ciphers (named tls-* settings only; never passwords)":
            (_DB, ('"tls-port"', '"tls-protocols"', '"tls-ciphers"', "config_get(name)"), ('"requirepass"',)),
        "Whether AUTH is required": (_DB, ('"auth_required"',), ()),
        "Note: Redis ACLs cannot limit CONFIG GET to tls-* names, so this login could read any setting, including "
        "requirepass; the scan node never asks for those": (_DB, ("REDIS_TLS_SETTINGS",), ('"requirepass"',)),
    },
}


def test_reads_text_matches_collectors():
    from backend.utilities.cbom_sources import templates

    problems = []
    assert set(templates.DB_READS) == set(DB_EVIDENCE), "every engine on the Databases form has an evidence table"
    for engine, lines in templates.DB_READS.items():
        evidence = DB_EVIDENCE[engine]
        for line in lines:
            if line not in evidence:
                problems.append(f"{engine}: the form promises {line!r} but no collector evidence backs it")
                continue
            path, present, absent = evidence[line]
            source = (_NODE / path).read_text(encoding="utf-8")
            problems += [f"{engine}: {line!r} needs {tok!r} in {path}" for tok in present if tok not in source]
            problems += [f"{engine}: {line!r} is contradicted by {tok!r} in {path}" for tok in absent if tok in source]
        problems += [f"{engine}: evidence row {line!r} is not on the form" for line in evidence if line not in lines]
    assert not problems, "\n".join(problems)


def test_linux_command_list_is_what_the_collector_runs():
    """Every command on the Servers tab is a commands.py constant the Linux collector actually sends (and only those)."""
    import sys

    sys.path.insert(0, str(_REPO / "scan_node"))
    from zs_scan_node import commands as C

    tree = ast.parse((_NODE / "collectors" / "linux_ssh.py").read_text(encoding="utf-8"))
    used = {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "C"}
    strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    commands = {name: value for name, value in vars(C).items()
                if name.isupper() and isinstance(value, str) and name not in ("T1_ENV", "SUDO", "CRYPTO_LIBS_RE", "KEY_FILE_RE")}
    shown = {}
    for line in C.TIER1_DISPLAY:
        backing = [name for name, value in commands.items() if value.split("{file}")[0].strip() and
                   value.split("{file}")[0] in line]
        assert backing, f"the Servers tab shows {line!r}, which is no command the collector has"
        shown[line] = backing
    for line, names in shown.items():
        assert any(n in used for n in names), f"{line!r} is shown but linux_ssh.py never runs {names}"
    assert {n for n in commands if n in used} <= {n for names in shown.values() for n in names}, \
        "linux_ssh.py runs a command the Servers tab does not show"
    for check in C.TIER2:
        assert check in strings, f"Tier 2 check {check!r} is shown (and in the sudoers file) but never run"


# Kubernetes tiers: each claim on the form -> (tokens in kubernetes.py, ClusterRole resources it needs). The text is
# dev's CB36-BUG-04 wording; test_cbom_node_core_classify.py pins it to the exact ClusterRole grants, this test to the
# collector code.
K8S_EVIDENCE: dict[int, dict[str, tuple[tuple[str, ...], tuple[str, ...]]]] = {
    1: {
        "Cluster and node versions": (('"/version"', '"/api/v1/nodes"', '"kubelet"'), ('"nodes"',)),
        "API server TLS": (('"Kubernetes API server"', "#chain["), ()),
        "ingress TLS hosts and Secret names": (('"/apis/networking.k8s.io/v1/ingresses"', '"secretName"'), ('"ingresses"',)),
        "cert-manager Certificates": (('"/apis/cert-manager.io/v1/certificates"',), ('"certificates"',)),
        "certificates and private keys in ConfigMaps": (('"/api/v1/configmaps"', "embedded_private_keys("), ('"configmaps"',)),
        "Istio and Linkerd mTLS policy": (('peerauthentications', 'destinationrules', 'policy.linkerd.io'),
                                          ('"peerauthentications"', '"destinationrules"', '"servers"')),
    },
    2: {
        "Adds the certificates of TLS Secrets (kubernetes.io/tls); the API also returns their private keys, which are "
        "dropped unparsed and never stored or sent":
            (('"type=kubernetes.io/tls"', 'data.pop("tls.key", None)'), ('"secrets"',)),
    },
}


def _ui_k8s_tiers() -> dict[int, list[str]]:
    """The tier claims as the Clusters form shows them: Tier 1 is a comma list of reads; Tier 2 is one sentence."""
    tsx = (_UI / "ClustersDatabasesTab.tsx").read_text(encoding="utf-8")
    cards = re.findall(r'title: "Tier (\d) [^"]*",\s*description: "([^"]*)"', tsx)
    return {int(t): ([c.strip() for c in text.split(", ")] if t == "1" else [text]) for t, text in cards}


def test_k8s_reads_text_matches_collector():
    from backend.utilities.cbom_sources import templates

    collector = (_NODE / "collectors" / "kubernetes.py").read_text(encoding="utf-8")
    roles = {1: templates.K8S_TIER1, 2: templates.K8S_TIER2}
    tiers = _ui_k8s_tiers()
    assert set(tiers) == {1, 2}, tiers
    problems = []
    for tier, claims in tiers.items():
        for claim in claims:
            if claim not in K8S_EVIDENCE[tier]:
                problems.append(f"Tier {tier} promises {claim!r} but the collector and ClusterRole do not back it")
                continue
            code, resources = K8S_EVIDENCE[tier][claim]
            problems += [f"Tier {tier} {claim!r}: {t!r} missing from kubernetes.py" for t in code if t not in collector]
            problems += [f"Tier {tier} {claim!r}: ClusterRole lacks {r}" for r in resources if r not in roles[tier]]
    assert not problems, "\n".join(problems)
    assert '"pods"' not in templates.K8S_TIER2, "the ClusterRole reads no pods, so the form must not promise images"


# ----------------------------------------------------------------------------- certificate domains
def test_cert_domains_stated_unsupported():
    """Nothing reads the certificate domains saved in the settings (the Certificate Transparency collector reads its
    ct_logs source's own domains; creating that source moves the saved ones into it), so the form and Review & Run
    say they are not read."""
    allowed = {"new_models.py", "utilities/cbom_sources/schemas.py", "utilities/cbom_sources/serialize.py",
               "routers/cbom_sources.py"}  # stored, validated, returned, counted: never collected
    readers = []
    for root, base in ((_REPO / "backend", _REPO / "backend"), (_NODE, _NODE)):
        for path in root.rglob("*.py"):
            rel = str(path.relative_to(base))
            if "tests" in path.parts or ".venv" in path.parts or "alembic" in path.parts:
                continue
            if "cert_domains" in path.read_text(encoding="utf-8", errors="replace") and rel not in allowed:
                readers.append(rel)
    assert not readers, f"{readers} read cert_domains: update the Certificates copy, then this test"
    cloud = (_UI / "CloudIdentityTab.tsx").read_text(encoding="utf-8")
    hint = re.search(r'label="Domains to search in Certificate Transparency logs"\s+htmlFor="cert-domain-input"\s+'
                     r'error=\{error\}\s+hint="([^"]*)"', cloud)
    assert hint, "the certificate domains field has a hint"
    assert "not read" in hint.group(1) and "certificate collector" not in hint.group(1), hint.group(1)
    assert "does not query Certificate Transparency" not in hint.group(1), "CT discovery exists; say it is off here"
    review = (_UI / "ReviewRunTab.tsx").read_text(encoding="utf-8")
    assert '"certificate domain")} (not read yet)' in review, "Review & Run must not count domains as coverage"


# ----------------------------------------------------------------------------- identity providers
def test_idp_collector_reads_public_metadata_only():
    """idp_collect builds public metadata URLs and sends no credential, so the form asks for no API permission."""
    from backend.utilities.cbom_sources import idp_collect

    source = Path(idp_collect.__file__).read_text(encoding="utf-8")
    for credential in ("client_secret", "api_token", "client_id", "Authorization"):
        assert credential not in source, f"idp_collect uses {credential}: the IdP copy may promise API reads again"
    urls = idp_collect.discovery_urls({"provider": "entra_id", "tenant_id": "00000000-0000-0000-0000-000000000001",
                                       "client_id": "app"})
    assert [k for k, _ in urls] == ["oidc", "saml"] and all(u.startswith("https://login.microsoftonline.com/") for _, u in urls)
    cloud = (_UI / "CloudIdentityTab.tsx").read_text(encoding="utf-8")
    assert "Application.Read.All application permission (read-only)" not in cloud
    assert 'detail: "Application.Read.All, read-only"' not in cloud
    assert "read-only access to clients and keys" not in cloud and "A read-only API token from your Okta" not in cloud
    assert "read from the Windows servers you add on the Servers tab" not in cloud  # nothing ADFS-specific is read there


# ----------------------------------------------------------------------------- AWS Private CA
READ_BY_AWS = "Read by its AWS account source; nothing separate to collect"


def _plan_for(build):
    """plan_run on SQLite for the sources ``build(session)`` adds (team 1); returns {name: item} and the plan."""
    from sqlmodel import Session, SQLModel, create_engine

    from backend.new_models import CbomCollectionSettings, CbomCollectionSource
    from backend.utilities.cbom_sources.planning import plan_run

    engine = create_engine("sqlite://")
    SQLModel.metadata.create_all(engine)

    def source(session, kind, name, config, **extra):
        row = CbomCollectionSource(team_id=1, owner_user_id=1, kind=kind, name=name, name_lower=name, config=config, **extra)
        session.add(row)
        session.flush()
        return row

    with Session(engine) as session:
        settings = CbomCollectionSettings(team_id=1, aws_external_id="ZS-CB08")
        session.add(settings)
        build(session, source)
        session.commit()
        plan = plan_run(session, 1, settings, dt.datetime(2026, 11, 12, 12, 0))
    return {i.name: i for i in plan.items}, plan


ROLE = {"role_arn": "arn:aws:iam::123456789012:role/ZeroShieldCBOMReader"}


def test_aws_private_ca_connector_is_read_by_its_aws_account():
    """The AWS account source reads ACM Private CA (aws_collect), so a connector pointing at a validated account is
    covered by it: no "not available", no issue, no charge."""
    from backend.utilities.cbom_sources import aws_collect

    assert 'client("acm-pca", region)' in Path(aws_collect.__file__).read_text(encoding="utf-8")

    def build(session, source):
        aws = source(session, "aws_account", "prod", ROLE, last_test_status="passed")
        source(session, "ca_connector", "pca", {"provider": "aws_private_ca", "aws_source_id": aws.id})
        source(session, "ca_connector", "venafi", {"provider": "venafi", "api_url": "https://venafi.example"})

    items, plan = _plan_for(build)
    assert items["prod"].status == "queued"
    assert items["pca"].reason == READ_BY_AWS and items["pca"].status == "covered" and items["pca"].credits_c == 0
    public = plan.public()
    assert "pca" not in [i["name"] for i in public["skipped"]], "a covered connector is not an issue to fix"
    assert public["groups"]["identity"]["skipped"] == 1  # Venafi only
    assert items["venafi"].reason == "Collection for this connector is not available yet" and items["venafi"].credits_c == 0


def test_aws_private_ca_connector_whose_account_is_skipped_or_removed():
    def build(session, source):
        aws = source(session, "aws_account", "prod", ROLE)  # never validated: skipped in this plan
        source(session, "ca_connector", "pca", {"provider": "aws_private_ca", "aws_source_id": aws.id})
        source(session, "ca_connector", "orphan", {"provider": "aws_private_ca", "aws_source_id": 9999})

    items, plan = _plan_for(build)
    assert items["prod"].status == "skipped"
    assert items["pca"].status == "skipped" and items["pca"].reason == (
        "Not read in this run: AWS account prod is skipped (Validate the AWS role first; only a role that passed "
        "validation is scanned)")
    assert items["orphan"].status == "skipped" and items["orphan"].reason == "Not read: its AWS account was removed"
    assert {"pca", "orphan"} <= {i["name"] for i in plan.public()["skipped"]}
