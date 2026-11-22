"""The Chola production deploy kit (deploy/chola-prod/, scripts/deploy/chola-prod.sh; README there).

Covers, among others, the PR #475 review findings:
* secrets: CSPRNG on first run, every existing value kept on re-runs, --data-exists never generates a key existing data
  depends on (database/queue passwords, ENCRYPTION_KEY, CERTIN_HMAC_SECRET) and refuses empty ones;
* mail: origin/ansh is read only on first setup or with --refresh-mail, with an explicit refspec, distinguishing a
  missing branch from missing keys; --mail-prompt; a normal deploy never touches origin/ansh;
* fail-closed volume check (yes/no or die), retried polls, ip target groups, IMDS failing preflight, PassRole check,
  the throwaway Docker config, detached jobs with STARTED records, rollback from an interrupted deploy;
* least-privilege env files per container, no password on any command line, sudo-safe Compose environment;
* nginx: real-IP sources (no /0 in any spelling, no prefix shorter than /8), the client once in X-Forwarded-For,
  hidden X-Powered-By, the 512 MB route, no includeSubDomains;
* --dry-run is read-only (no AWS/SSH/Docker/registry/git-fetch, no mailbox read), --help and flag order.

Run: cd backend && python -m pytest tests/test_chola_prod_kit.py -q -p no:cacheprovider
"""
import base64
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
KIT_DIR = REPO / "deploy" / "chola-prod"
COMPOSE = KIT_DIR / "docker-compose.yml"
OWNER = REPO / "scripts" / "deploy" / "chola-prod.sh"
REMOTE = KIT_DIR / "remote.sh"
TEMPLATE = KIT_DIR / "nginx" / "site.conf.template"
SITE_SH = KIT_DIR / "nginx" / "40-chola-site.sh"
README = KIT_DIR / "README.md"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kit = _load("chola_kit", KIT_DIR / "kit.py")

ANSH_ENV = (
    'JWT_SECRET_KEY=whatever\n'
    'OUTLOOK_EMAIL="support@example.com" #not in use \n'
    'OUTLOOK_PASSWORD="p@ss#word 1" #not in use \n'
    'TENANT_ID =abc\n'
)


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)


# ------------------------------------------------------------------------------------------------ dotenv
def test_parse_dotenv_reads_the_ansh_format():
    env = kit.parse_dotenv(ANSH_ENV)
    assert env["OUTLOOK_EMAIL"] == "support@example.com"
    assert env["OUTLOOK_PASSWORD"] == "p@ss#word 1"  # '#' inside quotes is part of the value; the comment is not
    assert env["TENANT_ID"] == "abc"


def test_parse_dotenv_unquoted_comment_export_and_single_quotes():
    env = kit.parse_dotenv("export A=1 # c\nB='x # y'\nC = two words\n# D=no\n")
    assert env == {"A": "1", "B": "x # y", "C": "two words"}


# ------------------------------------------------------------------------------------------------ merge
def test_first_run_generates_every_secret_and_sets_mail():
    merged, report, changed = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    assert changed
    for key in kit.GENERATED:
        assert kit.problem(key, merged[key]) is None, key
    assert len(merged["JWT_SECRET_KEY"]) == 64 and merged["JWT_SECRET_KEY"] != merged["JWT_REFRESH_SECRET_KEY"]
    assert len(base64.urlsafe_b64decode(merged["ENCRYPTION_KEY"])) == 32
    for key in ("PG_USER_PASS", "MONGO_INITDB_ROOT_PASSWORD", "RABBIT_ADMIN_PASSWORD"):
        assert re.fullmatch(r"[0-9a-f]{48}", merged[key])  # URL-safe: put into amqp:// and mongodb:// URLs unescaped
    assert merged["SMTP_USERNAME"] == merged["MAIL_FROM"] == "support@example.com"
    assert merged["SMTP_PASSWORD"] == "p@ss#word 1"
    assert "JWT_SECRET_KEY: generated" in report and "SMTP_PASSWORD: set from OUTLOOK_PASSWORD" in report


def test_two_runs_generate_different_values():
    a, _, _ = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    b, _, _ = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    assert all(a[k] != b[k] for k in kit.GENERATED)


def test_rerun_preserves_every_existing_value_and_needs_no_mail_source():
    first, _, _ = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    first["SOMETHING_ELSE"] = "kept-as-is"
    again, report, changed = kit.merge_app_secrets(dict(first), {})  # no origin/ansh at all
    assert again == first and not changed
    assert "SOMETHING_ELSE: kept (not managed by the kit)" in report and "SMTP_PASSWORD: kept" in report


def test_partial_secret_keeps_existing_and_fills_only_missing():
    existing = {"PG_USER_PASS": "a" * 48, "JWT_SECRET_KEY": "b" * 64}
    merged, report, changed = kit.merge_app_secrets(dict(existing), kit.parse_dotenv(ANSH_ENV))
    assert changed and merged["PG_USER_PASS"] == "a" * 48 and merged["JWT_SECRET_KEY"] == "b" * 64
    assert "PG_USER_PASS: kept" in report and "MONGO_INITDB_ROOT_PASSWORD: generated" in report


def test_mail_is_kept_unless_refresh_is_asked():
    first, _, _ = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    new_src = kit.parse_dotenv('OUTLOOK_EMAIL="new@example.com"\nOUTLOOK_PASSWORD="n3w-password"\n')
    kept, _, changed = kit.merge_app_secrets(dict(first), new_src)
    assert not changed and kept["SMTP_USERNAME"] == "support@example.com"
    refreshed, report, changed = kit.merge_app_secrets(dict(first), new_src, refresh_mail=True)
    assert changed and refreshed["SMTP_USERNAME"] == refreshed["MAIL_FROM"] == "new@example.com"
    assert refreshed["JWT_SECRET_KEY"] == first["JWT_SECRET_KEY"]  # refresh touches mail only
    assert "SMTP_PASSWORD: updated from OUTLOOK_PASSWORD" in report


@pytest.mark.parametrize("bad", [
    {"PG_USER_PASS": "has spaces and :@/"},       # would break the connection URLs
    {"JWT_SECRET_KEY": "short"},                   # the backend refuses < 32 bytes
    {"ENCRYPTION_KEY": "not-a-fernet-key"},
    {"JWT_SECRET_KEY": "x" * 40, "JWT_REFRESH_SECRET_KEY": "x" * 40},  # equal: refused by the backend
])
def test_unusable_stored_values_are_refused_never_replaced(bad):
    with pytest.raises(kit.Refused):
        kit.merge_app_secrets(dict(bad), kit.parse_dotenv(ANSH_ENV))


def test_missing_mail_source_is_refused():
    with pytest.raises(kit.Refused, match="OUTLOOK_EMAIL"):
        kit.merge_app_secrets({}, {})


# QA F1: with data on the instance nothing that data depends on is ever generated, and empty values do not count.
@pytest.mark.parametrize("existing, missing", [
    ({}, set(kit.DATA_KEYS)),
    ({"PG_USER_PASS": ""}, set(kit.DATA_KEYS)),
    ({"PG_USER_PASS": "a" * 48}, set(kit.DATA_KEYS) - {"PG_USER_PASS"}),
])
def test_data_exists_refuses_to_generate_data_keys(existing, missing):
    with pytest.raises(kit.Refused) as err:
        kit.merge_app_secrets(dict(existing), kit.parse_dotenv(ANSH_ENV), data_exists=True)
    for key in missing:
        assert key in str(err.value)
    assert set(kit.DATA_KEYS) >= {"PG_USER_PASS", "MONGO_INITDB_ROOT_PASSWORD", "RABBIT_ADMIN_PASSWORD",
                                  "ENCRYPTION_KEY", "CERTIN_HMAC_SECRET"}


def test_data_exists_still_fills_keys_no_data_depends_on():
    existing = {k: v for k, v in kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))[0].items()
                if k in kit.DATA_KEYS}
    merged, report, changed = kit.merge_app_secrets(dict(existing), kit.parse_dotenv(ANSH_ENV), data_exists=True)
    assert changed and "JWT_SECRET_KEY: generated" in report and "QDRANT_API_KEY: generated" in report
    assert all(merged[k] == existing[k] for k in kit.DATA_KEYS)


def _merge_cli(tmp_path, existing_text, *extra):
    cur = tmp_path / "cur.json"
    cur.write_text(existing_text)
    out = tmp_path / "out.json"
    return run(["python3", "-I", str(KIT_DIR / "kit.py"), "merge-app-secrets", "--existing", str(cur),
                "--out", str(out), *extra]), out


def test_merge_cli_writes_mode_600_and_prints_no_value(tmp_path):
    mail = tmp_path / "mail.env"
    mail.write_text(ANSH_ENV)
    proc, out = _merge_cli(tmp_path, "", "--mail-env", str(mail))  # an empty secret (no value yet)
    assert proc.returncode == 0, proc.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    merged = json.loads(out.read_text())
    for value in merged.values():
        assert value not in proc.stdout and value not in proc.stderr
    again, out2 = _merge_cli(tmp_path, out.read_text())  # re-run, no mail source given
    assert again.returncode == 3 and json.loads(out2.read_text()) == merged
    refused, _ = _merge_cli(tmp_path, "{}", "--mail-env", str(mail), "--data-exists")
    assert refused.returncode == 1 and "lock the application out" in refused.stderr


def test_merge_cli_mail_lines_from_the_prompt(tmp_path):
    lines = tmp_path / "mail.lines"
    lines.write_text("typed@example.com\nTyped-Pass word#1\n")
    proc, out = _merge_cli(tmp_path, "{}", "--mail-lines", str(lines), "--refresh-mail")
    assert proc.returncode == 0, proc.stderr
    merged = json.loads(out.read_text())
    assert merged["SMTP_USERNAME"] == "typed@example.com" and merged["SMTP_PASSWORD"] == "Typed-Pass word#1"
    assert "Typed-Pass" not in proc.stdout + proc.stderr
    lines.write_text("only-an-address@example.com\n")
    proc, _ = _merge_cli(tmp_path, "{}", "--mail-lines", str(lines))
    assert proc.returncode == 1 and "no password" in proc.stderr


def test_mail_state_names_only():
    full = json.dumps({"SMTP_USERNAME": "a@b.c", "SMTP_PASSWORD": "SECRETVALUE", "MAIL_FROM": "a@b.c"})
    for text, want in ((full, "present"), ("{}", "missing"), ("", "missing"),
                       (json.dumps({"SMTP_USERNAME": "a@b.c", "SMTP_PASSWORD": "", "MAIL_FROM": "a@b.c"}), "missing")):
        proc = run(["python3", "-I", str(KIT_DIR / "kit.py"), "mail-state"], input=text)
        assert proc.returncode == 0 and proc.stdout.strip() == want and "SECRETVALUE" not in proc.stdout


def test_json_field_aliases_and_names_only_error():
    assert kit.json_field({"AccessKeyId": "AKIA1"}, kit.ACCESS_KEY_NAMES) == "AKIA1"
    assert kit.json_field({"aws_secret_access_key": "s"}, kit.SECRET_KEY_NAMES) == "s"
    proc = run(["python3", "-I", str(KIT_DIR / "kit.py"), "json-field", "private_key_pem"],
               input=json.dumps({"other": "TOPSECRET"}))
    assert proc.returncode == 1 and "other" in proc.stderr and "TOPSECRET" not in proc.stderr + proc.stdout


# ------------------------------------------------------------------------------------------------ render
CFG = {"image_prefix": "935951870001.dkr.ecr.ap-south-1.amazonaws.com/devsec-chola", "frontend_host": "chola.zeroshield.ai",
       "api_host": "chola-api.zeroshield.ai", "real_ip_from": "10.60.1.0/24,10.60.2.0/24", "region": "ap-south-1",
       "llm_model": "openai.gpt-oss-120b-1:0", "smtp_host": "smtp.office365.com", "smtp_port": "587"}
APP_USER = {"access_key_id": "AKIAAPP", "secret_access_key": "appsecret"}


def _app():
    merged, _, _ = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    return merged


def _render(app=None, app_user=None, collector=None, tag="b669fa3c467f"):
    files, warnings = kit.render_env(app or _app(), APP_USER if app_user is None else app_user, collector or {}, CFG, tag)
    return {k: kit.parse_dotenv(v) for k, v in files.items()}, files, warnings


def test_render_env_files():
    env, files, warnings = _render(collector={"AWS_ACCESS_KEY_ID": "AKIACOL", "AWS_SECRET_ACCESS_KEY": "colsecret",
                                              "principal_arn": "arn:aws:iam::935951870001:user/collector"})
    i, b = env[".env"], env["backend.env"]
    assert not warnings
    assert i["DSS_TAG"] == "b669fa3c467f" and i["DSS_IMAGE_PREFIX"].endswith("/devsec-chola")
    assert i["DSS_REAL_IP_FROM"] == "10.60.1.0/24,10.60.2.0/24"
    assert "DSS_HTTP_PORT" not in i  # production publishes 80, the ALB's target port
    assert b["AWS_ACCESS_KEY_ID"] == "AKIAAPP" and b["AWS_DEFAULT_REGION"] == "ap-south-1"
    assert "AWS_ENDPOINT_URL_S3" not in b  # real S3, never an empty endpoint
    assert b["DSS_SBOM_REGISTRY"] == "0"
    assert b["CORS_ORIGINS"] == b["CBOM_PUBLIC_APP_URL"] == "https://chola.zeroshield.ai"
    assert (b["SMTP_HOST"], b["SMTP_PORT"], b["SMTP_SECURITY"]) == ("smtp.office365.com", "587", "starttls")
    assert b["SMTP_PASSWORD"] == "p@ss#word 1" and b["MAIL_FROM"] == "support@example.com"
    assert b["CBOM_AWS_ACCESS_KEY_ID"] == "AKIACOL" and b["CBOM_AWS_PRINCIPAL_ARN"].endswith(":user/collector")
    assert (b["CBOM_AI_PROVIDER"], b["CBOM_AI_AWS_CREDENTIALS"], b["CBOM_AI_MODEL"]) == \
        ("bedrock", "env", "openai.gpt-oss-120b-1:0")
    assert env["scan-worker.env"]["LLM_MODEL"] == "openai.gpt-oss-120b-1:0"
    for text in files.values():
        assert not re.search(r"^(DSS_DEV_MODE|LOCAL_DEV_VERIFICATION_)", text, re.MULTILINE)
        assert not re.search(r"^(TENANT_ID|CLIENT_ID|CLIENT_SECRET)=", text, re.MULTILINE)  # Graph is unreachable
        assert all(re.fullmatch(r"[A-Z0-9_]+='[^'\n]*'", line) for line in text.splitlines())


# Review item 5: each container gets only what its code reads.
def test_render_least_privilege_per_reader():
    env, _, _ = _render()
    interp, backend, scan, dast = env[".env"], env["backend.env"], env["scan-worker.env"], env["dast-worker.env"]
    api_only = {"JWT_SECRET_KEY", "JWT_REFRESH_SECRET_KEY", "ENCRYPTION_KEY", "CERTIN_HMAC_SECRET", "SMTP_PASSWORD",
                "SMTP_USERNAME", "PG_USER_PASS", "CORS_ORIGINS"}
    assert not api_only & set(scan) and not api_only & set(dast)
    assert {"QDRANT_API_KEY", "LLM_MODEL"} <= set(scan) and not {"QDRANT_API_KEY", "LLM_MODEL"} & set(dast)
    assert "QDRANT_API_KEY" not in backend and backend["BACKEND_WORKERS"] == "4"
    for name in ("RABBIT_ADMIN_PASSWORD", "MONGO_INITDB_ROOT_PASSWORD", "AWS_SECRET_ACCESS_KEY"):
        assert name in scan and name in dast and name in backend
    # the interpolation file feeds no application container and holds no application secret
    assert not {"AWS_SECRET_ACCESS_KEY", "JWT_SECRET_KEY", "SMTP_PASSWORD", "ENCRYPTION_KEY"} & set(interp)


def test_render_refuses_a_quote_and_requires_app_user_and_tag():
    app = _app()
    app["SMTP_PASSWORD"] = "it's"
    with pytest.raises(kit.Refused):
        kit.render_env(app, APP_USER, {}, CFG, "b669fa3c467f")
    with pytest.raises(kit.Refused, match="app-user"):
        kit.render_env(_app(), {}, {}, CFG, "b669fa3c467f")
    with pytest.raises(kit.Refused, match="12-character"):
        kit.render_env(_app(), APP_USER, {}, CFG, "latest")
    with pytest.raises(kit.Refused, match="app-secrets lacks"):
        kit.render_env({}, APP_USER, {}, CFG, "b669fa3c467f")


def test_render_without_collector_keys_warns_and_omits_cbom_aws():
    env, _, warnings = _render()
    assert "CBOM_AWS_ACCESS_KEY_ID" not in env["backend.env"] and any("cbom-collector" in w for w in warnings)


def test_render_env_cli_with_a_fake_aws(tmp_path):
    """render-env end to end: secrets come from `aws secretsmanager get-secret-value` (here a fake on PATH); the four
    files are mode 600; DSS_TAG of an existing .env is kept."""
    secrets_by_id = {
        "devsec-chola/prod/app-secrets": json.dumps(_app()),
        "devsec-chola/prod/app-user": json.dumps({"AccessKeyId": "AKIAAPP", "SecretAccessKey": "s3cr3t"}),
        "devsec-chola/prod/cbom-collector": "",
    }
    (tmp_path / "secrets.json").write_text(json.dumps(secrets_by_id))
    fake = tmp_path / "bin" / "aws"
    fake.parent.mkdir()
    fake.write_text("#!/usr/bin/env python3\nimport json,sys\nargs=sys.argv[1:]\n"
                    f"data=json.load(open({str(tmp_path / 'secrets.json')!r}))\n"
                    "sid=args[args.index('--secret-id')+1]\nprint(data[sid] or 'None')\n")
    fake.chmod(0o755)
    out = tmp_path / "kit"
    out.mkdir()
    env = dict(os.environ, PATH=f"{fake.parent}:{os.environ['PATH']}")
    cmd = ["python3", "-I", str(KIT_DIR / "kit.py"), "render-env", "--dir", str(out), "--tag", "aaaaaaaaaaaa"]
    proc = run(cmd, env=env)
    assert proc.returncode == 0, proc.stderr
    for name in kit.ENV_FILES:
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600, name
    assert "s3cr3t" not in proc.stdout + proc.stderr and "cbom-collector" in proc.stdout
    cmd[-1] = ""  # no --tag value: keep the .env's
    proc = run(cmd, env=env)
    assert proc.returncode == 0, proc.stderr
    assert kit.parse_dotenv((out / ".env").read_text())["DSS_TAG"] == "aaaaaaaaaaaa"


# ------------------------------------------------------------------------------------------------ compose
@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text())


def _bash_array(path, name):
    m = re.search(rf"^\s*{name}=\(([^)]*)\)", path.read_text(), re.MULTILINE)
    assert m, f"{name} not found in {path}"
    return m.group(1).split()


def test_only_nginx_publishes_and_only_port_80(compose):
    for name, svc in compose["services"].items():
        if name == "nginx":
            assert svc["ports"] == ["${DSS_HTTP_PORT:-80}:80"]
        else:
            assert "ports" not in svc, name
            assert "network_mode" not in svc, name


def test_datastores_only_on_the_internal_network(compose):
    assert compose["networks"]["data"]["internal"] is True
    for name in ("postgres", "mongo", "rabbitmq", "qdrant"):
        assert compose["services"][name]["networks"] == ["data"], name


def test_env_files_per_reader(compose):
    def files(svc):
        return [e if isinstance(e, str) else e["path"] for e in svc.get("env_file", [])]
    s = compose["services"]
    for name in ("backend", "migrate", "cbom-cloud-worker", "dast-scheduler"):
        assert files(s[name]) == ["backend.env"], name
    assert files(s["scan-worker"]) == files(s["cicd-worker"]) == ["scan-worker.env"]
    assert files(s["dast-worker"]) == ["dast-worker.env"]
    for name, svc in s.items():
        assert ".env" not in files(svc), name  # the interpolation file reaches no container
    assert files(s["frontend"]) == [] and files(s["nginx"]) == []


def test_backend_listens_on_8080_behind_nginx(compose):
    cmd = compose["services"]["backend"]["command"]
    assert cmd[cmd.index("--bind") + 1] == "0.0.0.0:8080"
    assert "set $backend http://backend:8080;" in TEMPLATE.read_text()
    assert "set $frontend http://frontend:3000;" in TEMPLATE.read_text()
    assert compose["services"]["backend"]["environment"]["FORWARDED_ALLOW_IPS"] == "${DSS_PROXY_IP:-172.30.251.10}"
    assert compose["services"]["nginx"]["networks"]["edge"]["ipv4_address"] == "${DSS_PROXY_IP:-172.30.251.10}"


def test_release_archive_holds_the_infrastructure_images_pinned_by_digest(compose):
    infra = {svc["image"] for svc in compose["services"].values() if "${" not in svc["image"]}
    owner = _bash_array(OWNER, "INFRA_IMAGES")
    assert all(re.fullmatch(r"[a-z0-9./-]+:[a-z0-9.-]+@sha256:[0-9a-f]{64}", i) for i in owner), owner
    assert infra == {i.split("@")[0] for i in owner} == set(_bash_array(REMOTE, "INFRA_IMAGES"))


def test_every_service_has_restart_limits_and_never_pulls(compose):
    total = 0
    for name, svc in compose["services"].items():
        assert svc.get("pull_policy") == "never", name  # ECR pulls / the archive load are explicit steps
        assert svc.get("restart") in ("unless-stopped", "no"), name
        if name == "migrate":
            continue
        v = str(svc["mem_limit"])
        total += float(v[:-1]) * (1024 if v.endswith("g") else 1)
    assert total <= 30 * 1024  # m7i.2xlarge: 32 GB, leave room for the OS


def test_bind_mounted_config_changes_recreate_their_containers(compose):
    for name in ("nginx", "backend", "migrate", "cbom-cloud-worker", "dast-scheduler"):
        assert compose["services"][name]["labels"]["com.zeroshield.dss.files-hash"] == "${DSS_FILES_HASH:-unset}", name
    # Review item 5: through sudo the variable must survive sudo's environment reset (`sudo env VAR=...`)
    assert '"${SUDO[@]}" env "DSS_FILES_HASH=${DSS_FILES_HASH:-$(files_hash)}" docker compose' in REMOTE.read_text()


def test_volumes_are_named_volumes(compose):
    for name, svc in compose["services"].items():
        for v in svc.get("volumes", []):
            src = v.split(":")[0]
            assert src in compose["volumes"] or src.startswith(("./", "../")), (name, v)
    for name in ("pgdata", "mongodata", "rabbitmq", "qdrant", "grype-db"):
        assert name in compose["volumes"]


def test_no_dev_settings_and_production_env(compose):
    text = COMPOSE.read_text()
    assert not re.search(r"^\s*(DSS_DEV_MODE|LOCAL_DEV_VERIFICATION_\w+)\s*:", text, re.MULTILINE)
    assert compose["services"]["backend"]["environment"]["DSS_ENV"] == "production"
    assert compose["services"]["backend"]["environment"]["DSS_EXPOSE_BUILD"] == "0"
    assert compose["services"]["migrate"]["environment"]["SKIP_ALEMBIC"] == "0"
    for name in ("backend", "cbom-cloud-worker", "dast-scheduler"):
        assert compose["services"][name]["depends_on"]["migrate"]["condition"] == "service_completed_successfully"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
def test_compose_config_renders_with_a_dummy_env(tmp_path):
    shutil.copy(COMPOSE, tmp_path / "docker-compose.yml")
    shutil.copytree(KIT_DIR / "nginx", tmp_path / "nginx")
    _, files, _ = _render()
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    proc = run(["docker", "compose", "--project-directory", str(tmp_path), "-f", str(tmp_path / "docker-compose.yml"),
                "--env-file", str(tmp_path / ".env"), "config", "--format", "json"])
    if proc.returncode != 0 and "is not a docker command" in proc.stderr:
        pytest.skip("docker compose plugin not installed")
    assert proc.returncode == 0, proc.stderr
    cfg = json.loads(proc.stdout)
    assert cfg["services"]["backend"]["image"].endswith("/devsec-chola/devsecshield-backend:b669fa3c467f")
    # single-quoted values are literal: '#' and '@' survive into the container environment
    assert cfg["services"]["backend"]["environment"]["SMTP_PASSWORD"] == "p@ss#word 1"
    assert "JWT_SECRET_KEY" not in cfg["services"]["scan-worker"]["environment"]
    published = [(n, p) for n, s in cfg["services"].items() for p in s.get("ports", [])]
    assert [(n, str(p["published"]), p["target"]) for n, p in published] == [("nginx", "80", 80)]


# ------------------------------------------------------------------------------------------------ nginx
def test_nginx_template_contract():
    t = TEMPLATE.read_text()
    assert 'location = /nginx-health { access_log off; default_type text/plain; return 200 "ok\\n"; }' in t
    assert "listen 443" not in t and "ssl_" not in t  # TLS ends at the ALB
    assert "geo $realip_remote_addr $dss_from_alb" in t
    assert '"1:https" https;' in t and "proxy_set_header X-Forwarded-Proto $dss_forwarded_proto;" in t
    assert "proxy_set_header X-Forwarded-Proto $scheme" not in t
    assert "proxy_buffering off;" in t  # SSE (frontend hooks/use-sse.ts)
    assert "client_max_body_size 64m;" in t


def test_nginx_review_fixes():
    t = TEMPLATE.read_text()
    # QA F8: the client once in X-Forwarded-For (the ALB already appended it)
    assert "$proxy_add_x_forwarded_for" not in t and t.count("proxy_set_header X-Forwarded-For $dss_xff;") == 3
    assert '"~^1:(?<alb_xff>.+)$" $alb_xff;' in t
    # QA F8: no framework banner on the API host (nginx itself says "nginx" without a version)
    assert t.count("proxy_hide_header X-Powered-By;") >= 2 and "server_tokens off;" in t
    # item 6: the 512 MB export-verify route, everything else 64 MB
    assert re.search(r"location ~ \^/\[0-9\]\+/cbom/sources/runs/\[0-9\]\+/signature/verify\$ \{\n\s+client_max_body_size 512m;", t)
    # item 6: no includeSubDomains / preload (other zeroshield.ai hosts are not ours to pin)
    assert "includeSubDomains" not in t.replace("No includeSubDomains", "") and "preload" not in t.replace("/ preload", "")


@pytest.mark.parametrize("value", ["0.0.0.0/0", "0.0.0.0/00", "::/0", "::", "0.0.0.0", "0::0", "10.0.0.0/7",
                                   "10.0.0.0/007", "10.0.0.0/33", "fd00::/8", "alb.example.com", "10.0.0.0/8;evil",
                                   "10.0.0/24", "1.2.3.4/", "10.0.0.0/8/1", "dead.beef.cafe.face", ""])
def test_site_script_refuses_unsafe_real_ip_sources(value):
    env = dict(os.environ, FRONTEND_HOST="a", API_HOST="b", DSS_REAL_IP_FROM=value)
    assert run(["sh", str(SITE_SH)], env=env).returncode != 0, value


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed")
def test_site_script_accepts_the_alb_subnets_and_nginx_t_passes():
    if run(["docker", "image", "inspect", "nginx:1.27-alpine"]).returncode != 0:
        pytest.skip("nginx:1.27-alpine not available locally")
    proc = run(["docker", "run", "--rm", "-e", "FRONTEND_HOST=chola.zeroshield.ai", "-e", "API_HOST=chola-api.zeroshield.ai",
                "-e", "DSS_REAL_IP_FROM=10.60.1.0/24,10.60.2.0/24,fd00::/64",
                "-v", f"{SITE_SH}:/docker-entrypoint.d/40-chola-site.sh:ro",
                "-v", f"{TEMPLATE}:/etc/dss-nginx/site.conf.template:ro", "--entrypoint", "sh", "nginx:1.27-alpine",
                "-c", "sh /docker-entrypoint.d/40-chola-site.sh && nginx -t"])
    assert proc.returncode == 0, proc.stderr


# ------------------------------------------------------------------------------------------------ remote.sh units
def _source(tmp_path, script, env=None):
    return run(["bash", "-c", f"source {REMOTE}; {script}"],
               env=dict(os.environ, CHOLA_BASE_DIR=str(tmp_path), **(env or {})))


def test_previous_comes_from_the_started_record_of_an_interrupted_deploy(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "deploy-history").write_text(
        "2026-11-22T18:38:19Z started cccccccccccc previous none alembic-before none\n"
        "2026-11-22T18:39:00Z deploy cccccccccccc previous none alembic r1\n"
        "2026-11-22T18:41:09Z started dddddddddddd previous cccccccccccc alembic-before r1\n")
    proc = _source(tmp_path, "previous_of dddddddddddd; previous_of cccccccccccc; interrupted && echo interrupted")
    # "none" is never a rollback target: previous_of prints nothing for cccc
    assert proc.stdout.split() == ["cccccccccccc", "interrupted"], proc.stderr
    with open(tmp_path / "state" / "deploy-history", "a") as fh:
        fh.write("2026-11-22T18:42:10Z rollback cccccccccccc previous dddddddddddd alembic r1\n")
    assert _source(tmp_path, "interrupted || echo clean").stdout.strip() == "clean"


def _history(tmp_path, text, passed=""):
    (tmp_path / "state").mkdir(exist_ok=True)
    (tmp_path / "state" / "deploy-history").write_text(text)
    (tmp_path / "state" / "passed").write_text(passed)


# QA N1: deploy A, interrupt B, retry B with a failing `up recover` (no backend container left), deploy B: the rollback
# target stays A.
def test_rollback_target_survives_a_failed_recovery(tmp_path):
    _history(tmp_path,
             "t0 started aaaaaaaaaaaa previous none alembic-before none\n"
             "t0 switched aaaaaaaaaaaa previous none\n"
             "t1 deploy aaaaaaaaaaaa previous none alembic r1\n"
             "t2 started bbbbbbbbbbbb previous aaaaaaaaaaaa alembic-before r1\n"
             "t2 switched bbbbbbbbbbbb previous aaaaaaaaaaaa\n"
             "t3 started bbbbbbbbbbbb previous aaaaaaaaaaaa alembic-before r1\n"
             "t3 switched bbbbbbbbbbbb previous aaaaaaaaaaaa\n"
             "t4 deploy bbbbbbbbbbbb previous aaaaaaaaaaaa alembic r2 FAILED\n",
             passed="aaaaaaaaaaaa\n")
    out = _source(tmp_path, 'target_for bbbbbbbbbbbb ""; target_for bbbbbbbbbbbb bbbbbbbbbbbb; '
                            'target_for bbbbbbbbbbbb cccccccccccc').stdout.split()
    assert out == ["aaaaaaaaaaaa", "aaaaaaaaaaaa", "cccccccccccc"]
    # even when an older line recorded "none", previous_of skips it
    with open(tmp_path / "state" / "deploy-history", "a") as fh:
        fh.write("t5 deploy bbbbbbbbbbbb previous none alembic r2\n")
    assert _source(tmp_path, "previous_of bbbbbbbbbbbb").stdout.strip() == "aaaaaaaaaaaa"
    # no history at all: the last release that passed its checks
    (tmp_path / "state" / "deploy-history").write_text("")
    assert _source(tmp_path, 'target_for bbbbbbbbbbbb ""').stdout.strip() == "aaaaaaaaaaaa"


# QA nit: an interruption between STARTED and the tag switch must not roll back one release too far.
def test_rollback_after_an_unswitched_interruption_restarts_the_current_release(tmp_path):
    _history(tmp_path, "t1 deploy aaaaaaaaaaaa previous zzzzzzzzzzzz alembic r1\n"
                       "t2 started bbbbbbbbbbbb previous aaaaaaaaaaaa alembic-before r1\n")
    assert _source(tmp_path, "rollback_pair aaaaaaaaaaaa; interrupted && echo yes").stdout.split() == \
        ["aaaaaaaaaaaa", "1", "deploy-unswitched", "yes"]
    with open(tmp_path / "state" / "deploy-history", "a") as fh:
        fh.write("t2 switched bbbbbbbbbbbb previous aaaaaaaaaaaa\n")
    assert _source(tmp_path, "rollback_pair bbbbbbbbbbbb; interrupted && echo yes").stdout.split() == \
        ["aaaaaaaaaaaa", "0", "normal", "yes"]
    _history(tmp_path, "t1 deploy aaaaaaaaaaaa previous none alembic r1\n")
    assert _source(tmp_path, "rollback_pair aaaaaaaaaaaa").stdout.split() == ["none", "0", "normal"]


def test_deploy_records_the_switch_right_after_it():
    body = REMOTE.read_text().split("cmd_deploy() {", 1)[1].split("\n}\n", 1)[0]
    assert body.index('set_tag "${tag}"') < body.index("switched %s previous %s") < body.index('up "${recover}"')
    assert 'previous="$(target_for "${tag}" "${running}")"' in body


# QA N2: a job whose process is gone without an rc is reported lost (also when its pid now belongs to another process).
@pytest.mark.parametrize("case", ["dead", "reused"])
def test_job_follow_reports_a_lost_job(tmp_path, case):
    job = "20261122T120000Z-deploy-1"
    d = tmp_path / "state" / "jobs" / job
    d.mkdir(parents=True)
    (d / "log").write_text("half a deploy\n")
    if case == "dead":
        p = subprocess.Popen(["sleep", "30"])
        stat_fields = Path(f"/proc/{p.pid}/stat").read_text().split()
        p.kill()
        p.wait()
        (d / "pid").write_text(f"{p.pid} {stat_fields[21]}\n")
    else:  # a live pid whose start time differs: the job's pid was reused after a reboot
        (d / "pid").write_text(f"{os.getpid()} 1\n")
    proc = run(["bash", str(REMOTE), "job-follow", job, "0", "2"], env=dict(os.environ, CHOLA_BASE_DIR=str(tmp_path)))
    assert "half a deploy" in proc.stdout and re.search(r"^chola-job: lost \d+$", proc.stderr, re.MULTILINE), proc.stderr
    status = _source(tmp_path, 'JOBS_DIR="$JOBS_DIR"; job_alive "$JOBS_DIR/' + job + '" && echo alive || echo gone')
    assert status.stdout.strip() == "gone"


def test_status_says_lost_not_running():
    body = REMOTE.read_text().split("cmd_status() {", 1)[1].split("\n}\n", 1)[0]
    assert "LOST" in body and "job_alive" in body and "running (or killed" not in body


# Architecture minors: the first render creates the live kit 700; restore and install replace directories by rename.
def test_render_creates_the_live_kit_private(tmp_path):
    secrets_by_id = {"devsec-chola/prod/app-secrets": json.dumps(_app()),
                     "devsec-chola/prod/app-user": json.dumps(APP_USER), "devsec-chola/prod/cbom-collector": ""}
    (tmp_path / "s.json").write_text(json.dumps(secrets_by_id))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "aws").write_text("#!/usr/bin/env python3\nimport json,sys\na=sys.argv[1:]\n"
                                 f"print(json.load(open({str(tmp_path / 's.json')!r}))[a[a.index('--secret-id')+1]] or 'None')\n")
    (bin_dir / "aws").chmod(0o755)
    base = tmp_path / "base"
    run_dir = tmp_path / "run" / "deploy" / "chola-prod"
    run_dir.mkdir(parents=True)
    for f in ("remote.sh", "kit.py"):
        shutil.copy(KIT_DIR / f, run_dir / f)
    proc = run(["bash", str(run_dir / "remote.sh"), "render", "aaaaaaaaaaaa"],
               env=dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", CHOLA_BASE_DIR=str(base)))
    assert proc.returncode == 0, proc.stderr
    live = base / "deploy" / "chola-prod"
    assert stat.S_IMODE(live.stat().st_mode) == 0o700
    assert kit.parse_dotenv((live / "backend.env").read_text())["BACKEND_WORKERS"] == "4"


def test_restore_replaces_kit_and_overlay_atomically_and_keeps_env_files(tmp_path):
    base = tmp_path
    live = base / "deploy" / "chola-prod"
    overlay = base / "compose" / "aibom-config-overlay"
    live.mkdir(parents=True)
    overlay.mkdir(parents=True)
    (live / "docker-compose.yml").write_text("new\n")
    (live / "stale-new-only.txt").write_text("x")
    (live / "backend.env").write_text("SECRET='1'\n")
    (live / "backend.env").chmod(0o600)
    (overlay / "new-only.json").write_text("{}")
    rel = base / "state" / "releases" / "aaaaaaaaaaaa"
    rel.mkdir(parents=True)
    src = tmp_path / "src"
    (src / "deploy" / "chola-prod").mkdir(parents=True)
    (src / "compose" / "aibom-config-overlay").mkdir(parents=True)
    (src / "deploy" / "chola-prod" / "docker-compose.yml").write_text("old\n")
    (src / "compose" / "aibom-config-overlay" / "old.json").write_text("{}")
    subprocess.run(["tar", "-C", str(src), "-czf", str(rel / "files.tar.gz"), "deploy/chola-prod",
                    "compose/aibom-config-overlay"], check=True)
    proc = _source(tmp_path, "restore_files aaaaaaaaaaaa")
    assert proc.returncode == 0, proc.stderr
    assert (live / "docker-compose.yml").read_text() == "old\n" and not (live / "stale-new-only.txt").exists()
    assert (live / "backend.env").read_text() == "SECRET='1'\n" and stat.S_IMODE((live / "backend.env").stat().st_mode) == 0o600
    assert sorted(p.name for p in overlay.iterdir()) == ["old.json"]
    assert not list(base.glob(".restore.*")) and not list(base.glob(".stage.*"))
    # the replaced generations stay (a running container may still bind-mount them) until prune_old_dirs after up
    old = list((base / "compose").glob("aibom-config-overlay.old.*"))
    assert len(old) == 1 and (old[0] / "new-only.json").exists()
    assert _source(tmp_path, "prune_old_dirs").returncode == 0
    assert not list((base / "compose").glob("*.old.*")) and not list((base / "deploy").glob("*.old.*"))
    # an identical overlay is not swapped: its readers keep using the same directory
    inode = overlay.stat().st_ino
    assert _source(tmp_path, "restore_files aaaaaaaaaaaa").returncode == 0
    assert overlay.stat().st_ino == inode and not list((base / "compose").glob("*.old.*"))


def test_old_generations_are_pruned_only_after_a_successful_up():
    text = REMOTE.read_text()
    for fn in ("cmd_deploy", "cmd_rollback"):
        body = text.split(f"{fn}() {{", 1)[1].split("\n}\n", 1)[0]
        assert body.index("FAILED") < body.index("prune_old_dirs"), fn
    assert "rm -rf" not in text.split("swap_dir() {", 1)[1].split("\n}\n", 1)[0]


def test_preflight_reads_an_s3_object_not_only_lists():
    body = REMOTE.read_text().split("cmd_preflight() {", 1)[1].split("\n}\n", 1)[0]
    assert "s3api get-object" in body and "CHOLA_S3_PROBE_KEY" in body and "--expected-bucket-owner" in body


def test_deploy_writes_started_before_switching_the_tag():
    body = REMOTE.read_text().split("cmd_deploy() {", 1)[1].split("\n}\n", 1)[0]
    assert body.index("started %s previous %s alembic-before %s") < body.index('set_tag "${tag}"') < body.index("up \"${recover}\"")
    assert body.index("frontend_url_ok") < body.index("up \"${recover}\"")  # item 5: URL checked before up
    assert "frontend_url_ok" in REMOTE.read_text().split("cmd_pull() {", 1)[1].split("\n}\n", 1)[0]


def _fake_docker(tmp_path, volumes=None, fail=False, slow=0):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = "#!/bin/sh\n"
    if slow:
        script += f"sleep {slow}\n"
    if fail:
        script += 'case "$1" in info) exit 0;; esac\necho "Cannot connect to the Docker daemon" >&2\nexit 1\n'
    else:
        script += 'case "$1 $2" in "volume ls") printf "%s\\n" ' + " ".join(volumes or []) + ";; esac\nexit 0\n"
    (bin_dir / "docker").write_text(script)
    (bin_dir / "docker").chmod(0o755)
    return dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}")


@pytest.mark.parametrize("volumes, want", [([], "no"), (["dss-chola_pgdata"], "yes"), (["dss-chola_rabbitmq", "x"], "yes"),
                                           (["other_pgdata"], "no")])
def test_volume_exists_answers_yes_or_no(tmp_path, volumes, want):
    proc = run(["bash", str(REMOTE), "volume-exists"], env=_fake_docker(tmp_path, volumes))
    assert proc.returncode == 0 and proc.stdout.strip() == want, proc.stderr


def test_volume_exists_fails_closed_when_docker_cannot_answer(tmp_path):
    proc = run(["bash", str(REMOTE), "volume-exists"], env=_fake_docker(tmp_path, fail=True))
    assert proc.returncode != 0 and proc.stdout.strip() not in ("yes", "no")


@pytest.mark.skipif(shutil.which("setsid") is None or shutil.which("flock") is None, reason="util-linux missing")
def test_detached_job_survives_its_caller_and_records_its_exit(tmp_path):
    kit_copy = tmp_path / "kit" / "deploy" / "chola-prod"
    kit_copy.mkdir(parents=True)
    shutil.copy(REMOTE, kit_copy / "remote.sh")
    base = tmp_path / "base"
    env = _fake_docker(tmp_path, slow=3)
    env["CHOLA_BASE_DIR"] = str(base)
    # the job (a deploy without env files) fails after docker answers (3 s): long enough to kill its caller first
    caller = subprocess.Popen(["bash", str(kit_copy / "remote.sh"), "job-start", "deploy", "aaaaaaaaaaaa"], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    out, err = caller.communicate(timeout=30)
    job = out.strip()
    assert caller.returncode == 0 and re.fullmatch(r"[0-9TZ]+-deploy-[0-9]+", job), err
    os.killpg(caller.pid, signal.SIGHUP) if _alive_group(caller.pid) else None  # what a dropped tunnel would send
    rc_file = base / "state" / "jobs" / job / "rc"
    for _ in range(100):
        if rc_file.exists():
            break
        time.sleep(0.1)
    assert rc_file.read_text().strip() == "1"
    follow = run(["bash", str(kit_copy / "remote.sh"), "job-follow", job, "0", "1"], env=env)
    assert "missing" in follow.stdout and re.search(r"^chola-job: done 1 \d+$", follow.stderr, re.MULTILINE)
    assert "chola-prod.sh renders it" in follow.stdout  # the job's own message, from its log


def _alive_group(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def test_no_password_on_any_command_line():
    text = REMOTE.read_text()
    assert "--config" in text and 'printf "password: ' in text  # mongodump reads a 0600 config file
    assert not re.search(r"mongo(dump|sh|restore)[^\n]*(-p |--password)", text)
    assert not re.search(r"PGPASSWORD=|psql[^\n]*password=", text)
    assert "-p \"$MONGO" not in text and not re.search(r"--password(?!-stdin)", text)


@pytest.mark.skipif(shutil.which("flock") is None, reason="flock not installed")
def test_remote_changing_commands_take_one_lock(tmp_path):
    kit_copy = tmp_path / "deploy" / "chola-prod"
    kit_copy.mkdir(parents=True)
    shutil.copy(REMOTE, kit_copy / "remote.sh")
    state = tmp_path / "state"
    state.mkdir()
    holder = subprocess.Popen(["flock", str(state / ".lock"), "sleep", "30"])
    try:
        for _ in range(50):  # until the holder has the lock
            if run(["flock", "-n", str(state / ".lock"), "true"]).returncode != 0:
                break
            time.sleep(0.1)
        for cmd in (["render"], ["deploy", "aaaaaaaaaaaa"], ["rollback"], ["job-start", "deploy", "aaaaaaaaaaaa"]):
            proc = run(["bash", str(kit_copy / "remote.sh"), *cmd])
            assert proc.returncode == 1 and "another chola-prod command is running" in proc.stderr, cmd
    finally:
        holder.kill()
        holder.wait()


def test_remote_refuses_dev_switches(tmp_path):
    kit_copy = tmp_path / "deploy" / "chola-prod"
    kit_copy.mkdir(parents=True)
    shutil.copy(REMOTE, kit_copy / "remote.sh")
    for name in kit.ENV_FILES:
        (kit_copy / name).write_text("DSS_TAG='aaaaaaaaaaaa'\n" if name == ".env" else "")
        (kit_copy / name).chmod(0o600)
    (kit_copy / "backend.env").write_text("LOCAL_DEV_VERIFICATION_CODE='123456'\n")
    proc = run(["bash", str(kit_copy / "remote.sh"), "smtp-test"], env=_fake_docker(tmp_path))
    assert proc.returncode == 1 and "must never be set in production" in proc.stderr


def test_remote_help_and_preflight_checks_listed():
    proc = run(["bash", str(REMOTE), "--help"])
    assert proc.returncode == 0 and "job-follow" in proc.stdout and "set -" not in proc.stdout
    text = REMOTE.read_text()
    for needle in ('MIN_COMPOSE=2.24.0', "--expected-bucket-owner", "image_store", "CHOLA_ALLOW_IMDS"):
        assert needle in text


# ------------------------------------------------------------------------------------------------ rollback retries (QA R1)
A12, B12, C12 = "a" * 12, "b" * 12, "c" * 12


# The pair a rollback takes from each last history line: a failed or interrupted rollback is retried, never extended.
@pytest.mark.parametrize("last, current, want", [
    (f"t9 rollback-started {B12} from {C12} alembic-before revC", B12, [B12, "1", "rollback-switched"]),
    (f"t9 rollback-started {B12} from {C12} alembic-before revC", C12, [B12, "0", "rollback-retry"]),
    (f"t9 rollback {B12} previous {C12} alembic revB FAILED", B12, [B12, "1", "rollback-failed"]),
    (f"t9 rollback {B12} previous {C12} alembic revB1 revB2 FAILED", B12, [B12, "1", "rollback-failed"]),
    (f"t9 rollback {B12} previous {C12} alembic revB FAILED", C12, [B12, "0", "rollback-retry"]),  # downgrade failed
    (f"t9 rollback {B12} previous {C12} alembic revB", B12, [A12, "0", "normal"]),  # it succeeded: B's predecessor
    (f"t9 rollback-started {A12} from {A12} alembic-before revA", A12, [A12, "1", "rollback-switched"]),
])
def test_rollback_pair_retries_a_failed_or_interrupted_rollback(tmp_path, last, current, want):
    _history(tmp_path, f"t1 deploy {A12} previous none alembic revA\n"
                       f"t2 deploy {B12} previous {A12} alembic revB\n"
                       f"t3 deploy {C12} previous {B12} alembic revC\n{last}\n")
    assert _source(tmp_path, f"rollback_pair {current}").stdout.split() == want
    started = "rollback-started" in last
    assert (_source(tmp_path, "interrupted && echo yes || echo no").stdout.strip() == "yes") == started


FAKE_REMOTE_DOCKER = r'''#!/usr/bin/env python3
"""docker for the real remote.sh: alembic heads/show per tag, the database revision, compose up (ok / fail / hang)."""
import json, os, re, sys, time
F = os.environ["FAKE_DIR"]; a = sys.argv[1:]; P = os.environ["CHOLA_IMAGE_PREFIX"]
open(F + "/docker.log", "a").write("docker " + " ".join(a) + "\n")
st = json.load(open(F + "/state.json"))
def save(): json.dump(st, open(F + "/state.json", "w"))
if a[0] in ("info", "ps", "rm") or a[:2] in (["image", "inspect"], ["image", "ls"]): sys.exit(0)
if a[0] == "run":  # alembic_offline: run --rm --network none --entrypoint PY IMAGE -m alembic --config INI <cmd>
    i = a.index("-m"); tag = a[i - 1].rsplit(":", 1)[1]; cmd = a[i + 4:]
    if cmd[0] == "heads": print(st["heads"][tag] + " (head)")
    if cmd[0] == "show": sys.exit(0 if cmd[1] in st["knows"][tag] else 1)
    sys.exit(0)
if a[0] != "compose": sys.exit(0)
i = a.index("--env-file"); envf = a[i + 1]; sub = a[i + 2:]
if sub[0] == "config": print("postgres\nmigrate\nbackend\nfrontend\nnginx"); sys.exit(0)
if sub[0] == "exec": sys.stdin.read(); print(st["db"]); sys.exit(0)
if sub[0] == "run" and "downgrade" in sub: st["db"] = sub[-1]; st["downgrades"].append(sub[-1]); save(); sys.exit(0)
if sub[0] == "up" and sub[-1] == "postgres": sys.exit(0)
if sub[0] == "up":
    tag = re.search(r"^DSS_TAG='([0-9a-f]{12})'", open(envf).read(), re.M).group(1)
    mode = st["up_modes"].pop(0) if st["up_modes"] else "ok"
    st["ups"].append(tag + ":" + mode); save()
    if mode == "fail": sys.exit(1)
    if mode == "hang":
        open(F + "/hanging.pid", "w").write(str(os.getpid())); open(F + "/hanging", "w").write(tag)
        time.sleep(300); sys.exit(1)
    st["running"] = tag; save(); sys.exit(0)
if sub[0] == "ps" and "{{.Service}}|{{.Image}}" in " ".join(sub):
    t = st["running"]
    print(f"postgres|postgres:15-alpine|running|healthy|0\nmigrate|{P}/devsecshield-backend:{t}|exited||0\n"
          f"backend|{P}/devsecshield-backend:{t}|running|healthy|0\nfrontend|{P}/devsecshield-frontend:{t}|running||0\n"
          "nginx|nginx:1.27-alpine|running|healthy|0")
sys.exit(0)
'''
FAKE_REMOTE_CURL = r'''#!/usr/bin/env python3
import os, sys, time
a = sys.argv[1:]; url = a[-1]; F = os.environ["FAKE_DIR"]
if os.path.exists(F + "/curl-fail"): sys.exit(7)  # connection refused
if os.path.exists(F + "/curl-hang"): open(F + "/curl-hanging", "w").write(str(os.getpid())); time.sleep(300); sys.exit(28)
body = ("ok" if url.endswith("/nginx-health") else '{"status":"healthy"}' if url.endswith("/health") else
        '<script src="/_next/static/chunks/main-1.js"></script>' if url.endswith("/login") else
        "u='https://chola-api.zeroshield.ai'")
open(a[a.index("-o") + 1], "w").write(body); sys.stdout.write("200")
'''


@pytest.fixture
def instance(tmp_path):
    """A stand-in for /opt/devsecshield-chola on which the REAL remote.sh runs (fake docker / curl): releases A (revA),
    B (revB), C (revC) deployed in that order, C running, the database at revC."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("docker", FAKE_REMOTE_DOCKER), ("curl", FAKE_REMOTE_CURL),
                       ("sleep", '#!/bin/sh\n[ "$1" = 20 ] && exit 0\nexec /bin/sleep "$@"\n')):  # up's retry pause
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    base = tmp_path / "base"
    live = base / "deploy" / "chola-prod"
    live.mkdir(parents=True)
    (live / "docker-compose.yml").write_text("services: {}\n")
    for name in kit.ENV_FILES:
        (live / name).write_text(f"DSS_TAG='{C12}'\n" if name == ".env" else "")
        (live / name).chmod(0o600)
    (base / "state").mkdir()
    (base / "state" / "deploy-history").write_text(
        f"t1 started {A12} previous none alembic-before none\nt1 switched {A12} previous none\n"
        f"t1 deploy {A12} previous none alembic revA\n"
        f"t2 started {B12} previous {A12} alembic-before revA\nt2 switched {B12} previous {A12}\n"
        f"t2 deploy {B12} previous {A12} alembic revB\n"
        f"t3 started {C12} previous {B12} alembic-before revB\nt3 switched {C12} previous {B12}\n"
        f"t3 deploy {C12} previous {B12} alembic revC\n")
    (base / "state" / "passed").write_text(f"{A12}\n{B12}\n{C12}\n")
    state = {"heads": {A12: "revA", B12: "revB", C12: "revC"},
             "knows": {A12: ["revA"], B12: ["revA", "revB"], C12: ["revA", "revB", "revC"]},
             "db": "revC", "running": C12, "up_modes": [], "ups": [], "downgrades": []}
    (tmp_path / "state.json").write_text(json.dumps(state))
    env = {"PATH": f"{bin_dir}:/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path), "LC_ALL": "C",
           "FAKE_DIR": str(tmp_path), "CHOLA_BASE_DIR": str(base), "CHOLA_IMAGE_PREFIX": "reg.example/devsec-chola",
           "CHOLA_WAIT_S": "5"}

    class Instance:
        dir = tmp_path

        @staticmethod
        def remote(*args, **kw):
            return run(["bash", str(REMOTE), *args], env=env, stdin=subprocess.DEVNULL, **kw)

        @staticmethod
        def popen(*args):
            return subprocess.Popen(["bash", str(REMOTE), *args], env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)

        @staticmethod
        def state():
            return json.loads((tmp_path / "state.json").read_text())

        @staticmethod
        def set_up_modes(*modes):
            st = Instance.state()
            st["up_modes"] = list(modes)
            (tmp_path / "state.json").write_text(json.dumps(st))

        @staticmethod
        def tag():
            return kit.parse_dotenv((live / ".env").read_text())["DSS_TAG"]

        @staticmethod
        def history():
            return (base / "state" / "deploy-history").read_text().splitlines()

        @staticmethod
        def job(*args):
            """remote.sh job-start <args>: (job id, job directory)."""
            proc = run(["bash", str(REMOTE), "job-start", *args], env=env, stdin=subprocess.DEVNULL)
            assert proc.returncode == 0, proc.stderr
            return proc.stdout.strip(), base / "state" / "jobs" / proc.stdout.strip()

        @staticmethod
        def wait_for(path, seconds=30):
            for _ in range(seconds * 10):
                if path.exists() and path.stat().st_size:
                    return path
                time.sleep(0.1)
            raise AssertionError(f"{path} never appeared")
    return Instance


# QA R1, repro 1: C -> B downgrades to revB and fails in `compose up` (DSS_TAG is B, nothing runs). The retry must
# start B again (no second downgrade to revA), and only a rollback after that goes on to A.
def test_retry_of_a_failed_rollback_restarts_its_target(instance):
    instance.set_up_modes("fail", "fail")  # `up recover` tries twice
    first = instance.remote("rollback", "--allow-downgrade")
    assert first.returncode == 1 and "compose up failed for " + B12 in first.stderr, first.stderr
    assert instance.tag() == B12 and instance.state()["downgrades"] == ["revB"]
    assert instance.history()[-2].split()[1:4] == ["rollback-started", B12, "from"]
    assert instance.history()[-2].split()[4:] == [C12, "alembic-before", "revC"]
    assert instance.history()[-1].split()[1:] == ["rollback", B12, "previous", C12, "alembic", "revB", "FAILED"]
    plan = instance.remote("rollback", "--plan")
    assert plan.returncode == 0 and f"rollback {B12} -> {B12}" in plan.stdout and "NOT going back" in plan.stdout
    retry = instance.remote("rollback", "--allow-downgrade")
    assert retry.returncode == 0, retry.stdout + retry.stderr
    st = instance.state()
    assert instance.tag() == B12 and st["running"] == B12 and st["db"] == "revB"
    assert st["downgrades"] == ["revB"]  # the retry downgraded nothing (the bug went on to revA)
    assert f"{B12} is running again" not in retry.stdout and "rolled back to " + B12 in retry.stdout
    assert instance.history()[-1].split()[1:3] == ["rollback", B12]
    # B runs: a further rollback is a NEW step back, to A (and needs the downgrade to revA)
    further = instance.remote("rollback", "--plan")
    assert further.returncode == 3 and f"rollback {B12} -> {A12}" in further.stdout, further.stdout + further.stderr


# QA R1, repro 2: the rollback job is killed while `compose up` hangs (after the switch to B; no outcome recorded).
def test_retry_of_an_interrupted_rollback_restarts_its_target(instance):
    instance.set_up_modes("hang")
    p = instance.popen("rollback", "--allow-downgrade")
    try:
        for _ in range(300):
            if (instance.dir / "hanging").exists():
                break
            time.sleep(0.1)
        assert (instance.dir / "hanging").exists(), "compose up never started"
    finally:
        os.killpg(p.pid, signal.SIGKILL)  # the job's session: remote.sh and the hanging compose
        p.communicate(timeout=30)
    assert instance.tag() == B12 and instance.history()[-1].split()[1:3] == ["rollback-started", B12]
    assert _source_base(instance, "interrupted && echo yes").stdout.strip() == "yes"
    retry = instance.remote("rollback", "--allow-downgrade")
    assert retry.returncode == 0, retry.stdout + retry.stderr
    assert "switched the tag and then failed or was interrupted" in retry.stdout
    st = instance.state()
    assert instance.tag() == B12 and st["running"] == B12 and st["downgrades"] == ["revB"]
    assert st["ups"][-1] == B12 + ":ok"


# A rollback stopped before its switch (the downgrade failed: C was restarted) is run again, C -> B, not C -> B's
# predecessor; and nothing about it touches A.
def test_rollback_whose_downgrade_failed_is_run_again(instance):
    (instance.dir / "bin" / "docker").write_text(FAKE_REMOTE_DOCKER.replace(
        'if sub[0] == "run" and "downgrade" in sub:',
        'if sub[0] == "run" and "downgrade" in sub and os.path.exists(F + "/deny"): sys.exit(1)\n'
        'if sub[0] == "run" and "downgrade" in sub:'))
    (instance.dir / "deny").write_text("")
    first = instance.remote("rollback", "--allow-downgrade")
    assert first.returncode == 1 and "alembic downgrade failed" in first.stderr
    assert instance.tag() == C12 and instance.history()[-1].split()[-1] == "FAILED"
    (instance.dir / "deny").unlink()
    retry = instance.remote("rollback", "--allow-downgrade")
    assert retry.returncode == 0, retry.stdout + retry.stderr
    assert "stopped before it switched: running the same rollback again" in retry.stdout
    assert instance.tag() == B12 and instance.state()["downgrades"] == ["revB"]


def _source_base(instance, script):
    return run(["bash", "-c", f"source {REMOTE}; {script}"],
               env=dict(os.environ, CHOLA_BASE_DIR=str(instance.dir / "base")))


# ------------------------------------------------------------------------------------------------ job liveness (QA R3)
@pytest.mark.skipif(shutil.which("setsid") is None or shutil.which("flock") is None, reason="util-linux missing")
def test_a_killed_wrapper_does_not_lose_a_running_job(tmp_path):
    kit_copy = tmp_path / "kit" / "deploy" / "chola-prod"
    kit_copy.mkdir(parents=True)
    shutil.copy(REMOTE, kit_copy / "remote.sh")
    base = tmp_path / "base"
    live = base / "deploy" / "chola-prod"
    live.mkdir(parents=True)
    for name in kit.ENV_FILES:
        (live / name).write_text("")
        (live / name).chmod(0o600)
    slow = _fake_docker(tmp_path, slow=3)  # dump: docker info, then compose ps (postgres not running: exit 0)
    slow["CHOLA_BASE_DIR"] = str(base)
    proc = run(["bash", str(kit_copy / "remote.sh"), "job-start", "dump"], env=slow)
    job = proc.stdout.strip()
    assert proc.returncode == 0 and re.fullmatch(r"[0-9TZ]+-dump-[0-9]+", job), proc.stderr
    jdir = base / "state" / "jobs" / job
    for _ in range(100):
        if (jdir / "worker").exists():
            break
        time.sleep(0.1)
    wrapper = int((jdir / "pid").read_text().split()[0])
    os.kill(wrapper, signal.SIGKILL)  # only the wrapper: the worker (remote.sh dump) keeps going
    for _ in range(50):
        if not Path(f"/proc/{wrapper}").exists() or "Z" in Path(f"/proc/{wrapper}/stat").read_text().split()[2]:
            break
        time.sleep(0.1)
    follow = run(["bash", str(kit_copy / "remote.sh"), "job-follow", job, "0", "1"], env=slow)
    assert re.search(r"^chola-job: running \d+$", follow.stderr, re.MULTILINE), follow.stderr  # not "lost"
    for _ in range(200):
        if (jdir / "rc").exists():
            break
        time.sleep(0.1)
    assert (jdir / "rc").read_text().strip() == "0"  # written by the worker itself
    follow = run(["bash", str(kit_copy / "remote.sh"), "job-follow", job, "0", "1"], env=slow)
    assert re.search(r"^chola-job: done 0 \d+$", follow.stderr, re.MULTILINE) and "no logical dump" in follow.stdout
    (tmp_path / "fast").mkdir()
    fast = _fake_docker(tmp_path / "fast")
    fast["CHOLA_BASE_DIR"] = str(base)
    status = run(["bash", str(kit_copy / "remote.sh"), "status"], env=fast)
    assert f"{job} exit 0" in status.stdout and "LOST" not in status.stdout, status.stdout + status.stderr
    assert status.returncode == 0 and "ERROR" not in status.stderr, status.stderr


def test_job_alive_follows_the_worker_too(tmp_path):
    d = tmp_path / "state" / "jobs" / "20261122T120000Z-deploy-1"
    d.mkdir(parents=True)
    p = subprocess.Popen(["sleep", "30"])
    try:
        start = Path(f"/proc/{p.pid}/stat").read_text().split()[21]
        (d / "pid").write_text(f"{os.getpid()} 1\n")  # the wrapper: gone (its pid now someone else's)
        (d / "worker").write_text(f"{p.pid} {start}\n")
        assert _source(tmp_path, f'job_alive "{d}" && echo alive').stdout.strip() == "alive"
    finally:
        p.kill()
        p.wait()
    assert _source(tmp_path, f'job_alive "{d}" || echo gone').stdout.strip() == "gone"


# Backend CI on 33f416ff (runner without /var/lib/docker): `df` exits 1 for a path it cannot read, pipefail failed the
# pipeline inside `status`'s $(...), and the ERR trap (inherited by set -E) printed an ERROR line from a working status.
@pytest.mark.parametrize("df_mode", ["docker-root-unreadable", "df-broken"])
def test_status_reports_disk_without_an_error_when_df_cannot_read_a_path(tmp_path, df_mode):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").write_text('#!/bin/sh\ncase "$*" in "info --format {{.DockerRootDir}}") echo /var/lib/docker;; esac\n'
                                    'exit 0\n')
    real_df = shutil.which("df")
    if df_mode == "docker-root-unreadable":  # what the runner's df did: the other rows, then exit 1
        df = ('#!/bin/sh\nkeep=""\nfor a; do case "$a" in /var/lib/docker) echo "df: /var/lib/docker: No such file or '
              'directory" >&2;; *) keep="$keep $a";; esac; done\n'
              f'{real_df} $keep\ncase " $* " in *" /var/lib/docker "*) exit 1;; esac\n')
    else:
        df = '#!/bin/sh\necho "df: cannot read table of mounted file systems" >&2\nexit 1\n'
    (bin_dir / "df").write_text(df)
    for name in ("docker", "df"):
        (bin_dir / name).chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", CHOLA_BASE_DIR=str(tmp_path / "base"))
    proc = run(["bash", str(REMOTE), "status"], env=env)
    assert proc.returncode == 0 and "ERROR" not in proc.stderr, proc.stderr
    disk = re.search(r"\] disk: (.*)$", proc.stdout, re.MULTILINE).group(1)
    if df_mode == "df-broken":
        assert disk == "unknown", proc.stdout
    else:
        assert disk.startswith("/ ") and "/var/lib/docker" not in disk, proc.stdout


# ------------------------------------------------------------------------------------------------ files on the instance
# Architecture nit: the files-hash label includes the overlay directory's inode, so a swapped overlay with the same
# content still recreates its readers (a later prune of the old generation cannot empty a container's /aibom/config).
def test_files_hash_follows_the_overlay_directory_not_only_its_content(tmp_path):
    overlay = tmp_path / "compose" / "aibom-config-overlay"
    overlay.mkdir(parents=True)
    (overlay / "rollup.json").write_text("{}")
    (tmp_path / "deploy" / "chola-prod" / "nginx").mkdir(parents=True)
    (tmp_path / "deploy" / "chola-prod" / "nginx" / "site.conf.template").write_text("server {}")
    first = _source(tmp_path, "files_hash").stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{16}", first) and _source(tmp_path, "files_hash").stdout.strip() == first
    copy = tmp_path / "copy"
    shutil.copytree(overlay, copy)
    assert _source(tmp_path, f'swap_dir "{copy}" "{overlay}"').returncode == 0  # same content, new directory
    second = _source(tmp_path, "files_hash").stdout.strip()
    assert second != first
    (tmp_path / "deploy" / "chola-prod" / "nginx" / "site.conf.template").write_text("server { }")
    assert _source(tmp_path, "files_hash").stdout.strip() not in (first, second)  # content still counts


# Architecture nit: no secret copies outside the live kit after a killed or failed run.
def test_changing_commands_sweep_stale_stage_restore_and_old_env_files(tmp_path):
    live = tmp_path / "deploy" / "chola-prod"
    old = tmp_path / "deploy" / "chola-prod.old.20261122T000000000"
    for d in (live, old / "nginx", tmp_path / ".stage.AbC123" / "kit", tmp_path / ".restore.XyZ789" / "deploy"):
        d.mkdir(parents=True)
    for d in (live, old, tmp_path / ".stage.AbC123" / "kit"):
        for name in kit.ENV_FILES:
            (d / name).write_text("SECRET='x'\n")
    (old / "nginx" / "site.conf.template").write_text("server {}")
    (old / "docker-compose.yml").write_text("services: {}\n")
    assert _source(tmp_path, "lock && echo locked").stdout.strip() == "locked"
    assert not list(tmp_path.glob(".stage.*")) and not list(tmp_path.glob(".restore.*"))
    assert sorted(p.name for p in old.iterdir()) == ["docker-compose.yml", "nginx"]  # generation kept, secrets gone
    assert all((live / name).exists() for name in kit.ENV_FILES)  # the live kit is untouched


# QA R2: only an assignment from a failing $(...) is left to its inner command; every other failure names itself.
def test_err_trap_reports_commands_with_a_substitution_argument(tmp_path):
    proc = _source(tmp_path, 'ls "/nonexistent-$(echo dir)"')
    assert re.search(r"^\[chola-remote\] ERROR: line \d+: ls .*\(exit 2\)$", proc.stderr, re.MULTILINE), proc.stderr
    proc = _source(tmp_path, 'x="$(exit 4)"')
    assert proc.returncode == 4 and "ERROR" not in proc.stderr
    for script in (OWNER, REMOTE):
        assert "ASSIGN_FROM_SUBST=" in script.read_text() and '== *"\\$("*' not in script.read_text()


# Round-4 nit: export / readonly / declare / typeset / local with options are assignments too; both scripts agree.
def test_err_filter_knows_every_assignment_form(tmp_path):
    forms = ['x="$(f)"', 'local x="$(f)"', 'export X="$(f)"', 'readonly X="$(f)"', 'declare -x X="$(f)"',
             'typeset -r X="$(f)"', 'local -a xs=("$(f)")', 'a[1]="$(f)"', 'x+="$(f)"']
    script = "; ".join(f"[[ {shlex.quote(f)} =~ $ASSIGN_FROM_SUBST ]] && echo yes || echo no" for f in forms)
    assert _source(tmp_path, script).stdout.split() == ["yes"] * len(forms)
    others = ['ssh -i k host "$(remote_cmdline x)"', 'docker run "$(image_of a b)"', 'echo x=$(f)']
    script = "; ".join(f"[[ {shlex.quote(f)} =~ $ASSIGN_FROM_SUBST ]] && echo yes || echo no" for f in others)
    assert _source(tmp_path, script).stdout.split() == ["no"] * len(others)
    pattern = re.compile(r"^ASSIGN_FROM_SUBST=.*$", re.MULTILINE)
    assert pattern.search(OWNER.read_text()).group(0) == pattern.search(REMOTE.read_text()).group(0)


# Round-4 nit: a blank last line or trailing whitespace (a hand edit) does not change what a rollback does.
@pytest.mark.parametrize("tail", ["\n\n", "\n\n  \n", "   \n", "\r\n", "\t \n\n"])
def test_history_parsing_ignores_blank_lines_and_trailing_space(tmp_path, tail):
    base = f"t1 deploy {A12} previous none alembic revA\nt2 deploy {B12} previous {A12} alembic revB\n" \
           f"t3 deploy {C12} previous {B12} alembic revC\n"
    _history(tmp_path, base + f"t9 rollback {B12} previous {C12} alembic revB FAILED" + tail)
    assert _source(tmp_path, f"rollback_pair {B12}").stdout.split() == [B12, "1", "rollback-failed"]
    _history(tmp_path, base + f"t9 rollback-started {B12} from {C12} alembic-before revC" + tail)
    assert _source(tmp_path, f"rollback_pair {B12}; interrupted && echo yes").stdout.split() == \
        [B12, "1", "rollback-switched", "yes"]


# Round-4 F1 / A1: a job's worker killed by SIGTERM (a graceful reboot or stop, `kill <pid>`) never reads as success.
@pytest.mark.skipif(shutil.which("setsid") is None or shutil.which("flock") is None, reason="util-linux missing")
def test_sigterm_to_the_worker_never_reads_as_success(instance):
    instance.set_up_modes("hang")
    job, jdir = instance.job("rollback", "--allow-downgrade")
    instance.wait_for(instance.dir / "hanging.pid")
    worker = int(instance.wait_for(jdir / "worker").read_text().split()[0])
    hung = int((instance.dir / "hanging.pid").read_text())
    try:
        os.kill(worker, signal.SIGTERM)  # the worker alone: bash waits for its foreground child
        time.sleep(0.5)
    finally:
        os.kill(hung, signal.SIGTERM)  # the hanging `compose up` ends; the worker then acts on its TERM
    assert instance.wait_for(jdir / "rc").read_text().strip() == "143"
    follow = instance.remote("job-follow", job, "0", "1")
    assert re.search(r"^chola-job: done 143 \d+$", follow.stderr, re.MULTILINE), follow.stderr
    assert instance.history()[-1].split()[1:3] == ["rollback-started", B12]  # no outcome recorded: unfinished
    assert "exit 143" in instance.remote("status").stdout


@pytest.mark.skipif(shutil.which("setsid") is None or shutil.which("flock") is None, reason="util-linux missing")
def test_sigterm_to_the_whole_session_never_reads_as_success(instance):
    """What systemd does to the session scope at shutdown: TERM to every process of the job's session."""
    instance.set_up_modes("hang")
    job, jdir = instance.job("rollback", "--allow-downgrade")
    instance.wait_for(instance.dir / "hanging.pid")
    instance.wait_for(jdir / "worker")
    sid = int((jdir / "pid").read_text().split()[0])  # the wrapper is the session leader (setsid)
    assert Path(f"/proc/{sid}/stat").read_text().split()[5] == str(sid)
    if shutil.which("pkill"):
        subprocess.run(["pkill", "-TERM", "-s", str(sid)], check=False)
    else:
        os.killpg(sid, signal.SIGTERM)
    rc = instance.wait_for(jdir / "rc").read_text().strip()
    assert rc == "143", rc
    follow = instance.remote("job-follow", job, "0", "1")
    assert "chola-job: done 0" not in follow.stderr and "chola-job: done 143" in follow.stderr, follow.stderr


# Round-5 L1: any other fatal signal to the worker never reads as success either: the worker writes rc only when it
# ends on purpose, so the wrapper records the real 128 + n. (No core-dumping signals here: ABRT/XCPU/XFSZ would drop a
# core file; the code path is the same.)
@pytest.mark.skipif(shutil.which("setsid") is None or shutil.which("flock") is None, reason="util-linux missing")
@pytest.mark.parametrize("sig", [signal.SIGUSR1, signal.SIGUSR2, signal.SIGALRM, signal.SIGPIPE])
def test_other_fatal_signals_to_the_worker_never_read_as_success(instance, sig):
    instance.set_up_modes("hang")
    job, jdir = instance.job("rollback", "--allow-downgrade")
    instance.wait_for(instance.dir / "hanging.pid")
    worker = int(instance.wait_for(jdir / "worker").read_text().split()[0])
    try:
        os.kill(worker, sig)
        rc = instance.wait_for(jdir / "rc").read_text().strip()
    finally:
        os.kill(int((instance.dir / "hanging.pid").read_text()), signal.SIGKILL)  # the orphaned `compose up`
    assert rc == str(128 + sig), rc  # written by the wrapper, from the worker's real status
    follow = instance.remote("job-follow", job, "0", "1")
    assert f"chola-job: done {128 + sig} " in follow.stderr and "chola-job: done 0 " not in follow.stderr
    assert instance.history()[-1].split()[1] == "rollback-started"
    assert "exit 131" not in REMOTE.read_text()  # no QUIT trap: QUIT is ignored on entry and cannot be trapped


# Regression guard for L1's completion flag (passes before and after): a worker that ends through `die` still writes
# its own rc when its wrapper is gone.
@pytest.mark.skipif(shutil.which("setsid") is None or shutil.which("flock") is None, reason="util-linux missing")
def test_a_worker_ending_in_die_writes_its_rc_without_its_wrapper(tmp_path):
    kit_copy = tmp_path / "kit" / "deploy" / "chola-prod"
    kit_copy.mkdir(parents=True)
    shutil.copy(REMOTE, kit_copy / "remote.sh")
    env = _fake_docker(tmp_path, slow=3)  # dump without env files: docker info (3 s), then die
    env["CHOLA_BASE_DIR"] = str(tmp_path / "base")
    proc = run(["bash", str(kit_copy / "remote.sh"), "job-start", "dump"], env=env)
    jdir = tmp_path / "base" / "state" / "jobs" / proc.stdout.strip()
    for _ in range(100):
        if (jdir / "worker").exists():
            break
        time.sleep(0.1)
    os.kill(int((jdir / "pid").read_text().split()[0]), signal.SIGKILL)
    for _ in range(200):
        if (jdir / "rc").exists():
            break
        time.sleep(0.1)
    assert (jdir / "rc").read_text().strip() == "1" and "chola-prod.sh renders it" in (jdir / "log").read_text()


# Round-5: `rollback --to` only goes back (forward is deploy), and `status` lists what it accepts.
def test_rollback_to_refuses_a_newer_release_and_status_lists_the_accepted_ones(instance):
    status = instance.remote("status")
    assert f"rollback --to accepts (deployed, passed, not newer; newest first): {C12} {B12} {A12}" in status.stdout
    assert instance.remote("rollback", "--to", A12, "--allow-downgrade").returncode == 0 and instance.tag() == A12
    for newer in (C12, B12):
        proc = instance.remote("rollback", "--plan", "--to", newer)
        assert proc.returncode == 1 and f"--to {newer} is newer than {A12}" in proc.stderr, proc.stderr
        assert f"deploy --sha {newer}" in proc.stderr
    assert instance.history()[-1].split()[1:3] == ["rollback", A12]  # the refusals changed nothing
    assert instance.remote("rollback", "--plan", "--to", A12).returncode == 0  # the running release itself: a restart
    status = instance.remote("status")
    assert f"rollback --to accepts (deployed, passed, not newer; newest first): {A12}" in status.stdout


# Round-6 L1: a deploy of D interrupted after its switch has STARTED/SWITCHED but no deploy line. D is still the newest
# release: --to B is older (accepted, with its downgrade plan), and status lists C B A, not "none".
def test_rollback_to_after_an_interrupted_deploy_orders_by_first_started(instance):
    d12 = "d" * 12
    with open(instance.dir / "base" / "state" / "deploy-history", "a") as fh:
        fh.write(f"t4 started {d12} previous {C12} alembic-before revC\nt4 switched {d12} previous {C12}\n")
    env_file = instance.dir / "base" / "deploy" / "chola-prod" / ".env"
    env_file.write_text(f"DSS_TAG='{d12}'\n")
    st = instance.state()
    st["heads"][d12], st["knows"][d12] = "revD", ["revA", "revB", "revC", "revD"]
    (instance.dir / "state.json").write_text(json.dumps(st))
    status = instance.remote("status")
    assert f"rollback --to accepts (deployed, passed, not newer; newest first): {C12} {B12} {A12}" in status.stdout, \
        status.stdout + status.stderr
    plan = instance.remote("rollback", "--plan", "--to", B12)
    assert "is newer than" not in plan.stderr and "deploy --sha" not in plan.stderr, plan.stderr
    assert plan.returncode == 3 and f"rollback {d12} -> {B12}" in plan.stdout, plan.stdout + plan.stderr
    assert _source_base(instance, f"newer_release {B12} {d12} && echo newer || echo older").stdout.strip() == "older"
    assert _source_base(instance, f"newer_release {d12} {C12} && echo newer || echo older").stdout.strip() == "newer"


# Round-6 nit: a zombie (exited, not yet reaped) is dead, so a killed job reads as lost at once, not "running" for ~1 s.
def test_job_alive_treats_a_zombie_as_dead(tmp_path):
    d = tmp_path / "state" / "jobs" / "20261122T120000Z-deploy-1"
    d.mkdir(parents=True)
    p = subprocess.Popen(["true"])  # never waited for until the end: a zombie child of this test
    try:
        for _ in range(100):
            fields = Path(f"/proc/{p.pid}/stat").read_text().split()
            if fields[2] == "Z":
                break
            time.sleep(0.05)
        assert fields[2] == "Z"
        (d / "pid").write_text(f"{p.pid} {fields[21]}\n")
        assert _source(tmp_path, f'job_alive "{d}" && echo alive || echo gone').stdout.strip() == "gone"
    finally:
        p.wait()


# Round-5: --to and --allow-downgrade are refused on every other command, before any call.
@pytest.mark.parametrize("args, flag", [(["status", "--to", A12], "--to"), (["deploy", "--sha", "HEAD", "--to", A12, "--yes"], "--to"),
                                        (["backup", "--allow-downgrade"], "--allow-downgrade"),
                                        (["verify", "--allow-downgrade"], "--allow-downgrade")])
def test_rollback_only_flags_are_refused_elsewhere(fake_world, args, flag):
    head = run(["git", "-C", str(REPO), "rev-parse", "HEAD"]).stdout.strip()
    proc = fake_world(*[head if a == "HEAD" else a for a in args])
    assert proc.returncode == 1 and f"[chola] ERROR: {flag} is only for rollback" in proc.stderr, proc.stderr
    assert fake_world.log() == ""


# Round-4 F2: C -> B whose `up` succeeds but whose checks fail: the retry starts B again, never B -> A.
def test_rollback_whose_checks_fail_is_retried_not_extended(instance):
    (instance.dir / "curl-fail").write_text("")
    first = instance.remote("rollback", "--allow-downgrade")
    assert first.returncode == 1 and instance.tag() == B12 and instance.state()["running"] == B12
    plan = instance.remote("rollback", "--plan")  # QA's repro: this said B -> A, with a downgrade to revA
    assert plan.returncode == 0 and f"rollback {B12} -> {B12}" in plan.stdout, plan.stdout + plan.stderr
    assert instance.history()[-1].split()[1:] == ["rollback", B12, "previous", C12, "alembic", "revB", "FAILED"]
    assert (instance.dir / "base" / "state" / "passed").read_text().split()[-1] == C12  # B did not pass
    assert "started but its checks failed" in first.stderr, first.stdout + first.stderr
    (instance.dir / "curl-fail").unlink()
    retry = instance.remote("rollback", "--allow-downgrade")
    assert retry.returncode == 0, retry.stdout + retry.stderr
    assert instance.tag() == B12 and instance.state()["downgrades"] == ["revB"]
    assert instance.history()[-1].split()[1:3] == ["rollback", B12] and instance.history()[-1].split()[-1] != "FAILED"
    assert (instance.dir / "base" / "state" / "passed").read_text().split()[-1] == B12


def test_rollback_killed_during_its_checks_is_retried_not_extended(instance):
    (instance.dir / "curl-hang").write_text("")
    p = instance.popen("rollback", "--allow-downgrade")
    try:
        instance.wait_for(instance.dir / "curl-hanging")
    finally:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate(timeout=30)
    (instance.dir / "curl-hang").unlink()
    assert instance.tag() == B12 and instance.history()[-1].split()[1:3] == ["rollback-started", B12]
    plan = instance.remote("rollback", "--plan")
    assert plan.returncode == 0 and f"rollback {B12} -> {B12}" in plan.stdout, plan.stdout + plan.stderr


# Round-4 F4: a deploy after an unfinished rollback C -> B (nothing runs) records B, where the operator was heading.
@pytest.mark.parametrize("last", [f"t9 rollback-started {B12} from {C12} alembic-before revC",
                                  f"t9 rollback {B12} previous {C12} alembic revB FAILED"])
def test_a_deploy_after_an_unfinished_rollback_targets_where_it_was_heading(tmp_path, last):
    _history(tmp_path, f"t1 deploy {A12} previous none alembic revA\nt2 deploy {B12} previous {A12} alembic revB\n"
                       f"t3 deploy {C12} previous {B12} alembic revC\n{last}\n", passed=f"{A12}\n{B12}\n{C12}\n")
    (tmp_path / "deploy" / "chola-prod").mkdir(parents=True)
    (tmp_path / "deploy" / "chola-prod" / ".env").write_text(f"DSS_TAG='{B12}'\n")
    d12 = "d" * 12
    out = _source(tmp_path, f'target_for {d12} ""; target_for {d12} {C12}; target_for {B12} ""').stdout.split()
    assert out == [B12, C12, A12]  # nothing runs: B; C runs: C; redeploying B itself: B's own predecessor


# Round-4 F5: B can never start; `rollback --to A` is the explicit, guarded way past it.
def test_rollback_to_an_explicit_release_gets_past_a_target_that_cannot_start(instance):
    instance.set_up_modes(*["fail"] * 4)
    assert instance.remote("rollback", "--allow-downgrade").returncode == 1  # C -> B fails
    again = instance.remote("rollback", "--allow-downgrade")  # B -> B fails too
    assert again.returncode == 1 and "rollback --to" in again.stdout and instance.tag() == B12
    for bad, why in (("d" * 12, "not a release that was deployed and passed"), ("latest", "not a 12-character commit")):
        proc = instance.remote("rollback", "--plan", "--to", bad)
        assert proc.returncode == 1 and why in proc.stderr, proc.stderr
    plan = instance.remote("rollback", "--plan", "--to", A12)
    assert plan.returncode == 3 and f"rollback {B12} -> {A12}" in plan.stdout and "--to" in plan.stdout
    refused = instance.remote("rollback", "--to", A12)
    assert refused.returncode == 1 and "--allow-downgrade" in refused.stderr and instance.tag() == B12
    done = instance.remote("rollback", "--to", A12, "--allow-downgrade")
    assert done.returncode == 0, done.stdout + done.stderr
    assert instance.tag() == A12 and instance.state()["downgrades"] == ["revB", "revA"]
    assert instance.history()[-1].split()[1:5] == ["rollback", A12, "previous", B12]


# ------------------------------------------------------------------------------------------------ owner script
FAKE_AWS = r'''#!/usr/bin/env python3
import json, os, sys
F = os.environ["FAKE_DIR"]; a = sys.argv[1:]
open(F + "/calls.log", "a").write("aws " + " ".join(a) + "\n")
if "--region" in a: i = a.index("--region"); del a[i:i + 2]
def arg(n): return a[a.index(n) + 1]
def count(name):
    p = F + "/" + name; k = int(open(p).read()) if os.path.exists(p) else 0; open(p, "w").write(str(k + 1)); return k
st = F + "/app-secrets.json"; c = a[:2]
if a[:1] == ["--version"]: print("aws-cli/2.31.0"); sys.exit(0)
if c == ["sts", "get-caller-identity"]: print("935951870001\tarn:aws:iam::935951870001:user/Owner"); sys.exit(0)
if c == ["secretsmanager", "get-secret-value"]:
    sid = arg("--secret-id")
    if sid.endswith("ssh-admin"): print(json.dumps({"private_key_pem": "-----BEGIN OPENSSH PRIVATE KEY-----\nX\n"})); sys.exit(0)
    if not os.path.exists(st):
        print("An error occurred (ResourceNotFoundException): can't find the specified secret value for staging label: AWSCURRENT", file=sys.stderr); sys.exit(254)
    print(open(st).read()); sys.exit(0)
if c == ["secretsmanager", "put-secret-value"]: open(st, "w").write(open(arg("--secret-string")[7:]).read()); print("v"); sys.exit(0)
if c == ["secretsmanager", "describe-secret"]: print("x"); sys.exit(0)
if c == ["ec2", "describe-instances"]:
    if arg("--query").endswith("PrivateIpAddress"): print("10.60.10.108"); sys.exit(0)
    print("running\tm7i.2xlarge\t10.60.10.108\t" + os.environ.get("FAKE_TOKENS", "required") + "\t" + os.environ.get("FAKE_HOP", "1") + "\tenabled"); sys.exit(0)
if c == ["elbv2", "describe-target-groups"]: print("ip\tHTTP\t80\t/nginx-health"); sys.exit(0)
if c == ["elbv2", "describe-target-health"]:
    if count("th") == 0: print("An error occurred (Throttling): Rate exceeded", file=sys.stderr); sys.exit(254)
    print("10.60.10.108\t80\thealthy\tNone"); sys.exit(0)
if c == ["ecr", "describe-repositories"]: print("IMMUTABLE"); sys.exit(0)
if c == ["ecr", "describe-images"]: sys.exit(254)  # the tag is not in ECR yet
if c == ["ecr", "get-login-password"]: print("fake-token"); sys.exit(0)
if c == ["s3api", "head-bucket"]: sys.exit(0 if arg("--expected-bucket-owner") == "935951870001" else 1)
if c == ["s3api", "put-object"] and os.environ.get("FAKE_S3_PUT") == "deny":
    print("An error occurred (AccessDenied) when calling the PutObject operation: Access Denied", file=sys.stderr); sys.exit(254)
if c == ["s3api", "delete-object"] and os.environ.get("FAKE_S3_DELETE") == "deny":
    print("An error occurred (AccessDenied) when calling the DeleteObject operation: Access Denied", file=sys.stderr); sys.exit(254)
if c[0] == "s3api" and c[1] in ("put-object", "delete-object"): sys.exit(0 if arg("--expected-bucket-owner") == "935951870001" else 1)
if c == ["iam", "simulate-principal-policy"]: print(os.environ.get("FAKE_SIM", "allowed")); sys.exit(0)
if c == ["backup", "describe-backup-vault"]: print("v"); sys.exit(0)
if c == ["backup", "start-backup-job"]: print("job-42"); sys.exit(0)
if c == ["backup", "describe-backup-job"]:
    k = count("bj")
    if k == 0: print("An error occurred (ThrottlingException): Rate exceeded", file=sys.stderr); sys.exit(254)
    print("COMPLETED\t100.0" if k >= 2 else "RUNNING\t40.0"); sys.exit(0)
print("fake aws: unhandled " + " ".join(a), file=sys.stderr); sys.exit(1)
'''
FAKE_SSH = r'''#!/bin/bash
for last; do :; done
case "$*" in *" -O exit "*) exit 0;; esac
echo "ssh $last" >> "$FAKE_DIR/calls.log"
if [ -n "${FAKE_SSH_DROP:-}" ]; then  # the connection drops while remote.sh $FAKE_SSH_DROP runs
  case "$last" in *"remote.sh $FAKE_SSH_DROP"*) echo "Connection to UNKNOWN closed by remote host." >&2; exit 255;; esac
fi
case "$last" in
  true) exit 0;;
  *"tar -xzf -"*) cat >/dev/null; exit 0;;
  *"remote.sh volume-exists"*) case "${FAKE_VOL:-no}" in fail) echo "Connection closed" >&2; exit 255;; *) echo "${FAKE_VOL:-no}";; esac;;
  *"remote.sh job-start"*) echo "20261122T120000Z-$(sed -E 's/.*job-start ([a-z-]+).*/\1/' <<<"$last")-4242";;
  *"remote.sh infra-missing"*) echo "qdrant/qdrant:v1.13.5";;
  *"nginx-health"*) echo ok;;
  *"remote.sh job-follow"*) n=$(cat "$FAKE_DIR/jf" 2>/dev/null || echo 0); echo $((n+1)) > "$FAKE_DIR/jf"
     if [ "$n" = 0 ]; then echo "Connection closed by remote host" >&2; exit 255; fi
     echo "job output"; echo "chola-job: done ${FAKE_JOB_RC:-0} 11" >&2; echo 1 > "$FAKE_DIR/jf";;
  *) exit 0;;
esac
'''
FAKE_GIT_TMPL = r'''#!/bin/bash
case "$*" in
  *fetch*ansh*) echo "git $*" >> "$FAKE_DIR/calls.log"; [ "${FAKE_ANSH:-ok}" = missing ] && exit 128; exit 0;;
  *ls-remote*ansh*) echo "git $*" >> "$FAKE_DIR/calls.log"; [ "${FAKE_ANSH:-ok}" = missing ] && exit 2; exit 0;;
  *"cat-file -e refs/remotes/origin/ansh:backend/.env"*) echo "git $*" >> "$FAKE_DIR/calls.log"; [ "${FAKE_ANSH:-ok}" = nofile ] && exit 128; exit 0;;
  *"show refs/remotes/origin/ansh:backend/.env"*) echo "git $*" >> "$FAKE_DIR/calls.log"
     if [ "${FAKE_ANSH:-ok}" = nokeys ]; then echo 'OTHER=1'; else printf 'OUTLOOK_EMAIL="dummy@example.com"\nOUTLOOK_PASSWORD="dummy-pass-1"\n'; fi; exit 0;;
  *"rev-parse --short=12 refs/remotes/origin/ansh"*) echo 0123456789ab; exit 0;;
esac
exec REALGIT "$@"
'''
FAKE_OTHER = '#!/bin/sh\necho "$(basename "$0") $*" >> "$FAKE_DIR/calls.log"\nexit 0\n'
FAKE_DOCKER = r'''#!/bin/sh
echo "docker $* [DOCKER_CONFIG=${DOCKER_CONFIG:-default}]" >> "$FAKE_DIR/calls.log"
case "$1" in
  context) echo "unix:///var/run/docker.sock";;
  info) [ "$2" = "--format" ] && echo '[["driver-type","io.containerd.snapshotter.v1"]]';;
  login) cat >/dev/null;;
  create) echo cid123;;
  cp) echo "chunk https://chola-api.zeroshield.ai";;
  push|save|image) case "$*" in *--help*) echo "  --platform string"; exit 0;; esac
     case "$*" in *"image inspect"*) case "$*" in *revision*) echo "";; *) echo "linux/amd64";; esac; exit 0;; esac
     [ "$1" = save ] && { o=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && o=$2; shift; done; echo fake > "$o"; };;
  buildx) case "$2" in build) cat >/dev/null;; imagetools) case "$*" in *dev-*) exit 0;; esac; exit 1;; esac;;
esac
exit 0
'''
FAKE_CURL = r'''#!/bin/sh
echo "curl $*" >> "$FAKE_DIR/calls.log"
case "$*" in
  *"-I --max-time 30 https://chola.zeroshield.ai/login"*) printf 'HTTP/2 200\r\nstrict-transport-security: max-age=31536000\r\n\r\n';;
  *"-w %{http_code} --max-time 30 -I https://chola.zeroshield.ai"*) printf '307';;
  *"chola-api.zeroshield.ai/health"*) printf '{"status":"healthy"}\n200';;
esac
exit 0
'''
FAKE_GH = '#!/bin/sh\necho "gh $*" >> "$FAKE_DIR/calls.log"\ncase "$*" in "auth token") echo tok;; "api user --jq .login") echo owner;; esac\nexit 0\n'


def hermetic_env(bin_dir, home, tmp, **extra):
    """A process environment built from nothing (CI's own AWS_*, HOME, PATH or config can never leak in): the fakes
    first, then only the directories of the real tools the scripts need."""
    tools = ("bash", "python3", "git", "sort", "sed", "awk", "mktemp", "tar", "flock", "setsid", "stat", "date")
    dirs = []
    for tool in tools:
        found = shutil.which(tool)
        if found and os.path.dirname(found) not in dirs:
            dirs.append(os.path.dirname(found))
    env = {"PATH": ":".join([str(bin_dir), *dirs, "/usr/bin", "/bin"]), "HOME": str(home), "TMPDIR": str(tmp),
           "LANG": "C.UTF-8", "LC_ALL": "C",
           # junk credentials and no config: a real aws CLI, if one were reached, could not talk to any account
           "AWS_ACCESS_KEY_ID": "AKIAJUNKJUNKJUNKJUNK", "AWS_SECRET_ACCESS_KEY": "junk", "AWS_DEFAULT_REGION": "us-east-1",
           "AWS_CONFIG_FILE": "/nonexistent/aws-config", "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent/aws-credentials",
           "AWS_EC2_METADATA_DISABLED": "true", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}
    env.update(extra)
    return env


@pytest.fixture
def fake_world(tmp_path):
    """aws, ssh, docker, gh, curl and a git wrapper (origin/ansh only) on PATH, in an environment built from scratch;
    nothing reaches a real service."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("aws", FAKE_AWS), ("ssh", FAKE_SSH),
                       ("git", FAKE_GIT_TMPL.replace("REALGIT", shutil.which("git") or "/usr/bin/git")),
                       ("docker", FAKE_DOCKER), ("gh", FAKE_GH), ("curl", FAKE_CURL)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    (tmp_path / "home").mkdir()

    def call(*args, **env):
        e = hermetic_env(bin_dir, tmp_path / "home", tmp_path, FAKE_DIR=str(tmp_path), CHOLA_POLL_S="0", **env)
        return run(["bash", str(OWNER), *args], env=e, stdin=subprocess.DEVNULL)
    call.dir = tmp_path
    call.log = lambda: (tmp_path / "calls.log").read_text() if (tmp_path / "calls.log").exists() else ""
    return call


def test_secrets_first_setup_reads_ansh_with_an_explicit_refspec(fake_world):
    proc = fake_world("secrets")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "fetch -q origin +refs/heads/ansh:refs/remotes/origin/ansh" in fake_world.log()
    stored = json.loads((fake_world.dir / "app-secrets.json").read_text())
    assert stored["SMTP_USERNAME"] == "dummy@example.com"
    assert "dummy-pass-1" not in proc.stdout + proc.stderr
    assert not list(fake_world.dir.glob("chola-prod.*"))  # scratch (key, mail copy) removed


def test_secrets_rerun_and_deploy_never_touch_ansh(fake_world):
    assert fake_world("secrets").returncode == 0
    (fake_world.dir / "calls.log").unlink()
    proc = fake_world("secrets")
    assert proc.returncode == 0 and "origin/ansh not read" in proc.stdout
    assert "ansh" not in fake_world.log()


@pytest.mark.parametrize("mode, message", [("missing", "origin has no branch 'ansh'"),
                                           ("nofile", "has no backend/.env"),
                                           ("nokeys", "lacks OUTLOOK_EMAIL / OUTLOOK_PASSWORD")])
def test_mail_source_errors_are_distinct(fake_world, mode, message):
    proc = fake_world("secrets", FAKE_ANSH=mode)
    assert proc.returncode == 1 and message in proc.stderr and "--mail-prompt" in proc.stderr
    assert not (fake_world.dir / "app-secrets.json").exists()


def test_mail_prompt_needs_a_terminal(fake_world):
    proc = fake_world("secrets", "--mail-prompt")
    assert proc.returncode == 1 and "needs a terminal" in proc.stderr


def test_secrets_fail_closed_when_the_volume_check_fails(fake_world):
    proc = fake_world("secrets", FAKE_VOL="fail")
    assert proc.returncode == 1 and "cannot tell whether the instance already has database volumes" in proc.stderr
    assert "put-secret-value" not in fake_world.log()


def test_secrets_refuse_new_data_keys_when_data_exists(fake_world):
    (fake_world.dir / "app-secrets.json").write_text(json.dumps({"PG_USER_PASS": ""}))
    proc = fake_world("secrets", FAKE_VOL="yes")
    assert proc.returncode == 1 and "lock the application out" in proc.stderr
    assert "put-secret-value" not in fake_world.log()


def test_backup_retries_a_throttled_poll_and_follows_a_dropped_job(fake_world):
    proc = fake_world("backup")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "describe-backup-job failed (1/10" in proc.stderr and "COMPLETED" in proc.stdout
    assert "no answer from the instance while following" in proc.stderr and "job output" in proc.stdout


def test_verify_accepts_an_ip_target_after_a_throttled_poll(fake_world):
    proc = fake_world("verify")
    assert "describe-target-health failed (1/10" in proc.stderr
    assert "ALB target: 10.60.10.108 80 healthy" in proc.stdout


@pytest.mark.parametrize("env, allow, ok", [({"FAKE_HOP": "2"}, False, False), ({"FAKE_TOKENS": "optional"}, False, False),
                                            ({"FAKE_HOP": "2"}, True, True)])
def test_imds_options_fail_preflight_unless_allowed(fake_world, env, allow, ok):
    args = ["preflight"] + (["--allow-imds"] if allow else [])
    proc = fake_world(*args, **env)
    assert ("HttpPutResponseHopLimit" in proc.stderr) and ((proc.returncode == 0) == ok), proc.stderr


def test_preflight_refuses_a_denied_passrole(fake_world):
    proc = fake_world("preflight", FAKE_SIM="implicitDeny")
    assert proc.returncode == 1 and "iam:PassRole" in proc.stderr and "implicitDeny" in proc.stderr


def test_preflight_runs_remote_from_a_run_copy_not_the_live_kit(fake_world):
    assert fake_world("preflight").returncode == 0
    log = fake_world.log()
    assert "/opt/devsecshield-chola/.kit/" in log and "CHOLA_BASE_DIR=/opt/devsecshield-chola" in log
    assert "tar -xzf - -C /opt/devsecshield-chola " not in log + " "  # never extracted over the live tree


def test_logins_use_a_throwaway_docker_config():
    text = OWNER.read_text()
    body = text.split("cmd_images() {", 1)[1].split("\n}\n", 1)[0]
    assert body.index("docker_isolate") < body.index("ghcr_login") < body.index("ecr_login_local")
    assert 'export DOCKER_CONFIG="${cfg}"' in text and '"${WORK}/docker-config"' in text


def _shims(tmp_path):
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("aws", "ssh", "docker", "gh", "curl", "scp", "gpg", "unzip"):
        p = shim_dir / tool
        p.write_text(f"#!/bin/sh\necho \"{tool} $*\" >> {log}\nexit 97\n")
        p.chmod(0o755)
    real = shutil.which("git") or "/usr/bin/git"
    (shim_dir / "git").write_text(f"#!/bin/sh\ncase \"$*\" in *fetch*|*ls-remote*|*ansh*) echo \"git $*\" >> {log};; esac\n"
                                  f"exec {real} \"$@\"\n")
    (shim_dir / "git").chmod(0o755)
    return shim_dir, log


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("args", [["secrets"], ["secrets", "--refresh-mail"], ["backup"], ["verify"],
                                  ["rollback", "--allow-downgrade"], ["status"], ["logs", "--service", "backend"],
                                  ["smtp-test"], ["admin", "--email", "a@b.co"], ["host-setup"], ["infra"],
                                  ["attach", "--job", "20261122T120000Z-deploy-1"], ["--dry-run", "status"]])
def test_dry_run_touches_nothing(tmp_path, args):
    shim_dir, log = _shims(tmp_path)
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}", HOME=str(tmp_path), TMPDIR=str(tmp_path))
    proc = run(["bash", str(OWNER), *args, "--dry-run"] if "--dry-run" not in args else ["bash", str(OWNER), *args],
               env=env, stdin=subprocess.DEVNULL)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "[dry-run]" in proc.stdout
    assert not log.exists(), log.read_text()  # no AWS/SSH/Docker/registry call, no git fetch, no origin/ansh read
    assert not list(tmp_path.glob("chola-prod.*"))  # the scratch directory is removed


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_dry_run_deploy_summary_says_skipped(tmp_path):
    head = run(["git", "-C", str(REPO), "rev-parse", "HEAD"]).stdout.strip()
    shim_dir, log = _shims(tmp_path)
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}", HOME=str(tmp_path), TMPDIR=str(tmp_path))
    proc = run(["bash", str(OWNER), "--dry-run", "deploy", "--sha", head], env=env, stdin=subprocess.DEVNULL)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    summary = proc.stdout.split("==== summary", 1)[1]
    assert "OK" not in summary and "COMPLETED" not in summary and summary.count("skipped (dry-run)") >= 6
    assert not log.exists()


def test_owner_script_refuses_production_without_confirmation(tmp_path):
    shim_dir, log = _shims(tmp_path)
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}", HOME=str(tmp_path), TMPDIR=str(tmp_path))
    proc = run(["bash", str(OWNER), "rollback"], env=env, stdin=subprocess.DEVNULL)
    assert proc.returncode == 1 and "confirmation" in proc.stderr
    assert not log.exists()


@pytest.mark.parametrize("args", [["--help"], ["-h"], ["deploy", "--help"], ["--help", "rollback"], []])
def test_help_documents_commands_flags_and_environment(args):
    proc = run(["bash", str(OWNER), *args])
    assert proc.returncode == 0
    for word in ("attach --job", "--mail-prompt", "--refresh-mail", "--allow-imds", "--allow-downgrade", "--dry-run",
                 "CHOLA_POLL_RETRIES", "CHOLA_KNOWN_HOSTS", "AWS_PROFILE"):
        assert word in proc.stdout, word
    assert "set -" not in proc.stdout and "REPO_ROOT" not in proc.stdout  # usage text, not script lines


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_full_deploy_twice_in_the_fake_world(fake_world):
    """deploy --yes end to end against fakes: every step in order; the first run sets up app-secrets (reading the
    dummy origin/ansh), the second reads origin/ansh not at all; no secret value is ever printed or logged."""
    head = run(["git", "-C", str(REPO), "rev-parse", "HEAD"]).stdout.strip()
    first = fake_world("deploy", "--sha", head, "--yes")
    assert first.returncode == 0, first.stdout[-3000:] + first.stderr[-3000:]
    log1 = fake_world.log()
    steps = [m for m in re.findall(r"remote\.sh (?:job-start )?([a-z-]+)", log1) if m != "job-follow"]
    order = ["preflight", "volume-exists", "render", "ecr-login", "pull", "infra-missing", "infra-load", "dump",
             "deploy", "smtp-test", "check"]
    assert [s for s in dict.fromkeys(steps) if s in order] == order, steps
    assert "fetch -q origin +refs/heads/ansh:refs/remotes/origin/ansh" in log1
    assert "preflight-probe" in log1 and "delete-object" in log1
    assert "DOCKER_CONFIG=default] login" not in log1 and "[DOCKER_CONFIG=" in log1  # logins never in the real config
    summary = first.stdout.split("==== summary", 1)[1]
    for word in ("secrets: app-secrets updated", "deploy:", "verify: ALB target healthy"):
        assert word in summary
    (fake_world.dir / "calls.log").unlink()
    second = fake_world("deploy", "--sha", head, "--yes")
    assert second.returncode == 0 and "app-secrets unchanged" in second.stdout, second.stderr[-2000:]
    assert "ansh" not in fake_world.log()
    stored = json.loads((fake_world.dir / "app-secrets.json").read_text())
    everything = log1 + fake_world.log() + first.stdout + first.stderr + second.stdout + second.stderr
    assert [k for k, v in stored.items() if v in everything] == []
    assert not list(fake_world.dir.glob("chola-prod.*"))


def test_the_fake_aws_is_the_one_used(fake_world):
    proc = fake_world("verify")
    assert "aws --region ap-south-1 elbv2 describe-target-health" in fake_world.log(), proc.stderr


# CI (5317b1fd, dss-vm, non-root): cmd_verify wrote "${WORK}/err" while WORK was still empty, i.e. to /err; as root that
# silently worked (this sandbox), as a normal user every poll "failed". main now creates the scratch dir first.
def test_scratch_directory_exists_before_any_step():
    body = OWNER.read_text().split("main() {", 1)[1]
    assert body.index("\n  work\n") < body.index('case "${CMD}" in')


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which("runuser") is None, reason="needs root to drop to nobody")
def test_verify_as_a_non_root_user_like_the_ci_runner():
    import tempfile
    base = Path(tempfile.mkdtemp(prefix="chola-nonroot-"))
    try:
        base.chmod(0o777)
        bin_dir = base / "bin"
        bin_dir.mkdir()
        for name, body in (("aws", FAKE_AWS), ("ssh", FAKE_SSH), ("docker", FAKE_OTHER), ("gh", FAKE_OTHER),
                           ("curl", FAKE_OTHER)):
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        (base / "home").mkdir()
        (base / "home").chmod(0o777)
        env = hermetic_env(bin_dir, base / "home", base, FAKE_DIR=str(base), CHOLA_POLL_S="0")
        proc = run(["runuser", "-u", "nobody", "--", "env", "-i", *[f"{k}={v}" for k, v in env.items()],
                    "bash", str(OWNER), "verify"], stdin=subprocess.DEVNULL)
        assert "ALB target: 10.60.10.108 80 healthy" in proc.stdout, proc.stdout + proc.stderr
        assert "Permission denied" not in proc.stderr
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_one_error_line_per_failure(fake_world):
    proc = fake_world("secrets", FAKE_VOL="fail")
    errors = [line for line in proc.stderr.splitlines() if "ERROR" in line]
    assert len(errors) == 1 and "cannot tell whether" in errors[0], proc.stderr
    proc = fake_world("rollback")  # no terminal, no --yes
    assert [line for line in proc.stderr.splitlines() if "ERROR" in line] == \
        ["[chola] ERROR: Roll back needs confirmation: run it in a terminal or pass --yes"]


def test_ctrl_c_message_is_the_last_word(fake_world):
    e = hermetic_env(fake_world.dir / "bin", fake_world.dir / "home", fake_world.dir, FAKE_DIR=str(fake_world.dir),
                     CHOLA_POLL_S="0", FAKE_SLOW="1")
    (fake_world.dir / "bin" / "ssh").write_text(FAKE_SSH.replace('*"remote.sh job-follow"*)', '*"remote.sh job-follow"*) [ -n "$FAKE_SLOW" ] && sleep 20;'))
    p = subprocess.Popen(["bash", str(OWNER), "attach", "--job", "20261122T120000Z-deploy-1"], env=e,
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         start_new_session=True)
    time.sleep(3)
    os.killpg(p.pid, signal.SIGINT)  # a terminal's Ctrl-C reaches the whole foreground group
    _, err = p.communicate(timeout=60)
    assert p.returncode == 130 and "KEEPS RUNNING" in err and "attach --job 20261122T120000Z-deploy-1" in err
    assert "ERROR" not in err.split("KEEPS RUNNING", 1)[1]
    assert not list(fake_world.dir.glob("chola-prod.*"))


def test_mail_prompt_without_a_terminal_stops_before_any_call(fake_world):
    proc = fake_world("secrets", "--mail-prompt")
    assert proc.returncode == 1 and "needs a terminal" in proc.stderr
    assert fake_world.log() == ""


def test_data_check_comes_before_reading_ansh(fake_world):
    (fake_world.dir / "app-secrets.json").write_text("{}")
    proc = fake_world("secrets", FAKE_VOL="yes")
    assert proc.returncode == 1 and "lock the application out" in proc.stderr
    assert "ansh" not in fake_world.log() and "put-secret-value" not in fake_world.log()


def test_instance_settings_and_the_s3_probe_reach_the_instance(fake_world):
    proc = fake_world("preflight", CHOLA_MIN_FREE_GB="20", CHOLA_WAIT_S="1200", CHOLA_DUMPS_KEEP="5")
    assert proc.returncode == 0, proc.stderr
    log = fake_world.log()
    assert "CHOLA_MIN_FREE_GB=20 CHOLA_WAIT_S=1200 CHOLA_DUMPS_KEEP=5 CHOLA_S3_PROBE_KEY=releases/preflight-probe.txt " in log
    put = re.search(r"s3api put-object --bucket devsecshield-storage --key (releases/preflight-probe\S+) .*"
                    r"--expected-bucket-owner 935951870001", log)
    assert put and f"s3api delete-object --bucket devsecshield-storage --key {put.group(1)}" in log
    assert fake_world("preflight", CHOLA_WAIT_S="9; rm -rf /").returncode == 1


def test_owner_reports_a_lost_job(fake_world):
    (fake_world.dir / "bin" / "ssh").write_text(FAKE_SSH.replace(
        'echo "chola-job: done ${FAKE_JOB_RC:-0} 11" >&2;', 'echo "chola-job: lost 11" >&2;'))
    assert "chola-job: lost 11" in (fake_world.dir / "bin" / "ssh").read_text()
    proc = fake_world("attach", "--job", "20261122T120000Z-deploy-1")
    assert proc.returncode == 1 and "ended WITHOUT an exit status" in proc.stderr and "rollback" in proc.stderr


# QA R2: an SSH drop during a plain remote step ends with ONE kit error line that names the step and says what to do.
@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("step", ["render", "ecr-login", "pull"])
def test_ssh_drop_during_a_remote_step_names_the_step(fake_world, step):
    head = run(["git", "-C", str(REPO), "rev-parse", "HEAD"]).stdout.strip()
    proc = fake_world("deploy", "--sha", head, "--yes", FAKE_SSH_DROP=step)
    errors = [line for line in proc.stderr.splitlines() if "ERROR" in line]
    assert proc.returncode == 1 and len(errors) == 1, proc.stderr[-3000:]
    assert errors[0].startswith(f"[chola] ERROR: remote.sh {step}: the SSH connection to i-0b7fe756ebfd4d1e6 failed or "
                                "dropped (exit 255") and "nothing was switched yet: re-run the deploy" in errors[0]
    assert "Connection to UNKNOWN closed by remote host." in proc.stderr  # ssh's own message stays visible
    assert "job-start deploy" not in fake_world.log() and f"remote.sh {step}" in fake_world.log()
    assert not list(fake_world.dir.glob("chola-prod.*"))


def test_remote_step_names_a_failure_of_remote_sh_itself(fake_world):
    (fake_world.dir / "bin" / "ssh").write_text(FAKE_SSH.replace(
        '  *"nginx-health"*) echo ok;;',
        '  *"nginx-health"*) echo ok;;\n  *"remote.sh status"*) echo "[chola-remote] ERROR: boom" >&2; exit 1;;'))
    proc = fake_world("status")
    errors = [line for line in proc.stderr.splitlines() if "ERROR" in line]
    assert proc.returncode == 1 and errors == ["[chola-remote] ERROR: boom",
                                               "[chola] ERROR: remote.sh status failed on the instance (exit 1, above)"]


# Architecture nit: one fixed probe key (never a pile of probes), and a loud warning when it cannot be deleted.
def test_preflight_probe_uses_one_key_and_warns_when_it_cannot_delete_it(fake_world):
    for _ in range(2):
        proc = fake_world("preflight", FAKE_S3_DELETE="deny")
        assert proc.returncode == 0, proc.stderr
        assert "could NOT delete the preflight probe object s3://devsecshield-storage/releases/preflight-probe.txt" in proc.stderr
        assert "AccessDenied" in proc.stderr and "overwrites" in proc.stderr
    keys = set(re.findall(r"s3api put-object --bucket devsecshield-storage --key (\S+)", fake_world.log()))
    assert keys == {"releases/preflight-probe.txt"}
    assert not list(fake_world.dir.glob("chola-prod.*"))
    proc = fake_world("preflight")
    assert proc.returncode == 0 and "could NOT delete" not in proc.stderr


def _failing_local_tar(fake_world):
    real_tar = shutil.which("tar")
    (fake_world.dir / "bin" / "tar").write_text(
        '#!/bin/sh\ncase "$*" in *"-cf - deploy/chola-prod"*) echo "tar: write error: No space left on device" >&2; exit 2;; esac\n'
        f'exec {real_tar} "$@"\n')
    (fake_world.dir / "bin" / "tar").chmod(0o755)


def _stopped_before_any_remote_call(fake_world, proc):
    errors = [line for line in proc.stderr.splitlines() if "ERROR" in line]
    assert proc.returncode == 1 and "No space left on device" in proc.stderr, proc.stdout + proc.stderr
    assert len(errors) == 1 and errors[0].startswith("[chola] ERROR: preparing the kit copy in ") and \
        "nothing was sent to the instance" in errors[0], proc.stderr
    assert "remote.sh" not in fake_world.log() and "tar -xzf -" not in fake_world.log()
    assert not list(fake_world.dir.glob("chola-prod.*"))


# Round-4 F3: a failed LOCAL staging copy of the kit stops the run before anything runs on the instance.
@pytest.mark.parametrize("args", [["status"], ["preflight"], ["logs", "--service", "backend"]])
def test_a_failed_local_kit_copy_stops_the_run(fake_world, args):
    _failing_local_tar(fake_world)
    _stopped_before_any_remote_call(fake_world, fake_world(*args))


# Round-5 L2: the same where the first upload runs on the left of `||` (remote_job dump || die): errexit is off there,
# so kit_upload's own `|| die` must stop it. At 2f234fb3, backup exited 0 and rollback made 8 remote calls.
@pytest.mark.parametrize("args", [["backup"], ["rollback", "--yes"], ["rollback", "--yes", "--allow-downgrade"]])
def test_a_failed_local_kit_copy_stops_backup_and_rollback(fake_world, args):
    _failing_local_tar(fake_world)
    _stopped_before_any_remote_call(fake_world, fake_world(*args))


# Round-4 F5 (owner side): --to reaches both the plan and the job; anything but a commit id is refused before any call.
@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_owner_rollback_to_passes_the_tag_through(fake_world):
    full = "a" * 40
    proc = fake_world("rollback", "--to", full, "--allow-downgrade", "--yes")
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    log = fake_world.log()
    assert f"remote.sh rollback --plan --to {A12}" in log
    assert f"remote.sh job-start rollback --allow-downgrade --to {A12}" in log
    (fake_world.dir / "calls.log").unlink()
    bad = fake_world("rollback", "--to", "main", "--yes")
    assert bad.returncode == 1 and "--to needs a 12- or 40-character commit" in bad.stderr and fake_world.log() == ""


# Round-4 nit: cleanup deletes the probe only when THIS run put it (a failed put never deletes another run's probe).
def test_preflight_deletes_no_probe_it_did_not_put(fake_world):
    proc = fake_world("preflight", FAKE_S3_PUT="deny")
    assert proc.returncode == 1 and "cannot write the probe object" in proc.stderr
    assert "put-object" in fake_world.log() and "delete-object" not in fake_world.log()


# QA nit: preflight is not called read-only: it writes (and deletes) the S3 probe and copies the kit to the instance.
def test_preflight_is_not_documented_as_read_only():
    help_text = run(["bash", str(OWNER), "--help"]).stdout
    block = help_text.split("  preflight [--sha S]", 1)[1].split("\n  host-setup", 1)[0]
    assert "read-only" not in block and "WRITES" in block and "releases/preflight-probe.txt" in block.replace("\n", "").replace(" ", "")
    text = README.read_text()
    for line in text.splitlines():
        if "chola-prod.sh preflight" in line or line.lstrip().startswith("preflight "):
            assert "read-only" not in line, line
    probe = " ".join(text.split("releases/preflight-probe.txt", 1)[1].split()[:60])
    assert "overwritten by every preflight" in probe and "WARNING" in probe


# Round-4 nits: --help says a failed rollback is retried and offers --to; the probe wording names its limits; the
# README no longer says an interrupted job is always LOST.
def test_help_and_readme_describe_retry_escape_and_probe_limits():
    help_text = run(["bash", str(OWNER), "--help"]).stdout
    entry = help_text.split("\n  rollback ", 1)[1].split("\n  attach ", 1)[0]
    assert "RETRIED" in entry and "never taken one release further back" in entry and "--to TAG" in entry
    assert "--to TAG" in help_text.split("Flags", 1)[1]
    text = " ".join(README.read_text().split())
    assert "unversioned bucket" in text and "Any two owner commands that run a preflight at the same moment" in text
    assert "exit 143" in text and "never 0" in text and "rollback --to <tag>" in text
    assert "A job listed as LOST ended without an exit status (reboot or kill)" not in text


# Round-5 doc nits: a SIGKILLed rollback leaves ROLLBACK-STARTED (not FAILED); `kill` waits for the current step;
# --to never goes forward and status lists its candidates.
def test_readme_round5_wording():
    text = " ".join(README.read_text().split())
    assert "when the job is killed during them it is left unfinished, with ROLLBACK-STARTED last" in text
    assert "they fail (or the job is killed during them) it records FAILED" not in text
    assert "is not immediate" in text and "CHOLA_WAIT_S" in text.split("is not immediate", 1)[1][:200]
    assert "kill -9" in text and "not newer" in text and "`status` lists the releases `--to` accepts" in text
    help_text = " ".join(run(["bash", str(OWNER), "--help"]).stdout.split())
    assert "Never forward: that is deploy --sha" in help_text and "--to TAG rollback only" in help_text


# Round-6 doc nits: signal exits need the wrapper; a kill during the checks leaves ROLLBACK-STARTED or FAILED; a plain
# rollback can go "forward" after a redeploy of an old commit while --to cannot.
def test_readme_round6_wording():
    text = " ".join(README.read_text().split())
    assert "records 128 + its number while the job's wrapper process lives, and reads as LOST if the wrapper was killed" in text
    assert "with ROLLBACK-STARTED last (SIGKILL) or FAILED last (a whole-session SIGTERM" in text
    assert "a plain rollback goes \"forward\" to C (A's recorded predecessor) while `--to C` is refused as newer" in text
    assert "a deploy interrupted after its switch counts as the newest" in text


# ------------------------------------------------------------------------------------------------ README
def test_readme_never_asks_to_commit_a_password_and_lists_rotations():
    text = README.read_text()
    assert not re.search(r"update[^.\n]*(password|mailbox)[^.\n]*origin/ansh", text, re.IGNORECASE)
    section0 = text.split("## 0.", 1)[1].split("\n## 1.", 1)[0]
    assert "mailbox password" in section0.lower() and "backend/.env" in section0
    assert "-N ''" not in text and "ssh-keygen" in text  # no unencrypted key written into the cwd
    assert "off the instance" in text.lower() or "off-host" in text.lower()  # copy the dumps elsewhere
    for host_kind in ("DAST", "IdP metadata", "Integrations", "Certificate Transparency"):
        assert host_kind in text.split("## 9.", 1)[1]


# ------------------------------------------------------------------------------------------------ SMTP login check
def _load_smtp_check():
    return _load("chola_smtp_check", KIT_DIR / "smtp_check.py")


class _FakeSMTP:
    """Stands in for smtplib.SMTP: offers STARTTLS and AUTH, then answers the login with `reply`."""
    reply = None
    sent: list = []  # noqa: RUF012 (reset by each test)

    def __init__(self, host, port, timeout=None):
        self.extns = {"starttls", "auth"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        return 250, b"ok"

    def has_extn(self, name):
        return name in self.extns

    def starttls(self, context=None):
        return 220, b"ready"

    def login(self, user, password):
        if self.reply:
            import smtplib
            raise smtplib.SMTPAuthenticationError(535, self.reply.encode())
        return 235, b"ok"

    def quit(self):
        return 221, b"bye"

    def sendmail(self, *a, **k):  # never called: the check sends nothing
        self.sent.append(a)

    send_message = sendmail


@pytest.mark.parametrize("reply, code, words", [
    (None, 0, "OK"),
    ("5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Tenant. Visit https://aka.ms/smtp_auth_disabled", 2, "whole tenant"),
    ("5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Mailbox. Visit https://aka.ms/smtp_auth_disabled", 2, "this mailbox"),
    ("5.7.139 Authentication unsuccessful, basic authentication is disabled.", 2, "Basic authentication"),
    ("5.7.139 Authentication unsuccessful, the request did not meet the criteria to be authenticated successfully.", 2, "tenant policy"),
    ("5.7.139 Authentication unsuccessful, the user credentials were incorrect. hunter2-secret", 3, "password was refused"),
])
def test_smtp_check_classifies_office365_answers_and_never_prints_the_password(monkeypatch, capsys, reply, code, words):
    sc = _load_smtp_check()
    _FakeSMTP.reply, _FakeSMTP.sent = reply, []
    monkeypatch.setattr(sc.smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setenv("SMTP_HOST", "smtp.office365.com")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_SECURITY", "starttls")
    monkeypatch.setenv("SMTP_USERNAME", "mailbox@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "hunter2-secret")
    assert sc.main() == code
    out = capsys.readouterr().out
    assert words in out and "hunter2-secret" not in out and "mailbox@example.com" not in out
    assert _FakeSMTP.sent == []


def test_smtp_check_refuses_to_send_a_password_without_starttls_or_auth(monkeypatch):
    sc = _load_smtp_check()

    class NoTLS(_FakeSMTP):
        def __init__(self, *a, **k):
            self.extns = {"auth"}

    class NoAuth(_FakeSMTP):
        def __init__(self, *a, **k):
            self.extns = {"starttls"}

    for cls, code in ((NoTLS, 4), (NoAuth, 2)):
        monkeypatch.setattr(sc.smtplib, "SMTP", cls)
        for k, v in (("SMTP_HOST", "h"), ("SMTP_USERNAME", "u@x.y"), ("SMTP_PASSWORD", "pw-123456")):
            monkeypatch.setenv(k, v)
        assert sc.main() == code
    monkeypatch.delenv("SMTP_PASSWORD")
    assert sc.main() == 5
