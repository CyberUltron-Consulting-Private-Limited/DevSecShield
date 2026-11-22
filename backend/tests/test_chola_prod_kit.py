"""The Chola production deploy kit (deploy/chola-prod/, scripts/deploy/chola-prod.sh; README there).

* kit.py merge-app-secrets: the first run generates every secret with the CSPRNG, a re-run KEEPS every existing value
  (put-secret-value replaces the whole JSON), unusable stored values are refused instead of replaced, the mail login
  comes from the ansh branch's .env format (quotes, trailing comments), and nothing prints a value;
* kit.py render-env: which keys land in .env / backend.env, quoting, no dev switches, app-user field aliases;
* docker-compose.yml: only nginx publishes a port (80), databases only on the internal network, every image the kit
  ships in the release archive is the one compose runs, backend on 8080, no dev settings;
* nginx: /nginx-health, real_ip from the ALB subnets only, X-Forwarded-Proto believed only from them;
* `chola-prod.sh --dry-run` runs no AWS / SSH / Docker / registry command.

Run: cd backend && python -m pytest tests/test_chola_prod_kit.py -q -p no:cacheprovider
"""
import base64
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
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


def _load_kit():
    spec = importlib.util.spec_from_file_location("chola_kit", KIT_DIR / "kit.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kit = _load_kit()

ANSH_ENV = (
    'JWT_SECRET_KEY=whatever\n'
    'OUTLOOK_EMAIL="support@example.com" #not in use \n'
    'OUTLOOK_PASSWORD="p@ss#word 1" #not in use \n'
    'TENANT_ID =abc\n'
)


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


def test_rerun_preserves_every_existing_value_and_reports_unchanged():
    first, _, _ = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    first["SOMETHING_ELSE"] = "kept-as-is"
    again, report, changed = kit.merge_app_secrets(dict(first), kit.parse_dotenv(ANSH_ENV))
    assert again == first and not changed
    assert "SOMETHING_ELSE: kept (not managed by the kit)" in report


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


def test_merge_cli_writes_mode_600_and_prints_no_value(tmp_path):
    cur = tmp_path / "cur.json"
    cur.write_text("")  # an empty secret (no value yet)
    mail = tmp_path / "mail.env"
    mail.write_text(ANSH_ENV)
    out = tmp_path / "out.json"
    run = subprocess.run(["python3", "-I", str(KIT_DIR / "kit.py"), "merge-app-secrets", "--existing", str(cur),
                          "--mail-env", str(mail), "--out", str(out)], capture_output=True, check=False, text=True)
    assert run.returncode == 0, run.stderr
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    merged = json.loads(out.read_text())
    for value in merged.values():
        assert value not in run.stdout and value not in run.stderr
    # re-run on its own output: unchanged (exit 3), nothing new
    cur.write_text(out.read_text())
    again = subprocess.run(["python3", "-I", str(KIT_DIR / "kit.py"), "merge-app-secrets", "--existing", str(cur),
                            "--mail-env", str(mail), "--out", str(out)], capture_output=True, check=False, text=True)
    assert again.returncode == 3 and json.loads(out.read_text()) == merged


def test_json_field_aliases_and_names_only_error():
    assert kit.json_field({"AccessKeyId": "AKIA1"}, kit.ACCESS_KEY_NAMES) == "AKIA1"
    assert kit.json_field({"aws_secret_access_key": "s"}, kit.SECRET_KEY_NAMES) == "s"
    run = subprocess.run(["python3", "-I", str(KIT_DIR / "kit.py"), "json-field", "private_key_pem"],
                         input=json.dumps({"other": "TOPSECRET"}), capture_output=True, check=False, text=True)
    assert run.returncode == 1 and "other" in run.stderr and "TOPSECRET" not in run.stderr + run.stdout


# ------------------------------------------------------------------------------------------------ render
CFG = {"image_prefix": "935951870001.dkr.ecr.ap-south-1.amazonaws.com/devsec-chola", "frontend_host": "chola.zeroshield.ai",
       "api_host": "chola-api.zeroshield.ai", "real_ip_from": "10.60.1.0/24,10.60.2.0/24", "region": "ap-south-1",
       "llm_model": "openai.gpt-oss-120b-1:0", "smtp_host": "smtp.office365.com", "smtp_port": "587"}


def _app():
    merged, _, _ = kit.merge_app_secrets({}, kit.parse_dotenv(ANSH_ENV))
    return merged


def test_render_env_files():
    app = _app()
    shared, backend, warnings = kit.render_env(app, {"access_key_id": "AKIAAPP", "secret_access_key": "appsecret"},
                                               {"AWS_ACCESS_KEY_ID": "AKIACOL", "AWS_SECRET_ACCESS_KEY": "colsecret",
                                                "principal_arn": "arn:aws:iam::935951870001:user/collector"},
                                               CFG, "b669fa3c467f")
    s = kit.parse_dotenv(shared)
    b = kit.parse_dotenv(backend)
    assert not warnings
    assert s["DSS_TAG"] == "b669fa3c467f" and s["DSS_IMAGE_PREFIX"].endswith("/devsec-chola")
    assert s["AWS_ACCESS_KEY_ID"] == "AKIAAPP" and s["AWS_DEFAULT_REGION"] == "ap-south-1"
    assert "AWS_ENDPOINT_URL_S3" not in s  # real S3, never an empty endpoint
    assert s["LLM_MODEL"] == "openai.gpt-oss-120b-1:0" and s["DSS_SBOM_REGISTRY"] == "0"
    assert s["DSS_REAL_IP_FROM"] == "10.60.1.0/24,10.60.2.0/24"
    assert "DSS_HTTP_PORT" not in s  # production publishes 80, the ALB's target port
    assert b["CORS_ORIGINS"] == b["CBOM_PUBLIC_APP_URL"] == "https://chola.zeroshield.ai"
    assert (b["SMTP_HOST"], b["SMTP_PORT"], b["SMTP_SECURITY"]) == ("smtp.office365.com", "587", "starttls")
    assert b["SMTP_PASSWORD"] == "p@ss#word 1" and b["MAIL_FROM"] == "support@example.com"
    assert b["CBOM_AWS_ACCESS_KEY_ID"] == "AKIACOL" and b["CBOM_AWS_PRINCIPAL_ARN"].endswith(":user/collector")
    assert (b["CBOM_AI_PROVIDER"], b["CBOM_AI_AWS_CREDENTIALS"], b["CBOM_AI_MODEL"]) == \
        ("bedrock", "env", "openai.gpt-oss-120b-1:0")
    # API-only secrets never reach the shared file the workers read, and the reverse
    assert "JWT_SECRET_KEY" not in s and "SMTP_PASSWORD" not in s and "PG_USER_PASS" not in b
    for text in (shared, backend):
        assert not re.search(r"^(DSS_DEV_MODE|LOCAL_DEV_VERIFICATION_)", text, re.MULTILINE)
        assert not re.search(r"^(TENANT_ID|CLIENT_ID|CLIENT_SECRET)=", text, re.MULTILINE)  # Graph is unreachable
        assert all(re.fullmatch(r"[A-Z0-9_]+='[^'\n]*'", line) for line in text.splitlines())


def test_render_refuses_a_quote_and_requires_app_user_and_tag():
    app = _app()
    app["SMTP_PASSWORD"] = "it's"
    with pytest.raises(kit.Refused):
        kit.render_env(app, {"access_key_id": "a", "secret_access_key": "b"}, {}, CFG, "b669fa3c467f")
    with pytest.raises(kit.Refused, match="app-user"):
        kit.render_env(_app(), {}, {}, CFG, "b669fa3c467f")
    with pytest.raises(kit.Refused, match="12-character"):
        kit.render_env(_app(), {"access_key_id": "a", "secret_access_key": "b"}, {}, CFG, "latest")
    with pytest.raises(kit.Refused, match="app-secrets lacks"):
        kit.render_env({}, {"access_key_id": "a", "secret_access_key": "b"}, {}, CFG, "b669fa3c467f")


def test_render_without_collector_keys_warns_and_omits_cbom_aws():
    _, backend, warnings = kit.render_env(_app(), {"access_key_id": "a", "secret_access_key": "b"}, {}, CFG,
                                          "b669fa3c467f")
    assert "CBOM_AWS_ACCESS_KEY_ID" not in backend and any("cbom-collector" in w for w in warnings)


def test_render_env_cli_with_a_fake_aws(tmp_path):
    """render-env end to end: secrets come from `aws secretsmanager get-secret-value` (here a fake on PATH); the files
    are mode 600; DSS_TAG of an existing .env is kept."""
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
    run = subprocess.run(cmd, capture_output=True, check=False, text=True, env=env)
    assert run.returncode == 0, run.stderr
    for name in (".env", "backend.env"):
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600
    assert "s3cr3t" not in run.stdout + run.stderr and "cbom-collector" in run.stdout
    cmd[-1] = ""  # no --tag value: keep the .env's
    run = subprocess.run(cmd, capture_output=True, check=False, text=True, env=env)
    assert run.returncode == 0, run.stderr
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


def test_backend_listens_on_8080_behind_nginx(compose):
    cmd = compose["services"]["backend"]["command"]
    assert cmd[cmd.index("--bind") + 1] == "0.0.0.0:8080"
    assert "set $backend http://backend:8080;" in TEMPLATE.read_text()
    assert "set $frontend http://frontend:3000;" in TEMPLATE.read_text()
    assert compose["services"]["backend"]["environment"]["FORWARDED_ALLOW_IPS"] == "${DSS_PROXY_IP:-172.30.251.10}"
    assert compose["services"]["nginx"]["networks"]["edge"]["ipv4_address"] == "${DSS_PROXY_IP:-172.30.251.10}"


def test_release_archive_holds_exactly_the_infrastructure_images(compose):
    infra = {svc["image"] for svc in compose["services"].values() if "${" not in svc["image"]}
    assert infra == set(_bash_array(OWNER, "INFRA_IMAGES")) == set(_bash_array(REMOTE, "INFRA_IMAGES"))


def test_every_service_has_restart_limits_and_never_pulls(compose):
    for name, svc in compose["services"].items():
        assert svc.get("pull_policy") == "never", name  # ECR pulls / the archive load are explicit steps
        assert svc.get("restart") in ("unless-stopped", "no"), name
        if name != "migrate":
            assert svc.get("mem_limit"), name
    total = 0
    for name, svc in compose["services"].items():
        if name == "migrate":
            continue
        v = str(svc["mem_limit"])
        total += float(v[:-1]) * (1024 if v.endswith("g") else 1) if v[-1] in "gm" else 0
    assert total <= 30 * 1024  # m7i.2xlarge: 32 GB, leave room for the OS


def test_bind_mounted_config_changes_recreate_their_containers(compose):
    for name in ("nginx", "backend", "migrate", "cbom-cloud-worker", "dast-scheduler"):
        assert compose["services"][name]["labels"]["com.zeroshield.dss.files-hash"] == "${DSS_FILES_HASH:-unset}", name
    assert 'DSS_FILES_HASH="${DSS_FILES_HASH:-$(files_hash)}"' in REMOTE.read_text()


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
    for name in ("docker-compose.yml",):
        shutil.copy(COMPOSE, tmp_path / name)
    shutil.copytree(KIT_DIR / "nginx", tmp_path / "nginx")
    env = tmp_path / ".env"
    shared, backend, _ = kit.render_env(_app(), {"access_key_id": "a", "secret_access_key": "b"}, {}, CFG,
                                        "b669fa3c467f")
    env.write_text(shared)
    (tmp_path / "backend.env").write_text(backend)
    run = subprocess.run(["docker", "compose", "--project-directory", str(tmp_path), "-f", str(tmp_path / "docker-compose.yml"),
                          "--env-file", str(env), "config", "--format", "json"], capture_output=True, check=False, text=True)
    if run.returncode != 0 and "is not a docker command" in run.stderr:
        pytest.skip("docker compose plugin not installed")
    assert run.returncode == 0, run.stderr
    cfg = json.loads(run.stdout)
    assert cfg["services"]["backend"]["image"].endswith("/devsec-chola/devsecshield-backend:b669fa3c467f")
    # single-quoted values are literal: '#' and '@' survive into the container environment
    assert cfg["services"]["backend"]["environment"]["SMTP_PASSWORD"] == "p@ss#word 1"
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


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0", "alb.example.com", "10.0.0.0/8;evil", ""])
def test_site_script_refuses_unsafe_real_ip_sources(tmp_path, value):
    env = dict(os.environ, FRONTEND_HOST="a", API_HOST="b", DSS_REAL_IP_FROM=value)
    run = subprocess.run(["sh", str(SITE_SH)], capture_output=True, check=False, text=True, env=env)
    assert run.returncode != 0


# ------------------------------------------------------------------------------------------------ owner script
def _shims(tmp_path):
    shim_dir = tmp_path / "shims"
    shim_dir.mkdir()
    log = tmp_path / "calls.log"
    for tool in ("aws", "ssh", "docker", "gh", "curl", "scp", "gpg", "unzip"):
        p = shim_dir / tool
        p.write_text(f"#!/bin/sh\necho \"{tool} $*\" >> {log}\nexit 97\n")
        p.chmod(0o755)
    return shim_dir, log


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
@pytest.mark.parametrize("args", [["secrets"], ["backup"], ["verify"], ["rollback", "--allow-downgrade"], ["status"],
                                  ["logs", "--service", "backend"], ["smtp-test"], ["admin", "--email", "a@b.co"],
                                  ["host-setup"], ["infra"]])
def test_dry_run_touches_no_aws_ssh_docker_or_registry(tmp_path, args):
    shim_dir, log = _shims(tmp_path)
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}", HOME=str(tmp_path), TMPDIR=str(tmp_path))
    run = subprocess.run(["bash", str(OWNER), *args, "--dry-run"], capture_output=True, check=False, text=True, env=env,
                         stdin=subprocess.DEVNULL)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "[dry-run]" in run.stdout
    assert not log.exists(), log.read_text()
    assert not list(tmp_path.glob("chola-prod.*"))  # the scratch directory (SSH key, archive) is removed


def test_owner_script_refuses_production_without_confirmation(tmp_path):
    shim_dir, log = _shims(tmp_path)
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}", HOME=str(tmp_path), TMPDIR=str(tmp_path))
    run = subprocess.run(["bash", str(OWNER), "rollback"], capture_output=True, check=False, text=True, env=env,
                         stdin=subprocess.DEVNULL)
    assert run.returncode == 1 and "confirmation" in run.stderr
    assert not log.exists()


def test_remote_refuses_dev_switches(tmp_path):
    """remote.sh's require_env_files: DSS_DEV_MODE / LOCAL_DEV_VERIFICATION_* in either env file stop everything."""
    kit_copy = tmp_path / "deploy" / "chola-prod"
    kit_copy.mkdir(parents=True)
    shutil.copy(REMOTE, kit_copy / "remote.sh")
    (kit_copy / ".env").write_text("DSS_TAG='aaaaaaaaaaaa'\n")
    (kit_copy / "backend.env").write_text("LOCAL_DEV_VERIFICATION_CODE='123456'\n")
    for f in (".env", "backend.env"):
        (kit_copy / f).chmod(0o600)
    shim_dir, _ = _shims(tmp_path)
    fake_docker = shim_dir / "docker"
    fake_docker.write_text("#!/bin/sh\nexit 0\n")  # docker info works; nothing else is reached
    env = dict(os.environ, PATH=f"{shim_dir}:{os.environ['PATH']}")
    run = subprocess.run(["bash", str(kit_copy / "remote.sh"), "smtp-test"], capture_output=True, check=False, text=True, env=env)
    assert run.returncode == 1 and "must never be set in production" in run.stderr


# ------------------------------------------------------------------------------------------------ SMTP login check
def _load_smtp_check():
    spec = importlib.util.spec_from_file_location("chola_smtp_check", KIT_DIR / "smtp_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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


def test_smtp_check_refuses_to_send_a_password_without_starttls_or_auth(monkeypatch, capsys):
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
            if subprocess.run(["flock", "-n", str(state / ".lock"), "true"], check=False).returncode != 0:
                break
            import time
            time.sleep(0.1)
        for cmd in (["render"], ["deploy", "aaaaaaaaaaaa"], ["rollback"]):
            run = subprocess.run(["bash", str(kit_copy / "remote.sh"), *cmd], capture_output=True, check=False, text=True)
            assert run.returncode == 1 and "another chola-prod command is running" in run.stderr, cmd
    finally:
        holder.kill()
        holder.wait()
