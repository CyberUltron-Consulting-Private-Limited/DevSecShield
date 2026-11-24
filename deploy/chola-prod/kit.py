#!/usr/bin/env python3
"""Helpers of the Chola production kit (deploy/chola-prod/README.md). Standard library only, Python 3.8+.

Never prints a secret value: only key names and what happened to them.

  kit.py merge-app-secrets --existing F [--mail-env F | --mail-lines F] --out F [--refresh-mail] [--data-exists]
      Owner's machine. F (--existing) holds the current SecretString of devsec-chola/prod/app-secrets ("" or "{}" when
      empty). Every generated key that is missing is generated with the OS CSPRNG (secrets module); every existing
      value is KEPT (put-secret-value replaces the whole JSON, so this is the merge). The mail keys come from the
      owner's `git show origin/ansh:backend/.env` (--mail-env) or from two lines, address and password, typed at a
      hidden prompt (--mail-lines); only when missing or with --refresh-mail. --data-exists (the instance already has
      database volumes): every key that existing data depends on (DATA_KEYS) must be present and non-empty; none of
      them is ever generated then. Writes the merged JSON to --out (mode 600). Exit 0 = changed (put it),
      3 = unchanged (nothing to put), 1 = refused.
  kit.py data-check --existing F
      Exit 1 (names only) when F lacks, or has empty, any key existing data depends on (DATA_KEYS): run before any
      mail source is read when the instance already has data.
  kit.py mail-state < json
      "present" when the secret holds all three mail keys (non-empty), else "missing" (names only, never values).
  kit.py json-field NAME[,ALIAS...]  < json
      Prints one field of a JSON object (names compared without case, '_' or '-'); the error lists field NAMES only.
  kit.py render-env --dir D [--tag T] [--secret-prefix devsec-chola/prod] [--region R] ...
      Instance. Reads app-secrets, app-user and cbom-collector with `aws secretsmanager get-secret-value` (the instance
      role) and writes, mode 600 and replaced atomically, one file per reader (least privilege):
        D/.env               Compose interpolation only (images, hosts, the datastore containers' own credentials);
                             no application container reads it
        D/backend.env        backend-image services (API, migrate, CBOM cloud worker, DAST scheduler)
        D/scan-worker.env    scan-worker and cicd-worker
        D/dast-worker.env    dast-worker
      DSS_TAG is kept from the existing .env unless --tag is given.
  kit.py dotenv-keys FILE
      The key names a dotenv file sets (for checks; values are never printed).
"""
import argparse
import base64
import binascii
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile

# ------------------------------------------------------------------------------------------------- app-secrets schema
# Keys this kit generates once and then never changes (rotation is a deliberate act: README "Secrets").
# hex = URL-safe: the workers and the backend put the database / queue passwords into URLs without escaping them
# (RabbitMQ/worker/scan_worker.py builds amqp://user:password@..., mongodb://user:password@...).
GENERATED = {
    "JWT_SECRET_KEY": "hex32",
    "JWT_REFRESH_SECRET_KEY": "hex32",
    "ENCRYPTION_KEY": "fernet",
    "CERTIN_HMAC_SECRET": "hex32",
    "PG_USER_PASS": "hex24",
    "MONGO_INITDB_ROOT_PASSWORD": "hex24",
    "RABBIT_ADMIN_PASSWORD": "hex24",
    "QDRANT_API_KEY": "hex32",
}
# Mail for sign-in codes: Office 365 SMTP AUTH with the mailbox the owner chose (OUTLOOK_EMAIL / OUTLOOK_PASSWORD of
# the ansh branch's backend/.env). MAIL_FROM is the mailbox itself: Office 365 refuses another From without SendAs.
MAIL_SOURCE = {"SMTP_USERNAME": "OUTLOOK_EMAIL", "SMTP_PASSWORD": "OUTLOOK_PASSWORD", "MAIL_FROM": "OUTLOOK_EMAIL"}
SAFE_PASSWORD = re.compile(r"^[A-Za-z0-9._~-]{16,256}$")
# What data already on the instance depends on: the database / broker passwords (set only when a volume is first
# initialised), the key stored credentials are encrypted with, and the HMAC key of issued CERT-In attestations. With
# --data-exists none of them may be generated: a new value would lock the application out of its own data.
DATA_KEYS = ("PG_USER_PASS", "MONGO_INITDB_ROOT_PASSWORD", "RABBIT_ADMIN_PASSWORD", "ENCRYPTION_KEY",
             "CERTIN_HMAC_SECRET")


class Refused(Exception):
    pass


def generate(kind):
    if kind == "hex32":
        return secrets.token_hex(32)
    if kind == "hex24":
        return secrets.token_hex(24)
    if kind == "fernet":  # cryptography.fernet.Fernet.generate_key(): urlsafe base64 of 32 random bytes
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    raise ValueError(kind)


def problem(key, value):
    """Why an existing value cannot be used (None = fine). Never includes the value."""
    if not isinstance(value, str) or not value:
        return "empty or not a string"
    if "\n" in value or "\r" in value or "'" in value or "\x00" in value:
        return "contains a line break, a quote or NUL (cannot be written to an env file)"
    kind = GENERATED.get(key)
    if kind == "fernet":
        try:
            raw = base64.urlsafe_b64decode(value.encode("ascii"))
        except (ValueError, binascii.Error):  # UnicodeEncodeError is a ValueError
            return "not urlsafe base64"
        if len(raw) != 32:
            return "not a Fernet key (32 bytes, urlsafe base64)"
    elif key in ("JWT_SECRET_KEY", "JWT_REFRESH_SECRET_KEY", "CERTIN_HMAC_SECRET", "QDRANT_API_KEY"):
        if len(value.encode("utf-8")) < 32:
            return "shorter than 32 bytes (the backend refuses to start)"
    elif key in ("PG_USER_PASS", "MONGO_INITDB_ROOT_PASSWORD", "RABBIT_ADMIN_PASSWORD"):
        if not SAFE_PASSWORD.match(value):
            return "not 16+ URL-safe characters (it is put into connection URLs unescaped)"
    return None


def parse_dotenv(text):
    """KEY=VALUE lines as python-dotenv reads them: `export ` prefix, spaces around '=', single or double quotes,
    and a ' #' comment after an unquoted value or after the closing quote."""
    out = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$", line)
        if not m:
            continue
        key, rest = m.group(1), m.group(2)
        if rest[:1] in ("'", '"'):
            q = rest[0]
            end = rest.find(q, 1)
            if end == -1:
                value = rest[1:]
            else:
                value = rest[1:end]
                if q == '"':
                    value = value.replace("\\n", "\n").replace('\\"', '"')
        else:
            value = re.split(r"\s+#", rest, maxsplit=1)[0].strip()
        out[key] = value
    return out


def data_problem(existing):
    """None when every DATA_KEYS value is present and non-empty, else the refusal message (names only)."""
    lacking = [k for k in DATA_KEYS if not (isinstance(existing, dict) and isinstance(existing.get(k), str)
                                            and existing.get(k))]
    if not lacking:
        return None
    return ("the instance already has data, but app-secrets lacks (or has empty) " + ", ".join(lacking)
            + ": generating them would lock the application out of its data. Restore the earlier secret version"
            " (AWSPREVIOUS) instead")


def mail_present(existing):
    return isinstance(existing, dict) and all(isinstance(existing.get(k), str) and existing.get(k) for k in MAIL_SOURCE)


def merge_app_secrets(existing, mail_env, refresh_mail=False, gen=generate, data_exists=False):
    """(merged dict, report lines, changed). Existing values are kept; refuses unusable existing values instead of
    silently replacing them (a replaced database password would lock the application out of its own data)."""
    if existing is None:
        existing = {}
    if not isinstance(existing, dict):
        raise Refused("the secret is not a JSON object")
    if data_exists and data_problem(existing):
        raise Refused(data_problem(existing))
    merged = dict(existing)
    report = []
    for key, kind in GENERATED.items():
        if key in existing and existing[key] not in ("", None):
            why = problem(key, existing[key])
            if why:
                raise Refused(f"{key} in the secret is unusable ({why}); fix it in Secrets Manager by hand")
            report.append(f"{key}: kept")
        else:
            merged[key] = gen(kind)
            report.append(f"{key}: generated")
    if merged["JWT_SECRET_KEY"] == merged["JWT_REFRESH_SECRET_KEY"]:
        raise Refused("JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY are equal; the backend refuses to start")
    for key, source in MAIL_SOURCE.items():
        have = existing.get(key) not in ("", None)
        value = (mail_env or {}).get(source, "")
        if have and not refresh_mail:
            why = problem(key, existing[key])
            if why:
                raise Refused(f"{key} in the secret is unusable ({why})")
            report.append(f"{key}: kept")
            continue
        if not value:
            if have:
                report.append(f"{key}: kept ({source} not found in the mail source)")
                continue
            raise Refused(f"{source} is missing or empty in the mail source (origin/ansh:backend/.env)")
        why = problem(key, value)
        if why:
            raise Refused(f"{source} from the mail source is unusable ({why})")
        if have and existing[key] == value:
            report.append(f"{key}: kept (same as {source})")
        else:
            merged[key] = value
            report.append(f"{key}: {'updated' if have else 'set'} from {source}")
    if "@" not in merged["SMTP_USERNAME"]:
        raise Refused("SMTP_USERNAME is not an e-mail address")
    for key in sorted(set(existing) - set(GENERATED) - set(MAIL_SOURCE)):
        report.append(f"{key}: kept (not managed by the kit)")
    return merged, report, merged != existing


def write_private(path, text):
    """Write text to path with mode 600, atomically (temp file in the same directory, then rename)."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".kit-", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _norm(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def json_field(obj, names):
    """The value of the first of names (compared without case, '_' or '-') in obj, else None."""
    if not isinstance(obj, dict):
        return None
    index = {_norm(k): k for k in obj}
    for name in names:
        k = index.get(_norm(name))
        if k is not None and obj[k] not in ("", None):
            return obj[k]
    return None


ACCESS_KEY_NAMES = ["AWS_ACCESS_KEY_ID", "access_key_id", "AccessKeyId", "access_key"]
SECRET_KEY_NAMES = ["AWS_SECRET_ACCESS_KEY", "secret_access_key", "SecretAccessKey", "secret_key"]
PRINCIPAL_NAMES = ["CBOM_AWS_PRINCIPAL_ARN", "principal_arn", "user_arn", "iam_user_arn", "arn"]


# ------------------------------------------------------------------------------------------------- env rendering
def env_line(key, value):
    value = "" if value is None else str(value)
    if "'" in value or "\n" in value or "\r" in value or "\x00" in value:
        raise Refused(f"the value of {key} cannot be written to an env file (quote or line break)")
    # Single quotes: Compose reads the value literally (no ${...} interpolation, no '#' comment), in --env-file and
    # in env_file alike.
    return f"{key}='{value}'\n"


def read_dotenv_value(path, key):
    try:
        with open(path) as fh:
            return parse_dotenv(fh.read()).get(key, "")
    except FileNotFoundError:
        return ""


def aws_secret(secret_id, region, runner=subprocess.run):
    """The SecretString of secret_id as a dict (instance role). {} when the secret has no value yet."""
    proc = runner(["aws", "secretsmanager", "get-secret-value", "--region", region, "--secret-id", secret_id,
                   "--query", "SecretString", "--output", "text"], capture_output=True, text=True)
    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        raise Refused(f"cannot read {secret_id}: {err[-1][:300] if err else 'aws exited ' + str(proc.returncode)}")
    text = (proc.stdout or "").strip()
    if not text or text == "None":
        return {}
    try:
        value = json.loads(text)
    except ValueError:
        raise Refused(f"{secret_id} is not a JSON object") from None
    if not isinstance(value, dict):
        raise Refused(f"{secret_id} is not a JSON object")
    return value


def principal_of(access_key, secret_key, region, runner=subprocess.run):
    """The IAM principal ARN of a key pair (sts:GetCallerIdentity needs no permission). Keys go in the environment of
    the aws process only, never on its command line."""
    env = dict(os.environ)
    for k in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        env.pop(k, None)
    env.update(AWS_ACCESS_KEY_ID=access_key, AWS_SECRET_ACCESS_KEY=secret_key, AWS_DEFAULT_REGION=region)
    proc = runner(["aws", "sts", "get-caller-identity", "--query", "Arn", "--output", "text"],
                  capture_output=True, text=True, env=env)
    arn = (proc.stdout or "").strip()
    return arn if proc.returncode == 0 and arn.startswith("arn:aws") else ""


def render_env(app, app_user, collector, cfg, tag, principal=None):
    """{file name: text} for .env, backend.env, scan-worker.env, dast-worker.env, plus warnings. Each application
    container gets only the variables its code reads (RabbitMQ/worker, RabbitMQ/dast_worker, backend)."""
    warnings = []
    missing = [k for k in list(GENERATED) + list(MAIL_SOURCE) if not app.get(k)]
    if missing:
        raise Refused("devsec-chola/prod/app-secrets lacks " + ", ".join(missing) + " (run: chola-prod.sh secrets)")
    for k in list(GENERATED) + list(MAIL_SOURCE):
        why = problem(k, app[k])
        if why:
            raise Refused(f"{k} in app-secrets is unusable ({why})")
    key_id = json_field(app_user, ACCESS_KEY_NAMES)
    key_secret = json_field(app_user, SECRET_KEY_NAMES)
    if not key_id or not key_secret:
        raise Refused("devsec-chola/prod/app-user has no access key pair; its fields are: "
                      + ", ".join(sorted(app_user)) if app_user else "devsec-chola/prod/app-user is empty")
    if not tag:
        raise Refused("no DSS_TAG (give --tag or deploy once)")
    if not re.match(r"^[0-9a-f]{12}$", tag):
        raise Refused("DSS_TAG must be a 12-character commit")
    rabbit = [("RABBITMQ_HOST", "rabbitmq"), ("RABBITMQ_PORT", "5672"), ("RABBIT_ADMIN_USERNAME", "devsecshield"),
              ("RABBIT_ADMIN_PASSWORD", app["RABBIT_ADMIN_PASSWORD"])]
    mongo = [("MONGO_HOST", "mongo"), ("MONGO_PORT", "27017"), ("MONGO_INITDB_ROOT_USERNAME", "devsecshield"),
             ("MONGO_INITDB_ROOT_PASSWORD", app["MONGO_INITDB_ROOT_PASSWORD"])]
    # S3 (bucket devsecshield-storage) and Bedrock: the app-user IAM user. The code builds its S3 and Bedrock clients
    # from these two variables explicitly (backend/utilities/db/s3_utils.py, utilities/ai/llm.py,
    # RabbitMQ/worker/helpers/context/*): it cannot use the instance role. AWS_ENDPOINT_URL_S3 stays unset (real S3).
    aws = [("AWS_ACCESS_KEY_ID", key_id), ("AWS_SECRET_ACCESS_KEY", key_secret), ("AWS_DEFAULT_REGION", cfg["region"])]
    docker = [("IS_DOCKER_CONTAINER", "True")]
    # Compose interpolation only: image names, hosts, nginx, and the datastore containers' own credentials.
    interp = [
        ("DSS_IMAGE_PREFIX", cfg["image_prefix"]), ("DSS_TAG", tag),
        ("FRONTEND_HOST", cfg["frontend_host"]), ("API_HOST", cfg["api_host"]),
        ("DSS_REAL_IP_FROM", cfg["real_ip_from"]),
        ("DSS_EDGE_SUBNET", "172.30.251.0/24"), ("DSS_PROXY_IP", "172.30.251.10"),
        ("BACKEND_WORKERS", "4"),
        ("PG_USER", "devsecshield"), ("PG_USER_PASS", app["PG_USER_PASS"]), ("PG_DB", "devsecshield"),
        ("MONGO_INITDB_ROOT_USERNAME", "devsecshield"), ("MONGO_INITDB_ROOT_PASSWORD", app["MONGO_INITDB_ROOT_PASSWORD"]),
        ("RABBIT_ADMIN_USERNAME", "devsecshield"), ("RABBIT_ADMIN_PASSWORD", app["RABBIT_ADMIN_PASSWORD"]),
        ("QDRANT_API_KEY", app["QDRANT_API_KEY"]),
    ]
    backend = docker + [
        # gunicorn's --workers comes from .env (Compose interpolation); the API also reads it at run time to size the
        # CBOM dispatch (backend/utilities/cbom_sources/dispatch.py), so it is here too.
        ("BACKEND_WORKERS", "4"),
        ("PG_HOST", "postgres"), ("PG_PORT", "5432"), ("PG_USER", "devsecshield"),
        ("PG_USER_PASS", app["PG_USER_PASS"]), ("PG_DB", "devsecshield"),
    ] + mongo + rabbit + aws + [
        # The instance cannot reach the public package registries: no SBOM registry lookups (they would only time out).
        ("DSS_SBOM_REGISTRY", "0"),
        ("JWT_SECRET_KEY", app["JWT_SECRET_KEY"]), ("JWT_REFRESH_SECRET_KEY", app["JWT_REFRESH_SECRET_KEY"]),
        ("ENCRYPTION_KEY", app["ENCRYPTION_KEY"]), ("CERTIN_HMAC_SECRET", app["CERTIN_HMAC_SECRET"]),
        ("CORS_ORIGINS", "https://" + cfg["frontend_host"]), ("CBOM_PUBLIC_APP_URL", "https://" + cfg["frontend_host"]),
        # Sign-in codes: Office 365 SMTP AUTH (the instance cannot reach graph.microsoft.com; TENANT_ID etc. unset).
        ("SMTP_HOST", cfg["smtp_host"]), ("SMTP_PORT", cfg["smtp_port"]), ("SMTP_SECURITY", "starttls"),
        ("SMTP_USERNAME", app["SMTP_USERNAME"]), ("SMTP_PASSWORD", app["SMTP_PASSWORD"]),
        ("MAIL_FROM", app["MAIL_FROM"]),
        # CBOM remediation assistant: Bedrock Converse with the AWS_* above (credential source env). The only Bedrock
        # models this account may call: openai.gpt-oss-120b-1:0 (every AI feature of the app) and
        # global.anthropic.claude-haiku-4-5-20251001-v1:0 (not used by the application).
        ("CBOM_AI_PROVIDER", "bedrock"), ("CBOM_AI_BEDROCK_REGION", cfg["region"]),
        ("CBOM_AI_AWS_CREDENTIALS", "env"), ("CBOM_AI_MODEL", cfg["llm_model"]),
    ]
    c_id = json_field(collector, ACCESS_KEY_NAMES)
    c_secret = json_field(collector, SECRET_KEY_NAMES)
    if c_id and c_secret:
        arn = json_field(collector, PRINCIPAL_NAMES) or principal or ""
        backend += [("CBOM_AWS_ACCESS_KEY_ID", c_id), ("CBOM_AWS_SECRET_ACCESS_KEY", c_secret)]
        if arn:
            backend.append(("CBOM_AWS_PRINCIPAL_ARN", arn))
        else:
            warnings.append("CBOM_AWS_PRINCIPAL_ARN unknown (not in cbom-collector and STS did not answer)")
    else:
        warnings.append("devsec-chola/prod/cbom-collector has no access key pair (fields: "
                        + (", ".join(sorted(collector)) or "none") + "): CBOM AWS sources are unavailable")
    # Scan / CI-CD workers: queue, results store, S3 download + Bedrock, the vector store, the model.
    scan = docker + rabbit + mongo + aws + [("QDRANT_HOST", "qdrant"), ("QDRANT_PORT", "6333"),
                                           ("QDRANT_API_KEY", app["QDRANT_API_KEY"]), ("LLM_MODEL", cfg["llm_model"]),
                                           # SBOM scans resolve licences in the worker (registry_enrich.py): no
                                           # public-registry lookups here either (opt-in only, never set to 1)
                                           ("DSS_SBOM_REGISTRY", "0")]
    # DAST worker: queue, results store, Bedrock (its agent's model id is fixed in the code).
    dast = docker + rabbit + mongo + aws

    def text(pairs):
        return "".join(env_line(k, v) for k, v in pairs)
    return {".env": text(interp), "backend.env": text(backend), "scan-worker.env": text(scan),
            "dast-worker.env": text(dast)}, warnings


ENV_FILES = (".env", "backend.env", "scan-worker.env", "dast-worker.env")


HEADER = ("# Rendered by deploy/chola-prod/kit.py render-env from AWS Secrets Manager (devsec-chola/prod/*).\n"
          "# Do not edit: the next deploy writes it again. Never copy it anywhere.\n")


# ------------------------------------------------------------------------------------------------- commands
def cmd_merge(args):
    with open(args.existing) as fh:
        text = fh.read().strip()
    try:
        existing = json.loads(text) if text and text != "None" else {}
    except ValueError:
        raise Refused("the current app-secrets value is not JSON; fix it in Secrets Manager first") from None
    mail_env = {}
    if args.mail_env:
        with open(args.mail_env) as fh:
            mail_env = parse_dotenv(fh.read())
    elif args.mail_lines:
        with open(args.mail_lines) as fh:
            lines = fh.read().split("\n")
        if len(lines) < 2 or not lines[0].strip() or not lines[1]:
            raise Refused("the prompt gave no mailbox address or no password")
        mail_env = {"OUTLOOK_EMAIL": lines[0].strip(), "OUTLOOK_PASSWORD": lines[1]}
    merged, report, changed = merge_app_secrets(existing, mail_env, refresh_mail=args.refresh_mail,
                                                data_exists=args.data_exists)
    write_private(args.out, json.dumps(merged, sort_keys=True))
    for line in report:
        print("  " + line)
    return 0 if changed else 3


def cmd_json_field(args):
    try:
        obj = json.loads(sys.stdin.read())
    except ValueError:
        raise Refused("the input is not JSON") from None
    value = json_field(obj, args.names.split(","))
    if value is None:
        raise Refused(f"no field {args.names} (fields: {', '.join(sorted(obj)) if isinstance(obj, dict) else 'none'})")
    sys.stdout.write(str(value))
    if not str(value).endswith("\n"):
        sys.stdout.write("\n")
    return 0


def cmd_render(args):
    prefix = args.secret_prefix.rstrip("/")
    app = aws_secret(prefix + "/app-secrets", args.region)
    app_user = aws_secret(prefix + "/app-user", args.region)
    collector = aws_secret(prefix + "/cbom-collector", args.region)
    env_path = os.path.join(args.dir, ".env")
    tag = args.tag or read_dotenv_value(env_path, "DSS_TAG")
    principal = None
    if json_field(collector, ACCESS_KEY_NAMES) and json_field(collector, SECRET_KEY_NAMES) \
            and not json_field(collector, PRINCIPAL_NAMES):
        principal = principal_of(json_field(collector, ACCESS_KEY_NAMES), json_field(collector, SECRET_KEY_NAMES),
                                 args.region)
    cfg = {"image_prefix": args.image_prefix, "frontend_host": args.frontend_host, "api_host": args.api_host,
           "real_ip_from": args.real_ip_from, "region": args.region, "llm_model": args.llm_model,
           "smtp_host": args.smtp_host, "smtp_port": args.smtp_port}
    files, warnings = render_env(app, app_user, collector, cfg, tag, principal)
    for name in ENV_FILES:
        write_private(os.path.join(args.dir, name), HEADER + files[name])
    for w in warnings:
        print("  WARNING: " + w)
    print("  rendered " + ", ".join(f"{n} ({files[n].count(chr(10))} keys)" for n in ENV_FILES) + ", mode 600")
    return 0


def _read_existing(path):
    with open(path) as fh:
        text = fh.read().strip()
    try:
        return json.loads(text) if text and text != "None" else {}
    except ValueError:
        raise Refused("the current app-secrets value is not JSON; fix it in Secrets Manager first") from None


def cmd_data_check(args):
    why = data_problem(_read_existing(args.existing))
    if why:
        raise Refused(why)
    return 0


def cmd_mail_state(args):
    text = sys.stdin.read().strip()
    try:
        obj = json.loads(text) if text and text != "None" else {}
    except ValueError:
        raise Refused("the input is not JSON") from None
    print("present" if mail_present(obj) else "missing")
    return 0


def cmd_dotenv_keys(args):
    with open(args.file) as fh:
        for key in parse_dotenv(fh.read()):
            print(key)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge-app-secrets")
    m.add_argument("--existing", required=True)
    mail = m.add_mutually_exclusive_group()
    mail.add_argument("--mail-env")
    mail.add_argument("--mail-lines")
    m.add_argument("--out", required=True)
    m.add_argument("--refresh-mail", action="store_true")
    m.add_argument("--data-exists", action="store_true")
    sub.add_parser("mail-state")
    dc = sub.add_parser("data-check")
    dc.add_argument("--existing", required=True)
    j = sub.add_parser("json-field")
    j.add_argument("names")
    r = sub.add_parser("render-env")
    r.add_argument("--dir", required=True)
    r.add_argument("--tag", default="")
    r.add_argument("--secret-prefix", default="devsec-chola/prod")
    r.add_argument("--region", default="ap-south-1")
    r.add_argument("--image-prefix", default="935951870001.dkr.ecr.ap-south-1.amazonaws.com/devsec-chola")
    r.add_argument("--frontend-host", default="chola.zeroshield.ai")
    r.add_argument("--api-host", default="chola-api.zeroshield.ai")
    r.add_argument("--real-ip-from", default="10.60.1.0/24,10.60.2.0/24")
    r.add_argument("--llm-model", default="openai.gpt-oss-120b-1:0")
    r.add_argument("--smtp-host", default="smtp.office365.com")
    r.add_argument("--smtp-port", default="587")
    k = sub.add_parser("dotenv-keys")
    k.add_argument("file")
    args = p.parse_args(argv)
    try:
        return {"merge-app-secrets": cmd_merge, "json-field": cmd_json_field, "render-env": cmd_render,
                "dotenv-keys": cmd_dotenv_keys, "mail-state": cmd_mail_state,
                "data-check": cmd_data_check}[args.cmd](args)
    except Refused as e:
        print(f"kit.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
