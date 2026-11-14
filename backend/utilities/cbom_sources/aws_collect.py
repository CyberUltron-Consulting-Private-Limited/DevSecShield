"""Read-only AWS inventory of cryptographic configuration for one customer account (or organisation).

Runs in the cloud worker.  Safety rules, all checked before anything is read:
* only ZeroShield's own principal (CBOM_AWS_*) is used, never ambient credentials;
* the role must REFUSE AssumeRole without the team's external ID (confused-deputy protection);
* the assumed identity must be in the account named by the role ARN.
Every service is read in its own try block: AccessDenied, a disabled opt-in region or throttling
becomes a ``coverage`` asset and a target row, never a silent "nothing found".

Coverage gaps inside a service that was read (a list cut at its cap, one function's environment or one bucket's
policy not readable) are ``coverage`` rows too, and they make the service and its target ``partial``.  Each row names
its ``scope``: the location prefixes of the assets it may have left out, which drift never reports as removed or
resolved (``drift.job_gaps``).  ``incomplete`` rows say the asset itself is listed with facts missing.  ``by_choice``
rows are options the customer left off (Lambda decryption, Glue connections): known, stable gaps that keep the target
``ok`` but still hide what they cover from drift.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import time
from typing import Any, Callable

from backend.utilities.cbom_sources.aws_validate import _boto, _code
from backend.utilities.cbom_sources.common import log, new_ref
from backend.utilities.cbom_sources.idp_collect import saml_assets_from_xml
from backend.utilities.cbom_sources.kinds import aws_account_id

PER_SERVICE_CAP = 1000
GLOBAL_REGION = "us-east-1"
_DENIED = ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError",
           "AuthorizationErrorException")
_NOT_ENABLED = ("OptInRequired", "UnrecognizedClientException", "InvalidClientTokenId", "AuthFailure")

Emit = Callable[[dict[str, Any]], None]


class AwsCollectError(Exception):
    """``str(err)`` is safe to show."""


def _iso(value: Any) -> str | None:
    if isinstance(value, _dt.datetime):
        if value.tzinfo is not None:
            value = value.astimezone(_dt.timezone.utc).replace(tzinfo=None)
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _bits(spec: str | None) -> int | None:
    match = re.search(r"(\d{3,5})", spec or "")
    if match:
        return int(match.group(1))
    curve = {"P256": 256, "P384": 384, "P521": 521, "SECG_P256K1": 256, "PRIME256V1": 256, "SECP384R1": 384}
    for name, bits in curve.items():
        if name in (spec or "").upper().replace("_", ""):
            return bits
    return None


class _Account:
    """Assumed-role session for one account, re-assumed before the 1-hour credentials expire."""

    def __init__(self, base, cfg, role_arn: str, external_id: str, team_id: int):
        self.base, self.cfg, self.role_arn, self.external_id, self.team_id = base, cfg, role_arn, external_id, team_id
        self.account = aws_account_id(role_arn)
        self.session = None
        self.expires = 0.0

    def assume(self, region: str) -> None:
        import boto3

        sts = self.base.client("sts", region_name=region, config=self.cfg)
        out = sts.assume_role(RoleArn=self.role_arn, RoleSessionName=f"zs-cbom-collect-{self.team_id}"[:64],
                              ExternalId=self.external_id, DurationSeconds=3600)
        creds = out["Credentials"]
        self.session = boto3.session.Session(aws_access_key_id=creds["AccessKeyId"],
                                             aws_secret_access_key=creds["SecretAccessKey"],
                                             aws_session_token=creds["SessionToken"])
        self.expires = time.monotonic() + 3300  # re-assume 5 minutes early
        who = self.session.client("sts", region_name=region, config=self.cfg).get_caller_identity()
        if str(who.get("Account")) != str(self.account):
            raise AwsCollectError("The assumed role is not in the account named by its ARN")

    def client(self, service: str, region: str):
        if self.session is None or time.monotonic() > self.expires:
            self.assume(region if region != "global" else GLOBAL_REGION)
        return self.session.client(service, region_name=GLOBAL_REGION if region == "global" else region, config=self.cfg)


def _gap(label: str, location: str, check: str, status: str, detail: str | None, scope: list[str] | None = None, *,
         incomplete: bool = False, by_choice: bool = False, **facts: Any) -> dict[str, Any]:
    """A coverage row (see the module docstring for ``scope`` / ``incomplete`` / ``by_choice``)."""
    out: dict[str, Any] = {"check": check, "status": status, "detail": detail, **facts}
    if scope:
        out["scope"] = list(scope)
    if incomplete:
        out["incomplete"] = True
    if by_choice:
        out["by_choice"] = True
    return {"type": "coverage", "target": label, "location": location, "facts": out}


class _GapTally:
    """Passes every asset on and counts what the coverage gaps left unread, which makes a target partial: not the
    ``by_choice`` rows (an option left off) nor the ``not_reported`` ones (a state in which AWS reports nothing, e.g.
    a key's rotation while it is pending deletion: known and stable, but still hidden from drift).  A row that lists
    several items counts each (``not_read_count``).  ``codes`` counts them by service and error code for the log."""

    def __init__(self, emit: Emit):
        self.emit, self.gaps = emit, 0
        self.codes: dict[tuple[str, str], int] = {}

    def __call__(self, asset: dict[str, Any]) -> None:
        facts = asset.get("facts") or {}
        if asset.get("type") == "coverage" and not facts.get("by_choice") and facts.get("status") != "not_reported":
            count = facts.get("not_read_count")
            # 0: a row that only follows from others already counted (custom key stores behind unread keys)
            count = count if isinstance(count, int) and not isinstance(count, bool) and count >= 0 else 1
            self.gaps += count
            location = str(asset.get("location") or "")
            service = location.split(":")[2] if location.startswith("arn:aws:") and location.count(":") >= 2 else "?"
            codes = facts.get("codes") if isinstance(facts.get("codes"), dict) else {
                str(facts.get("code") or facts.get("detail") or facts.get("status") or "?")[:64]: count}
            for code, n in codes.items():
                if int(n):
                    self.codes[(service, code)] = self.codes.get((service, code), 0) + int(n)
        self.emit(asset)


def _paginate(client, method: str, key: str, cap: int = PER_SERVICE_CAP, **kwargs) -> tuple[list[Any], bool]:
    """At most ``cap`` items; truncated only when AWS had more (exactly ``cap`` items is complete)."""
    out: list[Any] = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        out.extend(page.get(key) or [])
        if len(out) > cap:
            return out[:cap], True
    return out, False


def _paginate_kept(client, method: str, key: str, cap: int = PER_SERVICE_CAP,
                   **kwargs) -> tuple[list[Any], bool, str | None]:
    """``_paginate`` that keeps what was listed when a LATER page fails (CB-33 EC-8): (items, truncated, error code of
    the failed page).  A failing first page raises, as before: nothing was listed."""
    out: list[Any] = []
    pages = iter(client.get_paginator(method).paginate(**kwargs))
    while True:
        try:
            page = next(pages)
        except StopIteration:
            return out, False, None
        except AwsCollectError:
            raise
        except Exception as exc:
            if not out:
                raise
            return out, False, _code(exc)
        out.extend(page.get(key) or [])
        if len(out) > cap:
            return out[:cap], True, None


# --- per-item reads (CB-33 PR-A) -----------------------------------------------------------------------------------
# Each item a service lists (a KMS key, an ACM certificate) is read on its own: one item that cannot be read is a
# coverage row scoped to its exact ARN, never the end of the region nor a silent "nothing found".  Botocore's own list
# of throttling codes, so the two stay in step.
try:
    from botocore.retries.standard import ThrottledRetryableChecker as _Throttled

    _THROTTLE = frozenset(_Throttled._THROTTLED_ERROR_CODES)
except Exception:  # pragma: no cover - an older botocore
    _THROTTLE = frozenset({"Throttling", "ThrottlingException", "ThrottledException", "RequestThrottledException",
                           "TooManyRequestsException", "ProvisionedThroughputExceededException", "RequestLimitExceeded",
                           "LimitExceededException", "RequestThrottled", "SlowDown"})
_UNSUPPORTED = ("UnsupportedOperationException",)
ITEM_ROWS = 50  # coverage rows with one exact ARN each, per operation and service-region; the rest go in chunks
CHUNK_ARNS = 100  # exact ARNs per chunk row beyond ITEM_ROWS (never a prefix: that would hide real fixes nearby)
BREAKER_THROTTLES = 10  # consecutive throttles that stop one operation (the rest of its items become rows)
ROLE_WIDE_DENIALS = 25  # consecutive denials with no success: the role cannot do this at all (one row)
SERVICE_BUDGET_S = 480  # per service-region; what is left after it becomes rows, so the lease never runs out
_clock = time.monotonic  # the tests drive a fake clock


def _item_class(exc: Exception) -> tuple[str, str]:
    code = _code(exc)
    if code in _THROTTLE:
        return "throttled", code
    if code in _DENIED:
        return "denied", code
    if code in _UNSUPPORTED:
        return "not_supported", code
    return "error", code  # NotFound, KMSInvalidState, internal errors, timeouts, connection errors: not read


class _Op:
    def __init__(self) -> None:
        self.ok = self.throttles = self.denials = 0
        self.stopped: str | None = None
        self.role_wide: str | None = None
        self.failed: list[tuple[str, str, str, str]] = []  # (arn, status, code, detail)


class _Items:
    """Per-item reads of one service in one region (state local to one call of ``kms()`` / ``acm()``, so a retried
    job starts clean).  ``call`` isolates each read; ``step`` (once per item) calls the worker's ``tick`` (lease
    renewal, cancel, deadline) and keeps to the service's time budget; ``flush`` emits the coverage rows."""

    def __init__(self, service: str, region: str, account: str, label: str, tick: Callable[[], str | None] | None):
        self.service, self.region, self.account, self.label, self.tick = service, region, account, label, tick
        self.ops: dict[str, _Op] = {}
        self.started = _clock()
        self.stop: str | None = None

    def step(self) -> None:
        if self.stop is not None:
            return
        reason = self.tick() if self.tick is not None else None
        if reason:
            self.stop = f"stopped: {reason}"[:200]
        elif _clock() - self.started >= SERVICE_BUDGET_S:
            self.stop = f"time budget of {SERVICE_BUDGET_S} s for {self.service} in {self.region} used up"

    def call(self, op: str, arn: str, fn: Callable[[], Any]) -> tuple[str, Any]:
        """("ok", value) | ("not_supported", code) | (status, code) with the item recorded as not read."""
        state = self.ops.setdefault(op, _Op())
        if self.stop:  # cancelled, past the deadline, or the time budget is used up: not asked
            state.failed.append((arn, "stopped", "stopped", self.stop))
            return "stopped", self.stop
        if state.stopped:  # this operation's breaker tripped: not asked
            status = "denied" if state.role_wide else "throttled"
            state.failed.append((arn, status, state.role_wide or "breaker", state.stopped))
            return status, state.stopped
        try:
            value = fn()
        except AwsCollectError:
            raise
        except Exception as exc:
            status, code = _item_class(exc)
            if status == "not_supported":
                state.throttles = state.denials = 0
                return status, code
            state.failed.append((arn, status, code, code))
            state.throttles = state.throttles + 1 if status == "throttled" else 0
            state.denials = state.denials + 1 if status == "denied" else 0
            if state.throttles >= BREAKER_THROTTLES:
                state.stopped = f"throttled; stopped after {BREAKER_THROTTLES} in a row ({code})"
            elif state.ok == 0 and state.denials >= ROLE_WIDE_DENIALS:
                state.stopped = state.role_wide = code
            return status, code
        state.ok += 1
        state.throttles = state.denials = 0
        return "ok", value

    def flush(self, emit: Emit, ops: dict[str, tuple[str, bool]]) -> None:
        """Coverage rows for what was not read.  ``ops``: operation -> (check text, incomplete): ``incomplete`` when
        the item is still listed with that fact missing (rotation, key material), plain when it was not emitted."""
        prefix = f"arn:aws:{self.service}:{self.region}:{self.account}:"
        for op, (what, incomplete) in ops.items():
            state = self.ops.get(op)
            if state is None or not state.failed:
                continue
            if state.role_wide is not None:  # the role may not do this at all here: one row, never a row per item
                emit(_gap(self.label, f"{prefix}{self.service}#{op}-denied", f"{self.service} {what} in {self.region}",
                          "denied", f"{state.role_wide}: no {what} could be read ({len(state.failed)} not read, "
                          f"{ROLE_WIDE_DENIALS} denied in a row and none allowed)", [prefix], incomplete=incomplete,
                          code=state.role_wide, not_read_count=len(state.failed)))
                continue
            single, rest = state.failed[:ITEM_ROWS], state.failed[ITEM_ROWS:]
            for arn, status, code, detail in single:
                emit(_gap(self.label, f"{arn}#{op}", f"{self.service} {what} of {arn.rsplit('/', 1)[-1]}", status,
                          detail[:200], [arn], incomplete=incomplete, code=code))
            for n, start in enumerate(range(0, len(rest), CHUNK_ARNS), 1):
                chunk = rest[start:start + CHUNK_ARNS]
                codes: dict[str, int] = {}
                for _arn, _status, code, _detail in chunk:
                    codes[code] = codes.get(code, 0) + 1
                statuses = {status for _a, status, _c, _d in chunk}
                details = sorted({detail for _a, _s, _c, detail in chunk})
                emit(_gap(self.label, f"{prefix}{self.service}#{op}-not-read-{n}",
                          f"{self.service} {what} in {self.region} ({len(chunk)} items)",
                          statuses.pop() if len(statuses) == 1 else "error", "; ".join(details)[:200],
                          [arn for arn, _s, _c, _d in chunk], incomplete=incomplete, not_read_count=len(chunk),
                          codes=codes))


# KMS rotation (CB-33 RC-1): automatic rotation exists only for customer-managed SYMMETRIC_DEFAULT keys of AWS_KMS
# origin; its status is readable in these states.  EXTERNAL Enabled keys are still asked as before CB-33 (the rule
# that reads their answer changes in PR-B, so this PR changes no verdict); custom-store keys never are (AWS raises).
_ROTATION_STATES = ("Enabled", "Disabled", "Creating", "Updating")
_ROTATION_NOT_REPORTED = ("PendingDeletion", "PendingReplicaDeletion")  # AWS answers an artificial "false"


def _kms_facts(meta: dict[str, Any]) -> dict[str, Any]:
    """A KMS key's facts from its DescribeKey metadata (rotation is added by the caller)."""
    spec = meta.get("KeySpec") or meta.get("CustomerMasterKeySpec")
    multi = meta.get("MultiRegionConfiguration") or {}
    return {"key_spec": spec, "key_usage": meta.get("KeyUsage"), "key_manager": meta.get("KeyManager"),
            "key_state": meta.get("KeyState"), "origin": meta.get("Origin"), "multi_region": meta.get("MultiRegion"),
            "rotation_enabled": None, "signing_algorithms": meta.get("SigningAlgorithms"), "identity": meta["Arn"],
            "expiration_model": meta.get("ExpirationModel"), "valid_to": _iso(meta.get("ValidTo")),
            "custom_key_store_id": meta.get("CustomKeyStoreId"), "cloud_hsm_cluster_id": meta.get("CloudHsmClusterId"),
            "xks_key_id": (meta.get("XksKeyConfiguration") or {}).get("Id"),
            "multi_region_type": multi.get("MultiRegionKeyType"),
            "primary_key_arn": (multi.get("PrimaryKey") or {}).get("Arn"),
            "current_key_material_id": meta.get("CurrentKeyMaterialId")}


def _cert_asset(arn: str, label: str, detail: dict[str, Any], kind: str = "certificate", *,
                summary: dict[str, Any] | None = None) -> dict[str, Any]:
    """``summary``: the ACM ListCertificates entry, for the export facts (an exported certificate's key is used
    outside AWS; ``exported`` is None when ACM does not say)."""
    key_alg = detail.get("KeyAlgorithm") or ""
    family = "RSA" if key_alg.upper().startswith("RSA") else ("ECDSA" if key_alg.upper().startswith("EC") else key_alg)
    in_use = detail.get("InUseBy")
    return {"type": kind, "target": label, "location": arn, "name": detail.get("DomainName") or arn.rsplit("/", 1)[-1],
            "algorithm": family or None, "key_size": _bits(key_alg),
            "facts": {"subject": detail.get("Subject"), "issuer": detail.get("Issuer"), "serial": detail.get("Serial"),
                      "not_before": _iso(detail.get("NotBefore")), "not_after": _iso(detail.get("NotAfter")),
                      "sig_alg": detail.get("SignatureAlgorithm"), "key_alg": family, "key_size": _bits(key_alg),
                      "san": (detail.get("SubjectAlternativeNames") or [])[:50], "status": detail.get("Status"),
                      "aws_type": detail.get("Type"), "in_use": bool(in_use) if in_use is not None else None,
                      "in_use_by": (in_use or [])[:10], "renewal_eligibility": detail.get("RenewalEligibility"),
                      "source": "aws", "identity": arn,
                      **({"exported": summary.get("Exported"),
                          "export_option": summary.get("ExportOption") or (detail.get("Options") or {}).get("Export")}
                         if summary is not None else {})}}


_SECRET_NAME = re.compile(r"(private|secret|passw|pwd|token|api[-_]?key|credential|tls[-_]?key|ssh[-_]?key|"
                          r"(^|[/_.-])key($|[/_.-]))", re.I)


# --- secrets written into configuration (Lambda environment, ECS task definitions, EC2 user data) -----------------
# The value is inspected in memory and only its shape leaves this module: material (private key / secret), encoding,
# length, and for a private key its algorithm and size.  Nothing that could rebuild the value is ever emitted.
_PEM_KEY = re.compile(r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----.*?-----END \1-----", re.S)
_DER_B64 = re.compile(r"MI[A-Za-z0-9+/]{100,}={0,2}")  # a DER SEQUENCE; kept only if it parses as a private key
_ENV_SECRET_NAME = re.compile(r"(KEY|SECRET|PASSWORD|PASSWD|PASSPHRASE|TOKEN|CREDENTIAL)", re.I)
_ENV_NOT_SECRET = re.compile(r"(_FILE|_PATH|_DIR|_ID|_URL|_URI|_NAME|_ARN|_ALIAS|_TYPE|_SIZE|_LEN|_BITS|_ALG|_REGION|_ENABLED)$", re.I)
_REFERENCE = ("arn:", "{{resolve:", "${", "$(", "ssm:", "secretsmanager:", "s3://", "/", "file:", "alias/", "http://", "https://")
_USERDATA_ASSIGN = re.compile(r"^\s*(?:export\s+|set\s+|\$env:)?([A-Za-z_][A-Za-z0-9_]{0,127})\s*=\s*(.+?)\s*$")
CONFIG_SCAN_CAP = 300  # functions / task definitions / instances read per region


def _key_shape(data: bytes, label: str | None) -> tuple[str | None, int | None]:
    """Algorithm and size of a private key held in memory; (None, None) when it is encrypted or unreadable."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    try:
        if label == "OPENSSH PRIVATE KEY":
            key = serialization.load_ssh_private_key(data, password=None)
        elif label is None:
            key = serialization.load_der_private_key(data, password=None)
        else:
            key = serialization.load_pem_private_key(data, password=None)
    except Exception:
        return None, None
    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return "ECDSA", key.curve.key_size
    if isinstance(key, dsa.DSAPrivateKey):
        return "DSA", key.key_size
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ED25519", 256
    if isinstance(key, ed448.Ed448PrivateKey):
        return "ED448", 456
    return None, None


# Public material is inventory (public_key / certificate rows), never a secret.  A variable named for something public
# (JWT_PUBLIC_KEY, STRIPE_PUBLISHABLE_KEY) or for a KMS key (whose material cannot leave KMS, so the value is an id,
# ARN or alias) holds no secret unless it holds a private key, which is checked first.
_PEM_PUBLIC = re.compile(r"-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY|CERTIFICATE)-----.*?-----END \1-----", re.S)
_SSH_PUBLIC = re.compile(r"^(ssh-rsa|ssh-dss|ssh-ed25519|ssh-ed448|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+) AAAA[A-Za-z0-9+/=]+")
_ENV_PUBLIC_NAME = re.compile(r"(^|_)(PUBLIC|PUBLISHABLE|PUBKEY|KMS)(_|$)", re.I)
_PUBLIC_VALUE = ("pk_live_", "pk_test_")  # Stripe publishable keys, meant to be embedded in web pages
# Names that hold a setting about a secret rather than the secret (JWT audience, header name, object-key prefix ...)
_ENV_SETTING = re.compile(r"_(AUDIENCE|AUD|ISSUER|ISS|HEADER|PREFIX|SUFFIX|TTL|EXPIRY|EXPIRES|EXPIRATION|LIFETIME|"
                          r"TIMEOUT|ENDPOINT|HOST|PORT|VERSION|ALGORITHM|SCOPE|SCOPES|FIELD|PARAM)$", re.I)
# A lower-case path (a Secrets Manager or SSM name such as prod/rds/app-user, an S3 key prefix) is a reference.
# Random secrets mix case, so an AWS secret access key with '/' in it still counts as a secret.
_LOWER_PATH = re.compile(r"[a-z0-9_.@+=-]+(/[a-z0-9_.@+=-]+)+/?")


def _public_alg(key: Any) -> tuple[str | None, int | None]:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

    for kind, alg in ((rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "ECDSA"), (dsa.DSAPublicKey, "DSA")):
        if isinstance(key, kind):
            return alg, (key.curve.key_size if alg == "ECDSA" else key.key_size)
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ED25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "ED448", 456
    return None, None


def _public_shape(text: str, compact: str) -> dict[str, Any] | None:
    """A public key or certificate in a configuration value: its algorithm, size and (certificate) metadata."""
    import base64

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from backend.utilities.cbom_sources.idp_collect import cert_facts

    def cert(der: bytes, encoding: str) -> dict[str, Any] | None:
        try:
            alg, bits, facts = cert_facts(der, "aws")
        except Exception:
            return None
        return {"material": "certificate", "encoding": encoding, "algorithm": alg, "key_bits": bits,
                **{k: v for k, v in facts.items() if k != "source"}}

    pem = _PEM_PUBLIC.search(text)
    if pem:
        if pem.group(1) == "CERTIFICATE":
            try:
                der = x509.load_pem_x509_certificate(pem.group(0).encode()).public_bytes(serialization.Encoding.DER)
            except Exception:
                return {"material": "certificate", "encoding": "pem"}
            return cert(der, "pem") or {"material": "certificate", "encoding": "pem"}
        try:
            alg, bits = _public_alg(serialization.load_pem_public_key(pem.group(0).encode()))
        except Exception:
            alg, bits = None, None
        return {"material": "public-key", "encoding": "pem", "algorithm": alg, "key_bits": bits}
    ssh = _SSH_PUBLIC.match(text)
    if ssh:
        try:
            alg, bits = _public_alg(serialization.load_ssh_public_key(ssh.group(0).encode()))
        except Exception:
            alg, bits = None, None
        return {"material": "public-key", "encoding": "openssh", "algorithm": alg, "key_bits": bits}
    if _DER_B64.fullmatch(compact):
        try:
            der = base64.b64decode(compact + "=" * (-len(compact) % 4))
        except Exception:
            return None
        try:
            alg, bits = _public_alg(serialization.load_der_public_key(der))
            return {"material": "public-key", "encoding": "base64-der", "algorithm": alg, "key_bits": bits}
        except Exception:
            return cert(der, "base64-der")
    return None


def _value_shape(name: str, value: Any) -> dict[str, Any] | None:
    """What a configuration value holds -- never the value.  None when it is neither key material nor a secret."""
    import base64

    text = str(value or "").strip().replace("\\n", "\n")  # JSON-escaped newlines, as keys are often pasted
    if not text:
        return None
    pem = _PEM_KEY.search(text)
    if pem:
        label = pem.group(1)
        alg, bits = _key_shape(pem.group(0).encode(), label)
        return {"material": "private-key", "encoding": "pem", "pem_label": label, "algorithm": alg, "key_bits": bits,
                "passphrase_protected": "ENCRYPTED" in label or "Proc-Type: 4,ENCRYPTED" in pem.group(0) or None}
    compact = re.sub(r"\s+", "", text)
    if _DER_B64.fullmatch(compact):
        try:
            der = base64.b64decode(compact + "=" * (-len(compact) % 4))
        except Exception:
            der = b""
        alg, bits = _key_shape(der, None) if der else (None, None)
        if alg:
            return {"material": "private-key", "encoding": "base64-der", "algorithm": alg, "key_bits": bits}
    public = _public_shape(text, compact)
    if public:
        return public
    if not _ENV_SECRET_NAME.search(name) or _ENV_NOT_SECRET.search(name) or _ENV_PUBLIC_NAME.search(name) \
            or _ENV_SETTING.search(name):
        return None
    if text.startswith(_REFERENCE + _PUBLIC_VALUE) or text[0] in "$%@" \
            or text.lower() in ("true", "false", "none", "null", "changeme", "placeholder") \
            or len(text) < 8 or text.isdigit() or _LOWER_PATH.fullmatch(text):
        return None
    return {"material": "secret", "encoding": "text", "length": len(text)}


def _embedded_asset(label: str, location: str, name: str, shape: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
    """A private key becomes a private_key asset; any other secret a cloud_secret.  Both carry the store, never the value.
    Public material (a public key or certificate) becomes a public_key / certificate row: inventory, not a secret."""
    if shape["material"] in ("public-key", "certificate"):
        kind = "certificate" if shape["material"] == "certificate" else "public_key"
        return {"type": kind, "target": label, "location": location, "name": name, "algorithm": shape.get("algorithm"),
                "key_size": shape.get("key_bits"),
                "facts": {**facts, **{k: v for k, v in shape.items() if v is not None}, "identity": location}}
    facts = {**facts, **{k: v for k, v in shape.items() if v is not None}, "plaintext_in_cloud_config": True,
             "identity": location}
    if shape["material"] == "private-key":
        return {"type": "private_key", "target": label, "location": location, "name": name,
                "algorithm": shape.get("algorithm"), "key_size": shape.get("key_bits"),
                "facts": {**facts, "encrypted": bool(shape.get("passphrase_protected")) if shape.get("algorithm") else None}}
    return {"type": "cloud_secret", "target": label, "location": location, "name": name, "facts": facts}


def _userdata_shapes(raw: str) -> list[dict[str, Any]]:
    """EC2 user data (base64, possibly gzip) -> shapes of the key material and secret assignments it contains, with lines."""
    import base64
    import gzip

    try:
        blob = base64.b64decode(raw)
        if blob[:2] == b"\x1f\x8b":
            blob = gzip.decompress(blob)[:262144]
        text = blob[:262144].decode("utf-8", "replace")
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for pem in _PEM_KEY.finditer(text):
        shape = _value_shape("", pem.group(0)) or {}
        out.append({**shape, "line": text.count("\n", 0, pem.start()) + 1})
    covered = [(m.start(), m.end()) for m in _PEM_KEY.finditer(text)]
    offset = 0
    for number, line in enumerate(text.splitlines(), 1):
        start = offset
        offset += len(line) + 1
        if any(a <= start < b for a, b in covered):
            continue
        m = _USERDATA_ASSIGN.match(line)
        if not m:
            continue
        shape = _value_shape(m.group(1), m.group(2).strip().strip("'\""))
        if shape and shape["material"] in ("private-key", "secret"):  # the user-data row reports secrets only
            out.append({**shape, "variable": m.group(1), "line": number})
    return out[:50]


def _ssh_public_bits(public_key: str) -> int | None:
    """RSA modulus size from an OpenSSH public key line ("ssh-rsa AAAA... comment")."""
    import base64
    import struct

    try:
        blob = base64.b64decode(public_key.split()[1])
        parts, i = [], 0
        while i < len(blob) and len(parts) < 3:
            (n,) = struct.unpack(">I", blob[i:i + 4])
            parts.append(blob[i + 4:i + 4 + n])
            i += 4 + n
        if parts[0] != b"ssh-rsa":
            return None
        return int.from_bytes(parts[2], "big").bit_length()
    except Exception:
        return None


def _tls_protocol_names(values: list[str]) -> list[str]:
    out = []
    for value in values:
        text = str(value)
        out.append({"TLSv1": "TLSv1.0", "SSLv3": "SSLv3"}.get(text, text))
    return out


def _exposure(internet_facing: bool | None, basis: str) -> dict[str, Any]:
    """Facts the risk score reads: is the resource reachable from the internet, and what AWS setting says so."""
    return {"internet_facing": internet_facing, "exposure_basis": basis[:200]}


# --- Glue connections: only these property keys are ever kept (values are booleans or a credential-free URL) ------
_GLUE_BOOL_KEYS = ("JDBC_ENFORCE_SSL", "SKIP_CUSTOM_JDBC_CERT_VALIDATION", "KAFKA_SSL_ENABLED", "KAFKA_SKIP_CUSTOM_CERT_VALIDATION")
_GLUE_PRESENCE_KEYS = ("CUSTOM_JDBC_CERT", "KAFKA_CUSTOM_CERT", "SECRET_ID", "ENCRYPTED_PASSWORD", "USERNAME")
_JDBC_TLS_PARAM = re.compile(r"(?:^|[?&;])(ssl|usessl|requiressl|encrypt|sslmode|ssl-mode|sslenabled)=([^&;]*)", re.I)


def _strip_jdbc_url(url: str) -> tuple[str | None, bool]:
    """(jdbc:<engine>://host[:port][/database], whether the URL itself asks for TLS).  User names, passwords and every
    query or property part are dropped; Oracle's user/password@ form and descriptors keep only host and port."""
    text = str(url or "").strip()
    match = re.match(r"^jdbc:([a-z0-9]+)(?::[a-z0-9]+)*:", text, re.I)
    if not match:
        return None, False
    engine, rest = match.group(1).lower(), text[match.end():]
    tls = any(value.strip().lower() not in ("false", "0", "disable", "disabled", "allow", "prefer", "preferred", "")
              for _name, value in _JDBC_TLS_PARAM.findall(rest))
    if "(" in rest:  # Oracle descriptor: (DESCRIPTION=(ADDRESS=(PROTOCOL=TCPS)(HOST=h)(PORT=p))...)
        host = re.search(r"\(HOST\s*=\s*([A-Za-z0-9.\-]+)\)", rest, re.I)
        port = re.search(r"\(PORT\s*=\s*(\d{1,5})\)", rest, re.I)
        tls = tls or bool(re.search(r"\(PROTOCOL\s*=\s*TCPS\)", rest, re.I))
        return (f"jdbc:{engine}://{host.group(1)}{':' + port.group(1) if port else ''}" if host else None), tls
    rest = re.split(r"[?;]", rest, maxsplit=1)[0]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]  # user[:password]@host or Oracle user/password@host
    rest = rest.lstrip("/")
    hostport = re.match(r"^(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9.\-]+)(:\d{1,5})?(/[A-Za-z0-9_.\-$]{0,128})?", rest)
    if not hostport:
        return None, tls
    return f"jdbc:{engine}://{hostport.group(1)}{hostport.group(2) or ''}{hostport.group(3) or ''}", tls


def _glue_connection_facts(conn: dict[str, Any]) -> dict[str, Any]:
    """Allow-listed facts of one Glue connection.  No property value leaves this function except booleans, the
    connection type and a credential-free JDBC URL; a password key is reported as present/absent only."""
    props = {str(k).upper(): v for k, v in (conn.get("ConnectionProperties") or {}).items()}
    facts: dict[str, Any] = {"connection_type": conn.get("ConnectionType")}
    for key in _GLUE_BOOL_KEYS:
        if key in props:
            facts[key.lower()] = str(props[key]).strip().lower() == "true"
    for key in _GLUE_PRESENCE_KEYS:
        facts[f"has_{key.lower()}"] = bool(props.get(key))
    facts["has_password_key"] = any(k == "PASSWORD" or (k.endswith("_PASSWORD") and not k.startswith("ENCRYPTED_"))
                                    for k in props)
    facts["has_encrypted_password"] = any(k.startswith("ENCRYPTED_") and k.endswith("PASSWORD") for k in props)
    facts["uses_secrets_manager"] = bool(props.get("SECRET_ID")) or any(k.endswith("SECRETS_ARN") for k in props)
    url, url_tls = _strip_jdbc_url(props.get("JDBC_CONNECTION_URL") or "")
    if url:
        facts["jdbc_url"] = url
        facts["jdbc_url_requests_tls"] = url_tls
    return facts


def _region_services(acct: _Account, region: str, label: str, emit: Emit,
                     opts: dict[str, Any] | None = None,
                     tick: Callable[[], str | None] | None = None) -> list[tuple[str, str, str | None]]:
    """Read every regional service.  Returns (service, status, detail) rows; status ``partial`` when the service was
    read but emitted coverage gaps (a cap, an item it could not read).  ``tick`` is the worker's ``should_stop``
    (renews the lease, says when the job is cancelled or past its deadline), called inside per-item loops."""
    opts = opts or {}
    rows: list[tuple[str, str, str | None]] = []
    arn_prefix = f"arn:aws:{{svc}}:{region}:{acct.account}"
    cache: dict[str, Any] = {}
    tally = _GapTally(emit)
    emit = tally  # every row below goes through the tally, so a service's own gaps decide its status

    def capped(service: str, what: str, cap: int, scope: list[str], where: str = "cap") -> None:
        """A list cut at its cap is a coverage gap over the part that was not read, never a silent "that's all"."""
        emit(_gap(label, f"{arn_prefix.format(svc=service)}:{service}#{where}", f"{service} in {region}", "truncated",
                  f"More than {cap} {what}; the first {cap} were read", scope))

    def run(service: str, fn: Callable[[], str | None]) -> None:
        seen = tally.gaps
        try:
            note = fn()
            gaps = tally.gaps - seen
            rows.append((service, "partial", f"{gaps} not read" + (f" ({note})" if note else "")) if gaps
                        else (service, "ok", note))
        except AwsCollectError:
            raise
        except Exception as exc:  # one service failing never stops the others
            code = _code(exc)
            status = "denied" if code in _DENIED else ("not_enabled" if code in _NOT_ENABLED else "error")
            rows.append((service, status, code))
            emit({"type": "coverage", "target": label, "location": f"{arn_prefix.format(svc=service)}:{service}",
                  "facts": {"check": f"{service} in {region}", "status": status, "detail": code}})

    def reservations() -> tuple[list[Any], bool]:
        """DescribeInstances once per region (raises, so the service that needs it reports the failure itself)."""
        if "reservations" not in cache:
            cache["reservations"] = _paginate(acct.client("ec2", region), "describe_instances", "Reservations")
        return cache["reservations"]

    def instance_exposure() -> dict[str, dict[str, Any]]:
        """Instance id -> exposure facts.  A public IPv4 address means internet-facing; an IPv6 address alone is
        "unknown" (it is reachable only if the subnet routes to an internet gateway)."""
        if "exposure" not in cache:
            try:
                found, _t = reservations()
            except Exception:  # volumes are still reported, just without exposure facts
                found = []
            out: dict[str, dict[str, Any]] = {}
            for inst in (i for r in found for i in r.get("Instances") or []):
                public_ip = inst.get("PublicIpAddress")
                ipv6 = any(a.get("Ipv6Address") for n in inst.get("NetworkInterfaces") or [] for a in n.get("Ipv6Addresses") or [])
                out[inst["InstanceId"]] = _exposure(True if public_ip else (None if ipv6 else False),
                                                    f"EC2 instance {inst['InstanceId']} "
                                                    + ("has a public IP address" if public_ip else
                                                       "has only an IPv6 address" if ipv6 else "has no public IP address"))
            cache["exposure"] = out
        return cache["exposure"]

    def kms() -> str | None:
        client = acct.client("kms", region)
        prefix = f"arn:aws:kms:{region}:{acct.account}:"
        keys, truncated, page_error = _paginate_kept(client, "list_keys", "Keys",
                                                     PaginationConfig={"PageSize": PER_SERVICE_CAP})
        items = _Items("kms", region, acct.account, label, tick)
        found: list[dict[str, Any]] = []
        for key in keys:
            items.step()
            kid = key["KeyId"]
            arn = key.get("KeyArn") or f"{prefix}key/{kid}"
            status, meta = items.call("metadata", arn, lambda: client.describe_key(KeyId=kid)["KeyMetadata"])
            if status != "ok":
                continue  # not emitted: its exact-ARN row says it was not read (never "deleted")
            arn = meta.get("Arn") or arn
            facts = _kms_facts(meta)
            spec, origin, state = facts["key_spec"], meta.get("Origin"), meta.get("KeyState")
            rotation: bool | None = None
            if meta.get("KeyManager") != "CUSTOMER" or spec != "SYMMETRIC_DEFAULT":
                facts["rotation_status"] = "not applicable"
            elif (origin == "AWS_KMS" and state in _ROTATION_STATES) or (origin == "EXTERNAL" and state == "Enabled"):
                status, out = items.call("rotation", arn, lambda: client.get_key_rotation_status(KeyId=kid))
                if status == "ok":
                    rotation = bool(out.get("KeyRotationEnabled"))
                    facts.update(rotation_status="on" if rotation else "off",
                                 rotation_period_days=out.get("RotationPeriodInDays"),
                                 next_rotation=_iso(out.get("NextRotationDate")),
                                 on_demand_rotation_started=_iso(out.get("OnDemandRotationStartDate")))
                elif status == "not_supported":
                    facts["rotation_status"] = "not supported"
                else:  # listed, its rotation unknown: an unknown is not a fix (its row is incomplete)
                    facts["rotation_status"] = f"not read: {out}"[:120]
            elif origin == "AWS_KMS" and state in _ROTATION_NOT_REPORTED:
                facts["rotation_status"] = f"not reported while {state}"
                # AWS reports an artificial "false" in these states: not asked, and the key's rotation verdict is
                # neither resolved nor opened while it lasts (the row keeps the target "ok")
                emit(_gap(label, f"{arn}#rotation", f"kms key {kid} rotation status", "not_reported",
                          f"AWS does not report rotation while the key is {state}", [arn], incomplete=True))
            else:
                facts["rotation_status"] = "not applicable"  # imported material not Enabled, custom key stores
            facts["rotation_enabled"] = rotation
            if origin == "EXTERNAL" and spec == "SYMMETRIC_DEFAULT":
                status, out = items.call("materials", arn, lambda: _paginate(
                    client, "list_key_rotations", "Rotations", KeyId=kid, IncludeKeyMaterial="ALL_KEY_MATERIAL")[0])
                if status == "ok":  # identifiers and dates of each imported material, never the material
                    facts["key_materials"] = [
                        {"id": r.get("KeyMaterialId"), "state": r.get("KeyMaterialState"),
                         "import_state": r.get("ImportState"), "expiration_model": r.get("ExpirationModel"),
                         "valid_to": _iso(r.get("ValidTo"))} for r in out][:20]
            found.append({"type": "kms_key", "target": label, "location": arn,
                          "name": meta.get("Description") or meta["KeyId"], "algorithm": spec,
                          "key_size": 256 if spec == "SYMMETRIC_DEFAULT" else _bits(spec), "facts": facts})
        stores = [a for a in found if a["facts"].get("custom_key_store_id")]
        if stores:
            key_stores(client, prefix, stores)
        else:
            unread = len((items.ops.get("metadata") or _Op()).failed)
            if unread:  # a key not read may live in a custom key store: the stores are unknown, not gone (#136)
                emit(_gap(label, f"{prefix}custom-key-store#unread-keys", f"kms custom key stores in {region}",
                          "not_read", f"not read: {unread} key(s) whose metadata could not be read may use one",
                          [f"{prefix}custom-key-store/"], incomplete=True, code="UnreadKeys", not_read_count=0))
            else:  # read only when a key uses one: a store with no key is not inventoried, never "removed"
                emit(_gap(label, f"{prefix}custom-key-store#no-key", f"kms custom key stores in {region}",
                          "not_read", "read only when a key in this region uses a custom key store",
                          [f"{prefix}custom-key-store/"], by_choice=True))
        for asset in found:
            emit(asset)
        items.flush(emit, {"metadata": ("key metadata", False), "rotation": ("key rotation status", True),
                           "materials": ("imported key material", True)})
        if page_error:  # what was listed is read; only what the failed page would have listed is not read
            emit(_gap(label, f"{prefix}key#list", f"kms keys in {region}", "throttled" if page_error in _THROTTLE
                      else ("denied" if page_error in _DENIED else "error"),
                      f"{page_error}: the key list stopped after {len(keys)} keys", [f"{prefix}key/"], code=page_error))
        if truncated:
            capped("kms", "keys", PER_SERVICE_CAP, [f"{prefix}key/"])
        return "truncated" if truncated else None

    def key_stores(client, prefix: str, keys: list[dict[str, Any]]) -> None:
        """The custom key stores the region's keys live in (read only when a key names one): one ``key_store`` asset
        each, and each key gets its store's connection state.  The trust anchor certificate is never copied."""
        try:
            listed, _cut = _paginate(client, "describe_custom_key_stores", "CustomKeyStores")
        except AwsCollectError:
            raise
        except Exception as exc:  # the stores and the joined key fact are unknown, not "fine"
            code = _code(exc)
            emit(_gap(label, f"{prefix}custom-key-store#describe", f"kms custom key stores in {region}",
                      "denied" if code in _DENIED else ("throttled" if code in _THROTTLE else "error"), code,
                      [f"{prefix}custom-key-store/", *(k["location"] for k in keys)], incomplete=True, code=code))
            return
        state = {}
        for store in listed:
            sid = store.get("CustomKeyStoreId")
            state[sid] = store.get("ConnectionState")
            xks = store.get("XksProxyConfiguration") or {}
            emit({"type": "key_store", "target": label, "location": f"{prefix}custom-key-store/{sid}",
                  "name": store.get("CustomKeyStoreName") or sid,
                  "facts": {"store": "aws_kms_custom", "custom_key_store_type": store.get("CustomKeyStoreType"),
                            "connection_state": store.get("ConnectionState"),
                            "connection_error_code": store.get("ConnectionErrorCode"),
                            "cloud_hsm_cluster_id": store.get("CloudHsmClusterId"),
                            "xks_connectivity": xks.get("Connectivity"), "creation_date": _iso(store.get("CreationDate")),
                            "identity": f"{prefix}custom-key-store/{sid}"}})
        for key in keys:
            key["facts"]["key_store_connection_state"] = state.get(key["facts"]["custom_key_store_id"])

    def acm() -> str | None:
        client = acct.client("acm", region)
        prefix = f"arn:aws:acm:{region}:{acct.account}:"
        everything = {"keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]}
        summaries, truncated, page_error = _paginate_kept(client, "list_certificates", "CertificateSummaryList",
                                                          Includes=everything,
                                                          PaginationConfig={"PageSize": PER_SERVICE_CAP})
        items = _Items("acm", region, acct.account, label, tick)
        for summary in summaries:
            items.step()
            arn = summary["CertificateArn"]
            status, detail = items.call("metadata", arn,
                                        lambda: client.describe_certificate(CertificateArn=arn)["Certificate"])
            if status == "ok":
                emit(_cert_asset(arn, label, detail, summary=summary))
        items.flush(emit, {"metadata": ("certificate", False)})
        if page_error:
            emit(_gap(label, f"{prefix}certificate#list", f"acm certificates in {region}",
                      "throttled" if page_error in _THROTTLE else ("denied" if page_error in _DENIED else "error"),
                      f"{page_error}: the certificate list stopped after {len(summaries)} certificates",
                      [f"{prefix}certificate/"], code=page_error))
        if truncated:
            capped("acm", "certificates", PER_SERVICE_CAP, [f"{prefix}certificate/"])
        return "truncated" if truncated else None

    def pca() -> str | None:
        client = acct.client("acm-pca", region)
        cas, truncated = _paginate(client, "list_certificate_authorities", "CertificateAuthorities")
        if truncated:
            capped("acm-pca", "certificate authorities", PER_SERVICE_CAP,
                   [f"arn:aws:acm-pca:{region}:{acct.account}:certificate-authority/"])
        for ca in cas:
            cfg = ca.get("CertificateAuthorityConfiguration") or {}
            key_alg = cfg.get("KeyAlgorithm") or ""
            emit({"type": "cloud_ca", "target": label, "location": ca["Arn"],
                  "name": json.dumps(cfg.get("Subject") or {})[:255], "algorithm": "RSA" if key_alg.startswith("RSA") else "ECDSA",
                  "key_size": _bits(key_alg),
                  "facts": {"key_alg": key_alg, "sig_alg": cfg.get("SigningAlgorithm"), "status": ca.get("Status"),
                            "ca_type": ca.get("Type"), "not_after": _iso(ca.get("NotAfter")),
                            "not_before": _iso(ca.get("NotBefore")), "is_ca": True, "source": "aws", "identity": ca["Arn"]}})
        return "truncated" if truncated else None

    def secrets() -> str | None:
        client = acct.client("secretsmanager", region)
        items, truncated = _paginate(client, "list_secrets", "SecretList")
        if truncated:
            capped("secretsmanager", "secrets", PER_SERVICE_CAP, [f"arn:aws:secretsmanager:{region}:{acct.account}:secret:"])
        for item in items:  # metadata only; GetSecretValue is denied by the role and never called
            emit({"type": "cloud_secret", "target": label, "location": item["ARN"], "name": item.get("Name"),
                  "facts": {"rotation_enabled": bool(item.get("RotationEnabled")), "kms_key_id": item.get("KmsKeyId") or "aws/secretsmanager",
                            "last_rotated": _iso(item.get("LastRotatedDate")), "identity": item["ARN"]}})
        return "truncated" if truncated else None

    def ebs() -> str | None:
        client = acct.client("ec2", region)
        default = bool(client.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))
        emit({"type": "storage_encryption", "target": label, "location": f"arn:aws:ec2:{region}:{acct.account}:ebs-encryption-by-default",
              "name": f"EBS encryption by default ({region})", "facts": {"resource": "EBS default", "default_encryption": default}})
        volumes, truncated = _paginate(client, "describe_volumes", "Volumes")
        if truncated:
            capped("ec2", "volumes", PER_SERVICE_CAP, [f"arn:aws:ec2:{region}:{acct.account}:volume/"], "volumes-cap")
        plain = [v for v in volumes if not v.get("Encrypted")]
        exposure = instance_exposure() if any(v.get("Attachments") for v in volumes) else {}
        # every volume is inventory (encrypted ones with their KMS key); unencrypted ones first so the cap never hides them
        for volume in (plain + [v for v in volumes if v.get("Encrypted")])[:PER_SERVICE_CAP]:
            encrypted = bool(volume.get("Encrypted"))
            attached = [a.get("InstanceId") for a in volume.get("Attachments") or [] if a.get("InstanceId")]
            seen = [exposure[i] for i in attached if i in exposure]
            emit({"type": "storage_encryption", "target": label,
                  "location": f"arn:aws:ec2:{region}:{acct.account}:volume/{volume['VolumeId']}", "name": volume["VolumeId"],
                  "facts": {"resource": f"EBS volume {volume['VolumeId']}", "encrypted": encrypted, "size_gib": volume.get("Size"),
                            "kms_key_id": volume.get("KmsKeyId") if encrypted else None, "volume_type": volume.get("VolumeType"),
                            "attached_to": attached[:5], "identity": volume["VolumeId"],
                            **(max(seen, key=lambda e: {True: 2, None: 1, False: 0}[e["internet_facing"]]) if seen else {})}})
        return f"{len(volumes)} volumes, {len(plain)} unencrypted" + (" (truncated)" if truncated else "")

    def lambdas() -> str | None:
        # ListFunctions returns each function's environment, and Lambda decrypts it with the CALLER's KMS permissions
        # (https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html).  The default aws/lambda
        # key's policy needs no IAM grant, but the read-only role's explicit kms:Decrypt deny still applies to the
        # request Lambda makes for it: measured in the AWS lab (round 5), a function under aws/lambda came back as
        # Environment.Error AccessDeniedException with the switch off and was read with it on.  So the switch is what
        # opens every environment, customer-managed key or not (a customer-managed key's policy must also allow the
        # role).  Otherwise Environment.Error comes back instead of the variables.  Values are inspected
        # here and only their shape is kept.  FunctionVersion=ALL adds every published version (each has its own,
        # immutable environment).
        client = acct.client("lambda", region)
        functions, truncated = _paginate(client, "list_functions", "Functions", cap=CONFIG_SCAN_CAP, FunctionVersion="ALL")
        cmk_on = bool(opts.get("decrypt_lambda_cmk"))
        hits = unreadable = 0
        for fn in functions:
            env = fn.get("Environment") or {}
            where = f"{fn.get('FunctionName')}:{fn.get('Version') or '$LATEST'}"
            if env.get("Error"):  # say so per function version instead of reporting nothing
                unreadable += 1
                err = env["Error"] if isinstance(env["Error"], dict) else {}
                code = str(err.get("ErrorCode") or "not readable")[:80]
                if not cmk_on:  # a customer-managed key's ARN is in kms_key_id
                    detail = (f"{code}: Lambda decrypts environments with the caller's KMS permissions and the read-only "
                              "role denies kms:Decrypt; turn on 'Decrypt Lambda environment variables' for this account "
                              "to inspect it")
                elif fn.get("KMSKeyArn"):
                    detail = (f"{code}: the key policy of the customer-managed key does not let the ZeroShield role "
                              "decrypt through Lambda; add the role to the key's users")
                else:
                    detail = f"{code} (Lambda decrypts environments with the caller's KMS permissions)"
                # switch off: the customer's choice (the target stays ok); on: a real gap (the target is partial).
                # Either way the secrets this environment held before are not reported gone.
                emit(_gap(label, f"{fn['FunctionArn']}#environment", f"lambda {where} environment variables", "denied",
                          detail[:200], [f"{fn['FunctionArn']}#environment/"], by_choice=not cmk_on,
                          kms_key_id=fn.get("KMSKeyArn"), identity=fn["FunctionArn"]))
                continue
            for var, value in sorted((env.get("Variables") or {}).items()):
                shape = _value_shape(var, value)
                if not shape:
                    continue
                hits += 1
                emit(_embedded_asset(label, f"{fn['FunctionArn']}#environment/{var}", f"{where} env {var}", shape,
                                     {"service": "lambda", "store": f"Lambda function {where} environment",
                                      "variable": var, "kms_key_id": fn.get("KMSKeyArn") or "aws/lambda",
                                      "customer_managed_key": bool(fn.get("KMSKeyArn"))}))
        if truncated:  # the cap is a coverage gap, never a silent "nothing found"
            emit(_gap(label, f"arn:aws:lambda:{region}:{acct.account}:functions#cap", f"lambda in {region}", "truncated",
                      f"More than {CONFIG_SCAN_CAP} function versions; the first {CONFIG_SCAN_CAP} were inspected",
                      [f"arn:aws:lambda:{region}:{acct.account}:function:"]))
        return (f"{len(functions)} function versions, {hits} secrets in environment"
                + (f", {unreadable} environments not readable" if unreadable else "") + (" (truncated)" if truncated else ""))

    def ecs_taskdefs() -> str | None:
        # Active task definitions: plain `environment` entries are checked; `secrets` (valueFrom references) are fine.
        client = acct.client("ecs", region)
        arns, truncated = _paginate(client, "list_task_definitions", "taskDefinitionArns", cap=CONFIG_SCAN_CAP, status="ACTIVE")
        if truncated:
            capped("ecs", "active task definitions", CONFIG_SCAN_CAP, [f"arn:aws:ecs:{region}:{acct.account}:task-definition/"])
        hits = 0
        for arn in arns:
            td = client.describe_task_definition(taskDefinition=arn).get("taskDefinition") or {}
            for container in td.get("containerDefinitions") or []:
                for item in container.get("environment") or []:
                    var = str(item.get("name") or "")
                    shape = _value_shape(var, item.get("value"))
                    if not shape:
                        continue
                    hits += 1
                    family = f"{td.get('family')}:{td.get('revision')}"
                    emit(_embedded_asset(label, f"{arn}#containerDefinitions/{container.get('name')}/environment/{var}",
                                         f"{family} {container.get('name')} env {var}", shape,
                                         {"service": "ecs", "store": f"ECS task definition {family} container {container.get('name')}",
                                          "variable": var}))
        return f"{len(arns)} task definitions, {hits} secrets in environment" + (" (truncated)" if truncated else "")

    def userdata() -> str | None:
        # DescribeInstanceAttribute(userData): bootstrap scripts often carry keys; only shapes and line numbers are kept.
        client = acct.client("ec2", region)
        found, reservations_cut = reservations()
        exposure = instance_exposure()
        live = [i for r in found for i in r.get("Instances") or []
                if (i.get("State") or {}).get("Name") not in ("terminated", "shutting-down")]
        instances, truncated = live[:CONFIG_SCAN_CAP], len(live) > CONFIG_SCAN_CAP or reservations_cut
        if truncated:
            capped("ec2-userdata", "running instances", CONFIG_SCAN_CAP, [f"arn:aws:ec2:{region}:{acct.account}:instance/"])
        hits = 0
        for inst in instances:
            raw = ((client.describe_instance_attribute(InstanceId=inst["InstanceId"], Attribute="userData")
                    .get("UserData") or {}).get("Value")) or ""
            shapes = _userdata_shapes(raw) if raw else []
            if not shapes:
                continue
            hits += 1
            primary = next((s for s in shapes if s.get("material") == "private-key"), shapes[0])
            items = [{k: s.get(k) for k in ("material", "algorithm", "key_bits", "variable", "line", "encoding", "length") if s.get(k)}
                     for s in shapes]
            emit(_embedded_asset(label, f"arn:aws:ec2:{region}:{acct.account}:instance/{inst['InstanceId']}#userData",
                                 f"{inst['InstanceId']} user data", {k: v for k, v in primary.items() if k not in ("line", "variable")},
                                 {"service": "ec2", "store": f"EC2 instance {inst['InstanceId']} user data",
                                  "line": primary.get("line"), "items": items, **exposure.get(inst["InstanceId"], {})}))
        return f"{len(instances)} instances, {hits} with secrets in user data" + (" (truncated)" if truncated else "")

    # Parameters read from RDS parameter groups (engine-aware).  Effective values come from DescribeDBParameters /
    # DescribeDBClusterParameters (rds:Describe* in SecurityAudit); a parameter without ParameterValue is "unknown".
    rds_params_wanted = ("password_encryption", "rds.force_ssl", "rds.accepted_password_auth_method",
                         "require_secure_transport", "ssl_min_protocol_version", "tls_version", "rds.tls10", "rds.tls11")

    def rds_params(client, group: str | None, cluster: bool) -> dict[str, str]:
        if not group:
            return {}
        key = f"{'cluster' if cluster else 'instance'}:{group}"
        if key not in cache:
            method, arg = (("describe_db_cluster_parameters", "DBClusterParameterGroupName") if cluster
                           else ("describe_db_parameters", "DBParameterGroupName"))
            params, _t = _paginate(client, method, "Parameters", cap=5000, **{arg: group})
            cache[key] = {p["ParameterName"]: str(p["ParameterValue"]) for p in params
                          if p.get("ParameterName") in rds_params_wanted and p.get("ParameterValue") not in (None, "")}
        return cache[key]

    def rds_config_facts(engine: str, values: dict[str, str]) -> dict[str, Any]:
        """database_config facts the classifier reads, from one engine's parameters."""
        def on(name: str) -> bool | None:
            value = values.get(name)
            return None if value is None else value.strip().lower() in ("1", "on", "true")

        facts: dict[str, Any] = {"parameters": dict(sorted(values.items()))}
        if "postgres" in engine:
            facts["require_secure_transport"] = on("rds.force_ssl")
            if values.get("password_encryption"):
                facts["password_encryption"] = values["password_encryption"]
            method = values.get("rds.accepted_password_auth_method")
            if method:
                facts["accepted_password_auth_method"] = method
                facts["md5_auth_accepted"] = "md5" in method.lower()
            if values.get("ssl_min_protocol_version"):
                facts["min_version"] = values["ssl_min_protocol_version"]
        elif "mysql" in engine or "mariadb" in engine:
            facts["require_secure_transport"] = on("require_secure_transport")
            if values.get("tls_version"):
                facts["protocols"] = [p.strip() for p in values["tls_version"].split(",") if p.strip()]
        elif engine.startswith("sqlserver"):
            facts["require_secure_transport"] = on("rds.force_ssl")
            old = [label for name, label in (("rds.tls10", "TLSv1.0"), ("rds.tls11", "TLSv1.1"))
                   if str(values.get(name) or "").lower() == "enabled"]
            if old:
                facts["protocols"] = old + ["TLSv1.2"]
        return facts

    def rds() -> str | None:
        client = acct.client("rds", region)
        dbs, truncated = _paginate(client, "describe_db_instances", "DBInstances")
        db_prefix = f"arn:aws:rds:{region}:{acct.account}:db:"  # instances, their #parameters and #ca rows
        if truncated:
            capped("rds", "DB instances", PER_SERVICE_CAP, [db_prefix])
        clusters: dict[str, dict[str, Any]] = {}
        if any(db.get("DBClusterIdentifier") for db in dbs):
            try:
                found, clusters_cut = _paginate(client, "describe_db_clusters", "DBClusters")
                if clusters_cut:
                    capped("rds", "DB clusters", PER_SERVICE_CAP, [db_prefix], "clusters-cap")
            except Exception as exc:  # instances are still reported; their cluster-level parameters are not
                found = []
                emit(_gap(label, f"arn:aws:rds:{region}:{acct.account}:clusters", f"rds clusters in {region}",
                          "denied" if _code(exc) in _DENIED else "error",
                          f"{_code(exc)}: cluster parameter groups (Aurora) not read", [db_prefix], incomplete=True))
            clusters = {c["DBClusterIdentifier"]: c for c in found}
        params_failed: list[str] = []
        for db in dbs:
            endpoint = db.get("Endpoint") or {}
            address = f"{endpoint.get('Address')}:{endpoint.get('Port')}" if endpoint.get("Address") else None
            public = db.get("PubliclyAccessible")
            exposure = _exposure(bool(public) if public is not None else None,
                                 f"RDS PubliclyAccessible={str(bool(public)).lower()}" if public is not None else "RDS")
            emit({"type": "storage_encryption", "target": label, "location": db["DBInstanceArn"], "name": db["DBInstanceIdentifier"],
                  "facts": {"resource": f"RDS {db.get('Engine')} {db['DBInstanceIdentifier']}", "encrypted": bool(db.get("StorageEncrypted")),
                            "kms_key_id": db.get("KmsKeyId"), "engine": db.get("Engine"), "endpoint": address, **exposure}})
            engine = str(db.get("Engine") or "").lower()
            if not engine.startswith("oracle"):  # Oracle TLS lives in option groups, not parameters
                cluster = clusters.get(db.get("DBClusterIdentifier") or "")
                groups = [g.get("DBParameterGroupName") for g in db.get("DBParameterGroups") or []][:1]
                try:
                    values = dict(rds_params(client, groups[0] if groups else None, False))
                    if cluster:  # Aurora / Multi-AZ clusters: cluster-level parameters win
                        values.update(rds_params(client, cluster.get("DBClusterParameterGroup"), True))
                except Exception as exc:
                    params_failed.append(f"{db['DBInstanceIdentifier']}: {_code(exc)}")
                    emit(_gap(label, f"{db['DBInstanceArn']}#parameters", f"rds {db['DBInstanceIdentifier']} parameter group",
                              "denied" if _code(exc) in _DENIED else "error", _code(exc),
                              [f"{db['DBInstanceArn']}#parameters"]))
                    values = None
                if values is not None:
                    emit({"type": "database_config", "target": label, "location": f"{db['DBInstanceArn']}#parameters",
                          "name": f"{db['DBInstanceIdentifier']} parameters",
                          "facts": {"engine": engine, "engine_version": db.get("EngineVersion"), "endpoint": address,
                                    "parameter_group": groups[0] if groups else None,
                                    # pending-reboot: the instance still runs with the previous values
                                    "parameter_apply_status": ((db.get("DBParameterGroups") or [{}])[0]).get("ParameterApplyStatus"),
                                    "cluster_parameter_group": (cluster or {}).get("DBClusterParameterGroup"),
                                    "source": "aws", "identity": db["DBInstanceArn"],
                                    **rds_config_facts(engine, values), **exposure}})
            details = db.get("CertificateDetails") or {}
            ca_id = details.get("CAIdentifier") or db.get("CACertificateIdentifier")
            if ca_id:
                emit({"type": "cloud_ca", "target": label, "location": f"{db['DBInstanceArn']}#ca", "name": ca_id,
                      "algorithm": "ECDSA" if "ecc" in ca_id else "RSA", "key_size": 384 if "ecc384" in ca_id else (4096 if "rsa4096" in ca_id else 2048),
                      "facts": {"not_after": _iso(details.get("ValidTill")), "is_ca": True, "source": "aws", "identity": ca_id}})
        notes = [f"{len(dbs)} instances"] + ([f"parameters not read for {len(params_failed)}"] if params_failed else [])
        return ", ".join(notes) + (" (truncated)" if truncated else "")

    def scheme_exposure(scheme: Any, what: str) -> dict[str, Any]:
        text = str(scheme or "")
        return _exposure(True if text == "internet-facing" else (False if text == "internal" else None),
                         f"{what} scheme {text or 'unknown'}")

    def elbv2() -> str | None:
        client = acct.client("elbv2", region)
        lbs, truncated = _paginate(client, "describe_load_balancers", "LoadBalancers")
        listener_prefix = f"arn:aws:elasticloadbalancing:{region}:{acct.account}:listener/"
        if truncated:
            capped("elasticloadbalancing", "load balancers", PER_SERVICE_CAP, [listener_prefix])
        policies: dict[str, dict[str, Any]] = {}
        for lb in lbs:
            exposure = scheme_exposure(lb.get("Scheme"), f"{lb.get('Type') or 'load balancer'} {lb['LoadBalancerName']}")
            listeners, listeners_cut = _paginate(client, "describe_listeners", "Listeners", LoadBalancerArn=lb["LoadBalancerArn"])
            if listeners_cut:
                capped("elasticloadbalancing", f"listeners on {lb['LoadBalancerName']}", PER_SERVICE_CAP,
                       [listener_prefix], f"listeners-cap/{lb['LoadBalancerName']}")
            for listener in listeners:
                proto = listener.get("Protocol")
                if proto not in ("HTTPS", "TLS"):
                    if proto == "HTTP":
                        emit({"type": "load_balancer_tls", "target": label, "location": listener["ListenerArn"],
                              "name": f"{lb['LoadBalancerName']}:{listener.get('Port')}", "protocol": "HTTP",
                              "facts": {"tls": False, "port": listener.get("Port"), **exposure}})
                    continue
                name = listener.get("SslPolicy")
                if name and name not in policies:
                    found = client.describe_ssl_policies(Names=[name]).get("SslPolicies") or [{}]
                    policies[name] = found[0]
                policy = policies.get(name or "", {})
                ciphers = [c.get("Name") for c in policy.get("Ciphers") or [] if c.get("Name")]
                emit({"type": "load_balancer_tls", "target": label, "location": listener["ListenerArn"],
                      "name": f"{lb['LoadBalancerName']}:{listener.get('Port')}", "protocol": proto,
                      "facts": {"ssl_policy": name, "protocols": _tls_protocol_names(policy.get("SslProtocols") or []),
                                "ciphers": ciphers[:100],
                                "static_rsa_kex": any(not c.startswith(("ECDHE", "DHE", "TLS_")) for c in ciphers),
                                "certificates": [c.get("CertificateArn") for c in listener.get("Certificates") or []][:10],
                                **exposure}})
        return "truncated" if truncated else None

    def elb_classic() -> str | None:
        # Classic Load Balancers: listener TLS comes from the SSLNegotiationPolicyType policy attached to the listener
        # (Protocol-TLSv1 / Protocol-SSLv3 ... and cipher names set to "true").
        client = acct.client("elb", region)
        lbs, truncated = _paginate(client, "describe_load_balancers", "LoadBalancerDescriptions")
        if truncated:
            capped("elb-classic", "classic load balancers", PER_SERVICE_CAP,
                   [f"arn:aws:elasticloadbalancing:{region}:{acct.account}:loadbalancer/"])
        for lb in lbs:
            name = lb["LoadBalancerName"]
            exposure = scheme_exposure(lb.get("Scheme"), f"classic load balancer {name}")
            arn = f"arn:aws:elasticloadbalancing:{region}:{acct.account}:loadbalancer/{name}"
            for item in lb.get("ListenerDescriptions") or []:
                listener = item.get("Listener") or {}
                proto = str(listener.get("Protocol") or "").upper()
                where = f"{arn}#listener/{listener.get('LoadBalancerPort')}"
                if proto not in ("HTTPS", "SSL"):
                    if proto == "HTTP":
                        emit({"type": "load_balancer_tls", "target": label, "location": where,
                              "name": f"{name}:{listener.get('LoadBalancerPort')}", "protocol": "HTTP",
                              "facts": {"tls": False, "port": listener.get("LoadBalancerPort"), "classic": True, **exposure}})
                    continue
                attrs: dict[str, str] = {}
                names = list(item.get("PolicyNames") or [])
                if names:
                    described = client.describe_load_balancer_policies(LoadBalancerName=name, PolicyNames=names)
                    for policy in described.get("PolicyDescriptions") or []:
                        if policy.get("PolicyTypeName") == "SSLNegotiationPolicyType":
                            attrs = {a.get("AttributeName"): str(a.get("AttributeValue")) for a in
                                     policy.get("PolicyAttributeDescriptions") or [] if a.get("AttributeName")}
                protocols = [n[len("Protocol-"):] for n, v in attrs.items() if n.startswith("Protocol-") and v == "true"]
                ciphers = [n for n, v in attrs.items() if v == "true" and not n.startswith(("Protocol-", "Server-Defined"))]
                emit({"type": "load_balancer_tls", "target": label, "location": where,
                      "name": f"{name}:{listener.get('LoadBalancerPort')}", "protocol": proto,
                      "facts": {"ssl_policy": attrs.get("Reference-Security-Policy") or (names[0] if names else None),
                                "protocols": _tls_protocol_names(protocols), "ciphers": ciphers[:100],
                                "static_rsa_kex": any(not c.startswith(("ECDHE", "DHE")) for c in ciphers),
                                "certificates": [listener["SSLCertificateId"]] if listener.get("SSLCertificateId") else [],
                                "classic": True, **exposure}})
        return "truncated" if truncated else None

    def apigw() -> str | None:
        client = acct.client("apigateway", region)
        items, truncated = _paginate(client, "get_domain_names", "items")
        if truncated:
            capped("apigateway", "custom domain names", PER_SERVICE_CAP, [f"arn:aws:apigateway:{region}::/domainnames/"])
        for item in items:
            policy = item.get("securityPolicy") or "TLS_1_0"
            types = [str(t) for t in (item.get("endpointConfiguration") or {}).get("types") or []]
            exposure = _exposure(False if types == ["PRIVATE"] else (True if types else None),
                                 f"API Gateway {'/'.join(types) or 'unknown'} endpoint")
            emit({"type": "api_tls", "target": label, "location": f"arn:aws:apigateway:{region}::/domainnames/{item['domainName']}",
                  "name": item["domainName"], "protocol": "TLS",
                  "facts": {"security_policy": policy, "min_version": "TLSv1.0" if policy == "TLS_1_0" else "TLSv1.2",
                            "endpoint_types": types, **exposure}})
        return "truncated" if truncated else None

    def eks() -> str | None:
        client = acct.client("eks", region)
        names, truncated = _paginate(client, "list_clusters", "clusters")
        if truncated:
            capped("eks", "clusters", PER_SERVICE_CAP, [f"arn:aws:eks:{region}:{acct.account}:cluster/"])
        for name in names:
            cluster = client.describe_cluster(name=name)["cluster"]
            encrypted = bool(cluster.get("encryptionConfig"))
            vpc = cluster.get("resourcesVpcConfig") or {}
            public = vpc.get("endpointPublicAccess")
            cidrs = [str(c) for c in vpc.get("publicAccessCidrs") or []]
            basis = (f"EKS API endpoint public access {'on' if public else 'off'}"
                     + (f" (limited to {len(cidrs)} CIDR range(s))" if public and cidrs and cidrs != ["0.0.0.0/0"] else ""))
            emit({"type": "storage_encryption", "target": label, "location": cluster["arn"], "name": f"EKS {name} secrets",
                  "facts": {"resource": f"EKS cluster {name} Kubernetes secrets", "encrypted": encrypted,
                            "version": cluster.get("version"), "endpoint_public_access": public,
                            "endpoint_private_access": vpc.get("endpointPrivateAccess"), "public_access_cidrs": cidrs[:20],
                            **_exposure(bool(public) if public is not None else None, basis)}})
        return "truncated" if truncated else None

    def glue() -> str | None:
        # Data Catalog encryption, job security configurations and (opt-in) connections.  GetConnections is always
        # called with HidePassword=True ("retrieve the connection metadata without returning the password",
        # https://docs.aws.amazon.com/glue/latest/webapi/API_GetConnections.html) and only allow-listed facts are kept.
        client = acct.client("glue", region)
        settings = (client.get_data_catalog_encryption_settings().get("DataCatalogEncryptionSettings") or {})
        at_rest = settings.get("EncryptionAtRest") or {}
        password = settings.get("ConnectionPasswordEncryption") or {}
        catalog_mode = str(at_rest.get("CatalogEncryptionMode") or "DISABLED")
        password_encryption = bool(password.get("ReturnConnectionPasswordEncrypted"))
        configs, configs_cut = _paginate(client, "get_security_configurations", "SecurityConfigurations")
        jobs, jobs_truncated = _paginate(client, "get_jobs", "Jobs", cap=CONFIG_SCAN_CAP)
        databases = client.get_databases(MaxResults=1).get("DatabaseList") or []  # only "is the catalog in use?"
        connections: list[dict[str, Any]] | None = None
        connections_cut = False
        if opts.get("read_glue"):
            connections, connections_cut = _paginate(client, "get_connections", "ConnectionList", HidePassword=True)
        catalog_arn = f"arn:aws:glue:{region}:{acct.account}:catalog"
        glue_prefix = f"arn:aws:glue:{region}:{acct.account}:"
        if configs_cut:
            capped("glue", "security configurations", PER_SERVICE_CAP, [f"{glue_prefix}securityConfiguration/"])
        if jobs_truncated:  # job counts on the catalog and on each security configuration are incomplete
            capped("glue", "jobs", CONFIG_SCAN_CAP, [catalog_arn, f"{glue_prefix}securityConfiguration/"], "jobs-cap")
        if connections_cut:
            capped("glue", "connections", PER_SERVICE_CAP, [f"{glue_prefix}connection/"], "connections-cap")
        by_config: dict[str, int] = {}
        for job in jobs:  # only the name and the security configuration of a job are used
            by_config[str(job.get("SecurityConfiguration") or "")] = by_config.get(str(job.get("SecurityConfiguration") or ""), 0) + 1
        for config in configs:
            enc = config.get("EncryptionConfiguration") or {}
            s3 = [str(s.get("S3EncryptionMode") or "DISABLED") for s in enc.get("S3Encryption") or []] or ["DISABLED"]
            cw = str((enc.get("CloudWatchEncryption") or {}).get("CloudWatchEncryptionMode") or "DISABLED")
            bookmarks = str((enc.get("JobBookmarksEncryption") or {}).get("JobBookmarksEncryptionMode") or "DISABLED")
            emit({"type": "storage_encryption", "target": label,
                  "location": f"arn:aws:glue:{region}:{acct.account}:securityConfiguration/{config.get('Name')}",
                  "name": f"Glue security configuration {config.get('Name')}",
                  # S3 DISABLED is not "unencrypted": the bucket's default encryption (SSE-S3 at least) still applies, so
                  # only a KMS/S3 mode is reported as encrypted and DISABLED stays unknown rather than a finding.
                  "facts": {"resource": f"Glue security configuration {config.get('Name')} (job output in S3)",
                            "encrypted": True if all(m != "DISABLED" for m in s3) else None, "s3_encryption_mode": s3[0],
                            "cloudwatch_encryption_mode": cw, "job_bookmarks_encryption_mode": bookmarks,
                            "jobs_using": by_config.get(str(config.get("Name")), 0), "identity": config.get("Name")}})
        in_use = bool(databases or jobs or connections)
        if in_use:
            emit({"type": "glue_catalog", "target": label, "location": catalog_arn, "name": f"Glue Data Catalog ({region})",
                  "facts": {"catalog_encryption_mode": catalog_mode, "catalog_kms_key_id": at_rest.get("SseAwsKmsKeyId"),
                            "connection_password_encryption": password_encryption,
                            "password_kms_key_id": password.get("AwsKmsKeyId"),
                            "connections": len(connections) if connections is not None else None,
                            "connections_read": connections is not None, "jobs": len(jobs),
                            "jobs_without_security_configuration": by_config.get("", 0), "identity": catalog_arn}})
        for conn in connections or []:
            facts = _glue_connection_facts(conn)
            # Stored in the connection itself: a password key, an encrypted one, or (JDBC, where a credential is
            # required) a user name without a Secrets Manager reference -- HidePassword may leave the password out.
            inline = not facts["uses_secrets_manager"] and (
                facts["has_password_key"] or facts["has_encrypted_password"]
                or (facts["has_username"] and str(conn.get("ConnectionType") or "").upper() == "JDBC"))
            # Per connection, ENCRYPTED_PASSWORD shows the password was encrypted ("this field stores the encrypted
            # password"); otherwise the catalog setting at create/update time decides.  With encryption on now and
            # neither key visible, the state is unknown (the connection may predate the setting), never "encrypted".
            if facts["uses_secrets_manager"]:
                storage = "secrets_manager"
            elif not inline:
                storage = "none"
            elif facts["has_encrypted_password"]:
                storage = "encrypted"
            elif facts["has_password_key"] or not password_encryption:
                storage = "plaintext"
            else:
                storage = "unknown"
            emit({"type": "glue_connection", "target": label,
                  "location": f"arn:aws:glue:{region}:{acct.account}:connection/{conn.get('Name')}",
                  "name": f"Glue connection {conn.get('Name')}",
                  "facts": {**facts, "password_storage": storage,
                            "catalog_password_encryption": password_encryption, "identity": conn.get("Name")}})
        if not opts.get("read_glue"):
            note = "connections not read (option off)"
            # The customer's choice, so the target stays ok; but connections read while the option was on must not be
            # reported gone, nor the catalog row when connections were what put it in use.
            emit(_gap(label, f"{glue_prefix}connection#option-off", f"glue connections in {region}", "not_read",
                      "Glue connections were not read: the 'Read Glue connections' option is off for this source",
                      [f"{glue_prefix}connection/"] + ([] if in_use else [catalog_arn]), by_choice=True))
        else:
            note = f"{len(connections or [])} connections"
        return f"catalog {catalog_mode}, {len(configs)} security configurations, {note}" + (" (jobs truncated)" if jobs_truncated else "")

    def keypairs() -> str | None:
        # Public half only (IncludePublicKey): the key type and RSA modulus size; private keys never leave AWS.
        client = acct.client("ec2", region)
        pairs = client.describe_key_pairs(IncludePublicKey=True).get("KeyPairs") or []
        if len(pairs) > PER_SERVICE_CAP:
            capped("ec2-keypairs", "key pairs", PER_SERVICE_CAP, [f"arn:aws:ec2:{region}:{acct.account}:key-pair/"])
        for pair in pairs[:PER_SERVICE_CAP]:
            key_type = str(pair.get("KeyType") or "").lower()
            bits = _ssh_public_bits(pair.get("PublicKey") or "") if key_type == "rsa" else (256 if key_type == "ed25519" else None)
            emit({"type": "public_key", "target": label,
                  "location": f"arn:aws:ec2:{region}:{acct.account}:key-pair/{pair.get('KeyName')}",
                  "name": pair.get("KeyName"), "algorithm": "ED25519" if key_type == "ed25519" else "RSA", "key_size": bits,
                  "facts": {"service": "ec2", "key_type": key_type, "bits": bits, "key_pair_id": pair.get("KeyPairId"),
                            "created": _iso(pair.get("CreateTime")), "fingerprint": pair.get("KeyFingerprint")}})
        return f"{len(pairs)} key pairs"

    def ssm() -> str | None:
        # DescribeParameters is metadata (name, type, KMS key); GetParameter is denied to the role and never called.
        client = acct.client("ssm", region)
        params, truncated = _paginate(client, "describe_parameters", "Parameters")
        if truncated:
            capped("ssm", "parameters", PER_SERVICE_CAP, [f"arn:aws:ssm:{region}:{acct.account}:parameter/"])
        for param in params:
            name = param.get("Name") or ""
            emit({"type": "cloud_secret", "target": label,
                  "location": f"arn:aws:ssm:{region}:{acct.account}:parameter/{name.lstrip('/')}", "name": name,
                  "facts": {"service": "ssm", "parameter_type": param.get("Type"), "kms_key_id": param.get("KeyId"),
                            "tier": param.get("Tier"), "last_modified": _iso(param.get("LastModifiedDate")),
                            "secret_like_name": bool(_SECRET_NAME.search(name)), "identity": name}})
        return f"{len(params)} parameters" + (" (truncated)" if truncated else "")

    for service, fn in (("kms", kms), ("acm", acm), ("acm-pca", pca), ("secretsmanager", secrets), ("ec2", ebs),
                        ("ec2-keypairs", keypairs), ("ssm", ssm), ("lambda", lambdas), ("ecs", ecs_taskdefs),
                        ("ec2-userdata", userdata),
                        ("rds", rds), ("elasticloadbalancing", elbv2), ("elb-classic", elb_classic), ("apigateway", apigw),
                        ("eks", eks), ("glue", glue)):
        run(service, fn)
    return rows


def _global_services(acct: _Account, label: str, emit: Emit) -> list[tuple[str, str, str | None]]:
    rows: list[tuple[str, str, str | None]] = []
    tally = _GapTally(emit)
    emit = tally

    def capped(service: str, what: str, cap: int, scope: list[str], where: str = "cap") -> None:
        emit(_gap(label, f"arn:aws:{service}::{acct.account}:global#{where}", f"{service} (global)", "truncated",
                  f"More than {cap} {what}; the first {cap} were read", scope))

    def run(service: str, fn: Callable[[], str | None]) -> None:
        seen = tally.gaps
        try:
            note = fn()
            gaps = tally.gaps - seen
            rows.append((service, "partial", f"{gaps} not read" + (f" ({note})" if note else "")) if gaps
                        else (service, "ok", note))
        except AwsCollectError:
            raise
        except Exception as exc:
            code = _code(exc)
            status = "denied" if code in _DENIED else "error"
            rows.append((service, status, code))
            emit({"type": "coverage", "target": label, "location": f"arn:aws:{service}::{acct.account}:global",
                  "facts": {"check": f"{service} (global)", "status": status, "detail": code}})

    def iam() -> str | None:
        client = acct.client("iam", "global")
        certs, certs_cut = _paginate(client, "list_server_certificates", "ServerCertificateMetadataList")
        if certs_cut:
            capped("iam", "server certificates", PER_SERVICE_CAP, [f"arn:aws:iam::{acct.account}:server-certificate/"])
        for meta in certs:
            emit({"type": "iam_certificate", "target": label, "location": meta["Arn"], "name": meta.get("ServerCertificateName"),
                  "facts": {"not_after": _iso(meta.get("Expiration")), "not_before": _iso(meta.get("UploadDate")),
                            "source": "aws", "identity": meta["Arn"]}})
        saml = client.list_saml_providers().get("SAMLProviderList", [])
        if len(saml) > 50:
            capped("iam", "SAML providers", 50, [f"arn:aws:iam::{acct.account}:saml-provider/"], "saml-cap")
        for provider in saml[:50]:
            doc = client.get_saml_provider(SAMLProviderArn=provider["Arn"]).get("SAMLMetadataDocument") or ""
            for asset in saml_assets_from_xml(doc.encode(), provider["Arn"], label):
                emit(asset)
        oidc = client.list_open_id_connect_providers().get("OpenIDConnectProviderList", [])
        if len(oidc) > 50:
            capped("iam", "OIDC providers", 50, [f"arn:aws:iam::{acct.account}:oidc-provider/"], "oidc-cap")
        for provider in oidc[:50]:
            detail = client.get_open_id_connect_provider(OpenIDConnectProviderArn=provider["Arn"])
            emit({"type": "identity_provider", "target": label, "location": provider["Arn"], "name": detail.get("Url"),
                  "protocol": "OIDC", "facts": {"kind": "oidc", "thumbprints": (detail.get("ThumbprintList") or [])[:5]}})
        return None

    def s3() -> str | None:
        client = acct.client("s3", "global")
        listed = client.list_buckets().get("Buckets", [])
        if len(listed) > PER_SERVICE_CAP:
            capped("s3", "buckets", PER_SERVICE_CAP, ["arn:aws:s3:::"])
        buckets = listed[:PER_SERVICE_CAP]
        for bucket in buckets:
            name = bucket["Name"]
            arn = f"arn:aws:s3:::{name}"
            facts: dict[str, Any] = {"resource": f"S3 bucket {name}"}
            unread: list[str] = []
            try:
                rules = client.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
                sse = rules[0]["ApplyServerSideEncryptionByDefault"] if rules else {}
                facts.update(encrypted=True, sse_algorithm=sse.get("SSEAlgorithm"), kms_key_id=sse.get("KMSMasterKeyID"))
            except Exception as exc:
                code = _code(exc)
                facts.update(encrypted=False if code == "ServerSideEncryptionConfigurationNotFoundError" else None,
                             encryption_error=None if code == "ServerSideEncryptionConfigurationNotFoundError" else code)
                if code != "ServerSideEncryptionConfigurationNotFoundError":
                    unread.append(f"encryption: {code}")
            try:
                policy = json.loads(client.get_bucket_policy(Bucket=name)["Policy"])
                facts["tls_only_policy"] = any(
                    st.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(st.get("Condition") or {})
                    for st in policy.get("Statement", []))
            except Exception as exc:
                facts["tls_only_policy"] = False if _code(exc) == "NoSuchBucketPolicy" else None
                if _code(exc) != "NoSuchBucketPolicy":
                    unread.append(f"bucket policy: {_code(exc)}")
            emit({"type": "storage_encryption", "target": label, "location": arn, "name": name, "facts": facts})
            if unread:  # listed with unknown settings: an unknown is not a fix
                emit(_gap(label, f"{arn}#settings", f"s3 bucket {name} settings",
                          "denied" if any(c.split(": ", 1)[1] in _DENIED for c in unread) else "error",
                          "; ".join(unread)[:200], [arn], incomplete=True))
        return f"{len(buckets)} buckets"

    def cloudfront() -> str | None:
        client = acct.client("cloudfront", "global")
        items: list[dict[str, Any]] = []
        for page in client.get_paginator("list_distributions").paginate():
            items.extend((page.get("DistributionList") or {}).get("Items") or [])
            if len(items) > PER_SERVICE_CAP:
                capped("cloudfront", "distributions", PER_SERVICE_CAP, [f"arn:aws:cloudfront::{acct.account}:distribution/"])
                break
        for dist in items[:PER_SERVICE_CAP]:
            viewer = dist.get("ViewerCertificate") or {}
            minimum = str(viewer.get("MinimumProtocolVersion") or "TLSv1")
            version = minimum.split("_")[0]  # TLSv1.2_2021 -> TLSv1.2, TLSv1_2016 -> TLSv1
            emit({"type": "cdn_tls", "target": label, "location": dist["ARN"], "name": dist.get("DomainName"), "protocol": "TLS",
                  "facts": {"min_version": "TLSv1.0" if version == "TLSv1" else version,
                            "minimum_protocol_version": minimum, "default_certificate": bool(viewer.get("CloudFrontDefaultCertificate")),
                            "acm_certificate_arn": viewer.get("ACMCertificateArn"),
                            **_exposure(True, "CloudFront distribution (served from the public edge)")}})
        return None

    for service, fn in (("iam", iam), ("s3", s3), ("cloudfront", cloudfront)):
        run(service, fn)
    return rows


def collect_aws(team_id: int, cfg: dict[str, Any], external_id: str, emit: Emit,
                should_stop: Callable[[], str | None]) -> dict[str, Any]:
    """Collect one AWS source.  Raises AwsCollectError when nothing may be read (safety checks failed)."""
    started = time.monotonic()
    role_arn = cfg["role_arn"]
    regions = list(cfg.get("regions") or ["us-east-1"])
    try:
        base, boto_cfg = _boto(retries=5, mode="adaptive")
    except Exception as exc:
        raise AwsCollectError(f"ZeroShield AWS credentials are not configured (ref {new_ref()})") from exc
    first = regions[0]
    sts = base.client("sts", region_name=first, config=boto_cfg)
    try:  # the trust policy must refuse us without the external ID
        sts.assume_role(RoleArn=role_arn, RoleSessionName=f"zs-cbom-noext-{team_id}"[:64], DurationSeconds=900)
        raise AwsCollectError("The role can be assumed without the external ID; add the sts:ExternalId condition and validate again")
    except AwsCollectError:
        raise
    except Exception as exc:
        if _code(exc) not in _DENIED:
            raise AwsCollectError(f"Could not check the role's trust policy: {_code(exc)}") from exc
    accounts = [_Account(base, boto_cfg, role_arn, external_id, team_id)]
    try:
        accounts[0].assume(first)
    except AwsCollectError:
        raise
    except Exception as exc:
        raise AwsCollectError(f"AssumeRole failed: {_code(exc)}") from exc
    targets: list[dict[str, Any]] = []
    gap_codes: dict[tuple[str, str], int] = {}
    if cfg.get("scope") == "organization":
        # The member list decides which accounts are read at all: when it fails (or is cut) the accounts that were not
        # listed are unknown, so this is a failed target of its own (the job is partial and never compared), not a note.
        org_label = f"aws:{accounts[0].account}"
        org_where = f"arn:aws:organizations::{accounts[0].account}:accounts"
        try:
            org = accounts[0].client("organizations", "global")
            members, members_cut = _paginate(org, "list_accounts", "Accounts", cap=200)
            role_name = role_arn.split(":role/", 1)[1]
            partition = role_arn.split(":")[1]
            for member in members:
                if member.get("Status") != "ACTIVE" or member["Id"] == accounts[0].account:
                    continue
                accounts.append(_Account(base, boto_cfg, f"arn:{partition}:iam::{member['Id']}:role/{role_name}", external_id, team_id))
            if members_cut:
                emit(_gap(org_label, org_where, "organization member accounts", "truncated",
                          "More than 200 member accounts; the first 200 were read"))
                targets.append({"target": f"{org_label}/organization", "status": "error", "assets": 0,
                                "error": "More than 200 member accounts; the first 200 were read"})
        except Exception as exc:
            emit(_gap(org_label, org_where, "organization member accounts", "error", _code(exc)))
            targets.append({"target": f"{org_label}/organization", "status": "error", "assets": 0,
                            "error": f"organization member accounts not listed: {_code(exc)}"[:256]})
    for acct in accounts:
        label = f"aws:{acct.account}"
        for region in ["global", *regions]:
            reason = should_stop()
            if reason:
                targets.append({"target": f"{label}/{region}", "status": "skipped_cancelled", "error": reason[:256], "assets": 0})
                continue
            t0 = time.monotonic()
            tally = _GapTally(emit)
            try:
                rows = (_global_services(acct, label, tally) if region == "global"
                        else _region_services(acct, region, label, tally, cfg, tick=should_stop))
            except AwsCollectError as exc:
                targets.append({"target": f"{label}/{region}", "status": "error", "error": str(exc)[:256], "assets": 0})
                continue
            except Exception as exc:  # AssumeRole in a member account failed
                targets.append({"target": f"{label}/{region}", "status": "auth_failed", "error": _code(exc)[:256], "assets": 0})
                continue
            bad = [f"{svc}: {status} {detail or ''}".strip() for svc, status, detail in rows if status not in ("ok", "partial")]
            gappy = [f"{svc}: {detail or 'partial'}" for svc, status, detail in rows if status == "partial"]
            enabled = [r for r in rows if r[1] != "not_enabled"]
            # partial: every service answered, some of what they hold was not read (each gap is a scoped coverage row)
            status = ("error" if enabled else "not_supported") if bad else ("partial" if gappy else "ok")
            targets.append({"target": f"{label}/{region}", "status": status, "error": "; ".join(bad + gappy)[:256] or None,
                            "duration_ms": int((time.monotonic() - t0) * 1000), "gaps": tally.gaps,
                            "services": {svc: status_ for svc, status_, _d in rows}})
            for code_key, n in tally.codes.items():
                gap_codes[code_key] = gap_codes.get(code_key, 0) + n
        # ACM certificates issued through ACME are not returned by ListCertificates in this SDK version (CB-33 EC-3):
        # said once per account, so "no ACME certificate" is never read as "none exists"
        emit(_gap(label, f"arn:aws:acm::{acct.account}:certificate#acme", "ACME-issued ACM certificates",
                  "not_supported", "ACME-issued ACM certificates are not listed by this SDK version", by_choice=True))
    log_gaps = {"gaps": sum(gap_codes.values()),
                "gap_codes": ",".join(f"{svc}:{code}:{n}" for (svc, code), n in sorted(gap_codes.items()))[:500] or None}
    return _summary(targets, team_id, started, log_extra=log_gaps, accounts=len(accounts))


def _summary(targets: list[dict[str, Any]], team_id: int, started: float, *,
             log_extra: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    ok = sum(1 for t in targets if t["status"] == "ok")
    partial = sum(1 for t in targets if t["status"] == "partial")
    skipped = sum(1 for t in targets if t["status"].startswith("skipped"))
    log("aws collected", team=team_id, targets=len(targets), ok=ok, partial=partial, **extra, **(log_extra or {}),
        duration_s=int(time.monotonic() - started))
    return {"targets": targets, **extra,
            "counts": {"total": len(targets), "ok": ok, "partial": partial, "failed": len(targets) - ok - partial - skipped,
                       "skipped": skipped},
            "duration_s": int(time.monotonic() - started)}

