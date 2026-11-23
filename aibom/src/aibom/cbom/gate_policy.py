"""CBOM CI/CD policy gate: the policy format, its validation and its evaluation
over CBOM finding rows (SOW S1).

This file is vendored BYTE-IDENTICAL into the backend
(``backend/utilities/cicd/gate_policy.py``, the hosted gate of
``POST /cicd/cbom/scan``) and the code lane (``aibom/src/aibom/cbom/gate_policy.py``,
the offline ``aibom cbom`` gate), because those packages cannot import each other;
``backend/tests/test_cbom_gate_policy.py`` fails when the copies differ. Edit the
backend copy, then copy it over. Stdlib only.

A policy (JSON, ``version`` 1) holds:

* ``block_codes``: finding codes that fail the gate (default: the code-scan CLI's
  high set);
* ``banned_algorithms``: algorithm names that fail the gate wherever they are used
  (aliases: 3DES = TDEA = DESede);
* ``min_key_bits``: the smallest key size allowed per family (rsa, dsa, dh, ec,
  symmetric). A key whose size the scan did not read is never guessed, so it
  passes this rule;
* ``quantum_vulnerable`` and ``deprecated``: ``off``, ``warn`` (reported, the
  build passes) or ``fail``. "Deprecated" is the NIST SP 800-131A Rev. 2 list
  below (SHA-1 outside HMAC, DSA signatures, RSA PKCS #1 v1.5 key transport);
* ``exceptions``: allow-list entries, each with an algorithm and/or a location
  (glob), optionally one rule, a reason and an expiry date. An expired exception
  waives nothing and is listed in the verdict.

The default policy follows SP 800-131A Rev. 2 (RSA / DSA / DH 2048, EC 256,
symmetric 128; MD5, DES, 3DES, RC2 and RC4 banned) and reports quantum-vulnerable
and deprecated algorithms as warnings for the CNSA 2.0 transition; the
``cnsa-2.0`` preset fails on them and raises the minimums to RSA / DH 3072,
EC 384 and AES-256.

Every finding lists each rule it broke with its outcome (``fail``, ``warn`` or
``waived``) and a short detail.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
import hashlib
import json
import re
from typing import Any

FILE_KIND = "zeroshield.cbom-gate-policy"
VERSION = 1
RULES = (
    "finding_code",
    "banned_algorithm",
    "min_key_size",
    "deprecated_algorithm",
    "quantum_vulnerable",
)
MODES = ("off", "warn", "fail")
FAMILIES = ("rsa", "dsa", "dh", "ec", "symmetric")
FAMILY_LABEL = {
    "rsa": "RSA",
    "dsa": "DSA",
    "dh": "Finite-field DH",
    "ec": "Elliptic-curve",
    "symmetric": "Symmetric",
}
KEY_LIMITS = {
    "rsa": (1024, 16384),
    "dsa": (1024, 16384),
    "dh": (1024, 16384),
    "ec": (160, 571),
    "symmetric": (56, 256),
}
MAX_EXCEPTION_DAYS = 366
MAX_EXCEPTIONS = 200
MAX_BANNED = 100
MAX_CODES = 64

# == aibom.cbom.gate.FAIL_CODES (the code-scan CLI's high set)
LEGACY_FAIL_CODES = (
    "HARDCODED_KEY",
    "REUSED_NONCE",
    "STATIC_IV",
    "TLS_VERIFICATION_DISABLED",
    "VULNERABLE_CRYPTO_LIBRARY",
    "WEAK_ALGORITHM",
    "WEAK_CIPHER_MODE",
    "WEAK_KEY_SIZE",
    "WEAK_PADDING",
    "WEAK_RNG",
)

DEFAULT_POLICY: dict[str, Any] = {
    "version": VERSION,
    "name": "Default: NIST SP 800-131A Rev. 2 (quantum-vulnerable warns)",
    "block_codes": list(LEGACY_FAIL_CODES),
    "banned_algorithms": ["MD2", "MD4", "MD5", "DES", "3DES", "RC2", "RC4"],
    "min_key_bits": {"rsa": 2048, "dsa": 2048, "dh": 2048, "ec": 256, "symmetric": 128},
    "quantum_vulnerable": "warn",
    "deprecated": "warn",
    "exceptions": [],
}

PRESETS: dict[str, dict[str, Any]] = {
    "sp800-131a": DEFAULT_POLICY,
    "cnsa-2.0": {
        **DEFAULT_POLICY,
        "name": "CNSA 2.0 (strict: quantum-vulnerable and deprecated fail)",
        "banned_algorithms": ["MD2", "MD4", "MD5", "SHA1", "DES", "3DES", "RC2", "RC4"],
        "min_key_bits": {
            "rsa": 3072,
            "dsa": 3072,
            "dh": 3072,
            "ec": 384,
            "symmetric": 256,
        },
        "quantum_vulnerable": "fail",
        "deprecated": "fail",
    },
}

QV_CODE = "QUANTUM_VULNERABLE"
QV_DETAIL = (
    "Quantum-vulnerable public-key algorithm: CNSA 2.0 and NIST IR 8547 phase it "
    "out (deprecated after 2030, disallowed after 2035)"
)

# Aliases a banned name also matches (canonical: upper case, letters and digits).
ALIASES = {
    "3DES": ("3DES", "TDEA", "TDES", "DESEDE", "DESEDE3", "TRIPLEDES", "DES3", "3DEA"),
    "SHA1": ("SHA1",),
}

# NIST SP 800-131A Rev. 2 transitions beyond the banned list:
# (canonical n-gram, label, detail)
DEPRECATED = (
    (
        "SHA1",
        "SHA-1",
        "SHA-1 is disallowed for digital signature generation (NIST SP 800-131A "
        "Rev. 2, section 9; HMAC-SHA-1 stays acceptable)",
    ),
    (
        "DSA",
        "DSA",
        "DSA signature generation is no longer approved (FIPS 186-5); verification "
        "is legacy use only (NIST SP 800-131A Rev. 2)",
    ),
    (
        "PKCS1V15",
        "RSA PKCS #1 v1.5 key transport",
        "RSA key transport with PKCS #1 v1.5 padding is disallowed after "
        "2023 (NIST SP 800-131A Rev. 2, section 6)",
    ),
)

_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_ALG_RE = re.compile(r"^[A-Za-z0-9 ._/+#()-]{1,40}$")
_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_EC_TOKENS = {
    "EC",
    "ECDSA",
    "ECDH",
    "ECDHE",
    "ECIES",
    "ECMQV",
    "EDDSA",
    "ED25519",
    "ED448",
    "X25519",
    "X448",
    "CURVE25519",
    "CURVE448",
    "ECC",
}
_EC_CURVE = re.compile(
    r"^(?:SEC[PT](\d{3})[RK]\d|PRIME(\d{3})V\d|BRAINPOOLP(\d{3})[RT]\d|NISTP(\d{3})|P(\d{3})|"
    r"ANSIX9P(\d{3})V\d)$"
)
_DH_TOKENS = {"DH", "DHE", "DIFFIEHELLMAN", "FFDH", "FFDHE", "EDH"}
_SYMMETRIC = {
    "AES",
    "DES",
    "3DES",
    "TDEA",
    "DESEDE",
    "TRIPLEDES",
    "CAMELLIA",
    "ARIA",
    "SM4",
    "CHACHA20",
    "CHACHA",
    "BLOWFISH",
    "TWOFISH",
    "IDEA",
    "CAST5",
    "CAST128",
    "SEED",
    "SERPENT",
    "SALSA20",
    "RC2",
    "RC4",
    "RC5",
    "RC6",
    "XCHACHA20",
}
_SYMMETRIC_PRIMITIVES = {"block-cipher", "stream-cipher", "ae"}


class PolicyError(ValueError):
    """A policy that cannot be used. ``field`` names the place (``min_key_bits.rsa``,
    ``exceptions[2].expires``); the message never echoes the submitted value."""

    def __init__(self, field: str, message: str):
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


# ---------------------------------------------------------------------- names
def canonical(text: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(text or "").upper())


def _tokens(text: str) -> list[str]:
    upper = re.sub(r"WITH", " ", str(text or "").upper())
    return [t for t in re.split(r"[^A-Z0-9]+", upper) if t]


def _ngrams(tokens: list[str]) -> set[str]:
    out: set[str] = set()
    for size in (1, 2, 3):
        for i in range(len(tokens) - size + 1):
            out.add("".join(tokens[i : i + size]))
    return out


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _curve_bits(token: str) -> int | None:
    if token in ("X25519", "ED25519", "CURVE25519"):
        return 256
    if token in ("X448", "ED448", "CURVE448"):
        return 448
    match = _EC_CURVE.match(token)
    if not match:
        return None
    return int(next(g for g in match.groups() if g))


def classify(row: dict[str, Any]) -> tuple[str | None, int | None]:
    """(family, key bits) of an algorithm row; either may be None (never guessed)."""
    tokens = _tokens(row.get("title") or "")
    grams = _ngrams(tokens)
    curve_tokens = _tokens(row.get("curve") or "")
    curve_grams = _ngrams(curve_tokens)
    primitive = str(row.get("primitive") or "").lower()
    key_size = _int(row.get("key_size"))
    numbers = [int(t) for t in tokens if t.isdigit()]

    ec_bits = next(
        (b for g in sorted(curve_grams | grams) if (b := _curve_bits(g)) is not None),
        None,
    )
    if curve_tokens or ec_bits is not None or grams & _EC_TOKENS:
        return "ec", ec_bits if ec_bits is not None else key_size
    if any(t.startswith("RSA") for t in tokens):
        return "rsa", key_size if key_size is not None else next(
            (n for n in numbers if 512 <= n <= 16384), None
        )
    if "DSA" in tokens:
        return "dsa", key_size if key_size is not None else next(
            (n for n in numbers if 512 <= n <= 16384), None
        )
    ffdhe = next((t for t in tokens if re.fullmatch(r"FFDHE\d{4}", t)), None)
    if ffdhe or tokens and (set(tokens) & _DH_TOKENS or "MODP" in tokens[0]):
        bits = (
            key_size
            if key_size is not None
            else (
                int(ffdhe[5:])
                if ffdhe
                else next((n for n in numbers if 512 <= n <= 16384), None)
            )
        )
        return "dh", bits
    head = tokens[0] if tokens else ""
    if (
        head in _SYMMETRIC
        or re.fullmatch(r"AES\d{3}", head)
        or primitive in _SYMMETRIC_PRIMITIVES
    ):
        if key_size is not None:
            return "symmetric", key_size
        if re.fullmatch(r"AES\d{3}", head):
            return "symmetric", int(head[3:])
        if head == "AES" and len(tokens) > 1 and tokens[1] in ("128", "192", "256"):
            return "symmetric", int(tokens[1])
        if head in ("CHACHA20", "XCHACHA20", "SALSA20"):
            return "symmetric", 256
        if head in ("3DES", "TDEA", "DESEDE", "TRIPLEDES"):
            return "symmetric", 112
        if head == "DES":
            return "symmetric", 56
        return "symmetric", None
    return None, key_size


def banned_match(row: dict[str, Any], banned: list[str]) -> str | None:
    grams = _ngrams(_tokens(row.get("title") or ""))
    for name in banned:
        key = canonical(name)
        if any(alias in grams for alias in ALIASES.get(key, (key,))):
            return name
    return None


def deprecated_match(row: dict[str, Any]) -> tuple[str, str] | None:
    tokens = _tokens(row.get("title") or "")
    grams = _ngrams(tokens)
    is_mac = str(row.get("primitive") or "").lower() == "mac" or any(
        t.startswith("HMAC") for t in tokens
    )
    for key, label, detail in DEPRECATED:
        if key == "SHA1" and is_mac:
            continue
        if key == "DSA" and "DSA" not in tokens:
            continue
        if key in grams:
            return label, detail
    return None


# ----------------------------------------------------------------- validation
def _date(value: Any) -> _dt.date | None:
    if not isinstance(value, str) or not _DATE_RE.match(value):
        return None
    try:
        return _dt.date.fromisoformat(value)
    except ValueError:
        return None


def _text(value: Any, field: str, limit: int, *, required: bool) -> str | None:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise PolicyError(field, "required")
        return None
    if (
        not isinstance(value, str)
        or len(value.strip()) > limit
        or re.search(r"[\x00-\x1f\x7f]", value)
    ):
        raise PolicyError(field, f"at most {limit} printable characters")
    return value.strip()


def _exception(
    raw: Any, i: int, today: _dt.date | None, for_save: bool
) -> dict[str, Any]:
    field = f"exceptions[{i}]"
    if not isinstance(raw, dict):
        raise PolicyError(
            field, "an object with algorithm and/or location, reason and expires"
        )
    unknown = set(raw) - {"id", "rule", "algorithm", "location", "reason", "expires"}
    if unknown:
        raise PolicyError(
            f"{field}.{sorted(unknown)[0]}", "not a field of an exception"
        )
    algorithm = _text(raw.get("algorithm"), f"{field}.algorithm", 40, required=False)
    if algorithm is not None and not _ALG_RE.match(algorithm):
        raise PolicyError(f"{field}.algorithm", "an algorithm name such as RSA-1024")
    location = _text(raw.get("location"), f"{field}.location", 200, required=False)
    rule = raw.get("rule")
    if rule in ("", None):
        rule = None
    elif rule not in RULES:
        raise PolicyError(
            f"{field}.rule", f"one of {', '.join(RULES)}, or empty for every rule"
        )
    reason = _text(raw.get("reason"), f"{field}.reason", 300, required=True)
    expires = _date(raw.get("expires"))
    if expires is None:
        raise PolicyError(f"{field}.expires", "a date as YYYY-MM-DD")
    if for_save and today is not None:
        if expires < today:
            raise PolicyError(
                f"{field}.expires",
                "already passed; remove the exception or give a later date",
            )
        if (expires - today).days > MAX_EXCEPTION_DAYS:
            raise PolicyError(
                f"{field}.expires",
                f"at most {MAX_EXCEPTION_DAYS} days ahead; review it again then",
            )
    if algorithm is None and location is None:
        raise PolicyError(
            field,
            "name an algorithm or a location (glob); a waiver of everything "
            "is not allowed",
        )
    ident = raw.get("id")
    if ident in (None, ""):
        seed = json.dumps(
            [rule, algorithm, location, reason, expires.isoformat()], sort_keys=True
        )
        ident = "exc-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
    elif not isinstance(ident, str) or not _ID_RE.match(ident):
        raise PolicyError(
            f"{field}.id", "letters, digits, dot, dash and underscore (at most 40)"
        )
    return {
        "id": ident,
        "rule": rule,
        "algorithm": algorithm,
        "location": location,
        "reason": reason,
        "expires": expires.isoformat(),
    }


def _mode(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key, DEFAULT_POLICY[key])
    if value not in MODES:
        raise PolicyError(key, "off, warn or fail")
    return value


def validate_policy(
    raw: Any, *, today: _dt.date | None = None, for_save: bool = False
) -> dict[str, Any]:
    """The policy in its normal form, or ``PolicyError``. Missing top-level fields
    take the default's value. ``for_save`` (the API) also refuses an exception that
    has expired or runs more than a year ahead; a policy file for the offline gate
    may hold an expired one (it then waives nothing)."""
    if not isinstance(raw, dict):
        raise PolicyError("policy", "a JSON object")
    allowed = set(DEFAULT_POLICY) | {"kind"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise PolicyError(unknown[0], "not a field of a CBOM gate policy")
    if "kind" in raw and raw["kind"] != FILE_KIND:
        raise PolicyError("kind", f"must be {FILE_KIND}")
    if raw.get("version", VERSION) != VERSION or isinstance(raw.get("version"), bool):
        raise PolicyError("version", f"this gate reads version {VERSION}")
    name = _text(raw.get("name", DEFAULT_POLICY["name"]), "name", 80, required=True)

    codes = raw.get("block_codes", DEFAULT_POLICY["block_codes"])
    if (
        not isinstance(codes, list)
        or len(codes) > MAX_CODES
        or not all(isinstance(c, str) and _CODE_RE.match(c) for c in codes)
    ):
        raise PolicyError(
            "block_codes",
            f"a list of at most {MAX_CODES} finding codes such as WEAK_ALGORITHM",
        )

    banned_raw = raw.get("banned_algorithms", DEFAULT_POLICY["banned_algorithms"])
    if not isinstance(banned_raw, list) or len(banned_raw) > MAX_BANNED:
        raise PolicyError(
            "banned_algorithms", f"a list of at most {MAX_BANNED} algorithm names"
        )
    banned: list[str] = []
    seen: set[str] = set()
    for item in banned_raw:
        if (
            not isinstance(item, str)
            or not _ALG_RE.match(item.strip())
            or not canonical(item)
        ):
            raise PolicyError(
                "banned_algorithms",
                "algorithm names such as MD5 or 3DES (at most 40 characters)",
            )
        if canonical(item) not in seen:
            seen.add(canonical(item))
            banned.append(item.strip())

    sizes_raw = raw.get("min_key_bits", DEFAULT_POLICY["min_key_bits"])
    if not isinstance(sizes_raw, dict):
        raise PolicyError(
            "min_key_bits", "an object with rsa, dsa, dh, ec and symmetric"
        )
    extra = sorted(set(sizes_raw) - set(FAMILIES))
    if extra:
        raise PolicyError(
            f"min_key_bits.{extra[0]}", "not a key family (rsa, dsa, dh, ec, symmetric)"
        )
    sizes: dict[str, int] = {}
    for family in FAMILIES:
        value = sizes_raw.get(family)
        low, high = KEY_LIMITS[family]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not low <= value <= high
        ):
            raise PolicyError(
                f"min_key_bits.{family}", f"a whole number of bits from {low} to {high}"
            )
        sizes[family] = value

    exceptions_raw = raw.get("exceptions", [])
    if not isinstance(exceptions_raw, list) or len(exceptions_raw) > MAX_EXCEPTIONS:
        raise PolicyError(
            "exceptions", f"a list of at most {MAX_EXCEPTIONS} exceptions"
        )
    exceptions = [
        _exception(item, i, today, for_save) for i, item in enumerate(exceptions_raw)
    ]
    ids = [e["id"] for e in exceptions]
    if len(set(ids)) != len(ids):
        raise PolicyError("exceptions", "two exceptions have the same id")

    return {
        "version": VERSION,
        "name": name,
        "block_codes": sorted(set(codes)),
        "banned_algorithms": banned,
        "min_key_bits": sizes,
        "quantum_vulnerable": _mode(raw, "quantum_vulnerable"),
        "deprecated": _mode(raw, "deprecated"),
        "exceptions": exceptions,
    }


def policy_digest(policy: dict[str, Any]) -> str:
    text = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("ascii")).hexdigest()[:16]


def dump_policy_file(policy: dict[str, Any]) -> str:
    return (
        json.dumps({"kind": FILE_KIND, **policy}, indent=2, ensure_ascii=False) + "\n"
    )


def load_policy_file(text: str) -> dict[str, Any]:
    try:
        raw = json.loads(text)
    except ValueError:
        raise PolicyError("file", "not valid JSON") from None
    return validate_policy(raw)


# ----------------------------------------------------------------- evaluation
def _waiver(
    row: dict[str, Any], rule: str, active: list[dict[str, Any]]
) -> dict[str, Any] | None:
    grams = _ngrams(_tokens(row.get("title") or "")) | {canonical(row.get("title"))}
    location = str(row.get("location") or "")
    for exc in active:
        if exc["rule"] not in (None, rule):
            continue
        if exc["algorithm"] is not None and canonical(exc["algorithm"]) not in grams:
            continue
        if exc["location"] is not None and not fnmatch.fnmatchcase(
            location, exc["location"]
        ):
            continue
        return exc
    return None


def row_rules(
    row: dict[str, Any], policy: dict[str, Any], active: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Every rule of ``policy`` this finding row breaks, in ``RULES`` order, each
    with its outcome."""
    codes = [c for c in row.get("finding_codes") or [] if isinstance(c, str)]
    found: list[tuple[str, str, str]] = []  # (rule, mode, detail)
    blocked = sorted(set(codes) & set(policy["block_codes"]))
    if blocked:
        found.append(
            (
                "finding_code",
                "fail",
                f"Finding code {', '.join(blocked)} is blocked by the policy",
            )
        )
    if row.get("asset_type") in (None, "", "algorithm"):
        banned = banned_match(row, policy["banned_algorithms"])
        if banned is not None:
            found.append(
                ("banned_algorithm", "fail", f"{banned} is on the policy's banned list")
            )
        else:  # a banned algorithm is not judged again on its key size or deprecation
            family, bits = classify(row)
            minimum = policy["min_key_bits"].get(family or "")
            if family and bits is not None and minimum and bits < minimum:
                found.append(
                    (
                        "min_key_size",
                        "fail",
                        f"{FAMILY_LABEL[family]} key size {bits} bits is below the "
                        f"policy minimum of {minimum} bits",
                    )
                )
            dep = deprecated_match(row) if policy["deprecated"] != "off" else None
            if dep is not None:
                found.append(
                    (
                        "deprecated_algorithm",
                        policy["deprecated"],
                        f"{dep[0]}: {dep[1]}",
                    )
                )
    if policy["quantum_vulnerable"] != "off" and (
        row.get("quantum_vulnerable") is True or QV_CODE in codes
    ):
        found.append(("quantum_vulnerable", policy["quantum_vulnerable"], QV_DETAIL))
    out: list[dict[str, Any]] = []
    for rule, mode, detail in found:
        exc = _waiver(row, rule, active)
        if exc is not None:
            out.append(
                {
                    "rule": rule,
                    "outcome": "waived",
                    "detail": detail,
                    "exception_id": exc["id"],
                    "reason": exc["reason"],
                    "expires": exc["expires"],
                }
            )
        else:
            out.append({"rule": rule, "outcome": mode, "detail": detail})
    return out


def evaluate_rows(
    rows: list[Any], policy: dict[str, Any], *, today: _dt.date | None = None
) -> dict[str, Any]:
    """Judge finding rows. Returns failing / warnings / waived entries (uncapped),
    the number of failing rows per rule and the exceptions that have expired. Rows
    that are not objects, or have no list of codes, are skipped."""
    day = today or _dt.datetime.now(_dt.UTC).date()
    active = [e for e in policy["exceptions"] if e["expires"] >= day.isoformat()]
    expired = [
        {"id": e["id"], "expires": e["expires"], "reason": e["reason"]}
        for e in policy["exceptions"]
        if e["expires"] < day.isoformat()
    ]
    failing: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    waived: list[dict[str, Any]] = []
    rules_failed: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("finding_codes"), list):
            continue
        rules = row_rules(row, policy, active)
        if not rules:
            continue
        line = row.get("line")
        entry = {
            "codes": sorted(
                {c for c in row["finding_codes"] if isinstance(c, str)}
                & set(policy["block_codes"])
            ),
            "title": row.get("title") if isinstance(row.get("title"), str) else "",
            "location": row.get("location")
            if isinstance(row.get("location"), str)
            else "",
            "line": line
            if isinstance(line, int) and not isinstance(line, bool)
            else None,
            "impact": row.get("impact") if isinstance(row.get("impact"), str) else None,
            "rules": rules,
        }
        outcomes = {r["outcome"] for r in rules}
        if "fail" in outcomes:
            failing.append(entry)
            for rule in sorted(
                {r["rule"] for r in rules if r["outcome"] == "fail"}, key=RULES.index
            ):
                rules_failed[rule] = rules_failed.get(rule, 0) + 1
        elif "warn" in outcomes:
            warnings.append(entry)
        else:
            waived.append(entry)
    ordered = {rule: rules_failed[rule] for rule in RULES if rule in rules_failed}
    return {
        "failing": failing,
        "warnings": warnings,
        "waived": waived,
        "rules_failed": ordered,
        "expired_exceptions": expired,
    }


def summary_line(gate: dict[str, Any]) -> str:
    """One line for CI logs that grep / sed can cut out of the answer: no quotes,
    backslashes or line breaks."""
    rules = (
        ",".join(f"{k}:{v}" for k, v in (gate.get("rules_failed") or {}).items())
        or "none"
    )
    verdict = str(gate.get("verdict") or "no_result").upper()
    text = (
        f"{verdict} policy={gate.get('policy') or '-'} "
        f"failing={gate.get('failing_count', 0)} "
        f"warnings={gate.get('warning_count', 0)} "
        f"waived={gate.get('waived_count', 0)} rules_failed={rules}"
    )
    return re.sub(r"[^A-Za-z0-9 ._:,=()/+#-]", "_", text)[:300]
