"""Hardware security modules and tokens through PKCS#11 (python-pkcs11), read-only.

* The PKCS#11 library is native code that the node loads into its own process, so its path is NEVER taken from the
  server: the source names a module, and the node operator maps names to library paths in the node's own
  environment, ``ZS_PKCS11_MODULES="softhsm=/usr/lib/softhsm/libsofthsm2.so;luna=/usr/safenet/lunaclient/lib/libCryptoki2_64.so"``.
  A name that is not listed there is refused.
* Sessions are opened read-only (no C_InitToken, C_GenerateKey, C_SetAttributeValue or C_DestroyObject is ever
  called) and only attributes ABOUT objects are read: class, key type, size or curve, label, id, the
  extractable/sensitive/local flags, the usage flags and dates.  Values are never requested: ``CKA_VALUE`` is read for
  certificates only (a certificate is public), never for a key, and no private-key component is ever named.
* A vendor's library may itself talk to a network HSM; that connection is configured by the node operator in the
  vendor's client, not by ZeroShield, and is outside the scan node's network gate.
"""
from __future__ import annotations

import os
import time
from typing import Any

from zs_scan_node.certparse import cert_facts, load_certs
from zs_scan_node.collectors import ConfigError
from zs_scan_node.jobctx import JobContext, register_asset_types
from zs_scan_node.scrub import printable

register_asset_types("key_store", "managed_key")

MAX_TOKENS = 16
MAX_OBJECTS = 5000
# Attributes read for keys: about the key, never its value or a private component.
KEY_ATTRIBUTES = ("CLASS", "KEY_TYPE", "LABEL", "ID", "TOKEN", "PRIVATE", "SENSITIVE", "ALWAYS_SENSITIVE", "EXTRACTABLE",
                  "NEVER_EXTRACTABLE", "LOCAL", "WRAP", "UNWRAP", "ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "DERIVE",
                  "WRAP_WITH_TRUSTED", "TRUSTED", "START_DATE", "END_DATE", "MODULUS_BITS", "VALUE_LEN", "EC_PARAMS",
                  "MODULUS")
FORBIDDEN_ATTRIBUTES = frozenset({"VALUE", "PRIVATE_EXPONENT", "PRIME_1", "PRIME_2", "EXPONENT_1", "EXPONENT_2",
                                  "COEFFICIENT", "PRIME", "SUBPRIME", "BASE"})
assert not FORBIDDEN_ATTRIBUTES & set(KEY_ATTRIBUTES)
_DES_BITS = {"DES": 56, "DES2": 112, "DES3": 168}
_CURVES = {  # DER of the named-curve OID in CKA_EC_PARAMS -> (name, bits)
    "06082a8648ce3d030107": ("P-256", 256), "06052b81040022": ("P-384", 384), "06052b81040023": ("P-521", 521),
    "06052b8104001f": ("secp192k1", 192), "06082a8648ce3d030101": ("P-192", 192), "06052b81040021": ("P-224", 224),
    "06052b8104000a": ("secp256k1", 256), "06032b6570": ("Ed25519", 256), "06032b6571": ("Ed448", 448),
    "06032b656e": ("X25519", 256), "06032b656f": ("X448", 448),
    "130c656477617264733235353139": ("Ed25519", 256), "130a65647761726473343438": ("Ed448", 448),
}


def allowed_modules(env: str | None = None) -> dict[str, str]:
    """name -> library path from ZS_PKCS11_MODULES (``name=/path`` entries separated by ';' or newlines)."""
    text = os.environ.get("ZS_PKCS11_MODULES", "") if env is None else env
    out: dict[str, str] = {}
    for item in text.replace("\n", ";").split(";"):
        name, sep, path = item.partition("=")
        if sep and name.strip() and path.strip():
            out[name.strip().lower()] = path.strip()
    return out


def module_path(name: str, env: str | None = None) -> str:
    modules = allowed_modules(env)
    key = str(name or "").strip().lower()
    if key not in modules:
        listed = ", ".join(sorted(modules)) or "none"
        raise ConfigError(f"PKCS#11 module {name!r} is not allowed on this scan node (ZS_PKCS11_MODULES lists: {listed})")
    path = modules[key]
    if not os.path.isabs(path) or not os.path.isfile(path):
        raise ConfigError(f"PKCS#11 module {name!r} points at {path}, which is not a file on this scan node")
    return path


def _pin(ctx: JobContext, config: dict, secrets: dict) -> str | None:
    if config.get("credential_type") == "vault":
        from zs_scan_node import vault

        ref = config.get("vault") or {}
        creds = vault.fetch(str(ref.get("provider")), str(ref.get("path") or ""), ctx.vault_prefix)
        for v in creds.values():
            ctx.scrubber.add(v)
        return creds.get("pin") or creds.get("password")
    return secrets.get("pin") or None


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return printable(str(value or "").strip(), 128)


def _version(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return f"{value[0]}.{value[1]}"
    return _text(value) or None


def _enum_name(value: Any) -> str | None:
    if value is None:
        return None
    name = getattr(value, "name", None)
    return str(name) if name else str(value)


def _flags(value: Any) -> list[str]:
    if value is None:
        return []
    names = [f.name for f in type(value) if f.value and (value & f) == f] if hasattr(type(value), "__iter__") else []
    return sorted(n for n in names if n)


def read_attributes(obj, names: tuple[str, ...]) -> dict[str, Any]:
    """Each attribute on its own, so one the token does not have (or hides) does not hide the others."""
    from pkcs11 import Attribute
    from pkcs11.exceptions import PKCS11Error

    out: dict[str, Any] = {}
    for name in names:
        if name in FORBIDDEN_ATTRIBUTES:
            raise ValueError(f"refusing to read {name}")
        try:
            out[name] = obj[getattr(Attribute, name)]
        except (PKCS11Error, KeyError, AttributeError, NotImplementedError, ValueError, TypeError):
            continue  # not present, hidden, or a value the library cannot decode (an empty CK_DATE)
    return out


def _date(value: Any) -> str | None:
    if value is None or value == b"" or value == "":
        return None
    try:
        return value.isoformat()
    except AttributeError:
        return _text(value) or None


def key_facts(attrs: dict[str, Any]) -> tuple[str, str | None, int | None, dict[str, Any]]:
    """(key class, algorithm, size in bits, facts) from the attributes read for one key object."""
    klass = (_enum_name(attrs.get("CLASS")) or "").upper()
    key_class = {"PRIVATE_KEY": "private", "SECRET_KEY": "secret", "PUBLIC_KEY": "public"}.get(klass, klass.lower())
    algorithm = (_enum_name(attrs.get("KEY_TYPE")) or "").upper() or None
    size = None
    curve = None
    if attrs.get("MODULUS_BITS"):
        size = int(attrs["MODULUS_BITS"])
    elif isinstance(attrs.get("MODULUS"), (bytes, bytearray)) and attrs["MODULUS"]:
        size = int.from_bytes(bytes(attrs["MODULUS"]), "big").bit_length()  # the public modulus, never a secret part
    elif attrs.get("VALUE_LEN"):
        size = int(attrs["VALUE_LEN"]) * 8
    elif algorithm in _DES_BITS:
        size = _DES_BITS[algorithm]
    if isinstance(attrs.get("EC_PARAMS"), (bytes, bytearray)):
        curve, bits = _CURVES.get(bytes(attrs["EC_PARAMS"]).hex(), (None, None))
        size = size or bits
        if curve is None:
            curve = "OID " + bytes(attrs["EC_PARAMS"]).hex()[:40]
    if algorithm in _DES_BITS:
        size = _DES_BITS[algorithm]
    ident = attrs.get("ID")
    facts: dict[str, Any] = {
        "store": "pkcs11", "key_class": key_class, "key_type": algorithm, "curve": curve,
        "id": bytes(ident).hex()[:64] if isinstance(ident, (bytes, bytearray)) else None,
        "token_object": attrs.get("TOKEN"), "private_object": attrs.get("PRIVATE"),
    }
    for name in ("SENSITIVE", "ALWAYS_SENSITIVE", "EXTRACTABLE", "NEVER_EXTRACTABLE", "LOCAL", "WRAP", "UNWRAP",
                 "ENCRYPT", "DECRYPT", "SIGN", "VERIFY", "DERIVE", "WRAP_WITH_TRUSTED", "TRUSTED"):
        if name in attrs and attrs[name] is not None:
            facts[name.lower()] = bool(attrs[name])
    facts["start_date"], facts["end_date"] = _date(attrs.get("START_DATE")), _date(attrs.get("END_DATE"))
    return key_class, algorithm, size, facts


def _token_info(module: str, lib, slot, token) -> dict[str, Any]:
    info: dict[str, Any] = {"store": "pkcs11", "module": module}
    for key, getter in (("library_manufacturer", lambda: lib.manufacturer_id),
                        ("library_description", lambda: lib.library_description),
                        ("library_version", lambda: _version(lib.library_version)),
                        ("cryptoki_version", lambda: _version(lib.cryptoki_version)),
                        ("slot_description", lambda: slot.slot_description),
                        ("slot_manufacturer", lambda: slot.manufacturer_id),
                        ("token_label", lambda: token.label), ("token_manufacturer", lambda: token.manufacturer_id),
                        ("token_model", lambda: token.model), ("token_serial", lambda: token.serial),
                        ("hardware_version", lambda: _version(token.hardware_version)),
                        ("firmware_version", lambda: _version(token.firmware_version)),
                        ("token_flags", lambda: _flags(token.flags))):
        try:
            value = getter()
        except Exception:  # attribute missing in this library version or token
            continue
        info[key] = value if isinstance(value, list) else (_text(value) or None)
    text = " ".join(str(info.get(k) or "") for k in ("token_model", "token_label", "slot_description",
                                                     "library_description", "token_manufacturer"))
    # PKCS#11 has no standard FIPS flag; only say what the vendor's own strings say
    info["fips_hint"] = "FIPS" in text.upper() or None
    return info


def _read_token(ctx: JobContext, module: str, lib, slot, token, pin: str | None) -> tuple[int, str | None]:
    from pkcs11 import ObjectClass, TokenFlag
    from pkcs11.exceptions import PinIncorrect, PinLocked, PKCS11Error, UserPinNotInitialized

    info = _token_info(module, lib, slot, token)
    label = info.get("token_label") or f"slot-{getattr(slot, 'slot_id', '?')}"
    where = f"pkcs11:{module}/{label}"
    login_required = bool(token.flags & TokenFlag.LOGIN_REQUIRED) if token.flags is not None else True
    try:
        session = token.open(rw=False, user_pin=pin if (pin and login_required) else None)
    except (PinIncorrect, PinLocked, UserPinNotInitialized):
        ctx.emit("key_store", label, where, name=label, facts={**info, "logged_in": False})
        return 1, "auth_failed"
    except PKCS11Error as exc:
        ctx.emit("key_store", label, where, name=label, facts={**info, "logged_in": False})
        ctx.coverage(label, f"PKCS#11 token {label}", "error", f"could not open a session: {exc.__class__.__name__}")
        return 1, "error"
    n = 0
    counts: dict[str, int] = {}
    try:
        if login_required and not pin:
            ctx.coverage(label, f"PKCS#11 token {label}", "denied", "no PIN stored: only public objects were read")
        for i, obj in enumerate(session.get_objects()):
            if i >= MAX_OBJECTS:
                ctx.coverage(label, f"PKCS#11 token {label}", "error", f"more than {MAX_OBJECTS} objects; the rest were "
                             "not read")
                break
            klass = obj.object_class
            counts[klass.name] = counts.get(klass.name, 0) + 1
            if klass in (ObjectClass.PRIVATE_KEY, ObjectClass.SECRET_KEY, ObjectClass.PUBLIC_KEY):
                attrs = read_attributes(obj, KEY_ATTRIBUTES)
                key_class, algorithm, size, facts = key_facts(attrs)
                name = _text(attrs.get("LABEL")) or (f"id {facts['id']}" if facts.get("id") else f"object {i}")
                ctx.emit("managed_key", label, f"{where}/{key_class}/{name}", name=name, algorithm=algorithm, key_size=size,
                         facts={**facts, "module": module, "token": label, "token_serial": info.get("token_serial")})
                n += 1
            elif klass == ObjectClass.CERTIFICATE:
                attrs = read_attributes(obj, ("LABEL", "ID"))
                try:
                    from pkcs11 import Attribute

                    der = obj[Attribute.VALUE]  # a certificate's value is the public certificate
                except PKCS11Error:
                    der = None
                for cert in (load_certs(bytes(der)) if der else [])[:1]:
                    f = cert_facts(cert, "pkcs11")
                    name = _text(attrs.get("LABEL")) or f.get("subject", "")
                    ctx.emit("certificate", label, f"{where}/certificate/{name}", name=name, algorithm=f.get("key_alg"),
                             key_size=f.get("key_size"), facts={**f, "module": module, "token": label})
                    n += 1
    finally:
        session.close()
    ctx.emit("key_store", label, where, name=label,
             facts={**info, "logged_in": bool(pin and login_required), "login_required": login_required,
                    "objects": counts})
    return n + 1, None


def _open(config: dict):
    import pkcs11

    name = str(config.get("module") or "")
    path = module_path(name)
    try:
        return name, pkcs11.lib(path)
    except Exception as exc:
        raise ConfigError(f"PKCS#11 module {name!r} did not load ({exc.__class__.__name__})") from None


def _tokens(lib, config: dict) -> list[tuple[Any, Any]]:
    from pkcs11 import TokenFlag

    want = str(config.get("token_label") or "").strip()
    out = []
    for slot in lib.get_slots(token_present=True):
        token = slot.get_token()
        if token.flags is not None and not token.flags & TokenFlag.TOKEN_INITIALIZED:
            continue  # an empty slot waiting for C_InitToken (SoftHSM always shows one): nothing to read
        if want and _text(token.label) != want:
            continue
        out.append((slot, token))
        if len(out) >= MAX_TOKENS:
            break
    return out


def collect(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    started = time.monotonic()
    name, lib = _open(config)
    pin = _pin(ctx, config, secrets)
    tokens = _tokens(lib, config)
    if not tokens:
        ctx.outcome(f"pkcs11:{name}", "unreachable", "no token is present" + (
            f" with the label {config.get('token_label')}" if config.get("token_label") else ""), started=started)
        return f"pkcs11 {name}: no token"
    for slot, token in tokens:
        t0 = time.monotonic()
        if ctx.should_stop():
            ctx.outcome(_text(token.label), ctx.should_stop() or "skipped_deadline", started=t0)
            continue
        n, problem = _read_token(ctx, name, lib, slot, token, pin)
        ctx.outcome(_text(token.label), problem or "ok", "the token refused the PIN" if problem == "auth_failed" else
                    None, started=t0, assets=n)
    return f"pkcs11 {name}: {len(tokens)} token(s)"


def test(ctx: JobContext, config: dict, secrets: dict, scope: dict) -> str:
    from zs_scan_node.collectors import ConfigError as _CE

    try:
        name, lib = _open(config)
        tokens = _tokens(lib, config)
    except _CE as exc:
        ctx.samples.append({"target": str(config.get("module")), "status": "error", "reachable": None, "login": False,
                            "privilege": None, "note": str(exc)})
        return str(exc)
    pin = _pin(ctx, config, secrets)
    if not tokens:
        ctx.samples.append({"target": f"pkcs11:{name}", "status": "unreachable", "reachable": False, "login": False,
                            "privilege": None, "note": "no token is present"})
        return "no token is present"
    from pkcs11 import TokenFlag
    from pkcs11.exceptions import PKCS11Error

    for _slot, token in tokens[:5]:
        label = _text(token.label)
        login_required = bool(token.flags & TokenFlag.LOGIN_REQUIRED)
        try:
            with token.open(rw=False, user_pin=pin if (pin and login_required) else None) as session:
                count = sum(1 for _ in session.get_objects())
            ctx.samples.append({"target": label, "status": "ready", "reachable": True, "login": bool(pin),
                                "privilege": None, "note": f"{count} objects visible"})
        except PKCS11Error as exc:
            ctx.samples.append({"target": label, "status": "auth_failed" if "Pin" in exc.__class__.__name__ else "error",
                                "reachable": True, "login": False, "privilege": None, "note": exc.__class__.__name__})
    return f"{sum(1 for s in ctx.samples if s['status'] == 'ready')} of {len(ctx.samples)} tokens ready"
