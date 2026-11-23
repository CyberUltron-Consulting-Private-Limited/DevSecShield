"""Active Directory asset types (FIX-B3): the domain's Kerberos posture and per-account Kerberos encryption types.

Read by the scan node's read-only LDAPS / StartTLS collector (scan_node/zs_scan_node/collectors/active_directory.py).
Finding codes are documented in scripts/crypto_kb/kb_ext/ad_ldaps.py.  Every rule reads facts defensively: a fact of
any JSON shape other than the one expected is ignored (test_cbom_classify_followups fuzzes every rule).
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

from backend.utilities.cbom_sources import classify

KRBTGT_MAX_AGE_DAYS = 180  # Microsoft's guidance: reset the krbtgt password at least every 180 days
LEVEL_2008 = 3  # below this the domain cannot issue AES tickets for krbtgt (MS-KILE)
LEVEL_2016 = 7


def _true(facts: dict[str, Any], key: str) -> bool:
    return facts.get(key) is True


def _names(facts: dict[str, Any]) -> list[str]:
    value = facts.get("enc_types")
    return [str(v) for v in value if isinstance(v, str)] if isinstance(value, list) else []


def _kerberos_account(out, facts: dict[str, Any], _algorithm, _key_size, _now) -> bool | None:
    who = facts.get("account") if isinstance(facts.get("account"), str) else "This account"
    default = facts.get("enc_types_source") == "default"
    names = _names(facts)
    if _true(facts, "des_enabled"):
        des = [n for n in names if n.startswith("DES")] or ["DES"]
        out.add("KERBEROS_DES_ENABLED", "High",
                f"{who} can be issued Kerberos tickets with DES" + (" (USE_DES_KEY_ONLY is set)"
                                                                    if _true(facts, "use_des_key_only") else ""), des)
    if _true(facts, "rc4_only"):
        out.add("KERBEROS_RC4_ONLY", "High",
                f"{who} gets RC4-HMAC Kerberos tickets and no AES" + (
                    " (msDS-SupportedEncryptionTypes is not set, so the domain default applies)" if default else ""),
                "RC4-HMAC")
    elif _true(facts, "rc4_enabled"):
        out.add("KERBEROS_RC4_ENABLED", "Medium", f"{who} still allows RC4-HMAC Kerberos tickets beside AES",
                "RC4-HMAC")
    # Kerberos is symmetric: AES-256 keys are not broken by a quantum computer (Grover halves the margin), so the
    # verdict is not "vulnerable"; it stays unknown because PKINIT and the DC certificates are judged on their own rows
    return None


def _age_days(value: Any, now: _dt.datetime) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        moment = _dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None
    if not isinstance(now, _dt.datetime):
        now = _dt.datetime.now(_dt.timezone.utc)
    base = now if now.tzinfo else now.replace(tzinfo=_dt.timezone.utc)  # classify's clock is naive UTC
    return (base - moment).days


def _ad_domain(out, facts: dict[str, Any], _algorithm, _key_size, now) -> bool | None:
    level = facts.get("domain_functional_level")
    name = facts.get("domain_functional_level_name") if isinstance(facts.get("domain_functional_level_name"), str) \
        else f"level {level}"
    if isinstance(level, int) and not isinstance(level, bool):
        if level < LEVEL_2008:
            out.add("AD_FUNCTIONAL_LEVEL_LEGACY", "High",
                    f"Domain functional level is {name}: below Windows Server 2008 the krbtgt account has no AES keys")
        elif level < LEVEL_2016:
            out.add("AD_FUNCTIONAL_LEVEL_LEGACY", "Low",
                    f"Domain functional level is {name} (below Windows Server 2016): newer Kerberos protections "
                    "such as Protected Users' AES-only behaviour and claims armoring are not available domain-wide")
    days = _age_days(facts.get("krbtgt_password_last_set"), now)
    if days is not None and days > KRBTGT_MAX_AGE_DAYS:
        out.add("KRBTGT_KEY_OLD", "Medium",
                f"The krbtgt password (the key that signs every Kerberos ticket) was last set {days} days ago")
    return None


classify.register("ad_domain", _ad_domain, "other")
classify.register("kerberos_account", _kerberos_account, "related-crypto-material")
