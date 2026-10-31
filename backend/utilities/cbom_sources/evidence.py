"""Evidence areas that cannot be scanned, their questionnaires and confidence rules.

Confidence levels: Q0 Unknown, Q1 Self-attested, Q2 Documented, Q3 Verified.  A missing answer stays
Q0 and is shown as a gap; it is never treated as safe.  Evidence older than 12 months counts as Q0
until it is renewed.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

CONFIDENCE = ("Q0", "Q1", "Q2", "Q3")
CONFIDENCE_LABEL = {"Q0": "Unknown", "Q1": "Self-attested", "Q2": "Documented", "Q3": "Verified"}
EVIDENCE_MAX_AGE_DAYS = 365
VENDOR_LINK_DAYS = 14
VENDOR_DUE_DAYS = 7

AREAS: dict[str, dict[str, Any]] = {
    "key_hierarchy": {
        "title": "Key hierarchy",
        "owner_hint": "Head of PKI",
        "questions": [
            {"id": "roots", "prompt": "Where are your root and key-encryption keys held (HSM, KMS, software)?", "type": "text"},
            {"id": "all_in_hsm", "prompt": "Are all private keys for production TLS and signing held in an HSM?", "type": "choice"},
            {"id": "policy", "prompt": "Which document defines the key hierarchy?", "type": "text"},
        ],
    },
    "key_ceremonies": {
        "title": "Key ceremonies and custodianship",
        "owner_hint": "CISO office",
        "questions": [
            {"id": "ceremony", "prompt": "Are root key ceremonies scripted, witnessed and recorded?", "type": "choice"},
            {"id": "custodians", "prompt": "How many custodians hold key shares, and how is quorum enforced?", "type": "text"},
        ],
    },
    "escrow_recovery": {
        "title": "Escrow and recovery",
        "owner_hint": "Infrastructure lead",
        "questions": [
            {"id": "escrow", "prompt": "Are any keys escrowed, and with whom?", "type": "text"},
            {"id": "recovery_tested", "prompt": "Has key recovery been tested in the last 12 months?", "type": "choice"},
        ],
    },
    "hsm_firmware": {
        "title": "HSM firmware",
        "owner_hint": "Infrastructure lead",
        "questions": [
            {"id": "model", "prompt": "Which HSMs hold your root and key-encryption keys? (vendor and model)", "type": "text"},
            {"id": "firmware", "prompt": "Firmware version", "type": "text"},
            {"id": "fips_cert", "prompt": "FIPS 140 certificate number", "type": "text"},
            {"id": "process", "prompt": "Is firmware updated through a documented, approved process?", "type": "choice"},
        ],
    },
    "backup_encryption": {
        "title": "Backup encryption",
        "owner_hint": "Backup team",
        "questions": [
            {"id": "algorithm", "prompt": "Which algorithm and key size encrypt backups?", "type": "text"},
            {"id": "keys", "prompt": "Where are backup encryption keys stored and how are they rotated?", "type": "text"},
        ],
    },
    "third_party_vendors": {
        "title": "Third-party vendors",
        "owner_hint": "Vendor management",
        "questions": [
            {"id": "tls", "prompt": "Which TLS versions and cipher suites do your services that we use accept?", "type": "text"},
            {"id": "keys", "prompt": "Where are the keys that protect our data held, and who can use them?", "type": "text"},
            {"id": "pqc", "prompt": "Do you have a plan to move to post-quantum cryptography? By when?", "type": "text"},
        ],
    },
}
CHOICES = ("yes", "no", "dont_know")
MAX_ANSWER = 2000


def parse_date(value: str | None) -> _dt.date | None:
    if not value:
        return None
    return _dt.date.fromisoformat(value)


def effective_confidence(confidence: str, evidence_date: str | None, today: _dt.date) -> str:
    if confidence in ("Q2", "Q3"):
        dated = parse_date(evidence_date)
        if dated is None or (today - dated).days > EVIDENCE_MAX_AGE_DAYS:
            return "Q0"
    return confidence if confidence in CONFIDENCE else "Q0"


def lowest(levels: list[str]) -> str:
    if not levels:
        return "Q0"
    return min(levels, key=lambda q: CONFIDENCE.index(q) if q in CONFIDENCE else 0)


def clean_answers(area_key: str, answers: dict[str, Any] | None) -> dict[str, str]:
    """Keep only known question ids; values are plain text, capped; choices must be valid."""
    spec = AREAS.get(area_key) or AREAS["third_party_vendors"]
    known = {q["id"]: q["type"] for q in spec["questions"]}
    out: dict[str, str] = {}
    for key, value in (answers or {}).items():
        if key not in known or value is None:
            continue
        text = str(value).replace("\x00", "").strip()[:MAX_ANSWER]
        if not text:
            continue
        if known[key] == "choice" and text not in CHOICES:
            raise ValueError(f"{key}: answer yes, no or dont_know")
        out[key] = text
    return out


def vendor_status(vendor: Any, now: _dt.datetime) -> str:
    if vendor.answered_at:
        return "answered"
    if not vendor.link_created_at:
        return "not_sent"
    if vendor.link_expires_at and vendor.link_expires_at <= now:
        return "expired"
    if now - vendor.link_created_at > _dt.timedelta(days=VENDOR_DUE_DAYS):
        return "overdue"
    return "link_created"
