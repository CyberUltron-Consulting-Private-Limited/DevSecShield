"""Evidence areas that cannot be scanned, their questionnaires and confidence rules.

Evidence confidence levels (CB-18, DA §2.3): E0 Unknown, E1 Self-attested, E2 Documented, E3 Verified. They are not
the quantum risk grades (Q0..Q4): an item at E0 creates a "Q0 gap" in the risk register, with a reason, and is never
treated as safe. Evidence older than 12 months counts as E0 until it is renewed.

Levels were stored as Q0..Q3 before CB-18; the data migration ``cb18evconf001`` rewrites them, and ``level`` reads
either spelling (a row written by an older process during a rolling deploy, or after a code rollback), so every read of
a stored level goes through it.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any

CONFIDENCE = ("E0", "E1", "E2", "E3")
CONFIDENCE_LABEL = {"E0": "Unknown", "E1": "Self-attested", "E2": "Documented", "E3": "Verified"}
LEGACY_LEVELS = {"Q0": "E0", "Q1": "E1", "Q2": "E2", "Q3": "E3"}  # stored before CB-18 (cb18evconf001 rewrites them)
DOCUMENTED = ("E2", "E3")  # need an evidence document and its date; they expire after EVIDENCE_MAX_AGE_DAYS
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


def level(value: Any) -> str:
    """A stored or submitted level as E0..E3: E values as they are, the pre-CB-18 Q values mapped, anything else E0."""
    text = str(value or "").strip().upper()
    return text if text in CONFIDENCE else LEGACY_LEVELS.get(text, "E0")


def effective_confidence(confidence: str, evidence_date: str | None, today: _dt.date) -> str:
    """The level an area counts at today: E2/E3 whose evidence is undated or older than 365 days count as E0."""
    stored = level(confidence)
    if stored in DOCUMENTED and _expired(evidence_date, today):
        return "E0"
    return stored


def _expired(evidence_date: str | None, today: _dt.date) -> bool:
    try:
        dated = parse_date(evidence_date)
    except (TypeError, ValueError):  # one bad stored date must not take the Evidence tab down (EC-10)
        dated = None
    return dated is None or (today - dated).days > EVIDENCE_MAX_AGE_DAYS


def lowest(levels: list[str]) -> str:
    if not levels:
        return "E0"
    return min((level(v) for v in levels), key=CONFIDENCE.index)


# Why an item counts at E0: stable codes (CB-19 grades them as Q0 "evidence_e0" with this sub-reason; CB-23 tracks
# their closure). The text is the one sentence every surface shows (Evidence tab, Review & Run, the API).
GAP_REASONS = {
    "no_answer": "unanswered",
    "rated_unknown": "answered, but its confidence is set to E0 Unknown",
    "evidence_expired": "its evidence document is older than 12 months (or undated), so it counts as E0 until renewed",
    "vendor_not_asked": "no questionnaire link has been created for this vendor yet",
    "vendor_no_response": "the vendor has not answered the questionnaire link yet",
    "vendor_link_expired": "the questionnaire link expired without an answer",
    "vendors_missing": "one or more vendors have not answered",
}


def _gap(reason: str, detail: str | None = None) -> dict[str, Any]:
    return {"reason": reason, "text": GAP_REASONS[reason], "detail": detail}


def vendor_level(vendor: Any, now: _dt.datetime) -> tuple[str, dict[str, Any] | None]:
    """(effective level, Q0 gap or None) of a vendor: E0 until it answers, whatever level a user set (OB-4)."""
    if vendor.answered_at:
        effective = level(vendor.confidence)
        return effective, (_gap("rated_unknown") if effective == "E0" else None)
    status = vendor_status(vendor, now)
    reason = {"not_sent": "vendor_not_asked", "expired": "vendor_link_expired"}.get(status, "vendor_no_response")
    return "E0", _gap(reason, f"link created {vendor.link_created_at.date().isoformat()}"
                      if vendor.link_created_at and reason != "vendor_not_asked" else None)


def area_level(area: Any, today: _dt.date, vendor_levels: list[str] | None = None
               ) -> tuple[str, dict[str, Any] | None, bool]:
    """(effective level, Q0 gap or None, roll-up) of an area. The third-party-vendors area with vendors counts at its
    lowest vendor level; its gap is then a roll-up of the vendors' own gaps (``kind: area_rollup``), listed but not
    counted, so N unanswered vendors are N gaps, not N + 1 (FP-8)."""
    stored = level(area.confidence)
    if area.area_key == "third_party_vendors" and vendor_levels:
        effective = lowest(vendor_levels)
        if effective == "E0":
            missing = sum(1 for v in vendor_levels if level(v) == "E0")
            return "E0", _gap("vendors_missing", f"{missing} of {len(vendor_levels)} vendors at E0"), True
        return effective, None, False
    effective = effective_confidence(stored, area.evidence_date, today)
    if effective != "E0":
        return effective, None, False
    if stored in DOCUMENTED:
        return "E0", _gap("evidence_expired", f"evidence dated {area.evidence_date}" if area.evidence_date
                          else "no evidence date"), False
    if area.answers:
        return "E0", _gap("rated_unknown"), False
    return "E0", _gap("no_answer"), False


def q0_gaps(area_rows: list[dict[str, Any]], vendor_rows: list[dict[str, Any]], today: _dt.date
            ) -> tuple[list[dict[str, Any]], int]:
    """The register entries every E0 item creates, and the one gap count every surface shows (OB-3).

    Identity: ``id`` = ``area:<area_key>`` or ``vendor:<vendor_id>`` (the reason is an attribute, so a reason change is
    not a new gap); ``as_of`` = the day the server judged it (a level can drop on day 366 with no write, ST-G)."""
    as_of = today.isoformat()
    out: list[dict[str, Any]] = []
    for row in area_rows:
        gap = row.get("q0_gap")
        if gap:
            rollup = bool(row.get("q0_gap_rollup"))
            out.append({"id": f"area:{row['area_key']}", "kind": "area_rollup" if rollup else "area",
                        "area_key": row["area_key"], "vendor_id": None, "title": row["title"], **gap,
                        "counted": not rollup, "as_of": as_of})
    for row in vendor_rows:
        gap = row.get("q0_gap")
        if gap:
            out.append({"id": f"vendor:{row['id']}", "kind": "vendor", "area_key": row.get("area_key"),
                        "vendor_id": row["id"], "title": row["name"], **gap, "counted": True, "as_of": as_of})
    return out, sum(1 for g in out if g["counted"])


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
    """``answered``, ``refresh_pending`` (answered, and a new link is out: the answer and its level stay until the new
    answer arrives, EC-5), ``not_sent``, ``expired``, ``overdue`` or ``link_created``."""
    pending = bool(getattr(vendor, "link_token_hash", None)) and vendor.link_expires_at is not None \
        and vendor.link_expires_at > now
    if vendor.answered_at:
        renewed = vendor.link_created_at is not None and vendor.link_created_at > vendor.answered_at
        return "refresh_pending" if pending and renewed else "answered"
    if not vendor.link_created_at:
        return "not_sent"
    if vendor.link_expires_at and vendor.link_expires_at <= now:
        return "expired"
    if now - vendor.link_created_at > _dt.timedelta(days=VENDOR_DUE_DAYS):
        return "overdue"
    return "link_created"
