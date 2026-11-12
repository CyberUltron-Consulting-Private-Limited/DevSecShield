"""Turn the raw third-party HTML captures into the small normalised extracts algid is built from.

    python3 scripts/algid/extract_html.py <raw dir>            # (re)write sources/*.json extracts
    python3 scripts/algid/extract_html.py <raw dir> --check    # exit 1 if an extract differs from its raw page

The raw pages (NIST CSOR, the AWS ELB and API Gateway security-policy pages) are not committed; they are kept with
the CB-04 evidence. Each extract records the raw page's URL, capture time and sha256, so anyone holding the raw
capture can prove the extract was made from it. Stdlib only; reads files, runs nothing.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
import sys
from pathlib import Path

SOURCES = Path(__file__).resolve().parent / "sources"
RAW = {
    "nist-csor.html": ("https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration",
                       "2026-11-12T11:27:12Z"),
    "aws-elb-security-policies.html": (
        "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html",
        "2026-11-12T11:28:06Z"),
    "aws-apigw-security-policies.html": (
        "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html",
        "2026-11-12T11:28:07Z"),
    "aws-apigw-security-policies-overview.html": (
        "https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies.html",
        "2026-11-12T11:28:10Z"),
}
ELB_SENTENCE = ("The hybrid post-quantum policies support SecP256r1MLKEM768, SecP384r1MLKEM1024 and "
                "X25519MLKEM768")
APIGW_SENTENCE = "Use these policies for regulated workloads, advanced governance, or to use post-quantum cryptography"


def _text(raw: bytes) -> str:
    return " ".join(re.sub(r"<[^>]+>", " ", html.unescape(raw.decode("utf-8"))).split())


def _provenance(raw_dir: Path, name: str) -> dict:
    raw = (raw_dir / name).read_bytes()
    url, when = RAW[name]
    return {"raw_file": name, "url": url, "retrieved_utc": when, "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_bytes": len(raw)}


def extracts(raw_dir: Path) -> dict[str, dict]:
    csor_raw = (raw_dir / "nist-csor.html").read_bytes()
    definitions = [[name, " ".join(body.split())] for name, body in re.findall(
        r"([A-Za-z][\w-]*)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{([^}]*)\}", _text(csor_raw))]
    elb_text = _text((raw_dir / "aws-elb-security-policies.html").read_bytes())
    if ELB_SENTENCE not in elb_text:
        raise SystemExit("the ELB page no longer carries the hybrid-group sentence")
    elb = sorted(set(re.findall(r"\b(ELBSecurityPolicy[\w-]*-PQ-[\w-]*)\b", elb_text)))
    api_raw = (raw_dir / "aws-apigw-security-policies.html").read_bytes()
    api = sorted(set(re.findall(r"\b(SecurityPolicy_\w*_PQ_\w*)\b", html.unescape(api_raw.decode("utf-8")))))
    overview = _text((raw_dir / "aws-apigw-security-policies-overview.html").read_bytes())
    if APIGW_SENTENCE not in overview:
        raise SystemExit("the API Gateway overview no longer says its enhanced policies are post-quantum")
    return {
        "nist-csor-oids.json": {"provenance": [_provenance(raw_dir, "nist-csor.html")],
                                "object_identifier_definitions": definitions},
        "aws-elb-pq-policies.json": {"provenance": [_provenance(raw_dir, "aws-elb-security-policies.html")],
                                     "pq_policy_names": elb, "group_sentence": ELB_SENTENCE},
        "aws-apigw-pq-policies.json": {
            "provenance": [_provenance(raw_dir, "aws-apigw-security-policies.html"),
                           _provenance(raw_dir, "aws-apigw-security-policies-overview.html")],
            "pq_policy_names": api, "pq_statement": APIGW_SENTENCE},
    }


def render(doc: dict) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=True) + "\n"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    raw_dir = Path(argv[0])
    wanted = {name: render(doc) for name, doc in extracts(raw_dir).items()}
    if "--check" in argv:
        bad = [n for n, text in wanted.items() if (SOURCES / n).read_text(encoding="utf-8") != text]
        print("extracts differ from the raw captures: " + ", ".join(bad) if bad else "extracts match the raw captures")
        return 1 if bad else 0
    for name, text in wanted.items():
        (SOURCES / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(wanted)} extracts")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
