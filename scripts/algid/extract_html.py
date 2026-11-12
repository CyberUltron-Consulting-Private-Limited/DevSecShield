"""Turn the raw third-party captures into the small normalised extracts algid is built from.

    python3 scripts/algid/extract_html.py <raw dir>            # (re)write sources/*.json extracts
    python3 scripts/algid/extract_html.py <raw dir> --check    # exit 1 if an extract differs from its raw page

The raw captures are not committed; they are kept with the CB-04 evidence: the NIST CSOR page, the AWS ELB and API
Gateway security-policy pages, the Cloud KMS v1 discovery document, the OASIS PKCS#11 3.2 pkcs11t.h header and the
OASIS KMIP 3.0 specification (HTML). Each extract records the raw capture's URL, capture time and sha256, so anyone
holding the raw capture can prove the extract was made from it. (The name is historical: not every capture is HTML.)
Stdlib only; reads files, runs nothing.
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
    "cloudkms-v1-discovery.json": ("https://cloudkms.googleapis.com/$discovery/rest?version=v1",
                                   "2026-11-12T16:12:33Z"),
    "pkcs11t-3.2.h": ("https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/include/pkcs11-v3.2/pkcs11t.h",
                      "2026-11-12T16:12:47Z"),
    "kmip-spec-v3.0.html": ("https://docs.oasis-open.org/kmip/kmip-spec/v3.0/kmip-spec-v3.0.html",
                            "2026-11-12T16:13:40Z"),
}
# the PKCS#11 parameter-set groups CB-04 reads (CKA_PARAMETER_SET of ML-DSA, SLH-DSA and ML-KEM keys)
PKCS11_PARAMETER_GROUPS = ("CKP_ML_DSA_", "CKP_SLH_DSA_", "CKP_ML_KEM_")
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


def _gcp(raw_dir: Path) -> dict:
    """Cloud KMS CryptoKeyVersionAlgorithm: every enum value with its description (the discovery document's own)."""
    doc = json.loads((raw_dir / "cloudkms-v1-discovery.json").read_bytes())
    prop = doc["schemas"]["CryptoKeyVersion"]["properties"]["algorithm"]
    values = [[v, " ".join(d.split())] for v, d in zip(prop["enum"], prop["enumDescriptions"])]
    return {"provenance": [{**_provenance(raw_dir, "cloudkms-v1-discovery.json"), "revision": doc.get("revision")}],
            "schema": "CryptoKeyVersion.algorithm", "algorithms": values}


def _pkcs11(raw_dir: Path) -> dict:
    """CKK_* key types (every one) and the ML-DSA / SLH-DSA / ML-KEM CKP_* parameter sets, as the header defines."""
    text = (raw_dir / "pkcs11t-3.2.h").read_bytes().decode("utf-8")
    defines = re.findall(r"^#define\s+(CK[KP]_\w+)\s+(0x[0-9A-Fa-f]+)UL", text, re.M)
    key_types = [[name, int(value, 16)] for name, value in defines if name.startswith("CKK_")]
    params = [[name, int(value, 16)] for name, value in defines if name.startswith(PKCS11_PARAMETER_GROUPS)]
    return {"provenance": [_provenance(raw_dir, "pkcs11t-3.2.h")], "key_types": key_types,
            "parameter_sets": params}


def _kmip(raw_dir: Path) -> dict:
    """The KMIP 3.0 Cryptographic Algorithm Enumeration table: (name, value) in table order."""
    page = (raw_dir / "kmip-spec-v3.0.html").read_bytes().decode("utf-8", "replace")
    for table in re.findall(r"<table.*?</table>", page, re.S):
        cells = [" ".join(html.unescape(re.sub(r"<[^>]+>", " ", c)).split())
                 for c in re.findall(r"<td[^>]*>(.*?)</td>", table, re.S)]
        if cells[:3] == ["Cryptographic Algorithm", "Name", "Value"] and "Blowfish" in cells:
            pairs = list(zip(cells[3::2], cells[4::2]))
            rows = [[name, int(value, 16)] for name, value in pairs if re.fullmatch(r"[0-9A-F]{8}", value)]
            return {"provenance": [_provenance(raw_dir, "kmip-spec-v3.0.html")],
                    "enumeration": "Cryptographic Algorithm", "algorithms": rows}
    raise SystemExit("the KMIP specification no longer has the Cryptographic Algorithm Enumeration table")


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
        "gcp-kms-algorithms.json": _gcp(raw_dir),
        "pkcs11-3.2-constants.json": _pkcs11(raw_dir),
        "kmip-3.0-algorithms.json": _kmip(raw_dir),
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
