"""Lock the posture property dictionary to the keys the lane emits."""

from __future__ import annotations

from pathlib import Path

from aibom.cbom.posture.codec import encode_fact
from aibom.cbom.posture.model import EncryptionFact

REPO = Path(__file__).resolve().parents[2]
DOC = REPO / "docs" / "cbom-posture" / "property-dictionary.md"
POSTURE = REPO / "aibom" / "src" / "aibom" / "cbom" / "posture"
SCANNERS = REPO / "aibom" / "src" / "aibom" / "cbom" / "scanners"

EXTRA_KEYS = (
    # round 5 (WP10): cbom-mapping.yaml / CODEOWNERS on crypto asset rows (read from crypto:source)
    "crypto:businessDataClassification",
    "crypto:businessDataLifetime",
    "crypto:businessOwner",
    "crypto:businessOwnerHint",
    "crypto:businessSource",
    "crypto:businessSystem",
    "crypto:source",
    "crypto:algorithm",
    "crypto:assetType",
    "crypto:cipherSuite",
    "crypto:curve",
    "crypto:endpoint",
    "crypto:hardcoded",
    "crypto:keySize",
    "crypto:keyUsage",
    "crypto:listen",
    "crypto:materialKind",
    "crypto:mode",
    "crypto:notValidAfter",
    "crypto:policyName",
    "crypto:postureDropped",
    "crypto:postureTruncated",
    "crypto:primitive",
    "crypto:protocolType",
    "crypto:protocolVersion",
    "crypto:quantumVulnerable",
    "crypto:rotation",
    "crypto:strength",
    "crypto:subjectName",
    # round 5 (WP3a): Dockerfile crypto packages, Kubernetes Secret certificates, submodule / LFS coverage
    "crypto:coverage:lfsObjectsNotScanned",
    "crypto:coverage:submodulesNotScanned",
    "crypto:ecosystem",
    "crypto:isCertificateAuthority",
    "crypto:issuerName",
    "crypto:line",
    "crypto:notValidBefore",
    "crypto:publicKeyAlgorithm",
    "crypto:role",
    "crypto:selfSigned",
    "crypto:signatureAlgorithm",
    "crypto:version",
)


def parse_table(text: str, anchor: str) -> list[tuple[str, ...]]:
    marker = f"<!-- table:{anchor} -->"
    start = text.index(marker)
    rows: list[tuple[str, ...]] = []
    header = False
    for line in text[start:].splitlines()[1:]:
        if not line.startswith("|"):
            if header:
                break
            continue
        cells = tuple(part.strip() for part in line.strip().strip("|").split("|"))
        if all(set(cell) <= set("-: ") and cell for cell in cells):
            continue
        if not header:
            header = True
            continue
        rows.append(cells)
    return rows


def property_keys() -> list[str]:
    fact = EncryptionFact(
        id="a",
        kind="kms_key",
        provider="aws",
        native_type="aws_kms_key",
        address="aws_kms_key.example",
        path="main.tf",
        line=1,
        format="terraform",
        layers={"service": "UNKNOWN"},
        verdict="UNKNOWN",
    )
    keys = set(encode_fact(fact))
    keys.update(EXTRA_KEYS)
    return sorted(keys)


def test_property_dictionary_lists_the_emitted_crypto_keys() -> None:
    rows = parse_table(DOC.read_text(encoding="utf-8"), "properties")
    assert [row[0] for row in rows] == property_keys()
    for key in property_keys():
        assert key.startswith("crypto:")


def test_emitted_crypto_literals_are_in_the_dictionary() -> None:
    text = DOC.read_text(encoding="utf-8")
    documented = {row[0] for row in parse_table(text, "properties")}
    literals: set[str] = set()
    paths = list(POSTURE.glob("*.py")) + list(SCANNERS.glob("posture_*.py"))
    for path in paths:
        source = path.read_text(encoding="utf-8")
        start = 0
        while True:
            found = source.find('"crypto:', start)
            if found < 0:
                break
            end = source.find('"', found + 1)
            literals.add(source[found + 1 : end])
            start = end + 1
    literals.discard("crypto:fact")
    assert literals <= documented


def write_dictionary() -> None:
    rows = "\n".join(f"| {key} |" for key in property_keys())
    body = (
        "# Property dictionary\n\n"
        "Posture facts and the crypto assets this lane adds use the `crypto:` "
        "namespace. No other namespace is introduced.\n\n"
        "<!-- table:properties -->\n"
        "| key |\n"
        "| --- |\n"
        f"{rows}\n"
    )
    DOC.write_text(body, encoding="utf-8")


if __name__ == "__main__":
    write_dictionary()
