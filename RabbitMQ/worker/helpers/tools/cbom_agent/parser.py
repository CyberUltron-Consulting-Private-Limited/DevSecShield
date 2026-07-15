"""
Parser for CBOM scan results. Converts crypto asset detections into:
1. Readable strings for LLM map-reduce summarization
2. CycloneDX CBOM JSON format for download
"""

from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone


def detection_to_string(detection: dict, index: int) -> str:
    """Convert a single crypto asset detection dict into a readable string for LLM processing."""
    if not isinstance(detection, dict):
        return ""

    algorithm = detection.get("algorithm_name", "Unknown")
    algo_type = detection.get("algorithm_type", "unknown")
    strength = detection.get("crypto_strength", "unknown")
    key_size = detection.get("key_size")
    quantum_safe = detection.get("quantum_safe", False)
    location = detection.get("location", "unknown")
    snippet = detection.get("snippet", "")
    language = detection.get("language", "unknown")
    source = detection.get("source", "source_scanner")

    key_size_str = f", Key Size: {key_size} bits" if key_size else ""
    quantum_str = "Yes" if quantum_safe else "No"

    return (
        f"--- Crypto Asset #{index + 1} ---\n"
        f"Algorithm: {algorithm}\n"
        f"Type: {algo_type}\n"
        f"Strength: {strength}{key_size_str}\n"
        f"Quantum Safe: {quantum_str}\n"
        f"Location: {location}\n"
        f"Language: {language}\n"
        f"Source: {source}\n"
        f"Snippet: {snippet[:300]}\n"
        f"---\n"
    )


def parse_detections_to_strings(detections: list[dict]) -> list[str]:
    """Convert a list of crypto asset detections into readable strings for LLM processing."""
    results = []
    for i, detection in enumerate(detections):
        s = detection_to_string(detection, i)
        if s:
            results.append(s)
    return results


# Stable placeholder when no usable repo name/URL is available.
_DEFAULT_COMPONENT_NAME = "scanned-application"

# Directory roots used for transient clone/extract dirs; their basenames are
# random temp-dir names, not the repository name, so we must not surface them.
_TEMP_PATH_PREFIXES = ("/tmp/", "/var/folders/", "/private/var/folders/")


# Known symmetric ciphers classified by their CycloneDX 1.6 cryptographic
# primitive. Keys are lowercase substrings matched against the algorithm name so
# that mode/variant suffixes (e.g. "AES-256-GCM", "ChaCha20-Poly1305") still
# resolve. Order does not matter because stream and block ciphers are disjoint.
_STREAM_CIPHER_NAMES = ("chacha20", "chacha", "salsa20", "salsa", "rc4", "arc4")
_BLOCK_CIPHER_NAMES = (
    "aes",
    "3des",
    "tripledes",
    "triple-des",
    "des",  # checked after 3des/tripledes so "3DES" is not stolen by "des"
    "blowfish",
    "rc2",
    "camellia",
    "cast",
    "idea",
    "seed",
    "aria",
    "sm4",
)


def _symmetric_cipher_primitive(algorithm_name: str) -> str:
    """
    Classify a symmetric cipher as a CycloneDX 1.6 ``stream-cipher`` or
    ``block-cipher`` primitive from its algorithm name.

    Uses an explicit known-cipher table rather than a fragile ``aes``/``des``
    substring check, so stream ciphers (ChaCha20, RC4, Salsa20) are no longer
    misclassified as block ciphers and block ciphers (Blowfish, RC2, Camellia,
    3DES, ...) are no longer misclassified as stream ciphers. When the concrete
    cipher cannot be identified (e.g. a generic "algorithm from config"
    detection), it falls back to ``unknown`` rather than guessing.
    """
    name = (algorithm_name or "").lower()
    if any(s in name for s in _STREAM_CIPHER_NAMES):
        return "stream-cipher"
    if any(b in name for b in _BLOCK_CIPHER_NAMES):
        return "block-cipher"
    return "unknown"


def _repo_name_from_url(repo_url: str | None) -> str:
    """
    Derive a human-readable component name from a repo URL or name.

    Strips trailing slashes and a ``.git`` suffix and returns the final path
    segment. When ``repo_url`` is missing, empty, or a transient local scan
    directory (whose basename is a random temp-dir name rather than the repo
    name), a stable placeholder is returned so output stays deterministic and
    never leaks the temp-dir basename.
    """
    if not repo_url:
        return _DEFAULT_COMPONENT_NAME

    candidate = repo_url.strip()

    # A local temp/clone directory does not carry the real repo name.
    if candidate.startswith(_TEMP_PATH_PREFIXES):
        return _DEFAULT_COMPONENT_NAME

    # Normalise common URL/scp-like forms (https://host/org/repo.git, git@host:org/repo.git).
    candidate = candidate.rstrip("/")
    if candidate.endswith(".git"):
        candidate = candidate[: -len(".git")]

    # Split on both '/' and ':' to handle scp-style git remotes.
    for sep in ("/", ":"):
        if sep in candidate:
            candidate = candidate.rsplit(sep, 1)[-1]

    candidate = candidate.strip()
    return candidate or _DEFAULT_COMPONENT_NAME


def generate_cyclonedx_cbom(
    detections: list[dict],
    scan_id: str | None = None,
    repo_url: str | None = None,
    timestamp: str | None = None,
) -> dict:
    """
    Generate a CycloneDX 1.6 CBOM JSON from crypto asset detections.

    Args:
        detections: List of crypto asset detection dicts from source/binary scanners.
        scan_id: Optional scan ID, mixed into the deterministic serial number.
        repo_url: Optional repo URL/name for metadata.component.
        timestamp: Optional ISO-8601 timestamp for metadata.timestamp. This is the
            only field that is allowed to be non-deterministic; when omitted, the
            current UTC time is used. Pass an explicit value for reproducible output.

    Returns:
        CycloneDX BOM dict ready for JSON serialization.

    The serialNumber is always a valid ``urn:uuid:`` derived deterministically
    (RFC 4122 v5) from the scan_id and the detection content, so the same inputs
    always produce the same serial number regardless of whether scan_id is itself
    a UUID.
    """
    serial = f"urn:uuid:{_stable_serial_uuid(detections, scan_id, repo_url)}"

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "DevSecShield CBOM Scanner",
                        "version": "1.0.0",
                    }
                ]
            },
        },
        "components": [],
    }

    bom["metadata"]["component"] = {
        "type": "application",
        "name": _repo_name_from_url(repo_url),
        "bom-ref": "target-application",
    }

    seen_refs = set()
    for detection in detections:
        component = _detection_to_cyclonedx_component(detection, seen_refs)
        if component:
            bom["components"].append(component)

    return bom


# Stable namespace for deriving CBOM serial numbers (RFC 4122 v5).
_CBOM_SERIAL_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "devsecshield:cbom")


def _stable_serial_uuid(
    detections: list[dict],
    scan_id: str | None,
    repo_url: str | None,
) -> uuid.UUID:
    """
    Derive a deterministic, RFC-4122-valid UUID for the BOM serialNumber.

    Uses uuid5 over a stable string built from scan_id, repo_url, and the detection
    content. This guarantees:
      * a valid ``urn:uuid:`` even when scan_id is not itself a UUID, and
      * identical output for identical inputs (determinism).
    """
    # Build a stable, order-independent fingerprint of the detections so that the
    # same set of crypto assets always yields the same serial number.
    fingerprint_parts = sorted(
        "|".join(
            str(detection.get(field, ""))
            for field in (
                "algorithm_name",
                "algorithm_type",
                "crypto_strength",
                "key_size",
                "location",
            )
        )
        for detection in detections
        if isinstance(detection, dict)
    )
    seed = "\n".join([
        f"scan_id={scan_id or ''}",
        f"repo_url={repo_url or ''}",
        *fingerprint_parts,
    ])
    return uuid.uuid5(_CBOM_SERIAL_NAMESPACE, seed)


def _detection_to_cyclonedx_component(detection: dict, seen_refs: set) -> dict | None:
    """Convert a single detection to a CycloneDX component with cryptoProperties."""
    algorithm = detection.get("algorithm_name", "Unknown")
    algo_type = detection.get("algorithm_type", "unknown")
    strength = detection.get("crypto_strength", "unknown")
    key_size = detection.get("key_size")
    quantum_safe = detection.get("quantum_safe", False)
    location = detection.get("location", "")
    snippet = detection.get("snippet", "")

    # Generate deterministic bom-ref using SHA-256 (not Python hash() which is randomized)
    loc_hash = hashlib.sha256(location.encode("utf-8")).hexdigest()[:8]
    bom_ref = f"crypto-{algorithm}-{loc_hash}"
    if bom_ref in seen_refs:
        # Deterministic collision suffix from full content
        collision_src = f"{algorithm}|{location}|{algo_type}|{strength}"
        collision_hash = hashlib.sha256(collision_src.encode("utf-8")).hexdigest()[:8]
        bom_ref = f"{bom_ref}-{collision_hash}"
    seen_refs.add(bom_ref)

    # Map our type to CycloneDX assetType
    asset_type_map = {
        "hash": "algorithm",
        "symmetric_cipher": "algorithm",
        "asymmetric_cipher": "algorithm",
        "mac": "algorithm",
        "key_derivation": "algorithm",
        "signature": "algorithm",
        "random_number_generator": "algorithm",
        "protocol": "protocol",
        "certificate": "certificate",
        "key": "related-crypto-material",
        "secret": "related-crypto-material",
    }

    cdx_asset_type = asset_type_map.get(algo_type, "algorithm")

    # Build cryptoProperties
    crypto_props = {
        "assetType": cdx_asset_type,
    }

    # Add algorithmProperties for algorithms
    if cdx_asset_type == "algorithm":
        # Values must match the CycloneDX 1.6 cryptographic primitive enum:
        # drbg, mac, block-cipher, stream-cipher, signature, hash, pke, xof,
        # kdf, key-agree, kem, ae, combiner, other, unknown
        primitive_map = {
            "hash": "hash",
            # Symmetric ciphers are classified by the concrete algorithm name
            # (stream vs block) via a known-cipher table rather than a brittle
            # "aes"/"des" substring guess.
            "symmetric_cipher": _symmetric_cipher_primitive(algorithm),
            "asymmetric_cipher": "pke",
            "mac": "mac",
            "key_derivation": "kdf",
            "signature": "signature",
            "random_number_generator": "drbg",
        }
        algo_properties = {
            "primitive": primitive_map.get(algo_type, "unknown"),
        }
        if key_size:
            algo_properties["parameterSetIdentifier"] = str(key_size)

        crypto_props["algorithmProperties"] = algo_properties

    # Add relatedCryptoMaterialProperties for keys/secrets
    if cdx_asset_type == "related-crypto-material":
        material_type_map = {
            "key": "private-key",
            "secret": "secret-key",
        }
        material_props = {
            "type": material_type_map.get(algo_type, "unknown"),
        }
        if key_size:
            material_props["size"] = key_size
        crypto_props["relatedCryptoMaterialProperties"] = material_props

    component = {
        "type": "cryptographic-asset",
        "name": algorithm,
        "bom-ref": bom_ref,
        "cryptoProperties": crypto_props,
        "properties": [
            {"name": "crypto:strength", "value": strength},
            {"name": "crypto:quantum-safe", "value": str(quantum_safe).lower()},
        ],
    }

    # Add evidence/occurrences for location info
    if location:
        component["evidence"] = {
            "occurrences": [
                {"location": location}
            ]
        }

    return component


def cbom_json_to_string(cbom: dict) -> str:
    """Serialize a CycloneDX CBOM dict to a pretty-printed JSON string."""
    return json.dumps(cbom, indent=2, ensure_ascii=False)
