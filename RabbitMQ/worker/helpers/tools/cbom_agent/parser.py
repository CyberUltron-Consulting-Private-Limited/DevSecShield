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


def generate_cyclonedx_cbom(
    detections: list[dict],
    scan_id: str | None = None,
    repo_url: str | None = None,
) -> dict:
    """
    Generate a CycloneDX 1.6 CBOM JSON from crypto asset detections.

    Args:
        detections: List of crypto asset detection dicts from source/binary scanners.
        scan_id: Optional scan ID for the serial number.
        repo_url: Optional repo URL for metadata.

    Returns:
        CycloneDX BOM dict ready for JSON serialization.
    """
    serial = f"urn:uuid:{scan_id}" if scan_id else f"urn:uuid:{uuid.uuid4()}"

    # Use a stable timestamp when scan_id is provided (content-derived);
    # otherwise fall back to current time for ad-hoc runs.
    if scan_id:
        timestamp = "1970-01-01T00:00:00+00:00"  # deterministic placeholder when scan_id is known
    else:
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

    if repo_url:
        bom["metadata"]["component"] = {
            "type": "application",
            "name": repo_url.split("/")[-1] if "/" in repo_url else repo_url,
            "bom-ref": "target-application",
        }

    seen_refs = set()
    for detection in detections:
        component = _detection_to_cyclonedx_component(detection, seen_refs)
        if component:
            bom["components"].append(component)

    return bom


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
        primitive_map = {
            "hash": "hash",
            "symmetric_cipher": "block-cipher" if "aes" in algorithm.lower() or "des" in algorithm.lower() else "stream-cipher",
            "asymmetric_cipher": "public-key-encryption",
            "mac": "mac",
            "key_derivation": "key-derivation",
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
        "type": "crypto-asset",
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
