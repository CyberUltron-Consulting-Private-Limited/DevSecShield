"""
Parser for AI-BOM scan results. Converts AI/ML component detections into:
1. Readable strings for LLM map-reduce summarization
2. CycloneDX 1.6 ML-BOM JSON format for download
"""

from __future__ import annotations
import hashlib
import json
import uuid
from datetime import datetime, timezone

from helpers.tools.ai_bom_agent.ai_rules import (
    MODEL_FILE_EXTENSIONS,
    AI_RISK_RULES,
)
from helpers.context.enums import AIComponentType


def detection_to_string(detection: dict, index: int) -> str:
    """Convert a single AI component detection dict into a readable string for the LLM."""
    if not isinstance(detection, dict):
        return ""

    component_name = detection.get("component_name", "Unknown")
    component_type = detection.get("component_type", "unknown")
    framework = detection.get("framework") or "unknown"
    version = detection.get("version") or "unknown"
    source = detection.get("source", "unknown")
    license_str = detection.get("license") or "unknown"
    location = detection.get("location", "unknown")
    snippet = detection.get("snippet", "")
    risk_category = detection.get("risk_category", "unknown")

    return (
        f"--- AI/ML Component #{index + 1} ---\n"
        f"Component: {component_name}\n"
        f"Type: {component_type}\n"
        f"Framework: {framework}\n"
        f"Version: {version}\n"
        f"Source/Provider: {source}\n"
        f"License: {license_str}\n"
        f"Risk Category: {risk_category}\n"
        f"Location: {location}\n"
        f"Snippet: {snippet[:300]}\n"
        f"---\n"
    )


def parse_detections_to_strings(detections: list[dict]) -> list[str]:
    """Convert a list of AI component detections into readable strings for the LLM."""
    results = []
    for i, detection in enumerate(detections):
        s = detection_to_string(detection, i)
        if s:
            results.append(s)
    return results


def _sort_key(detection: dict) -> tuple:
    return (
        detection.get("component_name", ""),
        detection.get("location", ""),
        detection.get("component_type", ""),
        detection.get("source", ""),
    )


def _repo_url_to_component_name(repo_url: str) -> str:
    """Derive a stable metadata.component.name from a repo url.

    - strip a trailing '.git'
    - strip trailing slashes
    - take the last path segment (the repo name)
    - if the result looks like a scan temp dir (basename starts with 'repo_'),
      it is NOT a real repo identity, so fall back to 'target-application'
    """
    if not repo_url:
        return "target-application"

    cleaned = repo_url.rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[: -len(".git")]

    segment = cleaned.split("/")[-1] if "/" in cleaned else cleaned
    segment = segment.strip()

    if not segment or segment.startswith("repo_"):
        return "target-application"

    return segment


# Maps a precise AIComponentType -> the appropriate CycloneDX 1.6 component
# `type`. Datasets and local model files are handled in dedicated branches;
# this table covers the remaining types.
#   prompt_asset       -> file          (a prompt template file, not a model)
#   ml_framework /
#   ai_framework       -> library       (a code dependency, not a model)
#   external_provider /
#   huggingface_model /
#   embedding_model    -> machine-learning-model (these ARE model / model-access)
_AI_COMPONENT_TYPE_TO_CYCLONEDX_TYPE: dict[str, str] = {
    AIComponentType.PROMPT_ASSET.value: "file",
    AIComponentType.ML_FRAMEWORK.value: "library",
    AIComponentType.AI_FRAMEWORK.value: "library",
    AIComponentType.EXTERNAL_PROVIDER.value: "machine-learning-model",
    AIComponentType.HUGGINGFACE_MODEL.value: "machine-learning-model",
    AIComponentType.EMBEDDING_MODEL.value: "machine-learning-model",
    AIComponentType.LOCAL_MODEL_FILE.value: "machine-learning-model",
    AIComponentType.DATASET.value: "data",
}


def _cyclonedx_type_for(component_type: str) -> str:
    """Map an AIComponentType value to its CycloneDX component `type`.

    Unknown component types default to 'machine-learning-model' to preserve the
    previous behavior for any type not yet in the mapping table.
    """
    return _AI_COMPONENT_TYPE_TO_CYCLONEDX_TYPE.get(
        component_type, "machine-learning-model"
    )


def generate_cyclonedx_aibom(
    detections: list[dict],
    scan_id: str | None = None,
    repo_url: str | None = None,
) -> dict:
    """
    Generate a CycloneDX 1.6 ML-BOM JSON from AI/ML component detections.

    Component shapes:
      - local model files  -> "machine-learning-model" with modelCard.properties
                              carrying aibom:serialization-format /
                              aibom:untrusted-deserialization / aibom:risk-category
      - external providers / HF / embedding models -> "machine-learning-model"
                              with supplier/publisher/group + aibom:provider +
                              aibom:model-pinned
      - datasets           -> "data" with data[].governance

    Determinism:
      - serialNumber = urn:uuid:<deterministic uuid derived from scan_id> else uuid4()
      - timestamp = epoch placeholder when scan_id given, else now()
      - bom-ref = f"{kind}-{name}-{sha256(location)[:8]}" with seen_refs dedup
      - detections sorted before emit
    """
    if scan_id:
        # Derive a well-formed, deterministic UUID from the content-hash scan_id
        # so that identical repo content -> byte-identical serialNumber.
        deterministic_uuid = uuid.uuid5(uuid.NAMESPACE_URL, str(scan_id))
        serial = f"urn:uuid:{deterministic_uuid}"
        # Fixed epoch placeholder -> timestamp does not vary across runs.
        timestamp = "1970-01-01T00:00:00+00:00"
    else:
        serial = f"urn:uuid:{uuid.uuid4()}"
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
                        "name": "DevSecShield AI-BOM Scanner",
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
            "name": _repo_url_to_component_name(repo_url),
            "bom-ref": "target-application",
        }

    sorted_detections = sorted(detections, key=_sort_key)

    seen_refs: set[str] = set()
    for detection in sorted_detections:
        component = _detection_to_cyclonedx_component(detection, seen_refs)
        if component:
            bom["components"].append(component)

    return bom


def _make_bom_ref(kind: str, name: str, location: str, seen_refs: set, detection: dict) -> str:
    loc_hash = hashlib.sha256((location or "").encode("utf-8")).hexdigest()[:8]
    bom_ref = f"{kind}-{name}-{loc_hash}"
    if bom_ref in seen_refs:
        collision_src = f"{name}|{location}|{detection.get('component_type', '')}|{detection.get('source', '')}"
        collision_hash = hashlib.sha256(collision_src.encode("utf-8")).hexdigest()[:8]
        bom_ref = f"{bom_ref}-{collision_hash}"
    seen_refs.add(bom_ref)
    return bom_ref


def _detection_to_cyclonedx_component(detection: dict, seen_refs: set) -> dict | None:
    """Convert a single detection to a CycloneDX 1.6 component."""
    name = detection.get("component_name", "Unknown")
    component_type = detection.get("component_type", "unknown")
    framework = detection.get("framework")
    version = detection.get("version")
    source = detection.get("source", "unknown")
    license_str = detection.get("license")
    location = detection.get("location", "")
    snippet = detection.get("snippet", "")
    risk_category = detection.get("risk_category", "")

    risk_rule = AI_RISK_RULES.get(risk_category, {})

    # ----- Datasets -> CycloneDX "data" component with governance -----
    if component_type == AIComponentType.DATASET.value:
        bom_ref = _make_bom_ref("dataset", name, location, seen_refs, detection)
        component = {
            "type": "data",
            "name": name,
            "bom-ref": bom_ref,
            "data": [
                {
                    "type": "dataset",
                    "name": name,
                    "governance": {
                        "owners": [{"organization": {"name": str(source)}}],
                    },
                }
            ],
            "properties": [
                {"name": "aibom:component-type", "value": str(component_type)},
                {"name": "aibom:risk-category", "value": str(risk_category)},
            ],
        }
        if location:
            component["evidence"] = {"occurrences": [{"location": location}]}
        return component

    # ----- Local model weight files -> ML model with modelCard.properties -----
    if component_type == AIComponentType.LOCAL_MODEL_FILE.value:
        bom_ref = _make_bom_ref("model", name, location, seen_refs, detection)
        _, ext = (name, "")
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        model_info = MODEL_FILE_EXTENSIONS.get(ext, {})
        serialization = model_info.get("serialization", framework or "unknown")
        untrusted = (not model_info.get("trusted", True))

        component = {
            "type": "machine-learning-model",
            "name": name,
            "bom-ref": bom_ref,
            "modelCard": {
                "properties": [
                    {"name": "aibom:serialization-format", "value": str(serialization)},
                    {"name": "aibom:untrusted-deserialization", "value": str(untrusted).lower()},
                    {"name": "aibom:risk-category", "value": str(risk_category)},
                ],
            },
            "properties": [
                {"name": "aibom:component-type", "value": str(component_type)},
                {"name": "aibom:provider", "value": str(source)},
            ],
        }
        if license_str:
            component["licenses"] = [{"license": {"name": str(license_str)}}]
        if location:
            component["evidence"] = {"occurrences": [{"location": location}]}
        return component

    # ----- Everything else: map AIComponentType -> correct CycloneDX type -----
    #   external_provider / huggingface_model / embedding_model -> machine-learning-model
    #   ml_framework / ai_framework                             -> library
    #   prompt_asset                                            -> file
    cyclonedx_type = _cyclonedx_type_for(component_type)

    # bom-ref kind label reflects the resolved CycloneDX type so refs are not
    # mislabeled "model-" for libraries / files (still fully deterministic).
    ref_kind = {
        "machine-learning-model": "model",
        "library": "library",
        "file": "file",
    }.get(cyclonedx_type, "component")
    bom_ref = _make_bom_ref(ref_kind, name, location, seen_refs, detection)

    pinned = risk_category != "unpinned_model_version"
    group = str(source) if source else None

    component = {
        "type": cyclonedx_type,
        "name": name,
        "bom-ref": bom_ref,
        "supplier": {"name": str(source)},
        "publisher": str(source),
        "properties": [
            {"name": "aibom:component-type", "value": str(component_type)},
            {"name": "aibom:provider", "value": str(source)},
            {"name": "aibom:model-pinned", "value": str(pinned).lower()},
            {"name": "aibom:risk-category", "value": str(risk_category)},
        ],
    }

    if group:
        component["group"] = group
    if version:
        component["version"] = str(version)
    if framework:
        component["properties"].append({"name": "aibom:framework", "value": str(framework)})
    if license_str:
        component["licenses"] = [{"license": {"name": str(license_str)}}]
    if location:
        component["evidence"] = {"occurrences": [{"location": location}]}

    return component


def ai_bom_json_to_string(aibom: dict) -> str:
    """Serialize a CycloneDX AI-BOM dict to a pretty-printed JSON string."""
    return json.dumps(aibom, indent=2, ensure_ascii=False)
