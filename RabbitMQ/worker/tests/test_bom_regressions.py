"""
Regression tests locking in the CBOM + AI-BOM hardening fixes.

These are STACK-INDEPENDENT (no DB / RabbitMQ / Bedrock needed): they exercise the
deterministic scanner/parser code paths and validate generated BOMs against the
vendored official CycloneDX 1.6 JSON schema.

Run from RabbitMQ/worker:  uv run pytest tests/test_bom_regressions.py -q
"""
import dataclasses
import json
import os
import re
import sys

import pytest

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WORKER)

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "cyclonedx-1.6.schema.json")

VALID_PRIMITIVES = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash",
    "pke", "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
}


@pytest.fixture(scope="module")
def schema():
    with open(SCHEMA_PATH) as f:
        return json.load(f)


def _validate(doc, schema):
    import jsonschema
    jsonschema.validate(doc, schema)


def _to_dict(d):
    return dataclasses.asdict(d) if dataclasses.is_dataclass(d) else d


# ----------------------------- CBOM parser -----------------------------

CBOM_DETECTIONS = [
    {"algorithm_name": "RSA", "algorithm_type": "asymmetric_cipher", "crypto_strength": "strong", "key_size": 2048, "quantum_safe": False, "location": "a.go", "snippet": "rsa"},
    {"algorithm_name": "AES", "algorithm_type": "symmetric_cipher", "crypto_strength": "strong", "key_size": 256, "quantum_safe": False, "location": "b.go", "snippet": "aes"},
    {"algorithm_name": "ChaCha20", "algorithm_type": "symmetric_cipher", "crypto_strength": "strong", "key_size": 256, "quantum_safe": False, "location": "c.go", "snippet": "chacha20"},
    {"algorithm_name": "SHA-256", "algorithm_type": "hash", "crypto_strength": "strong", "key_size": None, "quantum_safe": False, "location": "d.go", "snippet": "sha256"},
]


def test_cbom_cyclonedx_schema_valid(schema):
    from helpers.tools.cbom_agent import parser
    bom = parser.generate_cyclonedx_cbom(CBOM_DETECTIONS, scan_id="42", repo_url="https://github.com/acme/widgets")
    _validate(bom, schema)
    assert bom["specVersion"] == "1.6"
    types = {c.get("type") for c in bom["components"]}
    assert types == {"cryptographic-asset"}, f"invalid component type(s): {types}"
    prims = {(c.get("cryptoProperties", {}).get("algorithmProperties", {}) or {}).get("primitive") for c in bom["components"]}
    prims.discard(None)
    assert prims <= VALID_PRIMITIVES, f"invalid CycloneDX primitives emitted: {prims - VALID_PRIMITIVES}"


def test_cbom_cyclonedx_deterministic():
    from helpers.tools.cbom_agent import parser
    a = parser.generate_cyclonedx_cbom(CBOM_DETECTIONS, scan_id="42", repo_url="x/y", timestamp="2026-01-01T00:00:00Z")
    b = parser.generate_cyclonedx_cbom(CBOM_DETECTIONS, scan_id="42", repo_url="x/y", timestamp="2026-01-01T00:00:00Z")
    assert a["serialNumber"] == b["serialNumber"]
    assert a["serialNumber"].startswith("urn:uuid:")
    assert json.dumps(a["components"]) == json.dumps(b["components"])


def test_cbom_stream_vs_block_cipher_primitive():
    from helpers.tools.cbom_agent import parser
    bom = parser.generate_cyclonedx_cbom(CBOM_DETECTIONS, scan_id="1")
    prim = {c["name"]: (c.get("cryptoProperties", {}).get("algorithmProperties", {}) or {}).get("primitive") for c in bom["components"]}
    assert prim.get("ChaCha20") == "stream-cipher"
    assert prim.get("AES") == "block-cipher"


# ----------------------- CBOM extractor false positives -----------------------

@pytest.mark.parametrize("line", [
    "src, des = get_path()",
    "rsa = remote_storage_account",
    "tls = total_line_size",
    "falcon = Flask(__name__)",
    "aesWithPadding = true",
    'log("we migrated away from DES to AES")',
])
def test_cbom_extractor_no_false_positives(line):
    from helpers.tools.cbom_agent.source_scanner import extract_algorithms_safe
    assert extract_algorithms_safe(line) == [], f"false positive on: {line!r}"


@pytest.mark.parametrize("line,expected", [
    ("hashlib.sha256(data)", {"sha256"}),
    ('"crypto/rsa"', {"rsa"}),
    ("rsa.GenerateKey(rand.Reader, 2048)", {"rsa"}),
    ('Cipher.getInstance("AES/GCM/NoPadding")', {"aes"}),
    ('"SHA256withRSA"', {"sha256", "rsa"}),
])
def test_cbom_extractor_true_positives(line, expected):
    from helpers.tools.cbom_agent.source_scanner import extract_algorithms_safe
    assert set(extract_algorithms_safe(line)) >= expected, f"missed on: {line!r}"


# ----------------------------- AI-BOM parser/scanner -----------------------------

def _aibom_synthetic_dir(tmp_path):
    (tmp_path / "manifest.json").write_text('{"name":"my pwa","icons":[]}')
    (tmp_path / "data.yaml").write_text("config: true\n")
    (tmp_path / "user_agent.py").write_text('def get_user_agent(): return "x"\n')
    (tmp_path / "firmware.bin").write_text("binary blob")
    (tmp_path / "app.py").write_text('import openai\nopenai.OpenAI().chat.completions.create(model="gpt-4")\n')
    return tmp_path


def test_aibom_scanner_false_positives(tmp_path):
    from helpers.tools.ai_bom_agent import source_scanner as ss
    dets = ss.scan_directory(str(_aibom_synthetic_dir(tmp_path)))
    names = {(_to_dict(d).get("component_name") or "").lower() for d in dets}
    types = {(_to_dict(d).get("component_type") or "").lower() for d in dets}
    assert not any("manifest" in n for n in names), "manifest.json must not be flagged"
    assert not any("user_agent" in n for n in names), "user_agent must not be flagged as prompt"
    # real AI usage still detected (openai sdk / gpt-4 provider)
    blob = " ".join(names)
    assert "openai" in blob or "gpt-4" in blob, "real AI assets must still be detected"


def test_aibom_cyclonedx_schema_valid(tmp_path, schema):
    from helpers.tools.ai_bom_agent import source_scanner as ss
    from helpers.tools.ai_bom_agent import parser
    dets = [_to_dict(d) for d in ss.scan_directory(str(_aibom_synthetic_dir(tmp_path)))]
    bom = parser.generate_cyclonedx_aibom(dets, scan_id="42", repo_url="https://github.com/acme/ml")
    _validate(bom, schema)
    assert bom["specVersion"] == "1.6"
    types = {c.get("type") for c in bom.get("components", [])}
    assert types <= {"machine-learning-model", "data"}, f"invalid AI-BOM component type(s): {types}"


# ----------------------- prompt <-> enum drift (the scan-failure bug) -----------------------

def _enum_values():
    from helpers.context.enums import ComplianceControls
    return {c.value for c in ComplianceControls}


@pytest.mark.parametrize("module_path", [
    "helpers/tools/ai_bom_agent/summary_manager.py",
])
def test_summary_prompt_compliance_strings_match_enum(module_path):
    """A truncated/edited compliance string in a MapPrompt makes structured-output
    validation reject the LLM result and FAILS THE WHOLE SCAN. This catches that drift:
    if a control's distinctive head is referenced in the prompt, its full enum value
    must also be present verbatim."""
    text = open(os.path.join(WORKER, module_path)).read()
    drift = []
    for value in _enum_values():
        head = value.split(",")[0]  # robust to commas inside enum values
        if len(head) >= 18 and head in text and value not in text:
            drift.append((head, value))
    assert not drift, f"{module_path}: truncated compliance strings (head present, full enum value missing): {drift}"
