"""SOW D3 CBOM code-scan deliverable: the defects the staging audit found on
peva3/SmarterRouter (audit-C G-D3-1..5).

``fixtures/cbom-d3-bank`` reproduces SmarterRouter's encryption module (Fernet keyed
by PBKDF2-HMAC-SHA256 with a fixed salt) and adds the other password KDFs
(hashlib.pbkdf2_hmac, hashlib.scrypt, argon2-cffi), an HKDF, an inline CBC IV, a
uv.lock, a multi-stage Dockerfile and a Compose file. Every CBOM is validated
against the official CycloneDX 1.6 schema.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aibom.cbom.image_refs import split_reference
from aibom.emit.validate import validate_cyclonedx
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

_FIXTURE = pathlib.Path(__file__).resolve().parent / "fixtures" / "cbom-d3-bank"
_SALT_LITERALS = (
    "bank_router_salt_v1",
    "constant-scrypt-salt",
    "0123456789abcdef",
    "fixed-iv-16bytes",
)


@pytest.fixture(scope="module")
def run() -> dict:
    return scan_crypto_to_devsecshield(_FIXTURE, level=4)


def _props(comp: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in comp.get("properties") or []}


def _comp(bom: dict, name: str, source: str) -> dict:
    return next(
        c
        for c in bom["components"]
        if c["name"] == name and _props(c).get("discovery:source") == source
    )


def test_cbom_is_valid_cyclonedx_1_6(run: dict) -> None:
    assert validate_cyclonedx(run["cbom_json"]) == []


# ------------------------------------------------------------------ G-D3-1 Fernet
def test_fernet_is_aes_128_cbc_plus_hmac_sha256(run: dict) -> None:
    bom = run["cbom_json"]
    fernet = _comp(bom, "Fernet", "app/encryption.py")
    algo = fernet["cryptoProperties"]["algorithmProperties"]
    # was parameterSetIdentifier 256 / NIST level 5 / classical 256 (the 256-bit key
    # is 128 signing + 128 encryption)
    assert algo["parameterSetIdentifier"] == "128"
    assert algo["nistQuantumSecurityLevel"] == 1
    assert algo["classicalSecurityLevel"] == 128
    aes = _comp(bom, "AES-128-CBC", "app/encryption.py")["cryptoProperties"]
    assert aes["algorithmProperties"]["mode"] == "cbc"
    assert aes["algorithmProperties"]["nistQuantumSecurityLevel"] == 1
    hmac = _comp(bom, "HMAC-SHA256", "app/encryption.py")
    deps = {d["ref"]: d for d in bom["dependencies"]}
    assert deps[fernet["bom-ref"]]["dependsOn"] == sorted(
        [_comp(bom, "AES-128-CBC", "app/encryption.py")["bom-ref"], hmac["bom-ref"]]
    )


# ------------------------------------------------------------------ G-D3-2 KDF
# parameters
@pytest.mark.parametrize(
    ("name", "source", "expected"),
    [
        (
            "PBKDF2",
            "app/encryption.py",
            {
                "crypto:kdfPrf": "HMAC-SHA256",
                "crypto:iterations": "480000",
                "crypto:kdfLength": "32",
                "crypto:saltLength": "19",
            },
        ),
        (
            "PBKDF2",
            "app/kdf.py",
            {
                "crypto:kdfPrf": "HMAC-SHA512",
                "crypto:iterations": "600000",
                "crypto:kdfLength": "64",
                "crypto:saltLength": "16",
            },
        ),
        (
            "scrypt",
            "app/kdf.py",
            {
                "crypto:scryptN": "16384",
                "crypto:scryptR": "8",
                "crypto:scryptP": "1",
                "crypto:kdfLength": "32",
                "crypto:saltLength": "20",
            },
        ),
        (
            "Argon2",
            "app/kdf.py",
            {
                "crypto:argon2TimeCost": "3",
                "crypto:argon2MemoryCost": "65536",
                "crypto:argon2Parallelism": "4",
                "crypto:kdfLength": "32",
                "crypto:saltLength": "16",
                "crypto:detectedBy": "argon2-cffi",
            },
        ),
        (
            "HKDF",
            "app/kdf.py",
            {"crypto:kdfPrf": "HMAC-SHA256", "crypto:kdfLength": "32"},
        ),
    ],
)
def test_kdf_parameters_are_captured(run, name, source, expected) -> None:
    props = _props(_comp(run["cbom_json"], name, source))
    assert {k: props.get(k) for k in expected} == expected


# ------------------------------------------------------------------ static salt / IV
def test_hard_coded_salt_and_iv_are_findings_with_the_literal_masked(run: dict) -> None:
    results = run["results"]
    codes = {r.get("title"): tuple(r.get("finding_codes") or []) for r in results}
    assert codes["salt (app/encryption.py:12)"] == ("STATIC_SALT",)  # SmarterRouter's
    # one row per literal, at its line (review of #491 m6): pbkdf2_hmac's inline salt,
    # scrypt's named one (the misuse lane's row, merged); HKDF's fixed salt is allowed
    # (RFC 5869) and feeds no finding
    assert codes["salt (app/kdf.py:13)"] == ("STATIC_SALT",)
    assert codes["salt (SCRYPT_SALT, kdf.py)"] == ("STATIC_SALT",)
    assert codes["salt (app/kdf.py:21)"] == ()
    assert codes["initialization-vector (app/kdf.py:28)"] == ("STATIC_IV",)
    used = {
        name: _props(_comp(run["cbom_json"], name, "app/kdf.py")).get("crypto:usedBy")
        for name in ("salt (app/kdf.py:13)", "salt (SCRYPT_SALT, kdf.py)")
    }
    assert used == {
        "salt (app/kdf.py:13)": "PBKDF2",
        "salt (SCRYPT_SALT, kdf.py)": "scrypt",
    }
    # nowhere: not in the BOM, not in any row's code window (the KDF row's window
    # shows the same line as the salt)
    text = json.dumps(run["cbom_json"]) + json.dumps(
        [r.get("snippet") for r in run["results"]]
    )
    for literal in _SALT_LITERALS:
        assert literal not in text


# ------------------------------------------------------------------ G-D3-3 graph +
# versions
def test_dependencies_graph_uses_and_provides(run: dict) -> None:
    bom = run["cbom_json"]
    deps = {d["ref"]: d for d in bom["dependencies"]}
    pbkdf2 = _comp(bom, "PBKDF2", "app/encryption.py")["bom-ref"]
    assert deps[pbkdf2]["dependsOn"] == sorted(
        [
            _comp(bom, "SHA-256", "app/encryption.py")["bom-ref"],
            _comp(bom, "salt (app/encryption.py:12)", "app/encryption.py")["bom-ref"],
        ]
    )
    pyca = next(c for c in bom["components"] if c["name"] == "pyca/cryptography")
    assert pbkdf2 in deps[pyca["bom-ref"]]["provides"]
    argon = next(c for c in bom["components"] if c["name"] == "argon2-cffi")
    assert deps[argon["bom-ref"]]["provides"] == [
        _comp(bom, "Argon2", "app/kdf.py")["bom-ref"]
    ]
    # a library implements algorithms, never a salt
    salts = {c["bom-ref"] for c in bom["components"] if c["name"].startswith("salt")}
    assert not salts & set(deps[pyca["bom-ref"]]["provides"])


def test_crypto_library_versions_from_lockfiles(run: dict) -> None:
    libs = {
        c["name"]: c
        for c in run["cbom_json"]["components"]
        if _props(c).get("crypto:role") == "library" and c["type"] == "library"
    }
    pyca = libs["pyca/cryptography"]
    assert (
        pyca["version"] == "43.0.1" and pyca["purl"] == "pkg:pypi/cryptography@43.0.1"
    )
    assert _props(pyca)["crypto:versionSource"] == "uv.lock"
    assert _props(pyca)["crypto:versionConstraint"] == ">=41.0"
    assert libs["argon2-cffi"]["version"] == "23.1.0"
    stdlib = _props(libs["hashlib (stdlib)"])
    assert "python:3.11-slim" in stdlib["crypto:versionUnknownReason"]


# ------------------------------------------------------------------ G-D3-5 images
def test_dockerfile_and_compose_images_are_listed(run: dict) -> None:
    images = {
        (c["name"], c.get("version")): _props(c)
        for c in run["cbom_json"]["components"]
        if c["type"] == "container"
    }
    assert set(images) == {
        (
            "python",
            "3.11-slim",
        ),  # FROM python:${PY_VERSION}-slim with ARG PY_VERSION=3.11
        (
            "gcr.io/distroless/python3-debian12",
            "sha256:0f1f7d2c4b3a6e5d8c9b0a1f2e3d4c5b6a7980716253443526170819a0b1c2d3",
        ),
        ("ghcr.io/acme/bank-router", "1.4.2"),
        ("redis", "7.2-alpine"),
    }  # not the build stages "build" / "test", not the "build: ." service
    assert images[("python", "3.11-slim")]["image:origin"] == "Dockerfile FROM"
    assert images[("python", "3.11-slim")]["discovery:line"] == "2"
    assert images[("redis", "7.2-alpine")]["image:origin"] == "Compose image"


@pytest.mark.parametrize(
    ("ref", "parts"),
    [
        ("python:3.11-slim", ("python", "3.11-slim", None)),
        ("localhost:5000/app", ("localhost:5000/app", None, None)),
        ("ghcr.io/o/a:1@sha256:ab", ("ghcr.io/o/a", "1", "sha256:ab")),
    ],
)
def test_split_reference(ref: str, parts: tuple) -> None:
    assert split_reference(ref) == parts


# ------------------------------------------------------------------ identity (G-X-4)
def test_cbom_metadata_identity_and_time(run: dict) -> None:
    meta = run["cbom_json"]["metadata"]
    (tool,) = meta["tools"]["components"]
    assert tool["name"] == "DevSecShield CBOM"
    assert meta["timestamp"] != "2026-06-21T00:00:00Z"
    text = json.dumps(run["cbom_json"])
    assert "clinithread" not in text and "HIPAA" not in text and "FDA" not in text
