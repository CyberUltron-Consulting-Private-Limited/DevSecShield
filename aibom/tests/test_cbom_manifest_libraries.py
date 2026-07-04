"""C12 — dependency-MANIFEST crypto-library scanner.

Extends the Python-only requirements/pyproject library lane to the other
ecosystems' native manifests (Maven pom.xml / build.gradle, Go go.mod, npm
package.json, Cargo.toml, NuGet *.csproj / packages.config). A crypto library is
inventoried the moment it is DECLARED, not only where it is imported.

Scans the REAL ``synthetic-crypto-manifests`` fixture through the public
``scan_crypto`` pipeline (never a mocked ScanResult) and asserts each ecosystem's
declared crypto library surfaces as a ``crypto:role=library`` framework component
sourced to its manifest, while non-crypto deps (commons-lang3, express, serde,
Newtonsoft.Json, log4net) are NOT inventoried.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.rules import match_dep_coordinate
from aibom.cbom.scanners.algorithm_scan import (
    _cargo_coordinates,
    _detect_manifest_libraries,
    _maven_coordinates,
    _package_json_coordinates,
)

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-manifests")


def _library_index() -> dict[str, str]:
    """{label -> discovery:source} for every crypto library the scanner found."""
    result = scan_crypto(_FX)
    return {
        c.name: (c.properties or {}).get("discovery:source", "")
        for c in result.components
        if c.kind == "framework"
        and (c.properties or {}).get("crypto:role") == "library"
    }


def test_maven_pom_and_gradle_libraries() -> None:
    libs = _library_index()
    assert libs.get("Bouncy Castle") == "pom.xml"       # group wildcard
    assert libs.get("Google Tink") == "pom.xml"
    assert libs.get("JJWT") == "pom.xml"                # jjwt-api via group:*
    assert libs.get("Conscrypt") == "build.gradle"
    assert libs.get("jBCrypt") == "build.gradle"


def test_go_mod_libraries_prefix_matched() -> None:
    libs = _library_index()
    # golang.org/x/crypto declared directly; jwt/v5 resolves by longest prefix.
    assert libs.get("golang.org/x/crypto") == "go.mod"
    assert libs.get("golang-jwt") == "go.mod"
    assert libs.get("CIRCL (PQC)") == "go.mod"


def test_npm_package_json_libraries() -> None:
    libs = _library_index()
    assert libs.get("node-forge") == "package.json"
    assert libs.get("jsonwebtoken") == "package.json"
    assert libs.get("noble-hashes") == "package.json"
    assert libs.get("TweetNaCl") == "package.json"      # from devDependencies


def test_cargo_toml_libraries_incl_subtable() -> None:
    libs = _library_index()
    assert libs.get("ring (Rust)") == "Cargo.toml"
    assert libs.get("RustCrypto") == "Cargo.toml"       # aes-gcm / ed25519-dalek
    assert libs.get("Rustls") == "Cargo.toml"           # [dependencies.rustls]


def test_nuget_csproj_and_packages_config_libraries() -> None:
    libs = _library_index()
    assert libs.get("NSec") == "CryptoSvc.csproj"
    assert libs.get("Konscious Argon2") == "CryptoSvc.csproj"
    assert libs.get("libsodium") == "packages.config"   # Sodium.Core -> libsodium


def test_non_crypto_dependencies_are_not_inventoried() -> None:
    labels = set(_library_index())
    # commons-lang3, express, serde, Newtonsoft.Json, log4net, cobra, junit
    # must never be treated as crypto libraries.
    for noise in ("commons-lang3", "express", "serde", "Newtonsoft.Json",
                  "log4net", "cobra", "junit"):
        assert noise not in labels


def test_every_manifest_library_carries_role_and_source() -> None:
    result = scan_crypto(_FX)
    frameworks = [
        c for c in result.components
        if c.kind == "framework"
        and (c.properties or {}).get("crypto:role") == "library"
    ]
    assert frameworks, "expected crypto libraries from the manifests"
    manifest_names = {
        "pom.xml", "build.gradle", "go.mod", "package.json",
        "Cargo.toml", "CryptoSvc.csproj", "packages.config",
    }
    for c in frameworks:
        props = c.properties or {}
        assert props.get("crypto:role") == "library"
        assert props.get("discovery:source") in manifest_names, c.name


def test_scan_is_deterministic() -> None:
    a = _library_index()
    b = _library_index()
    assert a == b


# --- unit-level parser + resolver checks ----------------------------------- #

def test_match_dep_coordinate_maven_wildcard_and_exact() -> None:
    assert match_dep_coordinate("maven", "org.bouncycastle:bcpkix-jdk18on") == \
        "Bouncy Castle"
    assert match_dep_coordinate("maven", "org.mindrot:jbcrypt") == "jBCrypt"
    assert match_dep_coordinate("maven", "org.apache.commons:commons-lang3") is None


def test_match_dep_coordinate_go_longest_prefix() -> None:
    assert match_dep_coordinate("go", "golang.org/x/crypto/ssh") == \
        "golang.org/x/crypto"
    assert match_dep_coordinate("go", "github.com/golang-jwt/jwt/v5") == "golang-jwt"
    assert match_dep_coordinate("go", "github.com/spf13/cobra") is None


def test_match_dep_coordinate_case_folded() -> None:
    assert match_dep_coordinate("nuget", "BouncyCastle.Cryptography") == \
        "Bouncy Castle"
    assert match_dep_coordinate("npm", "@noble/hashes") == "noble-hashes"


def test_pom_pairs_group_and_artifact_within_dependency_block() -> None:
    text = (
        "<dependency><groupId>org.bouncycastle</groupId>"
        "<artifactId>bcprov-jdk18on</artifactId></dependency>"
    )
    assert _maven_coordinates(text, is_pom=True) == ["org.bouncycastle:bcprov-jdk18on"]


def test_cargo_subtable_crate_extracted() -> None:
    text = (
        '[dependencies]\nring = "0.17"\n'
        '[dependencies.rustls]\nversion = "0.23"\n'
    )
    coords = _cargo_coordinates(text)
    assert "ring" in coords
    assert "rustls" in coords


def test_package_json_ignores_non_dict_sections() -> None:
    assert _package_json_coordinates('{"dependencies": null}') == []
    assert _package_json_coordinates("not json") == []


def test_detect_manifest_libraries_returns_sorted_pairs() -> None:
    from pathlib import Path

    pairs = _detect_manifest_libraries(Path(_FX))
    assert pairs == sorted(pairs)
    assert all(isinstance(label, str) and isinstance(src, str) for label, src in pairs)
