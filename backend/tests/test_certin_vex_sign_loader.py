"""Hermetic lock: CERT-In VEX/sign must load without aibom on PYTHONPATH.

The backend Docker image is built from ``backend/`` only. Production therefore
never has ``/aibom/src/aibom/compliance/cert_in/{vex,sign}.py`` unless those
stdlib modules are also shipped inside the backend tree. The API loader must
find them there (503 ``aibom vex/sign unavailable`` otherwise).
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_AIBOM_CERT_IN = _REPO / "aibom/src/aibom/compliance/cert_in"
_BACKEND_CERT_IN = _REPO / "backend/utilities/compliance/cert_in"


def test_backend_ships_stdlib_vex_and_sign_for_docker_image() -> None:
    """backend/ context cannot COPY aibom/; these files must live in backend/."""
    for name in ("vex.py", "sign.py"):
        path = _BACKEND_CERT_IN / name
        assert path.is_file(), (
            f"missing {path} — Docker backend looks for cert_in/{name} under "
            "/aibom/src/... which is not in the image"
        )


def test_vendored_vex_sign_match_aibom_source_of_truth() -> None:
    for name in ("vex.py", "sign.py"):
        src = _AIBOM_CERT_IN / name
        dst = _BACKEND_CERT_IN / name
        assert src.is_file(), f"aibom source missing: {src}"
        assert dst.is_file(), f"backend copy missing: {dst}"
        assert src.read_text(encoding="utf-8") == dst.read_text(encoding="utf-8"), (
            f"{name} drifted between aibom and backend/utilities/compliance/cert_in"
        )


def test_load_certin_module_candidates_include_backend_tree() -> None:
    from backend.routers.certin import _certin_module_candidates

    vex_paths = _certin_module_candidates("vex")
    sign_paths = _certin_module_candidates("sign")
    backend_vex = (_BACKEND_CERT_IN / "vex.py").resolve()
    backend_sign = (_BACKEND_CERT_IN / "sign.py").resolve()
    assert backend_vex in [p.resolve() for p in vex_paths]
    assert backend_sign in [p.resolve() for p in sign_paths]


def test_load_certin_module_vex_and_sign() -> None:
    from backend.routers.certin import _load_certin_module

    vex = _load_certin_module("vex")
    sign = _load_certin_module("sign")
    doc = vex.build_vex(
        bom={"components": [{"name": "AES", "bom-ref": "aes-1"}]},
        scan_type="cbom",
    )
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["vulnerabilities"]
    sig = sign.sign_bom({"serialNumber": "urn:uuid:test"}, secret=b"unit-test-secret")
    assert sig["alg"] == "HMAC-SHA256"
    assert sign.verify_signature(
        {"serialNumber": "urn:uuid:test"}, sig, secret=b"unit-test-secret"
    )


def test_load_certin_module_works_without_aibom_tree(tmp_path, monkeypatch) -> None:
    """Simulate the backend image: no repo-root aibom/, only vendored files."""
    from backend.routers import certin as certin_router

    isolated = tmp_path / "image"
    vendored = isolated / "backend" / "utilities" / "compliance" / "cert_in"
    vendored.mkdir(parents=True)
    for name in ("vex.py", "sign.py"):
        vendored.joinpath(name).write_text(
            _BACKEND_CERT_IN.joinpath(name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    fake_router = isolated / "backend" / "routers" / "certin.py"
    fake_router.parent.mkdir(parents=True, exist_ok=True)
    fake_router.write_text("# sentinel\n", encoding="utf-8")

    monkeypatch.setattr(certin_router, "__file__", str(fake_router))

    def _no_aibom(name: str):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(certin_router.importlib, "import_module", _no_aibom)

    vex = certin_router._load_certin_module("vex")
    assert callable(vex.build_vex)
    doc = vex.build_vex(bom={"components": [{"name": "x"}]}, scan_type="ai_bom")
    assert doc["specVersion"] == "1.6"
