"""Air-gap compose policy. Default mode stays the two loopback ports."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "e2e" / "scripts" / "compose_policy.py"
OVERLAY = ROOT / "e2e" / "compose" / "docker-compose.airgap.yml"


def _service(name: str, **extra: object) -> dict:
    body = {
        "image": "dss-e2e/backend:local",
        "labels": {"com.dss-e2e": "1"},
        "pull_policy": "never",
        "ports": [],
    }
    body.update(extra)
    return body


def _base() -> dict:
    return {
        "name": "dss-e2e",
        "services": {
            "postgres": {"image": "postgres:15-alpine", "labels": {"com.dss-e2e": "1"}, "ports": []},
            "mongo": {"image": "mongo:8.0.6", "labels": {"com.dss-e2e": "1"}},
            "backend": _service(
                "backend",
                command=["uv", "run", "gunicorn"],
                ports=[{"host_ip": "127.0.0.1", "published": "43080", "target": "8080"}],
                volumes=[
                    {
                        "target": "/aibom/config",
                        "read_only": True,
                        "source": "/repo/compose/aibom-config-overlay",
                    }
                ],
            ),
            "frontend": _service(
                "frontend",
                image="dss-e2e/frontend:local",
                ports=[{"host_ip": "127.0.0.1", "published": "43000", "target": "3000"}],
            ),
            "aibom-scan": _service(
                "aibom-scan",
                image="dss-e2e/aibom-scan:local",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
            ),
            "seed": _service("seed", image="dss-e2e/seed:local"),
        },
        "networks": {
            "default": {"name": "dss-e2e_default", "labels": {"com.dss-e2e": "1"}}
        },
        "volumes": {"pgdata": {"name": "dss-e2e_pgdata", "labels": {"com.dss-e2e": "1"}}},
    }


def _run(model: dict, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(POLICY), *args],
        input=json.dumps(model),
        text=True,
        capture_output=True,
        check=False,
    )


def test_default_mode_still_requires_the_two_loopback_ports() -> None:
    result = _run(_base())
    assert result.returncode == 0, result.stdout + result.stderr


def _airgap_model() -> dict:
    model = _base()
    model["services"]["backend"]["ports"] = []
    model["services"]["frontend"]["ports"] = []
    model["services"]["rabbitmq"] = {
        "image": "rabbitmq:3.13-alpine",
        "labels": {"com.dss-e2e": "1"},
        "ports": [],
    }
    model["services"]["object-store"] = {
        "image": "minio/minio:RELEASE.2024-10-02T17-50-41Z",
        "labels": {"com.dss-e2e": "1"},
        "ports": [],
    }
    model["services"]["scan-worker"] = _service(
        "scan-worker",
        image="dss-e2e/aibom-scan:local",
        network_mode="none",
    )
    model["services"]["gateway"] = _service(
        "gateway",
        networks=["default", "edge"],
        ports=[
            {"host_ip": "127.0.0.1", "published": "43000", "target": "3000"},
            {"host_ip": "127.0.0.1", "published": "43080", "target": "8080"},
        ],
    )
    model["networks"]["default"]["internal"] = True
    model["networks"]["edge"] = {"name": "dss-e2e_edge", "labels": {"com.dss-e2e": "1"}}
    return model


def test_airgap_mode_publishes_only_through_the_gateway() -> None:
    result = _run(_airgap_model(), "--airgap")
    assert result.returncode == 0, result.stdout + result.stderr
    published = _run(_base(), "--airgap")
    assert published.returncode == 1
    leaked = _airgap_model()
    leaked["services"]["backend"]["ports"] = [
        {"host_ip": "127.0.0.1", "published": "43080", "target": "8080"}
    ]
    assert _run(leaked, "--airgap").returncode == 1


def test_overlay_file_marks_the_network_internal() -> None:
    text = OVERLAY.read_text(encoding="utf-8")
    assert "internal: true" in text
    assert "network_mode: none" in text
    assert "ports: !override []" in text
    assert "gateway:" in text
    assert "edge:" in text
