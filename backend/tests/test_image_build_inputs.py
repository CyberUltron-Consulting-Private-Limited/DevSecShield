"""The production image builds (scripts/deploy/build_images.sh, `make build`) behind a TLS-intercepting proxy and on a
build host that shares its address with others.

Found on the local stack build (round 5, L1):
* build_images.sh passes UV_BASE_IMAGE to the scan-worker and DAST-worker builds, as deploy/staging/README.md tells
  operators behind a TLS-intercepting proxy, but both Dockerfiles hard-coded their base image, so the builds failed on
  the first download ("invalid peer certificate: UnknownIssuer"); the scan worker's cbomkit-theia stage (golang) had
  no way at all to trust the proxy;
* the DAST worker asked the unauthenticated GitHub API for nuclei's "latest" release (60 requests an hour per
  address); refused, it downloaded the error page and failed with "End-of-central-directory signature not found".

Run: cd backend && python -m pytest tests/test_image_build_inputs.py -q -p no:cacheprovider
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORKER = (REPO / "RabbitMQ" / "worker" / "Dockerfile").read_text()
DAST = (REPO / "RabbitMQ" / "dast_worker" / "Dockerfile").read_text()
BUILD = (REPO / "scripts" / "deploy" / "build_images.sh").read_text()


def froms(text: str) -> list[str]:
    return re.findall(r"^FROM\s+(\S+)", text, re.M)


def test_worker_images_take_the_base_image_build_arguments():
    assert re.search(r"^ARG UV_BASE_IMAGE=ghcr\.io/astral-sh/uv:python3\.12-bookworm-slim$", WORKER, re.M)
    assert re.search(r"^ARG GO_BASE_IMAGE=golang:1\.26-bookworm$", WORKER, re.M)
    assert froms(WORKER) == ["${UV_BASE_IMAGE}", "${GO_BASE_IMAGE}", "${UV_BASE_IMAGE}"]
    assert re.search(r"^ARG UV_BASE_IMAGE=ghcr\.io/astral-sh/uv:python3\.12-bookworm-slim$", DAST, re.M)
    assert froms(DAST) == ["${UV_BASE_IMAGE}", "${UV_BASE_IMAGE}"]


def test_build_script_passes_the_go_base_image_to_the_scan_worker_only():
    assert '[[ -n "${GO_BASE_IMAGE:-}" ]] && go_args+=(--build-arg "GO_BASE_IMAGE=${GO_BASE_IMAGE}")' in BUILD
    assert 'build scan-worker RabbitMQ/worker/Dockerfile . "${base_args[@]}" "${go_args[@]}"' in BUILD


def test_nuclei_is_a_pinned_release_checked_against_its_checksums():
    assert "api.github.com" not in DAST
    assert re.search(r"^ARG NUCLEI_VERSION=\d+\.\d+\.\d+$", DAST, re.M)
    step = DAST[DAST.index("ARG NUCLEI_VERSION"):]
    step = step[:step.index("rm \"/tmp/${zip}\"")]
    assert step.count("curl -fsSL") == 2  # -f: an HTTP error fails the step instead of saving the error page
    assert "nuclei_${NUCLEI_VERSION}_checksums.txt" in step and "sha256sum -c -" in step
