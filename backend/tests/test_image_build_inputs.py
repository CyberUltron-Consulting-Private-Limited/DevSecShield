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
    # #69 (#335) pins the scan worker's base images by digest; the defaults stay build arguments a proxy build overrides
    assert re.search(r"^ARG UV_BASE_IMAGE=ghcr\.io/astral-sh/uv:python3\.12-bookworm-slim@sha256:[0-9a-f]{64}$", WORKER, re.M)
    assert re.search(r"^ARG GO_BASE_IMAGE=golang:1\.26(\.\d+)?-bookworm@sha256:[0-9a-f]{64}$", WORKER, re.M)
    # builder, cbomkit-theia, cdxgen (FIX-C1), runtime
    assert froms(WORKER) == ["${UV_BASE_IMAGE}", "${GO_BASE_IMAGE}", "${UV_BASE_IMAGE}", "${UV_BASE_IMAGE}"]
    assert re.search(r"^ARG UV_BASE_IMAGE=ghcr\.io/astral-sh/uv:python3\.12-bookworm-slim$", DAST, re.M)
    assert froms(DAST) == ["${UV_BASE_IMAGE}", "${UV_BASE_IMAGE}"]


def test_worker_node_and_cdxgen_are_pinned_and_verified():
    """FIX-C1: cdxgen (SBOM inventory) runs from the image, never ``npx --yes`` at scan time: Node.js by version and
    SHA-256, cdxgen and its dependencies by the committed lockfile (npm ci), no install scripts."""
    assert re.search(r"^ARG NODE_VERSION=\d+\.\d+\.\d+$", WORKER, re.M)
    assert re.search(r"^ARG NODE_SHA256_AMD64=[0-9a-f]{64}$", WORKER, re.M)
    assert re.search(r"^ARG NODE_SHA256_ARM64=[0-9a-f]{64}$", WORKER, re.M)
    step = WORKER[WORKER.index("ARG NODE_VERSION"):WORKER.index("Stage 2: Runtime")]
    assert "curl -sSfL" in step and "sha256sum -c /tmp/node.sha256" in step
    assert "npm ci --omit=dev --omit=optional --ignore-scripts" in step
    assert "npm install" not in WORKER and "npx" not in WORKER


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


def test_backend_image_secret_check_covers_every_copied_tree():
    """Every tree the backend Dockerfile copies in (source, Alembic bundle, the aibom engine of CB-38 run parity) is
    scanned for secret-bearing files after the build."""
    backend = (REPO / "backend" / "Dockerfile").read_text()
    copied = set(re.findall(r"^COPY --from=(?:migrations|aibom) \S+ (/[a-z_]+)(?:/|\s|$)", backend, re.MULTILINE))
    assert copied == {"/prod_database_migrations", "/opt"}, copied
    line = re.search(r"^\s+assert_no_secrets backend (.+)$", BUILD, re.MULTILINE)
    assert line, "build_images.sh does not check the backend image"
    assert set(line.group(1).split()) == {"/backend", "/prod_database_migrations", "/opt/aibom"}
