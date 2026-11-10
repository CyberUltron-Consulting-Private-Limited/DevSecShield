"""The backend image keeps its virtualenv in a layer that only pyproject.toml / uv.lock change.

Round 5 (L1): the runtime stage did `COPY --from=builder /backend /backend`, venv and source in one layer, so every
release, even a one-line source change, added a new ~700 MB layer (about 1.6 GB of disk per release on the staging
build host). Now a deps stage builds the venv from the two lock files only, the runtime copies the venv first and
the source after it. pyproject.toml has no [build-system], so uv never installs the project into the venv and
copying the source as plain files is all the second sync used to do.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_backend_dockerfile_layers.py -q -p no:cacheprovider
"""
import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _stages(text: str) -> dict[str, str]:
    parts = re.split(r"^FROM\s+", text, flags=re.M)[1:]
    out = {}
    for i, part in enumerate(parts):
        head = part.splitlines()[0]
        m = re.search(r"\bAS\s+(\S+)", head, flags=re.I)
        out[m.group(1) if m else f"stage{i}"] = part
    return out


def test_the_venv_is_built_from_the_lock_files_only():
    deps = _stages((BACKEND / "Dockerfile").read_text())["deps"]
    assert "uv sync --locked --no-install-project" in deps
    assert not re.search(r"^COPY\s", deps, flags=re.M), "the deps stage must not see the source"


def test_runtime_copies_the_venv_before_the_source_and_never_both_at_once():
    text = (BACKEND / "Dockerfile").read_text()
    runtime = list(_stages(text).values())[-1]
    venv = runtime.index("COPY --from=deps /backend/.venv /backend/.venv")
    source = runtime.index("COPY . /backend")
    assert venv < source
    assert "COPY --from=builder /backend /backend" not in runtime
    assert ".venv/" in (BACKEND / ".dockerignore").read_text().splitlines()  # the context's .venv never lands on it


def test_the_project_is_not_a_package():
    # if a [build-system] is added, uv installs the project into the venv and the runtime needs `uv sync` again
    assert "[build-system]" not in (BACKEND / "pyproject.toml").read_text()
