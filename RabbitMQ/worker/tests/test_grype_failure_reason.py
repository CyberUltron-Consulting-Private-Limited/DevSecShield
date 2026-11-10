"""A failed grype run reports its cause, not its first warning (runs with any Python).

On the local stack (u2 UI run, round 5) an SCA + SBOM scan failed and the sidebar's reason was grype's first stderr
line, "WARN no explicit name and version provided for directory source ...": the cause, three lines later, was the
vulnerability database download ("no space left on device").
"""
from __future__ import annotations

import importlib.util
import os

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_spec = importlib.util.spec_from_file_location(
    "grype_errors", os.path.join(WORKER, "helpers/tools/sca_sbom_agent/grype_errors.py"))
grype_errors = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(grype_errors)

# stderr of the local stack's run (paths shortened)
STDERR = (
    "[0000]  WARN no explicit name and version provided for directory source, deriving artifact ID from the given "
    "path (which is not ideal) from=syft\n"
    "[0014]  WARN error updating db error=unable to update vulnerability database: unable to download db: write "
    "/root/.cache/grype/db/grype-db-download2850258481/vulnerability.db: no space left on device\n"
)


def test_the_cause_is_reported_not_the_first_warning():
    reason = grype_errors.grype_failure_reason(STDERR)
    assert reason.startswith("error updating db error=unable to update vulnerability database")
    assert reason.endswith("no space left on device")
    assert "no explicit name and version" not in reason


def test_edge_cases():
    assert grype_errors.grype_failure_reason("") == "grype exited with an error and printed nothing"
    assert grype_errors.grype_failure_reason(None) == "grype exited with an error and printed nothing"
    assert grype_errors.grype_failure_reason("[0001]  INFO something odd\n") == "something odd"
    assert len(grype_errors.grype_failure_reason("x error " * 200)) == 400


def test_grype_uses_it():
    src = open(os.path.join(WORKER, "helpers/tools/sca_sbom_agent/grype.py")).read()
    assert 'raise RuntimeError(f"SBOM scan failed: {grype_failure_reason(result.stderr)}")' in src
    assert "{result.stderr}" not in src.split("falling back to dir:")[1]
