"""clinithread-aibom CLI (`aibom`).

A Typer CLI over the clinithread-aibom engine. clinithread-aibom is a
healthcare-focused EXTENSION of DevSecShield's AIBOM: it scans a model repo into
a scored :class:`~aibom.model.result.ScanResult` (components + typed edges +
semantic flags + risk score) and renders it through a stateless reporter
registry into schema-validated CycloneDX 1.6 / SPDX 3.0 / SARIF documents.

HARD RULE (build-failure): every emitted BOM MUST schema-validate against the
bundled offline schemas. Reporters refuse to emit an invalid document;
``validate`` is the standalone schema gate.

Phase-1 surface:
    aibom scan <path>                     scan a repo -> ScanResult (JSON)
    aibom emit --format cyclonedx <path>  scan -> render a validated BOM
    aibom validate <file>                 schema-gate a BOM (auto-detect format)
    aibom map | discover                  later-phase stubs
"""

from __future__ import annotations

import json
import pathlib
import sys

import typer

# Importing aibom.emit self-registers every reporter into the registry.
from aibom.emit import available_formats, get_reporter
from aibom.emit.cyclonedx import ADVISORY_DISCLAIMER, BomValidationError
from aibom.emit.sarif import SarifValidationError
from aibom.emit.spdx import SpdxValidationError
from aibom.emit.validate import validate_auto
from aibom.scan.pipeline import scan_repo

_EMIT_ERRORS = (BomValidationError, SpdxValidationError, SarifValidationError)

app = typer.Typer(
    name="aibom",
    help=(
        "clinithread-aibom: generate and validate healthcare AI Bills of "
        "Materials (CycloneDX 1.6 / SPDX 3.0 / SARIF). Mappings are advisory only."
    ),
    no_args_is_help=True,
    add_completion=False,
)


def _eprint(msg: str) -> None:
    """Status/guidance to stderr so stdout stays a clean payload (pipe-friendly)."""
    typer.echo(msg, err=True)


def _write(payload: str, output: pathlib.Path | None) -> None:
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload)
    else:
        sys.stdout.write(payload)


# --------------------------------------------------------------------------- #
# scan -- repo -> scored ScanResult (components + edges + flags + scores)
# --------------------------------------------------------------------------- #


@app.command()
def scan(
    path: pathlib.Path = typer.Argument(
        ..., exists=True, file_okay=False, dir_okay=True, readable=True,
        help="Repo / model project directory to scan.",
    ),
    output: pathlib.Path = typer.Option(
        None, "--output", "-o", dir_okay=False, writable=True,
        help="Write the ScanResult JSON here instead of stdout.",
    ),
    indent: int = typer.Option(2, help="JSON indentation."),
) -> None:
    """Scan a repo/model project into a scored ScanResult (JSON)."""
    result = scan_repo(path)
    _write(json.dumps(result.to_dict(), indent=indent) + "\n", output)
    n_models = sum(1 for c in result.components if c.kind == "model")
    n_data = sum(1 for c in result.components if c.kind == "dataset")
    _eprint(
        f"# scan: {len(result.components)} components "
        f"({n_models} model, {n_data} dataset), {len(result.edges)} edges, "
        f"{len(result.flags)} flags, risk={result.scores.get('risk_total', 0)}"
    )


# --------------------------------------------------------------------------- #
# emit -- scan -> render via the reporter registry
# --------------------------------------------------------------------------- #


@app.command()
def emit(
    path: pathlib.Path = typer.Argument(
        ..., exists=True, file_okay=False, dir_okay=True, readable=True,
        help="Repo / model project directory to scan and emit a BOM for.",
    ),
    fmt: str = typer.Option(
        "cyclonedx", "--format", "-f",
        help="BOM format: cyclonedx | spdx | sarif.",
    ),
    output: pathlib.Path = typer.Option(
        None, "--output", "-o", dir_okay=False, writable=True,
        help="Write the BOM here instead of stdout.",
    ),
) -> None:
    """Scan a repo and render a schema-validated BOM via the reporter registry."""
    if fmt not in available_formats():
        choices = ", ".join(available_formats())
        _eprint(f"format {fmt!r} not supported (choose: {choices}).")
        raise typer.Exit(code=2)

    try:
        result = scan_repo(path)
        payload = get_reporter(fmt).render(result)  # validates; raises on error
    except _EMIT_ERRORS as exc:
        _eprint(f"BUILD FAILURE: emitted {fmt} did not schema-validate.")
        _eprint(str(exc))
        raise typer.Exit(code=1) from exc

    _write(payload, output)
    if output is not None:
        _eprint(f"VALID -- wrote {output} ({fmt})")
    elif fmt != "sarif":
        _eprint(f"# advisory: {ADVISORY_DISCLAIMER}")


# --------------------------------------------------------------------------- #
# validate -- the schema gate (auto-detect format)
# --------------------------------------------------------------------------- #


@app.command()
def validate(
    bom: pathlib.Path = typer.Argument(
        ..., exists=True, dir_okay=False, readable=True,
        help="Path to a CycloneDX 1.6 / SPDX 3.0 / SARIF JSON file to validate.",
    ),
) -> None:
    """Schema-validate a BOM, auto-detecting the format. Exit 1 if not valid."""
    try:
        doc = json.loads(bom.read_text())
    except json.JSONDecodeError as exc:
        _eprint(f"INVALID: {bom} is not valid JSON: {exc}")
        raise typer.Exit(code=1) from exc

    fmt, errors = validate_auto(doc)
    if errors:
        label = fmt or "unknown format"
        _eprint(f"INVALID ({label}, {len(errors)} error(s)) -- {bom}:")
        for e in errors[:25]:
            _eprint(f"  - {e}")
        if len(errors) > 25:
            _eprint(f"  ... and {len(errors) - 25} more")
        raise typer.Exit(code=1)

    _eprint(f"VALID against {fmt} schema -- {bom}")


# --------------------------------------------------------------------------- #
# Phase-stubs
# --------------------------------------------------------------------------- #

_NOT_IMPLEMENTED = "not yet implemented in phase 1"


@app.command()
def map(  # noqa: A001 - 'map' is the documented subcommand name
    bom: pathlib.Path = typer.Argument(
        None, help="BOM to map to FDA / EU AI Act compliance."
    ),
) -> None:
    """Map a BOM to FDA §524B / EU AI Act Annex IV readiness. (stub, advisory)"""
    _eprint(f"map: {_NOT_IMPLEMENTED}")
    raise typer.Exit(code=0)


@app.command()
def discover(
    target: str = typer.Argument(
        None, help="Org / repo / container / cloud target to sweep for shadow AI."
    ),
) -> None:
    """Discover shadow AI (unsanctioned models/services) across a target. (stub)"""
    _eprint(f"discover: {_NOT_IMPLEMENTED}")
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
