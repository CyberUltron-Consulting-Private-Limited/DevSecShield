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
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repo / model project directory to scan.",
    ),
    output: pathlib.Path = typer.Option(
        None,
        "--output",
        "-o",
        dir_okay=False,
        writable=True,
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
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repo / model project directory to scan and emit a BOM for.",
    ),
    fmt: str = typer.Option(
        "cyclonedx",
        "--format",
        "-f",
        help="BOM format: cyclonedx | spdx | sarif.",
    ),
    output: pathlib.Path = typer.Option(
        None,
        "--output",
        "-o",
        dir_okay=False,
        writable=True,
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


@app.command()
def cbom(
    path: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repository directory to scan. Nothing is installed there.",
    ),
    output: pathlib.Path = typer.Option(
        None,
        "--output",
        "-o",
        dir_okay=False,
        writable=True,
        help="Write the CycloneDX CBOM here instead of stdout.",
    ),
    no_fail: bool = typer.Option(
        False,
        "--no-fail",
        help="Exit 0 even when high findings are present.",
    ),
) -> None:
    """Scan a repository for cryptography and print a CycloneDX 1.6 CBOM.

    Exits 1 when a high finding is present (weak algorithm, ECB, weak key,
    hard-coded key, static IV, weak RNG, weak padding, disabled certificate
    verification, or a vulnerable crypto library). Reads only the tree and
    the shipped advisory file.
    """
    from aibom.cbom.gate import failing_flags
    from aibom.cbom.pipeline import scan_crypto
    from aibom.emit.cyclonedx import emit_cyclonedx

    result = scan_crypto(path, level=4)
    _write(json.dumps(emit_cyclonedx(result), indent=2) + "\n", output)
    failed = failing_flags(result.flags)
    if not failed:
        _eprint("# cbom: no high findings")
        return
    _eprint(f"# cbom: {len(failed)} high finding(s)")
    for flag in failed:
        _eprint(f"# {flag.code} {flag.message}")
    if not no_fail:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# validate -- the schema gate (auto-detect format)
# --------------------------------------------------------------------------- #


@app.command()
def validate(
    bom: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
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
    path: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repo / model project directory to scan and map to compliance.",
    ),
    framework: str = typer.Option(
        "all",
        "--framework",
        "-F",
        help="fda524b | euaiact | gmlp | hipaa | nist | all.",
    ),
    output: pathlib.Path = typer.Option(
        None,
        "--output",
        "-o",
        dir_okay=False,
        writable=True,
        help="Write the compliance JSON here instead of stdout.",
    ),
    indent: int = typer.Option(2, help="JSON indentation."),
) -> None:
    """Scan a repo and map its graph to advisory compliance readiness.

    Runs the graph-aware checks (CHECKS READ THE GRAPH, never flags) and reports
    {pass, fail, na} + coverage per framework. Mappings are ADVISORY only.
    """
    # Imported here so the engine sees every self-registered framework.
    import aibom.compliance as compliance
    from aibom.scan.pipeline import scan_repo

    result = scan_repo(path)
    full = compliance.run_all(result)
    if framework == "all":
        report = full
    else:
        try:
            fw = compliance.resolve_framework(framework)
        except KeyError as exc:
            _eprint(str(exc))
            raise typer.Exit(code=2) from exc
        report = {fw: full[fw], "disclaimer": full["disclaimer"]}

    _write(json.dumps(report, indent=indent) + "\n", output)
    # One-line readiness summary to stderr (stdout stays a clean payload).
    for fw in [k for k in report if k != "disclaimer"]:
        b = report[fw]
        cov = "N/A" if b["coverage"] is None else f"{b['coverage'] * 100:.0f}%"
        _eprint(
            f"# {fw}: pass={b['pass']} fail={b['fail']} na={b['na']} coverage={cov}"
        )
    _eprint(f"# advisory: {ADVISORY_DISCLAIMER}")


@app.command()
def report(
    path: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repo / model project directory to scan and report on.",
    ),
    fmt: str = typer.Option(
        "pdf",
        "--format",
        "-f",
        help="Deliverable: xlsx | pdf | docx.",
    ),
    output: pathlib.Path = typer.Option(
        None,
        "--output",
        "-o",
        dir_okay=False,
        writable=True,
        help="Output file (default: compliance.<ext>).",
    ),
) -> None:
    """Generate a client compliance deliverable from the scan's compliance report.

    xlsx = traceability matrix; pdf = readiness report; docx = SaMD/PCCP memo.
    All are ADVISORY and generated from ``ScanResult.compliance``.
    """
    import aibom.compliance as compliance
    from aibom.deliverables import available_formats, get_writer
    from aibom.scan.pipeline import scan_repo

    if fmt not in available_formats():
        choices = ", ".join(available_formats())
        _eprint(f"format {fmt!r} not supported (choose: {choices}).")
        raise typer.Exit(code=2)

    result = scan_repo(path)
    compliance.run_all(result)
    out = output or pathlib.Path(f"compliance.{fmt}")
    get_writer(fmt)(result.compliance, out, result.subject.name)
    _eprint(f"wrote {fmt} deliverable -> {out}")
    _eprint(f"# advisory: {ADVISORY_DISCLAIMER}")


@app.command()
def discover(
    root: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repo / project directory to sweep for shadow AI.",
    ),
    level: int = typer.Option(
        4,
        "--level",
        "-l",
        min=1,
        max=5,
        help="Scan depth: 1 filesystem, 2 docker, 3 net/env, 4 cloud IaC, 5 live.",
    ),
    allowlist: pathlib.Path = typer.Option(
        None,
        "--allowlist",
        "-a",
        exists=True,
        dir_okay=False,
        help="Allowlist YAML; discovered components not on it are flagged.",
    ),
    output: pathlib.Path = typer.Option(
        None,
        "--output",
        "-o",
        dir_okay=False,
        writable=True,
        help="Write the ScanResult JSON here (feeds the dashboard).",
    ),
    findings: pathlib.Path = typer.Option(
        None,
        "--findings",
        dir_okay=False,
        writable=True,
        help="Write a shadow-AI findings report (.xlsx or .pdf).",
    ),
) -> None:
    """Sweep a target across scan levels and flag unsanctioned shadow AI."""
    from aibom.scan.pipeline import scan_repo

    result = scan_repo(root, level=level, allowlist=allowlist)
    _write(json.dumps(result.to_dict(), indent=2) + "\n", output)

    discovered = [
        c
        for c in result.components
        if (c.properties or {}).get("discovery:source")
        or c.kind
        not in {"model", "dataset", "framework", "prompt", "service", "infra", "secret"}
    ]
    unsanctioned = [f for f in result.flags if f.code == "UNSANCTIONED_COMPONENT"]
    _eprint(
        f"# discovered {len(discovered)} AI component(s) at level {level}; "
        f"{len(unsanctioned)} UNSANCTIONED; risk={result.scores.get('risk_total', 0)}"
    )
    for f in unsanctioned:
        _eprint(f"#   UNSANCTIONED: {f.target}")

    if findings is not None:
        from aibom.deliverables.findings import write_findings

        write_findings(result, findings)
        _eprint(f"wrote findings report -> {findings}")
    _eprint(f"# advisory: {ADVISORY_DISCLAIMER}")


@app.command()
def cedar(
    root: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repo / project directory to scan and project into Cedar.",
    ),
    level: int = typer.Option(
        4,
        "--level",
        "-l",
        min=1,
        max=5,
        help="Discovery depth (same levels as `discover`).",
    ),
    allowlist: pathlib.Path = typer.Option(
        None,
        "--allowlist",
        "-a",
        exists=True,
        dir_okay=False,
        help="Allowlist YAML; sets each entity's `sanctioned` attribute.",
    ),
    output: pathlib.Path = typer.Option(
        pathlib.Path("entities.json"),
        "--output",
        "-o",
        dir_okay=False,
        writable=True,
        help="Write the Cedar entities JSON here.",
    ),
    policy: pathlib.Path = typer.Option(
        pathlib.Path("policies.cedar"),
        "--policy",
        "-p",
        dir_okay=False,
        writable=True,
        help="Write the sample Cedar policy set here.",
    ),
) -> None:
    """Project the inventory into Cedar entities + a sample runtime policy set.

    Thin, OPTIONAL governance layer: the BOM says what AI exists; Cedar governs
    what each component may do at runtime. Pure consumer of ``ScanResult``.
    """
    from aibom.governance.cedar import write_entities, write_policy
    from aibom.scan.pipeline import scan_repo

    result = scan_repo(root, level=level, allowlist=allowlist)
    write_entities(result, output)
    write_policy(policy)
    _eprint(
        f"wrote {len(result.components)} Cedar entities -> {output}; policy -> {policy}"
    )
    _eprint(f"# advisory: {ADVISORY_DISCLAIMER}")


@app.command()
def dashboard(
    root: pathlib.Path = typer.Argument(
        ...,
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        help="Repo / project directory to scan and visualize.",
    ),
    level: int = typer.Option(
        4,
        "--level",
        "-l",
        min=1,
        max=5,
        help="Discovery depth (see `discover`).",
    ),
    allowlist: pathlib.Path = typer.Option(
        None,
        "--allowlist",
        "-a",
        exists=True,
        dir_okay=False,
        help="Allowlist YAML for shadow-AI sanctioned/unsanctioned status.",
    ),
    output: pathlib.Path = typer.Option(
        pathlib.Path("dashboard-out"),
        "--output",
        "-o",
        file_okay=False,
        help="Output directory for the self-contained dashboard + scan.json.",
    ),
    open_browser: bool = typer.Option(
        False,
        "--open",
        help="Open the dashboard in the default browser.",
    ),
) -> None:
    """Scan + map a repo and emit a self-contained dashboard rendering it.

    Writes ``<output>/index.html`` (the SPA) and ``<output>/scan.json`` (a scored
    ScanResult WITH compliance). Open index.html via a static server (the SPA
    fetches the co-located scan.json). No localStorage; reload re-reads the file.
    """
    import importlib.resources as resources
    import shutil

    import aibom.compliance as compliance
    from aibom.scan.pipeline import scan_repo

    result = scan_repo(root, level=level, allowlist=allowlist)
    compliance.run_all(result)  # so the dashboard's compliance panel is populated

    output.mkdir(parents=True, exist_ok=True)
    (output / "scan.json").write_text(json.dumps(result.to_dict(), indent=2) + "\n")
    src_html = resources.files("aibom").joinpath("dashboard", "index.html")
    with resources.as_file(src_html) as html_path:
        shutil.copyfile(html_path, output / "index.html")

    index = output / "index.html"
    _eprint(
        f"wrote dashboard -> {index} (+ scan.json: {len(result.components)} "
        f"components, risk={result.scores.get('risk_normalized', 0)}/100 "
        f"{result.scores.get('risk_band', '')})"
    )
    _eprint(f"# serve it:  python -m http.server -d {output}  # then open :8000")
    if open_browser:
        import webbrowser

        webbrowser.open(index.resolve().as_uri())
    _eprint(f"# advisory: {ADVISORY_DISCLAIMER}")


if __name__ == "__main__":
    app()
