"""CBOM verification waves (DEVILS-ADVOCATE.md §4.5) and their nightly run (CB-35).

``waves.yaml`` lists each wave: the paths that trigger it on a PR and the steps it runs.  This module

* ``select``  the waves a change triggers (``--base origin/dev`` diffs the checkout against it; §4.6 merge rule);
* ``plan``    the nightly order: the hermetic steps first (no stack), then the live steps in two stack.lock holds, each
              within ``hold_budget_min`` (§4.5: a nightly full run split over two lock holds);
* ``run``     every step, in that order, into ``<run>/waves/<wave>/<step>/`` (``output.log``) and ``results.json``;
* ``report``  ``report.json`` / ``report.md``: a verdict per step and wave, budgets, and what changed since the
              previous nightly (new failures, fixes);
* ``issues``  one draft per NEW failure with its evidence set (command, SHA, exit, duration, log and its sha256, the
              log's tail; command and tail scrubbed of secrets); ``--file`` files them with ``gh issue create``, only when asked.

Verdicts: PASS (exit 0), FAIL (non-zero exit, or killed at twice the step's budget), NOT-RUN (a need is missing on
this machine, with the reason).  NOT-RUN is never a pass: a wave is PASS only when every step passed, INCOMPLETE when
nothing failed but a step did not run, FAIL otherwise.  The exit code is 1 when a step FAILED, 0 otherwise; a
nightly where everything was NOT-RUN says so in its report rather than in its exit code.

Like the rest of the harness this imports nothing from the product (backend/tests/test_cbom_e2e_harness.py); the
steps run the product's own suites as commands.
"""
from __future__ import annotations

import argparse
import fcntl
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .redact import scrub_text
from .rundir import iso, read_json, sha256_file, utc_now, write_json, write_text

CBOM = Path(__file__).resolve().parents[1]
WAVES_FILE = CBOM / "waves.yaml"
PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT-RUN"
INCOMPLETE = "INCOMPLETE"
TAIL_LINES = 60
DEFAULT_BACKEND_PYTEST = "cd backend && PYTHONPATH={repo} python3 -m pytest -q -p no:cacheprovider -o addopts="
DEFAULT_NODE_PYTEST = "cd scan_node && python3 -m pytest -q -p no:cacheprovider -o addopts="


class PlanError(ValueError):
    """waves.yaml does not describe a runnable nightly (a wave in no hold or two, a hold over its budget ...)."""


@dataclass
class Step:
    wave: str
    id: str
    run: str
    needs: list[str] = field(default_factory=list)
    live: bool = False
    budget_min: float = 10
    title: str = ""

    @property
    def key(self) -> str:
        return f"{self.wave}/{self.id}"


@dataclass
class Wave:
    id: str
    title: str
    paths: list[str]
    steps: list[Step]


@dataclass
class Config:
    hold_budget_min: float
    holds: dict[str, list[str]]
    waves: dict[str, Wave]


@dataclass
class StepResult:
    wave: str
    step: str
    verdict: str
    reason: str = ""
    command: str = ""
    live: bool = False
    hold: str | None = None
    exit: int | None = None
    started: str | None = None
    duration_s: float = 0.0
    budget_s: float = 0.0
    over_budget: bool = False
    log: str | None = None
    log_sha256: str | None = None


# ----------------------------------------------------------------------------- waves.yaml
def load(path: Path = WAVES_FILE) -> Config:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    waves: dict[str, Wave] = {}
    for wave_id, body in (data.get("waves") or {}).items():
        steps = []
        seen: set[str] = set()
        for raw in body.get("steps") or []:
            if raw["id"] in seen:
                raise PlanError(f"{wave_id}: step {raw['id']} is listed twice")
            seen.add(raw["id"])
            steps.append(Step(wave=wave_id, id=str(raw["id"]), run=str(raw["run"]), needs=list(raw.get("needs") or []),
                              live=bool(raw.get("live", False)), budget_min=float(raw.get("budget_min", 10)),
                              title=str(raw.get("title") or "")))
        if not steps:
            raise PlanError(f"{wave_id} has no steps")
        waves[wave_id] = Wave(wave_id, str(body.get("title") or ""), list(body.get("paths") or []), steps)
    holds = {str(k): list(v) for k, v in (data.get("holds") or {}).items()}
    return Config(float(data.get("hold_budget_min", 90)), holds, waves)


# ----------------------------------------------------------------------------- select (PR trigger)
def _braces(pattern: str) -> list[str]:
    match = re.search(r"\{([^{}]*)\}", pattern)
    if not match:
        return [pattern]
    return [p for option in match.group(1).split(",")
            for p in _braces(pattern[:match.start()] + option + pattern[match.end():])]


def glob_regex(pattern: str) -> re.Pattern:
    """A path glob as a regex: ``**/`` any directories (or none), ``**`` anything, ``*`` within one segment,
    ``{a,b}`` either.  Matches the whole repository-relative path."""
    out = []
    for option in _braces(pattern):
        text, i = "", 0
        while i < len(option):
            if option.startswith("**/", i):
                text, i = text + "(?:.*/)?", i + 3
            elif option.startswith("**", i):
                text, i = text + ".*", i + 2
            elif option[i] == "*":
                text, i = text + "[^/]*", i + 1
            elif option[i] == "?":
                text, i = text + "[^/]", i + 1
            else:
                text, i = text + re.escape(option[i]), i + 1
        out.append(text)
    return re.compile("^(?:" + "|".join(out) + ")$")


def select(paths: list[str], config: Config) -> list[str]:
    """The waves the changed ``paths`` trigger (§4.5), in waves.yaml order."""
    out = []
    for wave in config.waves.values():
        regexes = [glob_regex(p) for p in wave.paths]
        if any(r.match(path) for r in regexes for path in paths):
            out.append(wave.id)
    return out


def changed_paths(base: str, repo: Path) -> list[str]:
    proc = subprocess.run(["git", "-C", str(repo), "diff", "--name-only", f"{base}...HEAD"], capture_output=True,
                          text=True, check=True)
    return [line for line in proc.stdout.splitlines() if line.strip()]


# ----------------------------------------------------------------------------- plan (nightly order)
def plan(config: Config, waves: list[str] | None = None) -> dict[str, Any]:
    """{"hermetic": [Step], "holds": {name: [Step]}} for ``waves`` (default: all).  Raises PlanError when a wave is in
    no hold or in two, a hold names an unknown wave, or a hold's live steps exceed ``hold_budget_min``."""
    held: dict[str, str] = {}
    for hold, members in config.holds.items():
        for wave in members:
            if wave not in config.waves:
                raise PlanError(f"hold {hold} names an unknown wave {wave}")
            if wave in held:
                raise PlanError(f"{wave} is in holds {held[wave]} and {hold}")
            held[wave] = hold
    missing = [w for w in config.waves if w not in held]
    if missing:
        raise PlanError(f"in no hold: {', '.join(missing)}")
    wanted = list(config.waves) if waves is None else [w for w in config.waves if w in set(waves)]
    unknown = sorted(set(waves or []) - set(config.waves))
    if unknown:
        raise PlanError(f"unknown waves: {', '.join(unknown)}")
    out: dict[str, Any] = {"hermetic": [], "holds": {hold: [] for hold in config.holds}}
    for wave in wanted:
        for step in config.waves[wave].steps:
            (out["holds"][held[wave]] if step.live else out["hermetic"]).append(step)
    for hold in config.holds:  # the budget is the hold's whether or not every wave runs tonight
        minutes = sum(s.budget_min for w in config.holds[hold] for s in config.waves[w].steps if s.live)
        if minutes > config.hold_budget_min:
            raise PlanError(f"hold {hold}: live steps take {minutes:g} min, over the {config.hold_budget_min:g}-min hold")
    return out


# ----------------------------------------------------------------------------- needs
def _r6() -> Path:
    return Path(os.environ.get("R6", "/home/claude/round6"))


def _python_has(modules: str, python: str = "python3") -> bool:
    exe = shutil.which(python)
    if not exe:
        return False
    proc = subprocess.run([exe, "-c", f"import {modules}"], capture_output=True, timeout=60)
    return proc.returncode == 0


def _probe(name: str, ctx: "Context") -> str | None:
    """None when the need is met, else why not (shown in the report)."""
    env = os.environ
    if name == "backend-py":
        if env.get("CBOM_WAVES_BACKEND_PYTEST") or _python_has("fastapi, sqlmodel, pytest"):
            return None
        return "no Python with the backend's packages (set CBOM_WAVES_BACKEND_PYTEST)"
    if name == "node-py":
        if env.get("CBOM_WAVES_NODE_PYTEST") or _python_has("paramiko, httpx, pytest"):
            return None
        return "no Python with the scan node's packages (set CBOM_WAVES_NODE_PYTEST)"
    if name == "aibom-venv":
        return None if (ctx.repo / "aibom" / ".venv" / "bin" / "python").exists() else "aibom/.venv is not installed"
    if name in ("openssl", "docker"):
        if not shutil.which(name):
            return f"{name} is not installed"
        if name == "docker" and subprocess.run(["docker", "info"], capture_output=True, timeout=60).returncode != 0:
            return "docker is installed but not usable here"
        return None
    if name == "softhsm":
        libs = ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
        return None if shutil.which("softhsm2-util") and any(os.path.isfile(p) for p in libs) else "SoftHSM2 is not installed"
    if name == "stack":  # a Tier-L host: run-gate.sh restacks it to the SHA inside the hold
        local = _r6() / "local"
        if not (local / "STACK.md").is_file() or not (local / "restack.sh").is_file():
            return f"no Tier-L stack here ({local}/STACK.md and restack.sh)"
        return None
    if name == "chromium":
        return None if (_r6() / "local" / "pw" / "browsers").is_dir() else "no Playwright Chromium in $R6/local/pw"
    if name == "lab":
        return None if (ctx.repo / "e2e" / "cbom" / "lab" / "gen.py").is_file() else "no CB-02 lab (e2e/cbom/lab/gen.py)"
    if name.startswith("lab-wave:"):
        wave = name.split(":", 1)[1]
        gen = ctx.repo / "e2e" / "cbom" / "lab" / "gen.py"
        text = gen.read_text(encoding="utf-8", errors="replace") if gen.is_file() else ""
        return None if "--wave" in text and wave in text else f"the CB-02 lab has no {wave} targets yet (gen.py --wave)"
    if name == "release-dump":
        dump = env.get("CBOM_WAVES_RELEASE_DUMP")
        if not dump or not os.path.isfile(dump) or not env.get("CBOM_WAVES_UPGRADE_PG_URL"):
            return "no previous-release dump (CBOM_WAVES_RELEASE_DUMP and CBOM_WAVES_UPGRADE_PG_URL)"
        return None
    if name == "release-node-image":
        return None if env.get("CBOM_WAVES_RELEASE_NODE_IMAGE") else "no previous-release node image (CBOM_WAVES_RELEASE_NODE_IMAGE)"
    if name == "oa-4":
        return None if env.get("CBOM_WAVES_TIER_A") == "1" else "Tier A needs OA-4 (the owner's AWS sandbox)"
    if name.startswith("file:"):
        rel = name.split(":", 1)[1]
        return None if (ctx.repo / rel).exists() else f"{rel} is not on this SHA"
    return f"unknown need {name!r}"


# ----------------------------------------------------------------------------- run
@dataclass
class Context:
    repo: Path
    run_dir: Path
    sha: str
    hermetic: bool = False  # live steps are NOT-RUN (a GitHub-hosted runner, no Tier-L stack)
    lock: Path | None = None
    lock_wait_s: float = 4 * 3600
    probe: Callable[[str, "Context"], str | None] = _probe
    placeholders: dict[str, str] = field(default_factory=dict)


def _command(step: Step, ctx: Context, step_dir: Path) -> str:
    values = {
        "repo": shlex.quote(str(ctx.repo)), "run": shlex.quote(str(ctx.run_dir)), "sha": shlex.quote(ctx.sha),
        "step_dir": shlex.quote(str(step_dir)),
        "backend_pytest": os.environ.get("CBOM_WAVES_BACKEND_PYTEST") or DEFAULT_BACKEND_PYTEST,
        "node_pytest": os.environ.get("CBOM_WAVES_NODE_PYTEST") or DEFAULT_NODE_PYTEST,
        **ctx.placeholders,
    }
    text = step.run
    for _ in range(2):  # a pytest command may itself name {repo}
        text = re.sub(r"\{(\w+)\}", lambda m: values.get(m.group(1), m.group(0)), text)
    return text


def run_step(step: Step, ctx: Context, hold: str | None = None) -> StepResult:
    step_dir = ctx.run_dir / "waves" / step.wave / step.id
    step_dir.mkdir(parents=True, exist_ok=True)
    command = _command(step, ctx, step_dir)
    result = StepResult(step.wave, step.id, NOT_RUN, command=command, live=step.live, hold=hold,
                        budget_s=step.budget_min * 60)
    if step.live and ctx.hermetic:
        result.reason = "hermetic run: live steps run on the Tier-L host (run-waves.sh)"
        return result
    missing = [f"{need}: {why}" for need in step.needs if (why := ctx.probe(need, ctx))]
    if missing:
        result.reason = "; ".join(missing)
        return result
    log = step_dir / "output.log"
    started = time.monotonic()
    result.started = iso(utc_now())
    with open(log, "wb") as out:
        env = dict(os.environ)
        if step.live and ctx.lock is not None:  # run-gate.sh must not wait for the hold this step runs inside
            env["CBOM_STACK_LOCK_HELD"] = "1"
        proc = subprocess.Popen(["bash", "-c", command], cwd=ctx.repo, stdout=out, stderr=subprocess.STDOUT,
                                start_new_session=True, env=env)
        try:
            result.exit = proc.wait(timeout=2 * result.budget_s)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, 9)
            proc.wait()
            result.exit = None
    result.duration_s = round(time.monotonic() - started, 1)
    result.over_budget = result.duration_s > result.budget_s
    result.log = str(log.relative_to(ctx.run_dir))
    result.log_sha256 = sha256_file(log)
    if result.exit is None:
        result.verdict, result.reason = FAIL, f"killed after {2 * result.budget_s:.0f} s (twice its budget)"
    elif result.exit == 0:
        result.verdict = PASS
    else:
        result.verdict, result.reason = FAIL, f"exit {result.exit}"
    return result


class _Hold:
    """One stack.lock hold (flock), as run-gate.sh takes it; released between the holds."""

    def __init__(self, path: Path | None, wait_s: float):
        self.path, self.wait_s, self.fh = path, wait_s, None
        self.waited_s = 0.0

    def __enter__(self) -> "_Hold":
        if self.path is None:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a")
        started = time.monotonic()
        while True:
            try:
                fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() - started > self.wait_s:
                    self.fh.close()
                    raise TimeoutError(f"{self.path} was held for more than {self.wait_s:.0f} s")
                time.sleep(5)
        self.waited_s = round(time.monotonic() - started, 1)
        return self

    def __exit__(self, *exc) -> None:
        if self.fh is not None:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()


def run(config: Config, ctx: Context, waves: list[str] | None = None, mode: str = "nightly") -> dict[str, Any]:
    """Every planned step: hermetic ones first, then each hold's live steps inside one stack.lock hold."""
    order = plan(config, waves)
    started = iso(utc_now())
    results: list[StepResult] = [run_step(step, ctx) for step in order["hermetic"]]
    holds: list[dict[str, Any]] = []
    for name, steps in order["holds"].items():
        if not steps:
            continue
        live = [s for s in steps if not (ctx.hermetic or any(ctx.probe(n, ctx) for n in s.needs))]
        record: dict[str, Any] = {"hold": name, "steps": [s.key for s in steps], "taken": False}
        if not live:  # nothing can run: never take the lock for nothing
            results += [run_step(step, ctx, hold=name) for step in steps]
        else:
            t0 = time.monotonic()
            try:
                with _Hold(ctx.lock, ctx.lock_wait_s) as hold:
                    record.update(taken=True, waited_s=hold.waited_s)
                    results += [run_step(step, ctx, hold=name) for step in steps]
            except TimeoutError as exc:
                results += [StepResult(s.wave, s.id, NOT_RUN, reason=str(exc), live=True, hold=name,
                                       budget_s=s.budget_min * 60) for s in steps]
            record["held_s"] = round(time.monotonic() - t0, 1)
        holds.append(record)
    data = {"sha": ctx.sha, "mode": mode, "started": started, "finished": iso(utc_now()),
            "hermetic": ctx.hermetic, "waves": waves or list(config.waves), "holds": holds,
            "hold_budget_min": config.hold_budget_min, "results": [asdict(r) for r in results]}
    write_json(ctx.run_dir / "results.json", data)
    return data


# ----------------------------------------------------------------------------- report
def wave_verdicts(results: list[dict[str, Any]]) -> dict[str, str]:
    by_wave: dict[str, list[str]] = {}
    for r in results:
        by_wave.setdefault(r["wave"], []).append(r["verdict"])
    out = {}
    for wave, verdicts in by_wave.items():
        out[wave] = FAIL if FAIL in verdicts else (PASS if all(v == PASS for v in verdicts) else INCOMPLETE)
    return out


def _key(r: dict[str, Any]) -> str:
    return f"{r['wave']}/{r['step']}"


def previous_run(root: Path, current: Path) -> Path | None:
    """The latest other run under ``root`` that has a results.json (runs are named so they sort by time)."""
    runs = sorted(p for p in Path(root).iterdir() if p.is_dir() and p != current and (p / "results.json").is_file()) \
        if Path(root).is_dir() else []
    return runs[-1] if runs else None


def report(run_dir: Path, previous: Path | None = None) -> dict[str, Any]:
    data = read_json(run_dir / "results.json")
    if data is None:
        raise FileNotFoundError(f"{run_dir}/results.json: run the waves first")
    results = data["results"]
    before = {_key(r): r["verdict"] for r in (read_json(previous / "results.json", {}) or {}).get("results", [])} \
        if previous else {}
    new_failures = [_key(r) for r in results if r["verdict"] == FAIL and before.get(_key(r)) != FAIL]
    fixed = [_key(r) for r in results if r["verdict"] == PASS and before.get(_key(r)) == FAIL]
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in (PASS, FAIL, NOT_RUN)}
    out = {"sha": data["sha"], "mode": data["mode"], "started": data["started"], "finished": data["finished"],
           "hermetic": data["hermetic"], "counts": counts, "waves": wave_verdicts(results),
           "new_failures": new_failures, "fixed": fixed, "previous": str(previous) if previous else None,
           "holds": data["holds"], "verdict": FAIL if counts[FAIL] else (PASS if counts[NOT_RUN] == 0 else INCOMPLETE)}
    write_json(run_dir / "report.json", out)
    lines = [f"# CBOM nightly waves on {data['sha'][:12]} ({data['mode']})", "",
             f"{data['started']} to {data['finished']}; {'hermetic (live steps not run)' if data['hermetic'] else 'Tier L'}"
             f". Verdict **{out['verdict']}**: {counts[PASS]} passed, {counts[FAIL]} failed, {counts[NOT_RUN]} not run.",
             "", "| Wave | Verdict |", "|---|---|"]
    lines += [f"| {w} | {v} |" for w, v in out["waves"].items()]
    lines += ["", "| Step | Verdict | Time / budget | Hold | Reason | Log |", "|---|---|---|---|---|---|"]
    for r in results:
        timing = f"{r['duration_s']:.0f} s / {r['budget_s']:.0f} s" + (" (over)" if r["over_budget"] else "")
        lines.append(f"| {_key(r)} | {r['verdict']} | {timing} | {r['hold'] or '-'} | {r['reason'] or ''} | "
                     f"{r['log'] or '-'} |")
    lines += ["", "## Lock holds", ""]
    lines += [f"* {h['hold']}: {'taken' if h['taken'] else 'not taken (nothing could run)'}"
              + (f", waited {h.get('waited_s', 0):.0f} s, held {h.get('held_s', 0):.0f} s" if h["taken"] else "")
              + f" ({', '.join(h['steps'])})" for h in data["holds"]] or ["* none"]
    lines += ["", "## Since the previous nightly", "",
              f"Previous: {previous.name if previous else 'none'}.",
              "New failures: " + (", ".join(new_failures) or "none") + ".",
              "Fixed: " + (", ".join(fixed) or "none") + "."]
    write_text(run_dir / "report.md", "\n".join(lines) + "\n")
    return out


# ----------------------------------------------------------------------------- issues
def issues(run_dir: Path, file: bool = False, repo_slug: str | None = None,
           runner: Callable[..., Any] = subprocess.run) -> list[Path]:
    """A draft per new failure, with its evidence set.  ``file``: also ``gh issue create`` each (explicit only)."""
    rep = read_json(run_dir / "report.json")
    data = read_json(run_dir / "results.json")
    if rep is None or data is None:
        raise FileNotFoundError(f"{run_dir}: run and report first")
    by_key = {_key(r): r for r in data["results"]}
    drafts = []
    for key in rep["new_failures"]:
        r = by_key[key]
        log = run_dir / r["log"] if r["log"] else None
        tail = ""
        if log and log.is_file():
            tail = "\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-TAIL_LINES:])
        title = f"CBOM nightly wave {key} fails on {data['sha'][:12]}"
        body = "\n".join([
            f"**{title}** (CB-35 nightly, {rep['started']}).", "",
            "| Evidence | Value |", "|---|---|",
            f"| SHA | `{data['sha']}` |", f"| Wave / step | `{key}` |", f"| Command | `{scrub_text(r['command'])}` |",
            f"| Result | {r['verdict']}: {r['reason']} |", f"| Duration / budget | {r['duration_s']:.0f} s / {r['budget_s']:.0f} s |",
            f"| Log | `{r['log']}` (sha256 `{r['log_sha256']}`) in the nightly bundle `{run_dir.name}` |",
            f"| Previous nightly | {rep['previous'] or 'none'} |", "",
            f"Last {TAIL_LINES} lines of the log (secrets scrubbed):", "", "```", scrub_text(tail), "```", "",
            "Expected: the step passes (exit 0). Reproduce: run the command above from the repository root on this SHA.",
        ])
        path = write_text(run_dir / "issues" / f"{key.replace('/', '--')}.md", body + "\n")
        drafts.append(path)
        if file:
            cmd = ["gh", "issue", "create", "--title", title, "--body-file", str(path)]
            if repo_slug:
                cmd += ["--repo", repo_slug]
            runner(cmd, check=True)
    return drafts


# ----------------------------------------------------------------------------- CLI
def _repo() -> Path:
    return Path(subprocess.run(["git", "-C", str(CBOM), "rev-parse", "--show-toplevel"], capture_output=True,
                               text=True, check=True).stdout.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python3 -m harness.waves", description=__doc__.split("\n")[0])
    parser.add_argument("--waves-file", type=Path, default=WAVES_FILE)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_sel = sub.add_parser("select", help="the waves the changed paths trigger")
    p_sel.add_argument("--base", help="diff the checkout against this ref (e.g. origin/dev)")
    p_sel.add_argument("paths", nargs="*")
    sub.add_parser("plan", help="the nightly order and lock holds")
    p_run = sub.add_parser("run", help="run the waves into a run directory, then report")
    p_run.add_argument("run_dir", type=Path)
    p_run.add_argument("--sha", required=True)
    p_run.add_argument("--waves", help="comma-separated (default: all)")
    p_run.add_argument("--mode", default="nightly", choices=["nightly", "pr"])
    p_run.add_argument("--hermetic", action="store_true", help="no Tier-L stack: live steps are NOT-RUN")
    p_run.add_argument("--lock", type=Path, help="stack.lock to hold around each hold's live steps")
    p_run.add_argument("--previous", type=Path, help="the previous nightly run (default: latest beside run_dir)")
    p_rep = sub.add_parser("report")
    p_rep.add_argument("run_dir", type=Path)
    p_rep.add_argument("--previous", type=Path)
    p_iss = sub.add_parser("issues", help="drafts for new failures (and --file to open them)")
    p_iss.add_argument("run_dir", type=Path)
    p_iss.add_argument("--file", action="store_true")
    p_iss.add_argument("--repo")
    args = parser.parse_args(argv)
    config = load(args.waves_file)
    if args.cmd == "select":
        paths = list(args.paths) + (changed_paths(args.base, _repo()) if args.base else [])
        print("\n".join(select(paths, config)))
        return 0
    if args.cmd == "plan":
        order = plan(config)
        print("hermetic: " + ", ".join(s.key for s in order["hermetic"]))
        for hold, steps in order["holds"].items():
            minutes = sum(s.budget_min for s in steps)
            print(f"hold {hold} ({minutes:g} of {config.hold_budget_min:g} min): " + ", ".join(s.key for s in steps))
        return 0
    if args.cmd == "run":
        args.run_dir.mkdir(parents=True, exist_ok=True)
        ctx = Context(repo=_repo(), run_dir=args.run_dir.resolve(), sha=args.sha, hermetic=args.hermetic, lock=args.lock)
        run(config, ctx, args.waves.split(",") if args.waves else None, args.mode)
        previous = args.previous or previous_run(args.run_dir.resolve().parent, args.run_dir.resolve())
        out = report(args.run_dir, previous)
        print((args.run_dir / "report.md").read_text(encoding="utf-8"))
        return 1 if out["counts"][FAIL] else 0
    if args.cmd == "report":
        out = report(args.run_dir, args.previous or previous_run(args.run_dir.resolve().parent, args.run_dir.resolve()))
        return 1 if out["counts"][FAIL] else 0
    if args.cmd == "issues":
        for path in issues(args.run_dir, file=args.file, repo_slug=args.repo):
            print(path)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
