"""SAST "Exclude path patterns" and IaC "Include path patterns" match the path inside the repository (#45, #37).

Both go through file_path_matches_pattern (helpers/context/codebase_context.py). It built a regular expression from a
pattern's names and searched it in the file's absolute path:
- #45: the worker clones and unzips into /tmp/repo_*, so Ruby's built-in "tmp" exclusion matched every file and a Ruby
  scan analysed none, reporting a clean result. "." was any character, so ".min.js" also skipped admin.js.
- #37: a pattern of three or more names lost its last name (["src", "vendor", "x.py"] skipped all of src/vendor), and
  names were regular expressions ("*.py" matched happy.txt; "**/*.yaml" raised re.error and failed the scan).
The tests write real files into a throw-away clone under /tmp/repo_* and load them the way a scan does
(CodebaseContext.load_documents_of_extension), then check which files are analysed.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if WORKER not in sys.path:
    sys.path.insert(0, WORKER)

from helpers.context.codebase_context import CodebaseContext, file_path_matches_pattern  # noqa: E402
from helpers.tools.iac_agent import main as iac_main  # noqa: E402
from helpers.tools.iac_agent.context import IACTypeContext  # noqa: E402
from helpers.tools.sast_agent import main as sast_main  # noqa: E402

LANGUAGES = ["python", "javascript", "java", "php", "c", "ruby", "rust", "swift", "csharp", "kotlin"]


@pytest.fixture
def clone():
    """Makes throw-away repositories in /tmp/<prefix>*, where the worker clones and unzips
    (helpers/context/scan_context.py); /tmp is named explicitly so the test does not depend on TMPDIR."""
    made: list[Path] = []

    def make(files: list[str], prefix: str = "repo_") -> Path:
        repo = Path(tempfile.mkdtemp(prefix=prefix, dir="/tmp"))
        made.append(repo)
        write(repo, files)
        return repo

    yield make
    for repo in made:
        shutil.rmtree(repo, ignore_errors=True)


def write(repo: Path, files: list[str] | set[str]) -> None:
    for rel in files:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text("x = 1\n")


def analysed(context: CodebaseContext, extensions: list[str]) -> set[str]:
    """The files the scan analyses, as paths inside the clone."""
    return {
        os.path.relpath(document.metadata["source"], context.directory)
        for ext in dict.fromkeys(extensions)
        for document in context.load_documents_of_extension(ext)
    }


def analysed_with(repo: Path, path: str, *, exclude=None, include=None) -> set[str]:
    ext = Path(path).suffix
    return analysed(CodebaseContext(directory=str(repo), include_files_extensions=[ext], exclude_path_arrays=exclude,
                                    include_path_arrays=include), [ext])


# (pattern, path inside the clone, whether the pattern matches the path)
CASES = [
    # #45: the clone's own folder (/tmp/repo_*) is not part of the path
    (["tmp"], "app/models/user.rb", False),
    (["repo_*"], "app/models/user.rb", False),
    (["tmp"], "tmp/cache/user.rb", True),
    (["tmp"], "app/tmp/user.rb", True),
    # #45: a dot is a dot; one name starting with a dot matches the names that end with it
    ([".min.js"], "src/routes/admin.js", False),
    ([".min.js"], "public/app.min.js", True),
    ([".egg-info"], "mypkg.egg-info/x.py", True),
    ([".venv"], ".venv/lib/x.py", True),
    ([".tf"], "infra/main.tf", True),
    # #37: every name counts
    (["src", "vendor", "x.py"], "src/vendor/x.py", True),
    (["src", "vendor", "x.py"], "src/vendor/y.py", False),
    (["deploy", "k8s", "prod"], "deploy/k8s/staging/app.yaml", False),
    # #37: names are literal apart from the * and ** globs
    (["*.py"], "happy.txt", False),
    (["*.py"], "pkg/main.py", True),
    (["**/*.yaml"], "charts/web/values.yaml", True),  # the old IaC placeholder, typed in one box
    (["**", "*.yaml"], "k8s/app.yml", False),
    (["src", "**", "*.py"], "src/a/b/c.py", True),
    (["src", "**", "*.py"], "src/c.py", True),
    (["src", "**", "*.py"], "lib/c.py", False),
    (["file.name"], "fileXname/a.py", False),
    (["[team_id]"], "app/[team_id]/page.js", True),
    (["[team_id]"], "app/t/page.js", False),
    (["a?c"], "abc/x.py", False),
    (["a?c"], "a?c/x.py", True),
    (["src/vendor"], "src/vendor/x.py", True),  # a box holding "a/b" is two names, as before
    # whole names only, at any depth
    (["vendor"], "vendors/x.php", False),
    (["build"], "scripts/build.py", False),
    (["env"], "migrations/env.py", False),
    (["src", "legacy"], "packages/a/src/legacy/x.py", True),
    (["src", "legacy"], "src/legacy_v1/x.py", False),
    # a pattern without a name matches nothing (it used to match every file)
    ([""], "app/x.py", False),
]


@pytest.mark.parametrize("pattern, path, matches", CASES)
def test_exclude_pattern(clone, pattern, path, matches):
    """SAST: a file the pattern matches is skipped, any other file is analysed."""
    assert analysed_with(clone([path]), path, exclude=[pattern]) == (set() if matches else {path})


@pytest.mark.parametrize("pattern, path, matches", CASES)
def test_include_pattern(clone, pattern, path, matches):
    """IaC: the same matcher decides which files are analysed."""
    assert analysed_with(clone([path]), path, include=[pattern]) == ({path} if matches else set())


def test_a_pattern_cannot_make_the_scan_hang():
    """Many * and ** in a pattern, on a deep path that does not match. A regular expression built from the pattern
    ("**" as (?:[^/]+/)*, "*" as [^/]*) backtracks: it was still running after 60 s on this input."""
    pattern = ["**", "a*a*a*a*a*a*a*a*a*a*b", "**"] * 6 + ["c"]
    path = "/".join(["a" * 60] * 40) + "/x.py"
    started = time.monotonic()
    assert file_path_matches_pattern(path, pattern) is False
    assert time.monotonic() - started < 2


@pytest.mark.parametrize("prefix, pattern, path", [
    ("repo_", ["tmp"], "app/models/user.rb"),  # Ruby's built-in exclusion (#45)
    # The clone folder's random name could hold a built-in exclusion too: ".vs" (C#) and ".m2" (Java) read as "any
    # character, then vs / m2", so about 1 scan in 200 of each language analysed no file.
    ("repo_avs", [".vs"], "src/Program.cs"),
    ("repo_km2", [".m2"], "src/Main.java"),
])
def test_the_clone_folder_is_not_part_of_the_path(clone, prefix, pattern, path):
    assert analysed_with(clone([path], prefix=prefix), path, exclude=[pattern]) == {path}


@pytest.mark.parametrize("app_lang", LANGUAGES)
def test_built_in_exclusions_with_the_clone_under_tmp(clone, monkeypatch, app_lang):
    """#45: every language's built-in exclusions, on a clone under /tmp. The language's source files are analysed and
    each built-in folder is skipped; a folder whose name only starts like one (build_old, venv_old) is analysed."""
    repo = clone([])
    monkeypatch.setattr(sast_main, "get_directory_from_zip_context", lambda _zip: str(repo))
    agent = sast_main.SASTAgent(zip_context=object(), app_lang=app_lang)
    (ext,) = agent.include_files_extensions
    kept, skipped = {f"app/models/user{ext}"}, set()
    for (name,) in agent.exclude_path_arrays:
        folder = name.replace("*", "debug")  # cmake-build-* -> cmake-build-debug
        skipped.add(f"{folder}/lib/x{ext}")
        if "*" not in name:
            kept.add(f"src/{name.lstrip('.')}_old/x{ext}")
    write(repo, kept | skipped)
    context = CodebaseContext(directory=agent.directory, include_files_extensions=agent.include_files_extensions,
                              exclude_path_arrays=agent.exclude_path_arrays)
    assert analysed(context, agent.include_files_extensions) == kept


def test_iac_terraform_and_k8s_patterns_with_the_clone_under_tmp(clone, monkeypatch):
    """The IaC agent merges Terraform's own patterns (.tf, .tfvars, ...) with the other formats' include patterns;
    a three-name pattern keeps its third name."""
    repo = clone(["infra/main.tf", "infra/prod.tfvars", "deploy/k8s/prod/app.yaml", "deploy/k8s/staging/app.yaml",
                  "deploy/k8s/prod-old/app.yaml"])
    monkeypatch.setattr(iac_main, "get_directory_from_zip_context", lambda _zip: str(repo))
    agent = iac_main.IACAgent(zip_context=object(), iac_contexts=[
        IACTypeContext(mode="terraform"),
        IACTypeContext(mode="k8s", include_path_arrays=[["deploy", "k8s", "prod"]]),
    ])
    context = CodebaseContext(directory=agent.directory, include_files_extensions=agent.include_files_extensions,
                              include_path_arrays=agent.include_path_arrays)
    assert analysed(context, agent.include_files_extensions) == {
        "infra/main.tf", "infra/prod.tfvars", "deploy/k8s/prod/app.yaml"}
