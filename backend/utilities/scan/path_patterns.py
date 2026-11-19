"""
SAST exclude / IaC include path patterns: what the backend checks and translates (the worker matches them,
RabbitMQ/worker/helpers/context/codebase_context.py file_path_matches_pattern).

Since #443 (PATH_PATTERN_VERSION 2) a pattern's names match whole folder or file names; "*" is any characters within a
name and a "**" name any number of folders. Before #443 a pattern's last name matched any name STARTING with it
("k8s" also matched "k8s-prod", "test" also "tests"). Patterns saved before store no version, so "Run again"
(and the CI/CD settings page and run) translates their patterns to the glob that matches the same files ("k8s" -> "k8s*"), shown in the form, instead of
silently narrowing an IaC include or loosening a SAST exclude.
"""

PATH_PATTERN_VERSION = 2


def saved_with_prefix_meaning(meta: dict | None) -> bool:
    """
    Whether stored path patterns have the pre-#443 prefix meaning: anything saved without "path_pattern_v". Scans,
    and CI/CD settings, store the version from #468 on. No deploy-time cutoff: a deployment gets #443 and #468
    together (production), and staging's scans of 18-19 Nov (#443 without the version, test data only) are read as
    old, which at worst widens a pattern by a trailing "*".
    """
    return (meta or {}).get("path_pattern_v") != PATH_PATTERN_VERSION


def pattern_names(pattern: list[str] | None) -> list[str]:
    """A pattern's names: one per box, a box holding "a/b" is two names; empty names are dropped (as the worker)."""
    return [name for box in (pattern or []) if isinstance(box, str) for name in box.strip().split("/") if name.strip()]


def matches_everything(pattern: list[str] | None) -> bool:
    """True for a pattern made only of "*" / "**" names: it matches every file of the repository."""
    names = pattern_names(pattern)
    return bool(names) and all(set(name) <= {"*"} for name in names)


def legacy_to_glob(pattern: list[str]) -> list[str]:
    """
    A pattern saved before #443, written as the version-2 glob matching the files it matched then. The old matcher
    (worker, before 1f81d634) built a regex from the boxes and searched the absolute path with it:
    - one box ".x": the bare text, anywhere -> "*.x*" (names containing ".x", e.g. ".tf" also matched prod.tfvars);
    - one box: "/" + box, so its last name was a prefix -> "infra" becomes "infra*", "deploy/k8s" ["deploy", "k8s*"];
    - two boxes: box1 + "/" + box2, unanchored, so the first name was also a suffix -> ["*deploy", "k8s*"];
    - three or more: the same over all boxes but the last, which the old code dropped -> [a, b, c] ["*a", "b*"].
    A slash at a box's edge counted too: a trailing one ended the last name, which had to be a folder ("src/" ->
    ["src", "*"]); a leading one anchored the first name; one that made "//" ("a//b", or a leading slash after the
    joining one) matched nothing -> [] (a pattern without a name).
    Regex meaning is not reproduced ("." is taken literally). A pattern without a name is left as it is.
    """
    boxes = [box.strip() for box in (pattern or []) if isinstance(box, str) and box.strip()]
    if not pattern_names(boxes):
        return list(pattern)
    if len(boxes) == 1 and boxes[0].startswith("."):
        text, anchored = boxes[0], False  # the bare text, anywhere
    else:
        used = boxes if len(boxes) <= 2 else boxes[:-1]
        # one box: a separator before it; two or more: joined by separators, unanchored
        text, anchored = ("/" + used[0], True) if len(boxes) == 1 else ("/".join(used), False)
    if "//" in text:
        return []  # the path never holds an empty name: the old pattern matched nothing
    names = pattern_names([text])
    if not anchored and not text.startswith("/") and not names[0].startswith("*"):
        names[0] = "*" + names[0]  # the first name's start was free: it also matched as a suffix
    if text.endswith("/"):
        names.append("*")  # the last name was whole and followed by at least one more name
    elif not names[-1].endswith("*"):
        names[-1] = names[-1] + "*"  # the last name was a prefix
    return names


def legacy_patterns_to_glob(patterns: list[list[str]] | None) -> list[list[str]] | None:
    return None if patterns is None else [legacy_to_glob(p) for p in patterns if isinstance(p, list)]


def check_excludes(patterns: list[list[str]] | None) -> None:
    """
    Refuse a SAST exclude that matches every file ("*", "**", "**/*"): the scan would analyse nothing and report a
    clean result. Raises ValueError (pydantic turns it into a 422 with this message).
    """
    for pattern in patterns or []:
        if matches_everything(pattern):
            shown = "/".join(pattern_names(pattern))
            raise ValueError(
                f'The exclude pattern "{shown}" matches every file, so nothing would be '
                "scanned. Remove it, or name the folders or files to skip (for example tests or *.min.js).")


def cicd_sast_excludes(sast_settings: dict) -> list[list[str]] | None:
    """
    The SAST excludes a CI/CD run uses, from the integration's saved settings. Settings saved before #443 carry no
    "path_pattern_v" (any save since writes it, SastScanSettingsData), so their excludes are translated to what they
    skipped then. Raises ValueError for an exclude matching every file (the run is refused with this message).
    """
    excludes = (sast_settings or {}).get("exclude_path_arrays")
    if excludes and saved_with_prefix_meaning(sast_settings):
        excludes = legacy_patterns_to_glob(excludes)
    check_excludes(excludes)
    return excludes or None


def cicd_settings_for_form(scan_settings: dict | None) -> dict:
    """
    An integration's saved scan settings as the settings page shows them: SAST excludes saved before #443 come back
    as the globs they meant ("test" -> "test*"), so saving the page (which records the version) keeps what the
    integration skipped instead of narrowing it. The stored row is not changed.
    """
    settings = dict(scan_settings or {})
    sast = settings.get("sast")
    if isinstance(sast, dict) and isinstance(sast.get("exclude_path_arrays"), list) and saved_with_prefix_meaning(sast):
        settings["sast"] = {**sast, "exclude_path_arrays": legacy_patterns_to_glob(sast["exclude_path_arrays"])}
    return settings
