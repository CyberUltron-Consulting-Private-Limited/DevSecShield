"""
SAST exclude / IaC include path patterns: what the backend checks and translates (the worker matches them,
RabbitMQ/worker/helpers/context/codebase_context.py file_path_matches_pattern).

Since #443 (PATH_PATTERN_VERSION 2) a pattern's names match whole folder or file names; "*" is any characters within a
name and a "**" name any number of folders. Before #443 a pattern's last name matched any name STARTING with it
("k8s" also matched "k8s-prod", "test" also "tests"). Scans started before #443 store no version, so "Run again"
translates their patterns to the glob that matches the same files ("k8s" -> "k8s*"), shown in the form, instead of
silently narrowing an IaC include or loosening a SAST exclude.
"""

import datetime

PATH_PATTERN_VERSION = 2

# When the glob meaning reached staging (#443 promoted by #442, Deploy staging run 44357285170 started 2026-11-18
# 17:18 UTC). A scan with no "path_pattern_v" started before this used the prefix meaning; one started after it
# (before the version marker existed) already used globs. Scans store the marker from now on.
GLOB_MEANING_SINCE = datetime.datetime(2026, 11, 18, 17, 18, tzinfo=datetime.timezone.utc)


def saved_with_prefix_meaning(meta: dict, started_at: datetime.datetime | None) -> bool:
    """Whether a scan's stored path patterns have the pre-#443 prefix meaning (no version, started before the glob
    meaning was deployed; a scan of unknown start time counts as old)."""
    if (meta or {}).get("path_pattern_v") == PATH_PATTERN_VERSION:
        return False
    if started_at is None:
        return True
    if started_at.tzinfo is None:  # DateTime columns hold UTC without a zone
        started_at = started_at.replace(tzinfo=datetime.timezone.utc)
    return started_at < GLOB_MEANING_SINCE


def pattern_names(pattern: list[str] | None) -> list[str]:
    """A pattern's names: one per box, a box holding "a/b" is two names; empty names are dropped (as the worker)."""
    return [name for box in (pattern or []) if isinstance(box, str) for name in box.strip().split("/") if name.strip()]


def matches_everything(pattern: list[str] | None) -> bool:
    """True for a pattern made only of "*" / "**" names: it matches every file of the repository."""
    names = pattern_names(pattern)
    return bool(names) and all(set(name) <= {"*"} for name in names)


def legacy_to_glob(pattern: list[str]) -> list[str]:
    """
    A pattern saved before #443, written with the version-2 meaning of what it matched then: its last name becomes a
    prefix ("infra" -> "infra*", ["deploy", "k8s"] -> ["deploy", "k8s*"]). Left as it is: a single ".ext" name (it
    already means "names ending with"), a last name already ending with "*", and a pattern without a name.
    """
    names = pattern_names(pattern)
    if not names or (len(names) == 1 and names[0].startswith(".")) or names[-1].endswith("*"):
        return list(pattern)
    return [*names[:-1], names[-1] + "*"]


def legacy_patterns_to_glob(patterns: list[list[str]] | None) -> list[list[str]] | None:
    return None if patterns is None else [legacy_to_glob(p) for p in patterns if isinstance(p, list)]


def check_excludes(patterns: list[list[str]] | None) -> None:
    """
    Refuse a SAST exclude that matches every file ("*", "**", "**/*"): the scan would analyse nothing and report a
    clean result. Raises ValueError (pydantic turns it into a 422 with this message).
    """
    for pattern in patterns or []:
        if matches_everything(pattern):
            raise ValueError(
                f"The exclude pattern {'/'.join(pattern_names(pattern))!r} matches every file, so nothing would be "
                "scanned. Remove it, or name the folders or files to skip (for example tests or *.min.js).")


def cicd_sast_excludes(sast_settings: dict) -> list[list[str]] | None:
    """
    The SAST excludes a CI/CD run uses, from the integration's saved settings. Settings saved before #443 carry no
    "path_pattern_v" (any save since writes it, SastScanSettingsData), so their excludes are translated to what they
    skipped then. Raises ValueError for an exclude matching every file (the run is refused with this message).
    """
    excludes = (sast_settings or {}).get("exclude_path_arrays")
    if excludes and (sast_settings or {}).get("path_pattern_v") != PATH_PATTERN_VERSION:
        excludes = legacy_patterns_to_glob(excludes)
    check_excludes(excludes)
    return excludes or None
