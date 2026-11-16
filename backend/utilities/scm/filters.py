"""Include / exclude rules for repositories: the import filters of a connection and the selector of a scan policy.

Evaluation is a pure function of the repository's metadata and the rules, checked in a FIXED order, and the first
rule that excludes a repository is the reason the inventory shows:

    archived -> fork -> visibility -> too_large -> excluded_name -> not_included_name -> excluded_topic
    -> missing_topic -> language

Names are matched case-insensitively with shell globs (``*``, ``?``, ``[ab]``) against both ``owner/name`` and the bare
name, so ``payments-*`` and ``acme/payments-*`` both work. Exclusions win over inclusions. A manual override on a
repository (``include`` / ``exclude``) wins over every rule.
"""
from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_RULES = 100
MAX_PATTERN = 200

_Pattern = Field(default_factory=list, max_length=MAX_RULES)


class RepoFilters(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    include_names: list[str] = _Pattern
    exclude_names: list[str] = _Pattern
    topics_any: list[str] = _Pattern
    exclude_topics: list[str] = _Pattern
    languages: list[str] = _Pattern
    include_archived: bool = False
    include_forks: bool = False
    visibility: list[Literal["public", "private", "internal"]] = Field(default_factory=list, max_length=3)
    max_size_mb: float | None = Field(default=None, ge=0, le=1_000_000)

    @field_validator("include_names", "exclude_names", "topics_any", "exclude_topics", "languages")
    @classmethod
    def _patterns(cls, values: list[str]) -> list[str]:
        out = []
        for value in values:
            text = str(value).strip()
            if not text:
                continue
            if len(text) > MAX_PATTERN or any(ord(ch) < 32 for ch in text):
                raise ValueError(f"each entry is at most {MAX_PATTERN} printable characters")
            out.append(text)
        return out


def parse(data: Mapping[str, Any] | None) -> RepoFilters:
    return RepoFilters.model_validate(dict(data or {}))


def _name_match(patterns: list[str], full_name: str, name: str) -> bool:
    full, bare = full_name.lower(), name.lower()
    for pattern in patterns:
        p = pattern.lower()
        if fnmatch.fnmatchcase(full, p) or fnmatch.fnmatchcase(bare, p):
            return True
    return False


def evaluate(repo: Mapping[str, Any], f: RepoFilters) -> tuple[bool, str]:
    """(in scope, reason). ``repo`` needs full_name, name, archived, fork, topics, language, visibility, size_kb."""
    full_name = str(repo.get("full_name") or "")
    name = str(repo.get("name") or full_name.rsplit("/", 1)[-1])
    topics = {str(t).lower() for t in (repo.get("topics") or [])}
    if repo.get("archived") and not f.include_archived:
        return False, "archived"
    if repo.get("fork") and not f.include_forks:
        return False, "fork"
    if f.visibility and str(repo.get("visibility") or "").lower() not in f.visibility:
        return False, "visibility"
    if f.max_size_mb is not None and int(repo.get("size_kb") or 0) > f.max_size_mb * 1024:
        return False, "too_large"
    if f.exclude_names and _name_match(f.exclude_names, full_name, name):
        return False, "excluded_name"
    if f.include_names and not _name_match(f.include_names, full_name, name):
        return False, "not_included_name"
    if f.exclude_topics and topics & {t.lower() for t in f.exclude_topics}:
        return False, "excluded_topic"
    if f.topics_any and not topics & {t.lower() for t in f.topics_any}:
        return False, "missing_topic"
    if f.languages and str(repo.get("language") or "").lower() not in {lang.lower() for lang in f.languages}:
        return False, "language"
    return True, "matched"


def in_scope(repo: Mapping[str, Any], f: RepoFilters, manual_state: str | None) -> tuple[bool, str]:
    if manual_state == "include":
        return True, "manual_include"
    if manual_state == "exclude":
        return False, "manual_exclude"
    return evaluate(repo, f)


REASONS = ("matched", "manual_include", "manual_exclude", "archived", "fork", "visibility", "too_large",
           "excluded_name", "not_included_name", "excluded_topic", "missing_topic", "language", "removed")

__all__ = ["REASONS", "RepoFilters", "evaluate", "in_scope", "parse"]
