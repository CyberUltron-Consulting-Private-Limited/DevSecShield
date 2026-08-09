#!/usr/bin/env python3
"""Hermetic SBOM inventory gate — true_misses() for frozen baselines."""
from __future__ import annotations

from diff import our_unique, true_misses


def gate_repo(repo_id: str) -> tuple[list[str], int]:
    return true_misses(repo_id), our_unique(repo_id)
