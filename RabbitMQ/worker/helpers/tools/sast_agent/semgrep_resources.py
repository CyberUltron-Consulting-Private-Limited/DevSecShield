"""Semgrep + worker resource tuning — default to all logical CPUs."""

from __future__ import annotations

import os


def _cpu_count() -> int:
    return max(os.cpu_count() or 4, 1)


def semgrep_job_count() -> str:
    """Parallel Semgrep subprocess count (-j)."""
    raw = os.getenv("SEMGREP_JOBS", "").strip()
    if raw in ("0", "auto"):
        return str(_cpu_count())
    return raw if raw else str(_cpu_count())


def semgrep_subprocess_timeout() -> int | None:
    """subprocess.run timeout seconds; 0/none = unlimited for large repos."""
    raw = os.getenv("SEMGREP_SUBPROCESS_TIMEOUT_SECONDS", "0").strip().lower()
    if raw in ("0", "", "none", "unlimited"):
        return None
    return int(raw)


def semgrep_rule_timeout_seconds() -> str:
    return os.getenv("SEMGREP_RULE_TIMEOUT_SECONDS", "30")


def semgrep_timeout_threshold() -> str:
    return os.getenv("SEMGREP_TIMEOUT_THRESHOLD", "0")


def semgrep_max_memory_mb() -> str | None:
    raw = os.getenv("SEMGREP_MAX_MEMORY_MB", "").strip()
    return raw if raw else None


def celery_worker_concurrency() -> int:
    raw = os.getenv("CELERY_WORKER_CONCURRENCY", "").strip()
    if raw:
        return max(int(raw), 1)
    return _cpu_count()


def semgrep_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    jobs = semgrep_job_count()
    env.setdefault("SEMGREP_TIMEOUT", semgrep_rule_timeout_seconds())
    for key in (
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "MKL_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
        "NUMEXPR_NUM_THREADS",
    ):
        env.setdefault(key, jobs)
    return env
