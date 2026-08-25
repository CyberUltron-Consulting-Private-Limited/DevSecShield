from dataclasses import dataclass
import os


def _bounded_int(name: str, default: int, lo: int = 1, hi: int = 32) -> int:
    raw = os.getenv(name)
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return max(lo, min(int(raw), hi))
    except ValueError:
        return default


@dataclass(frozen=True)
class ScanRuntime:
    """URL-worker counts: slow=2, medium=5, fast=10.

    Every speed runs headers, Nuclei fetch, page analysis, XSS, and SQLi.
    XSS and SQLi always run side by side. Nuclei slots = 2x URL workers so
    both injection agents can hold a Chrome at once.
    Override with DAST_URL_WORKERS / DAST_NUCLEI_CONCURRENCY if needed.
    """

    interval_between_requests: float
    url_workers: int
    check_workers: int
    exploit_retries: int
    validation_retries: int
    skip_injection_if_no_surface: bool
    nuclei_timeout_seconds: int
    http_timeout_seconds: int
    llm_timeout_seconds: int
    nuclei_concurrency: int

    @classmethod
    def from_speed(cls, speed: str | None) -> "ScanRuntime":
        key = (speed or "medium").strip().lower()
        if key == "fast":
            url_workers = _bounded_int("DAST_URL_WORKERS", 10)
            return cls(
                interval_between_requests=0,
                url_workers=url_workers,
                check_workers=2,
                exploit_retries=1,
                validation_retries=1,
                skip_injection_if_no_surface=False,
                nuclei_timeout_seconds=60,
                http_timeout_seconds=15,
                llm_timeout_seconds=90,
                nuclei_concurrency=_bounded_int("DAST_NUCLEI_CONCURRENCY", url_workers * 2),
            )
        if key == "slow":
            url_workers = _bounded_int("DAST_URL_WORKERS", 2)
            return cls(
                interval_between_requests=0,
                url_workers=url_workers,
                check_workers=2,
                exploit_retries=2,
                validation_retries=2,
                skip_injection_if_no_surface=False,
                nuclei_timeout_seconds=180,
                http_timeout_seconds=30,
                llm_timeout_seconds=180,
                nuclei_concurrency=_bounded_int("DAST_NUCLEI_CONCURRENCY", url_workers * 2),
            )
        url_workers = _bounded_int("DAST_URL_WORKERS", 5)
        return cls(
            interval_between_requests=0,
            url_workers=url_workers,
            check_workers=2,
            exploit_retries=1,
            validation_retries=1,
            skip_injection_if_no_surface=False,
            nuclei_timeout_seconds=90,
            http_timeout_seconds=20,
            llm_timeout_seconds=120,
            nuclei_concurrency=_bounded_int("DAST_NUCLEI_CONCURRENCY", url_workers * 2),
        )
