"""Scanner package. Importing it self-registers every scanner. Adding a scanner
(or a scan level) is one module here — no special-casing (decision D4). The
pipeline runs scanners with ``scanner.level <= requested level``.
"""

from aibom.scan.scanners import (  # noqa: F401
    cloud_iac_scan,
    docker_scan,
    live_cloud_scan,
    model_repo,
    net_env_scan,
    requirements,
    secret_scan,
)

__all__ = [
    "requirements",
    "model_repo",
    "docker_scan",
    "net_env_scan",
    "cloud_iac_scan",
    "live_cloud_scan",
    "secret_scan",
]
