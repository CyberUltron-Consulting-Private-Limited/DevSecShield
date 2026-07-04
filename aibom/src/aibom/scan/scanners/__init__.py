"""Scanner package. Importing it self-registers every scanner. Adding a scanner
(or a scan level) is one module here — no special-casing (decision D4). The
pipeline runs scanners with ``scanner.level <= requested level``.
"""

from aibom.scan.scanners import (  # noqa: F401
    cloud_iac_scan,
    code_import_scan,
    docker_scan,
    live_cloud_scan,
    model_file_scan,
    model_graph_link,
    model_ref_scan,
    model_repo,
    net_env_scan,
    requirements,
    secret_scan,
)

__all__ = [
    "requirements",
    "code_import_scan",
    "model_repo",
    "model_file_scan",
    "model_ref_scan",
    "model_graph_link",
    "secret_scan",
    "docker_scan",
    "net_env_scan",
    "cloud_iac_scan",
    "live_cloud_scan",
]
