"""gunicorn hooks for the F1.1 bench (``-c bench/f1_node_api/gunicorn_bench.py``); bench only, never in an image.

``F1_BENCH_CAP_KIND=<kind>:<capability>``: jobs of that source kind need that node capability in this server (the
closed-window/capability scenarios L4 and E5 need a capability-gated kind; the product has none merged yet: F1.3 and
F1.4 add them).  A node that does not report the capability in ``capabilities.collectors`` is never hinted those jobs.
"""
import os


def post_worker_init(worker):  # noqa: ARG001 - gunicorn's hook signature
    spec = os.environ.get("F1_BENCH_CAP_KIND", "")
    if ":" in spec:
        kind, cap = spec.split(":", 1)
        from backend.utilities.cbom_sources import capabilities

        capabilities._BY_KIND[kind] = cap
