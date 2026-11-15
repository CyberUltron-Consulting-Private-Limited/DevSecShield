"""#208 / #209 on the scan node: a vault-held kubeconfig is only checked here, so the node refuses what the save refuses
(a context the kubeconfig does not have, a proxy-url it would ignore) instead of silently using something else."""
from __future__ import annotations

import time

import pytest
import yaml

from zs_scan_node.collectors import ConfigError
from zs_scan_node.collectors import kubernetes as K
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber


def _kc(cluster_extra=None) -> str:
    return yaml.safe_dump({
        "clusters": [{"name": "c-prod", "cluster": {"server": "https://k8s.lab:6443", **(cluster_extra or {})}},
                     {"name": "c-dev", "cluster": {"server": "https://k8s-dev.lab:6443"}}],
        "users": [{"name": "u", "user": {"token": "tok-not-real-123"}}],
        "contexts": [{"name": "prod", "context": {"cluster": "c-prod", "user": "u"}},
                     {"name": "dev", "context": {"cluster": "c-dev", "user": "u"}}],
        "current-context": "dev"})


def _api(config: dict, kubeconfig: str):
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="kubernetes", scrubber=Scrubber(),
                     never_scan=NeverScan(), deadline=time.monotonic() + 60)
    return K.Api(ctx, {"api_url": "https://k8s.lab:6443", **config}, {"kubeconfig": kubeconfig})


def test_an_unknown_context_is_refused_not_replaced_by_the_current_context():
    with pytest.raises(ConfigError, match="context 'no-such-context' is not in the kubeconfig; its contexts are prod, dev"):
        _api({"context": "no-such-context"}, _kc())


def test_a_known_context_and_a_blank_one_still_work():
    _api({"context": "prod"}, _kc())
    _api({}, _kc())


def test_a_proxy_url_is_refused_rather_than_ignored():
    with pytest.raises(ConfigError, match="proxy-url"):
        _api({"context": "prod"}, _kc({"proxy-url": "http://10.232.0.69:3128"}))
