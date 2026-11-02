"""Istio PeerAuthentication facts: the classifier needs mtls_mode (UNSET explicit), whether the policy is mesh-wide,
and port-level modes (WP5 mesh fixes)."""
import time

from zs_scan_node.collectors import kubernetes as K
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

POLICIES = [
    {"metadata": {"namespace": "istio-system", "name": "default"}, "spec": {}},
    {"metadata": {"namespace": "pay", "name": "ns"}, "spec": {"mtls": {"mode": "permissive"}}},
    {"metadata": {"namespace": "pay", "name": "api"}, "spec": {"selector": {"matchLabels": {"app": "api"}},
                                                                 "mtls": {"mode": "STRICT"},
                                                                 "portLevelMtls": {"8080": {"mode": "DISABLE"}}}},
]


class FakeApi:
    api_url, host, port = "https://k8s.test:6443", "k8s.test", 6443

    def __init__(self, *a):
        pass

    def check_scope(self):
        return "10.0.0.1"

    def get(self, path, params=None):
        return 200, {"gitVersion": "v1.31.0"}

    def list_all(self, path, params=None):
        if path.endswith("/peerauthentications"):
            for p in POLICIES:
                yield ("item", p)

    def close(self):
        pass


def test_peer_authentication_facts_carry_mode_scope_and_port_modes(monkeypatch):
    monkeypatch.setattr(K, "Api", FakeApi)
    monkeypatch.setattr(K.T, "have_openssl", lambda: False)
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="kubernetes", scrubber=Scrubber(),
                     never_scan=NeverScan(), deadline=time.monotonic() + 60)
    K.collect(ctx, {"api_url": FakeApi.api_url}, {}, {})
    ctx.flush()
    rows = {a["name"]: a["facts"] for a in ctx.collected if a["type"] == "k8s_mesh_policy"}
    assert rows["istio-system/default"] == {"namespace": "istio-system", "name": "default", "mtls_mode": "UNSET",
                                            "scope": "mesh", "port_modes": {}}
    assert rows["pay/ns"]["mtls_mode"] == "PERMISSIVE" and rows["pay/ns"]["scope"] == "namespace"
    assert rows["pay/api"]["scope"] == "workload" and rows["pay/api"]["port_modes"] == {"8080": "DISABLE"}
