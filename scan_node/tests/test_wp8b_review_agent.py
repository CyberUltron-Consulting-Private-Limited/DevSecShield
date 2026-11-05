"""Round-5 review (lens 6) of the agent's enrollment loop: a DaemonSet pod whose node token was revoked (node reset or
deleted) enrolls again with its agent pool token instead of waiting forever; a pool token ZeroShield refused is not
tried again; a single-use token stays spent; and every claim says which mode the node runs in."""
from __future__ import annotations

import hashlib

import pytest

from zs_scan_node import agent as A
from zs_scan_node.api import Unauthorized

POOL = "zsp_" + "A" * 43


def _pod(tmp_path, monkeypatch, token: str = POOL, mode: str = "agent") -> A.Agent:
    monkeypatch.setenv("ZS_API_URL", "https://zs.example")
    monkeypatch.setenv("ZS_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ZS_MODE", mode)
    monkeypatch.setenv("ZS_NODE_NAME", "k8s-worker-a")
    monkeypatch.setenv("ZS_REGISTRATION_TOKEN", token)
    pod = A.Agent()
    waits: list[float] = []

    def wait(seconds):
        waits.append(seconds)
        if len(waits) >= 2:
            pod.shutdown.set()
        return pod.shutdown.is_set()

    pod.shutdown.wait = wait
    pod.waits = waits
    return pod


def _reset_state(pod: A.Agent, token: str) -> None:
    """Enrolled once with ``token`` as node 7, then a 401 cleared the node token (node reset in ZeroShield)."""
    pod.state.enrolled_with = hashlib.sha256(token.encode()).hexdigest()
    pod.state.node_id, pod.state.deployment_id = 7, "dep-1"
    pod.state.node_token = None
    pod.api.deployment_id = "dep-1"


def test_a_pod_enrolls_again_with_its_pool_token_after_a_reset(tmp_path, monkeypatch, capsys):
    pod = _pod(tmp_path, monkeypatch)
    _reset_state(pod, POOL)
    sent = []
    monkeypatch.setattr(pod.api, "enroll", lambda body: sent.append(body) or {
        "node_token": "zsn_" + "b" * 40, "node_id": 7, "team_id": 1, "deployment_id": "dep-1"})
    pod.on_unauthorized()
    assert "enrolling again with the agent pool token" in capsys.readouterr().out
    pod.ensure_enrolled()  # before: "already used ... Scan nodes > Reset", then a 300 s wait, forever
    assert len(sent) == 1 and pod.waits == []
    assert (sent[0]["registration_token"], sent[0]["node_id"], sent[0]["mode"], sent[0]["node_name"]) == (
        POOL, 7, "agent", "k8s-worker-a")
    assert pod.state.node_token == "zsn_" + "b" * 40


def test_a_pool_token_zeroshield_refused_is_not_tried_again(tmp_path, monkeypatch, capsys):
    pod = _pod(tmp_path, monkeypatch)
    _reset_state(pod, POOL)
    calls = []

    def enroll(body):
        calls.append(body)
        raise Unauthorized("/cbom/node/enroll", "dep-1")  # our own ZeroShield: revoked, expired or full

    monkeypatch.setattr(pod.api, "enroll", enroll)
    pod.ensure_enrolled()
    assert len(calls) == 1 and pod.waits == [300, 300]
    assert pod.state.refused_with == hashlib.sha256(POOL.encode()).hexdigest()
    out = capsys.readouterr().out
    assert "refused the agent pool token" in out and "--set agent.poolToken" in out and "Scan nodes > Reset" not in out
    reloaded = A.NodeState.load(str(tmp_path / "state"))  # survives a pod restart
    assert reloaded.refused_with == pod.state.refused_with


def test_a_single_use_token_stays_spent_once_used(tmp_path, monkeypatch):
    token = "zsr_" + "c" * 40
    pod = _pod(tmp_path, monkeypatch, token=token, mode="agentless")
    _reset_state(pod, token)
    monkeypatch.setattr(pod.api, "enroll", lambda body: pytest.fail("a spent single-use token was sent again"))
    pod.ensure_enrolled()
    assert pod.waits == [300, 300]


@pytest.mark.parametrize("mode", ["agent", "agentless"])
def test_every_claim_says_which_mode_the_node_runs_in(tmp_path, monkeypatch, mode):
    pod = _pod(tmp_path, monkeypatch, mode=mode)
    pod.state.node_token = "zsn_" + "d" * 40
    bodies = []

    def claim(body=None):
        bodies.append(body)
        pod.shutdown.set()
        return None

    monkeypatch.setattr(pod.api, "claim", claim)
    pod.claim_loop()
    assert bodies == [{"mode": mode}]
