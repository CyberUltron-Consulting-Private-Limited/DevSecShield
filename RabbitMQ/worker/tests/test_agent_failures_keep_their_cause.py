"""A failing scan agent raises its cause instead of returning None (static proof; runs with any Python).

The IaC agent's run_agent caught every error and returned None, so the iac task failed with "cannot unpack
non-iterable NoneType object" and the scan's failure reason (scan.info.error, shown in the sidebar) said nothing
useful. Found in the lab UI run (u2, round 5), where the real cause was a model call refused by the cloud provider.
"""
from __future__ import annotations

import ast
import os

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENTS = ("iac_agent", "sast_agent", "sca_sbom_agent")


def _run_agent(agent: str) -> ast.FunctionDef:
    tree = ast.parse(open(os.path.join(WORKER, "helpers/tools", agent, "main.py")).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "run_agent":
            return node
    raise AssertionError(f"{agent}: no run_agent")


def test_run_agent_failures_raise_with_the_cause():
    for agent in AGENTS:
        fn = _run_agent(agent)
        handlers = [h for t in ast.walk(fn) if isinstance(t, ast.Try) for h in t.handlers]
        assert handlers, agent
        for handler in handlers:
            body = list(ast.walk(ast.Module(body=handler.body, type_ignores=[])))
            assert any(isinstance(n, ast.Raise) for n in body), f"{agent}: an except block of run_agent does not raise"
            assert not any(isinstance(n, ast.Return) for n in body), f"{agent}: run_agent returns from an except block"


def test_the_iac_task_unpacks_what_run_agent_returns():
    """The task unpacks three values; run_agent may only ever return that tuple."""
    src = open(os.path.join(WORKER, "scan_worker.py")).read()
    task = src[src.index("    def iac(\n"):src.index("    def iac_estimation(")]
    assert task.count("result , dependency_diagram , metadata = agent.run_agent()") == 2
    returns = [n for n in ast.walk(_run_agent("iac_agent")) if isinstance(n, ast.Return)]
    assert returns and all(isinstance(r.value, ast.Tuple) and len(r.value.elts) == 3 for r in returns)
