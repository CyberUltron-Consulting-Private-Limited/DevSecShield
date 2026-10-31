"""The CBOM worker paths call no language model and no network service (static proof; runs with any Python)."""
from __future__ import annotations

import ast
import os
import re

WORKER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORBIDDEN = re.compile(r"^(langchain|langchain_core|langchain_aws|langsmith|boto3|botocore|openai|anthropic|requests|"
                       r"httpx|helpers\.context\.open_source_context|helpers\.context\.codebase_context|"
                       r"helpers\.tools\.cbom_agent\.(summary_manager|binary_scanner))")


def _imports(tree: ast.AST) -> list[str]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.append(node.module)
    return out


def test_cbom_agent_imports_no_model_or_network_sdk():
    src = open(os.path.join(WORKER, "helpers/tools/cbom_agent/main.py")).read()
    bad = [m for m in _imports(ast.parse(src)) if FORBIDDEN.match(m)]
    assert not bad
    for word in ("generate_map_reduce_summary", "ChatBedrock", "fetch_recent_cves", "traceable"):
        assert word not in src


def test_cbom_prompt_module_is_gone():
    assert not os.path.exists(os.path.join(WORKER, "helpers/tools/cbom_agent/summary_manager.py"))


def test_cbom_task_runs_the_engine_and_always_cleans_up():
    src = open(os.path.join(WORKER, "scan_worker.py")).read()
    task = src[src.index("def cbom("):src.index("Registered CBOM task")]
    assert "agent.run_agent()" in task and "to_dict_list" not in task and "map_reduce" not in task
    main = open(os.path.join(WORKER, "helpers/tools/cbom_agent/main.py")).read()
    run_agent = main[main.index("def run_agent"):main.index("def _measure_directory_size")]
    assert "finally:" in run_agent and "self.clean_up()" in run_agent


def test_credit_estimate_has_no_model_constant_or_binary_surcharge():
    main = open(os.path.join(WORKER, "helpers/tools/cbom_agent/main.py")).read()
    est = main[main.index("def estimate_credits_required"):]
    assert "0.836" not in est and "1.4" not in est and "scan_binaries" not in est
