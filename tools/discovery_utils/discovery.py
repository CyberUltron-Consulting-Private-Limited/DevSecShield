from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import tempfile
from typing import Dict, Any
import logging
import hashlib

from tools.discovery_utils.extractor import extract_system_prompts, extract_langchain_agents
from tools.discovery_utils.role_assigner import summarize_prompt_role
import sys
import os
from git import Repo, GitCommandError
from rich.console import Console

def is_github_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "github.com" in url

def clone_repo(url: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="repo_"))
    Console().print(f":package: Cloning [blue]{url}[/] → {tmp}")
    try:
        Repo.clone_from(url, tmp, depth=1)
    except GitCommandError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"Clone failed: {e}") from e
    return tmp


sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from tools.discovery_utils.llm_service.llm import MissingApiKeyError


logger = logging.getLogger(__name__)


def discover_agents(directory: str) -> Dict[str, Any]:

    logger.info("Starting discovery in: %s", directory)
    items = extract_system_prompts(directory)
    # Also detect LangChain-based agents (create_react_agent)
    lc = extract_langchain_agents(directory)
    agents = []
    seen: set[str] = set()
    for file_path, s in items:
        key = s[:2000]
        if key in seen:
            continue
        seen.add(key)
        try:
            if s.strip():
                try:
                    role = summarize_prompt_role(s)
                except MissingApiKeyError:
                    # Fallback to simple role detection when API key is not available
                    role = "AI Assistant"
                except Exception as e:
                    role = "AI Assistant"
            else:
                role = "Unknown"
            
            agent_id = hashlib.sha256(s.encode("utf-8")).hexdigest()
            agents.append({
                "id": agent_id,
                "file": file_path,
                "role": role,
                "system_prompt": s,
                "framework": "Custom"
            })
            logger.info("Found system prompt in %s → id=%s role=%s", file_path, agent_id[:8], role)
        except Exception as e:
            logger.warning("Error processing string from %s: %s", file_path, e)
            continue
    # Add LangChain agents
    for file_path, data in lc:
        prompt = data.get("prompt") or ""
        key = (prompt or file_path)[:2000]
        if key in seen:
            continue
        seen.add(key)
        try:
            if prompt.strip():
                try:
                    role = summarize_prompt_role(prompt)
                except MissingApiKeyError:
                    role = "AI Assistant"
                except Exception as e:
                    role = "AI Assistant"
            else:
                role = "Unknown"
            agent_id = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            agent_entry = {
                "id": agent_id,
                "file": file_path,
                "role": role,
                "system_prompt": prompt,
                "framework": "Langchain"
            }
            # Pass through any extracted tool names (strings only)
            tools = data.get("tools") or []
            if isinstance(tools, list) and any(isinstance(t, str) for t in tools):
                agent_entry["__lc_tools__"] = [t for t in tools if isinstance(t, str)]
            agents.append(agent_entry)
            logger.info("Found LangChain agent in %s → id=%s role=%s", file_path, agent_id[:8], role)
        except Exception as e:
            logger.warning("Error processing LC agent in %s: %s", file_path, e)
            continue

    logger.info("Discovery complete. %d agents found", len(agents))
    return {"agents": agents}

# Alias for backward compatibility
d = discover_agents





if __name__ == "__main__":
    result = discover_agents(
        repo_url="https://github.com/CyberUltron-Nikhil/MCPTest",
        PAT="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",
    )
    print(result)
    with open("result.json", "w+") as f:
        json.dump(result, f, indent=4)

