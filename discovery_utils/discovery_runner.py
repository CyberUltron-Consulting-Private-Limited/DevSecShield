from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import tempfile
import json
from typing import Any, Dict, List, Optional


from discovery import discover_agents
from llm_service.llm import get_json_llm_response, MissingApiKeyError
from llm_service.prompts.tool_detection import TOOL_DETECTION_PROMPT
from llm_service.prompts.agent_risk import AGENT_RISK_PROMPT
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

class DiscoveryService:
    """Service for discovering agents"""
    
    @staticmethod
    def discover_agents_from_github(github_repo_url: str, PAT: str) -> List[Dict[str, Any]]:
        """Discover agents from GitHub repository"""
        temp_dir = None
        try:
            # Clone the repository
            Console().print(f"Starting Agent Discovery 🟨 🔍",style="bold yellow")
            if github_repo_url and is_github_url(github_repo_url):
                ind = github_repo_url.find("github.com")
                repo = github_repo_url[ind:]
                repo = f"https://{PAT}@{repo}"
                temp_dir = clone_repo(repo)
            
            # Use existing discovery function
            discovery_result = discover_agents(temp_dir)
            agents = discovery_result.get("agents", [])
            
            # Save discovered agents to database
            saved_agents = []
            for agent in agents:
                agent_data = {
                    "id": agent["id"],
                    "file_path": agent["file"],
                    "role": agent["role"],
                    "system_prompt": agent["system_prompt"],
                    "framework": agent.get("framework"),
                    "risk": None,
                    "risk_reason": None,
                }
                
                # Check if agent already exists
                saved_agents.append(agent_data)

                # Persist any pre-extracted tools (from LangChain visitor)
                # pre_tools = agent.get("__lc_tools__")
                # if pre_tools:
                #     for tname in pre_tools:
                #         try:
                #             # Avoid duplicates by checking first
                #             if not db.has_agent_tool(agent_data["id"], tname):
                #                 db.create_agent_tool({
                #                     "agent_id": agent_data["id"],
                #                     "name": tname,
                #                     "description": None,
                #                     "parameters": {}
                #                 })
                #         except Exception:
                #             pass

                # If custom agent: detect tools from prompt via LLM
                if agent_data.get("framework") == "Custom":
                    try:
                        prompt = TOOL_DETECTION_PROMPT + "\n\n" + agent_data["system_prompt"]
                        tools_json = get_json_llm_response(prompt, "")
                        for t in tools_json.get("tools", []) or []:
                            try:
                                tname = t.get("name")
                                agent_data["tools"].append({
                                    "name": tname,
                                    "description": t.get("description"),
                                    "parameters": t.get("parameters") or {}
                                })
                            except Exception:
                                pass
                    except MissingApiKeyError:
                        pass
                    except Exception:
                        pass

                # Compute agent risk via LLM using role and tool names
                try:
                    tools = agent.get("__lc_tools__") or []
                    Console().print(f"Tools: {tools}",style="bold green")
                    tool_names = [t for t in tools]
                    Console().print(f"Tool Names: {tool_names}",style="bold green")
                    prompt = AGENT_RISK_PROMPT.format(role=agent_data["role"], tools=tool_names)
                    risk_json = get_json_llm_response(prompt, "")
                    Console().print(f"Risk JSON: {risk_json}",style="bold yellow")
                    risk = (risk_json.get("risk") or "").lower()
                    # Update agent row with risk
                    agent_data["risk"] = risk
                    agent_data["risk_reason"] = risk_json.get("reason")
                    agent_data["tools"] = tools
                except MissingApiKeyError:
                    Console().print(f"Missing API Key",style="bold red")
                except Exception as e:
                    Console().print(f"Error: {e}",style="bold red")
                    
            return saved_agents
            
        finally:
            # Clean up temporary directory
            if temp_dir:
                shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    result = DiscoveryService.discover_agents_from_github(
        github_repo_url="https://github.com/yacwagh/double-trust",
        PAT="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",
    )
    with open("result.json", "w+") as f:
        json.dump(result, f, indent=4)
    
    print(result)
    