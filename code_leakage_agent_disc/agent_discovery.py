#!/usr/bin/env python3
"""
Agent Discovery Tool - Backend Implementation
Discovers AI agents from GitHub repositories and analyzes their risk levels.
"""

import argparse
import ast
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import git

# Simple console output for Windows compatibility
class SimpleConsole:
    def print(self, text, style=None):
        print(text)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

console = SimpleConsole()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/agent_discovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AgentDiscoveryError(Exception):
    """Custom exception for agent discovery errors"""
    pass


class SystemPromptVisitor(ast.NodeVisitor):
    """AST visitor to extract system prompts from Python code"""
    
    def __init__(self) -> None:
        self.prompts: List[Tuple[str, str]] = []  # (source_hint, content)
        self.env_stack: List[Dict[str, Optional[str]]] = []
    
    def visit_Module(self, node: ast.Module) -> None:
        self.env_stack.append(self._collect_assignments(node.body))
        self.generic_visit(node)
        self.env_stack.pop()
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        fn_env = self._collect_assignments(node.body)
        for arg in node.args.args:
            fn_env[arg.arg] = None
        self.env_stack.append(fn_env)
        self.generic_visit(node)
        self.env_stack.pop()
    
    def visit_Assign(self, node: ast.Assign) -> None:
        values = self._resolve_node_to_str(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._current_env()[target.id] = values
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        for kw in node.keywords:
            if kw.arg == "messages":
                msgs = self._collect_messages(kw.value)
                for src, content in msgs:
                    if content:
                        self.prompts.append((src, content))
        self.generic_visit(node)
    
    def visit_List(self, node: ast.List) -> None:
        msgs = self._collect_messages(node)
        for src, content in msgs:
            if content:
                self.prompts.append((src, content))
        self.generic_visit(node)
    
    def _collect_messages(self, node: ast.AST) -> List[Tuple[str, Optional[str]]]:
        results: List[Tuple[str, Optional[str]]] = []
        if isinstance(node, (ast.List, ast.Tuple)):
            for elt in node.elts:
                res = self._extract_role_content_from_node(elt)
                if res is not None:
                    results.append(res)
        else:
            res = self._extract_role_content_from_node(node)
            if res is not None:
                results.append(res)
        return results
    
    def _extract_role_content_from_node(self, node: ast.AST) -> Optional[Tuple[str, Optional[str]]]:
        if isinstance(node, ast.Dict):
            keys = [self._resolve_node_to_str(k) for k in node.keys]
            vals = node.values
            items: Dict[str, Optional[str]] = {}
            for k_node, v_node, k in zip(node.keys, vals, keys):
                if k is None:
                    continue
                items[k] = self._resolve_node_to_str(v_node)
            role = items.get("role")
            content = items.get("content")
            if role == "system":
                return ("dict", content)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
            items: Dict[str, Optional[str]] = {}
            for kw in node.keywords:
                if kw.arg:
                    items[kw.arg] = self._resolve_node_to_str(kw.value)
            role = items.get("role")
            content = items.get("content")
            if role == "system":
                return ("dict_call", content)
        return None
    
    def _collect_assignments(self, body: List[ast.stmt]) -> Dict[str, Optional[str]]:
        env: Dict[str, Optional[str]] = {}
        for stmt in body:
            if isinstance(stmt, ast.Assign):
                value = self._resolve_node_to_str(stmt.value)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
            elif isinstance(stmt, ast.AnnAssign):
                value = self._resolve_node_to_str(stmt.value) if stmt.value is not None else None
                target = stmt.target
                if isinstance(target, ast.Name):
                    env[target.id] = value
        return env
    
    def _resolve_node_to_str(self, node: Optional[ast.AST]) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                elif isinstance(v, ast.FormattedValue):
                    parts.append("{...}")
            res = "".join(parts).strip()
            return res if res else None
        if isinstance(node, ast.Name):
            return self._lookup_name(node.id)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                base_str = self._resolve_node_to_str(node.func.value)
                if base_str is None:
                    return None
                attr = node.func.attr
                if attr == "strip" and not node.args and not node.keywords:
                    return base_str.strip()
                if attr == "format":
                    return base_str
            if isinstance(node.func, ast.Name) and node.func.id == "str" and len(node.args) == 1:
                return self._resolve_node_to_str(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_node_to_str(node.left)
            right = self._resolve_node_to_str(node.right)
            if left is None or right is None:
                return None
            return left + right
        return None
    
    def _lookup_name(self, name: str) -> Optional[str]:
        for env in reversed(self.env_stack):
            if name in env:
                return env[name]
        return None
    
    def _current_env(self) -> Dict[str, Optional[str]]:
        if not self.env_stack:
            self.env_stack.append({})
        return self.env_stack[-1]


class LangChainAgentVisitor(ast.NodeVisitor):
    """AST visitor to detect LangChain create_react_agent calls"""
    
    def __init__(self) -> None:
        self.imported_create_react_agent_names: set[str] = set()
        self.assign_env: Dict[str, ast.AST] = {}
        self.found: List[Dict[str, Optional[str]]] = []
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module and node.module.startswith("langchain.agents"):
            for alias in node.names:
                if alias.name == "create_react_agent":
                    self.imported_create_react_agent_names.add(alias.asname or alias.name)
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assign_env[target.id] = node.value
        self.generic_visit(node)
    
    def _resolve_str(self, node: Optional[ast.AST]) -> Optional[str]:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name) and node.id in self.assign_env:
            return self._resolve_str(self.assign_env[node.id])
        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            for v in node.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    parts.append(v.value)
                else:
                    parts.append("{...}")
            res = "".join(parts).strip()
            return res if res else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_str(node.left)
            right = self._resolve_str(node.right)
            if left and right:
                return left + right
        return None
    
    def _resolve_tools(self, node: Optional[ast.AST]) -> List[str]:
        names: List[str] = []
        if node is None:
            return names
        if isinstance(node, ast.List):
            for elt in node.elts:
                if isinstance(elt, ast.Name):
                    names.append(elt.id)
                elif isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    names.append(str(elt.value))
        elif isinstance(node, ast.Name):
            assigned = self.assign_env.get(node.id)
            if assigned is not None:
                names.extend(self._resolve_tools(assigned))
        return names
    
    def visit_Call(self, node: ast.Call) -> None:
        name = None
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        if name and name in self.imported_create_react_agent_names:
            data: Dict[str, Optional[str] | List[str]] = {"framework": "LangChain", "prompt": None, "tools": []}
            for kw in node.keywords:
                if kw.arg == "prompt":
                    data["prompt"] = self._resolve_str(kw.value)
                if kw.arg == "tools":
                    data["tools"] = self._resolve_tools(kw.value)
            self.found.append(data)
        self.generic_visit(node)


def validate_github_token(token: str) -> bool:
    """Validate GitHub Personal Access Token format"""
    if not token:
        return False
    # Valid format: ghp_ followed by exactly 36 characters (total 40 characters)
    return token.startswith('ghp_') and len(token) == 40 and len(token[4:]) == 36


def is_github_url(url: str) -> bool:
    """Check if URL is a valid GitHub repository URL"""
    return url.startswith(("http://", "https://")) and "github.com" in url


def clone_repository(repo_url: str, token: str) -> str:
    """Clone GitHub repository to temporary directory"""
    if not is_github_url(repo_url):
        raise AgentDiscoveryError(f"Invalid GitHub URL: {repo_url}")
    
    # Create temporary directory
    temp_dir = tempfile.mkdtemp(prefix="agent_discovery_")
    
    try:
        # Clone the repository with authentication
        if token:
            # Use token for authentication
            auth_url = repo_url.replace("https://", f"https://{token}@")
            repo = git.Repo.clone_from(auth_url, temp_dir)
        else:
            repo = git.Repo.clone_from(repo_url, temp_dir)
        
        logger.info(f"Successfully cloned repository to {temp_dir}")
        return temp_dir
        
    except Exception as e:
        # Clean up on error
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        raise AgentDiscoveryError(f"Failed to clone repository: {str(e)}")


def extract_system_prompts(directory: str) -> List[Tuple[str, str]]:
    """Extract system prompts from Python files in directory"""
    logger.info(f"Scanning for system prompts in: {directory}")
    results: List[Tuple[str, str]] = []
    
    for file_path in Path(directory).rglob("*.py"):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        
        try:
            tree = ast.parse(text)
        except Exception:
            logger.debug(f"Skipping unparsable file: {file_path}")
            continue
        
        visitor = SystemPromptVisitor()
        visitor.visit(tree)
        
        for _, content in visitor.prompts:
            if content is not None and content.strip():
                results.append((str(file_path), content))
            else:
                results.append((str(file_path), ""))
        
        if visitor.prompts:
            logger.debug(f"{file_path}: found {len(visitor.prompts)} system prompt candidates")
    
    logger.info(f"System prompt scan complete. {len(results)} prompts found")
    return results


def extract_langchain_agents(directory: str) -> List[Tuple[str, Dict[str, Optional[str]]]]:
    """Extract LangChain agents from Python files in directory"""
    logger.info(f"Scanning for LangChain agents in: {directory}")
    results: List[Tuple[str, Dict[str, Optional[str]]]] = []
    
    for file_path in Path(directory).rglob("*.py"):
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except Exception:
            continue
        
        visitor = LangChainAgentVisitor()
        visitor.visit(tree)
        
        for item in visitor.found:
            results.append((str(file_path), item))
    
    logger.info(f"LangChain agent scan complete. {len(results)} agents found")
    return results


def analyze_agent_role(prompt: str) -> str:
    """Analyze agent role from system prompt using simple heuristics"""
    if not prompt or not prompt.strip():
        return "Unknown"
    
    prompt_lower = prompt.lower()
    
    # Role detection patterns
    if any(keyword in prompt_lower for keyword in ["code", "programming", "developer", "coding"]):
        return "Code Assistant"
    elif any(keyword in prompt_lower for keyword in ["financial", "finance", "investment", "trading"]):
        return "Financial Advisor"
    elif any(keyword in prompt_lower for keyword in ["creative", "writer", "story", "content"]):
        return "Creative Writer"
    elif any(keyword in prompt_lower for keyword in ["data", "analysis", "analytics", "research"]):
        return "Data Analyst"
    elif any(keyword in prompt_lower for keyword in ["customer", "support", "help", "assistant"]):
        return "Customer Support"
    elif any(keyword in prompt_lower for keyword in ["security", "security", "vulnerability", "threat"]):
        return "Security Analyst"
    else:
        return "General Assistant"


def detect_tools_from_prompt(prompt: str) -> List[Dict[str, Any]]:
    """Detect tools mentioned in system prompt using pattern matching"""
    if not prompt:
        return []
    
    tools = []
    prompt_lower = prompt.lower()
    
    # Tool detection patterns
    tool_patterns = {
        "filesystem": ["file", "filesystem", "read file", "write file", "directory"],
        "web_search": ["search", "web", "google", "browser", "internet"],
        "database": ["database", "db", "sql", "query", "table"],
        "api": ["api", "http", "request", "endpoint", "rest"],
        "email": ["email", "mail", "send message", "notification"],
        "calendar": ["calendar", "schedule", "meeting", "appointment"],
        "github": ["github", "git", "repository", "commit", "pull request"],
        "cloud": ["aws", "azure", "gcp", "cloud", "s3", "lambda"],
        "shell": ["shell", "terminal", "command", "execute", "run"],
        "network": ["network", "ping", "curl", "wget", "download"]
    }
    
    for tool_name, patterns in tool_patterns.items():
        if any(pattern in prompt_lower for pattern in patterns):
            tools.append({
                "name": tool_name,
                "description": f"Tool for {tool_name} operations",
                "risk_level": "medium" if tool_name in ["filesystem", "shell", "network"] else "low"
            })
    
    return tools


def assess_agent_risk(agent_data: Dict[str, Any]) -> Dict[str, Any]:
    """Assess agent risk level based on role and tools"""
    risk_score = 0.0
    risk_factors = []
    
    # Role-based risk assessment
    role = agent_data.get("role", "").lower()
    if any(keyword in role for keyword in ["security", "admin", "system"]):
        risk_score += 0.3
        risk_factors.append("High-privilege role")
    
    # Tool-based risk assessment
    tools = agent_data.get("tools", [])
    for tool in tools:
        tool_name = tool.get("name", "").lower()
        if tool_name in ["filesystem", "shell", "network", "cloud"]:
            risk_score += 0.2
            risk_factors.append(f"High-risk tool: {tool_name}")
        elif tool_name in ["api", "database"]:
            risk_score += 0.1
            risk_factors.append(f"Medium-risk tool: {tool_name}")
    
    # Determine risk level
    if risk_score >= 0.7:
        risk_level = "high"
    elif risk_score >= 0.3:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "risk_factors": risk_factors,
        "risk_reason": "; ".join(risk_factors) if risk_factors else "Low risk agent"
    }


def discover_agents(repo_url: str, token: str) -> Dict[str, Any]:
    """Main function to discover agents from GitHub repository"""
    temp_dir = None
    start_time = time.time()
    
    try:
        console.print(f"Starting agent discovery for: {repo_url}", style="bold blue")
        
        # Clone repository
        print("Cloning repository...")
        temp_dir = clone_repository(repo_url, token)
        print("Repository cloned successfully")
        
        # Extract system prompts
        print("Extracting system prompts...")
        system_prompts = extract_system_prompts(temp_dir)
        print(f"Found {len(system_prompts)} system prompts")
        
        # Extract LangChain agents
        print("Extracting LangChain agents...")
        langchain_agents = extract_langchain_agents(temp_dir)
        print(f"Found {len(langchain_agents)} LangChain agents")
        
        # Process agents
        agents = []
        seen_prompts = set()
        
        # Process system prompts
        for file_path, prompt in system_prompts:
            if not prompt.strip():
                continue
            
            prompt_key = prompt[:2000]  # Use first 2000 chars as key
            if prompt_key in seen_prompts:
                continue
            seen_prompts.add(prompt_key)
            
            agent_id = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            role = analyze_agent_role(prompt)
            tools = detect_tools_from_prompt(prompt)
            
            agent_data = {
                "id": agent_id,
                "file_path": file_path,
                "role": role,
                "system_prompt": prompt,
                "framework": "Custom",
                "tools": tools
            }
            
            # Assess risk
            risk_assessment = assess_agent_risk(agent_data)
            agent_data.update(risk_assessment)
            
            agents.append(agent_data)
            logger.info(f"Found Custom agent in {file_path} -> {agent_id[:8]} ({role})")
        
        # Process LangChain agents
        for file_path, data in langchain_agents:
            prompt = data.get("prompt") or ""
            if not prompt.strip():
                continue
            
            prompt_key = (prompt or file_path)[:2000]
            if prompt_key in seen_prompts:
                continue
            seen_prompts.add(prompt_key)
            
            agent_id = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
            role = analyze_agent_role(prompt)
            
            # Extract tools from LangChain data
            tools = []
            for tool_name in data.get("tools", []):
                tools.append({
                    "name": tool_name,
                    "description": f"LangChain tool: {tool_name}",
                    "risk_level": "medium" if tool_name in ["filesystem", "shell"] else "low"
                })
            
            agent_data = {
                "id": agent_id,
                "file_path": file_path,
                "role": role,
                "system_prompt": prompt,
                "framework": "LangChain",
                "tools": tools
            }
            
            # Assess risk
            risk_assessment = assess_agent_risk(agent_data)
            agent_data.update(risk_assessment)
            
            agents.append(agent_data)
            logger.info(f"Found LangChain agent in {file_path} -> {agent_id[:8]} ({role})")
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        return {
            "scan_metadata": {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "repository": repo_url,
                "total_agents": len(agents),
                "scan_duration": f"{scan_duration:.2f}s"
            },
            "agents": agents
        }
        
    except Exception as e:
        logger.error(f"Error during agent discovery: {str(e)}")
        raise AgentDiscoveryError(f"Agent discovery failed: {str(e)}")
    
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temporary directory: {temp_dir}")


def generate_json_report(discovery_result: Dict[str, Any], output_file: Optional[str] = None) -> str:
    """Generate JSON report"""
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(discovery_result, f, indent=2, ensure_ascii=False)
        return output_file
    else:
        return json.dumps(discovery_result, indent=2, ensure_ascii=False)


def generate_csv_report(discovery_result: Dict[str, Any], output_file: Optional[str] = None) -> str:
    """Generate CSV report"""
    import csv
    
    agents = discovery_result.get("agents", [])
    
    if not agents:
        csv_content = "agent_id,file_path,role,framework,risk_level,risk_reason,tools_count\n"
    else:
        csv_content = "agent_id,file_path,role,framework,risk_level,risk_reason,tools_count\n"
        for agent in agents:
            tools_count = len(agent.get("tools", []))
            csv_content += f"{agent['id']},{agent.get('file_path', '')},{agent.get('role', '')},{agent.get('framework', '')},{agent.get('risk_level', '')},{agent.get('risk_reason', '')},{tools_count}\n"
    
    if output_file:
        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            f.write(csv_content)
        return output_file
    else:
        return csv_content


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Discover AI agents from GitHub repositories")
    parser.add_argument("--repo-url", required=True, help="GitHub repository URL to scan")
    parser.add_argument("--token", help="GitHub Personal Access Token (required - provide via --token or GITHUB_TOKEN env var)")
    parser.add_argument("--format", choices=["json", "csv", "html"], default="json", help="Output format")
    parser.add_argument("--output", help="Output file path (default: stdout or auto-generated filename)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get token from args or environment
    token = args.token or os.getenv("GITHUB_TOKEN")
    if not token:
        console.print("ERROR: GitHub token is required. Provide --token or set GITHUB_TOKEN environment variable.", style="red")
        console.print("Example: --token ghp_1234567890abcdef1234567890abcdef1234", style="yellow")
        console.print("Or set: $env:GITHUB_TOKEN='ghp_1234567890abcdef1234567890abcdef1234'", style="yellow")
        sys.exit(1)
    
    # Validate token format
    if not validate_github_token(token):
        console.print("ERROR: Invalid GitHub token format. Token must be 'ghp_' followed by 36 characters.", style="red")
        console.print("Example: ghp_1234567890abcdef1234567890abcdef1234", style="yellow")
        sys.exit(1)
    
    try:
        # Discover agents
        discovery_result = discover_agents(args.repo_url, token)
        
        # Generate report
        if args.format == "json":
            if args.output:
                output_file = args.output
            else:
                output_file = f"reports/agents_discovery_{int(time.time())}.json"
            result = generate_json_report(discovery_result, output_file)
            console.print(f"JSON report generated: {output_file}", style="green")
        
        elif args.format == "csv":
            if args.output:
                output_file = args.output
            else:
                output_file = f"reports/agents_discovery_{int(time.time())}.csv"
            result = generate_csv_report(discovery_result, output_file)
            console.print(f"CSV report generated: {output_file}", style="green")
        
        elif args.format == "html":
            console.print("HTML format not yet implemented", style="yellow")
            sys.exit(1)
        
        # Print summary
        total_agents = discovery_result["scan_metadata"]["total_agents"]
        console.print(f"Agent discovery completed successfully. Found {total_agents} agents.", style="bold green")
        
    except AgentDiscoveryError as e:
        console.print(f"ERROR: {str(e)}", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"UNEXPECTED ERROR: {str(e)}", style="red")
        logger.exception("Unexpected error during agent discovery")
        sys.exit(1)


if __name__ == "__main__":
    repo_url = "https://github.com/CyberUltron-Nikhil/MCPTest"
    token = "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"
    result = discover_agents(repo_url, token)
    print(result)
