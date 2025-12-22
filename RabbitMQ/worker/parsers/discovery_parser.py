"""
Parser for Discovery scan results.
Converts raw discovery scan JSON into human-readable format.
"""

from typing import List, Dict, Any


def parse_discovery_results(raw_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Parse discovery scan results into a human-readable format.
    
    Args:
        raw_results: Raw discovery scan results list
        
    Returns:
        Dictionary with parsed, human-readable results
    """
    parsed = {
        "summary": {
            "total_agents": len(raw_results),
            "by_risk": {},
            "by_framework": {},
            "high_risk_agents": 0
        },
        "agents": []
    }
    
    # Process each agent
    for agent in raw_results:
        agent_id = agent.get("id", "Unknown")
        file_path = agent.get("file_path", "Unknown")
        role = agent.get("role", "Unknown")
        system_prompt = agent.get("system_prompt", "No prompt")
        framework = agent.get("framework", "Unknown")
        risk = agent.get("risk", "unknown")
        risk_reason = agent.get("risk_reason", "No reason provided")
        tools = agent.get("tools", [])
        
        # Count by risk
        parsed["summary"]["by_risk"][risk] = parsed["summary"]["by_risk"].get(risk, 0) + 1
        
        # Count by framework
        parsed["summary"]["by_framework"][framework] = parsed["summary"]["by_framework"].get(framework, 0) + 1
        
        # Count high risk agents
        if risk == "high":
            parsed["summary"]["high_risk_agents"] += 1
        
        # Create human-readable agent entry
        parsed_agent = {
            "id": agent_id[:16] + "..." if len(agent_id) > 16 else agent_id,  # Truncate long IDs
            "file_path": file_path,
            "role": role,
            "system_prompt": system_prompt[:200] + "..." if len(system_prompt) > 200 else system_prompt,
            "framework": framework,
            "risk": risk.upper(),
            "risk_reason": risk_reason,
            "tools": tools,
            "tool_count": len(tools)
        }
        
        parsed["agents"].append(parsed_agent)
    
    return parsed

