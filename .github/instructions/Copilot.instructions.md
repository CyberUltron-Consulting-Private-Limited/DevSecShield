---
description: "Mandatory global behavior for every chat/session/workspace in this repo: two-agent execution, GitHub MCP open-source reuse, and pre-implementation questioning."
applyTo: "**"
---

## Mandatory Global Policy

These rules are mandatory for every conversation in this repository.

1. Two-Agent Approach (Strict)
- Always use a two-agent workflow.
- Primary stream agent: owns planning, implementation, and verification.
- Secondary subagent: must be launched for parallel exploration, validation, or surveillance before implementation begins.
- Do not run single-agent implementation for non-trivial tasks.

2. GitHub MCP Open-Source Reuse (Strict)
- Before implementing from scratch, always use GitHub MCP tooling to find similar open-source solutions relevant to the user query.
- Reuse and adapt proven patterns when applicable.
- Implement from scratch only when suitable open-source patterns are unavailable or incompatible.
- Record what was reused, adapted, or rejected and why.

3. Mandatory Questions Before Implementation (Strict)
- Always ask clarifying questions before any implementation work.
- Do not edit files, run implementation commands, or start code changes until the user answers.
- Questions must confirm scope, constraints, and acceptance criteria.
