# Contributing to RedAmon

Thank you for your interest in contributing to RedAmon! This document provides guidelines and instructions to help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Legal and Ethical Responsibilities](#legal-and-ethical-responsibilities)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Environment Setup](#environment-setup)
  - [Running in Development Mode](#running-in-development-mode)
- [Project Architecture](#project-architecture)
- [Development Workflow](#development-workflow)
  - [Branching Strategy](#branching-strategy)
  - [Commit Messages](#commit-messages)
  - [Pull Requests](#pull-requests)
- [Code Style Guidelines](#code-style-guidelines)
  - [Python](#python)
  - [TypeScript / React](#typescript--react)
  - [CSS](#css)
- [Working with Docker](#working-with-docker)
- [Adding New Features](#adding-new-features)
  - [Adding Configuration Fields](#adding-configuration-fields)
  - [Adding WebSocket Message Types](#adding-websocket-message-types)
  - [Adding MCP Tools](#adding-mcp-tools)
- [Testing](#testing)
- [Documentation](#documentation)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

We are committed to providing a welcoming and inclusive experience for everyone. All participants are expected to:

- Be respectful and considerate in all interactions
- Accept constructive criticism gracefully
- Focus on what is best for the community and project
- Show empathy toward other contributors

Harassment, trolling, or abusive behavior of any kind will not be tolerated.

---

## Legal and Ethical Responsibilities

RedAmon is a security assessment framework. **All contributors must adhere to ethical and legal standards.**

Before contributing, read the [DISCLAIMER.md](DISCLAIMER.md) in full. Key points:

- **Only target systems you own or have explicit written authorization to test.** Unauthorized access is illegal under the CFAA, Computer Misuse Act, EU Directive 2013/40/EU, and similar laws.
- **Never include real-world target data** in commits, issues, or pull requests.
- **Use safe testing environments** such as the included `guinea_pigs/` VMs, HackTheBox, TryHackMe, DVWA, or your own lab infrastructure.
- **Do not add capabilities** designed for malicious use, detection evasion, or unauthorized access.

Contributors are personally responsible for ensuring their use of this tool complies with all applicable laws in their jurisdiction.

---

## Getting Started

### Prerequisites

| Requirement | Minimum Version |
|-------------|-----------------|
| Docker | 20.10+ |
| Docker Compose | v2+ |
| Node.js | 20.0+ |
| Git | 2.30+ |

An AI API key is required to run the agent component:
- **Anthropic API key** (recommended) or OpenAI API key

### Environment Setup

1. **Fork and clone** the repository:

   ```bash
   git clone https://github.com/<your-username>/RedAmon.git
   cd RedAmon
   ```

2. **Create your environment file** from the example:

   ```bash
   cp .env.example .env
   ```

3. **Set your API key** in `.env`:

   ```env
   ANTHROPIC_API_KEY=sk-ant-...
   ```

   All other values have sane defaults — you only need to set an AI key to get started.

4. **Build and start** all services:

   ```bash
   docker compose --profile tools build
   docker compose up -d
   ```

5. **Verify** services are running:

   | Service | URL |
   |---------|-----|
   | Webapp | http://localhost:3000 |
   | Agent API | http://localhost:8001 |
   | Recon Orchestrator | http://localhost:8010 |
   | Neo4j Browser | http://localhost:7474 |

### Running in Development Mode

For hot-reloading during frontend development:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

This mounts source code as volumes so changes are reflected immediately for the webapp. Python services require a container restart after code changes:

```bash
docker compose restart agent
docker compose restart recon-orchestrator
```

---

## Project Architecture

RedAmon is a modular, multi-service architecture. Each component lives in its own directory with its own Dockerfile:

```
RedAmon/
├── recon/                # OSINT & scanning pipeline (Kali-based)
├── recon_orchestrator/   # Container lifecycle manager (FastAPI)
├── agentic/              # AI agent orchestrator (LangGraph + FastAPI)
├── webapp/               # Frontend (Next.js 16 + TypeScript)
├── graph_db/             # Neo4j graph database client
├── mcp/                  # MCP tool servers (naabu, nuclei, curl, metasploit)
├── gvm_scan/             # GVM/OpenVAS vulnerability scanner
├── postgres_db/          # PostgreSQL database
└── guinea_pigs/          # Vulnerable test VMs
```

For detailed architecture, see:
- [README.md](README.md) — full project overview
- [.claude/CLAUDE.md](.claude/CLAUDE.md) — architecture and conventions
- [.claude/webapp.md](.claude/webapp.md) — frontend-specific guidelines

---

## Development Workflow

### Branching Strategy

Create branches from `main` using the following naming convention:

| Prefix | Use Case | Example |
|--------|----------|---------|
| `feature/` | New functionality | `feature/add-shodan-integration` |
| `fix/` | Bug fixes | `fix/websocket-reconnect` |
| `refactor/` | Code restructuring | `refactor/agent-state-management` |
| `docs/` | Documentation only | `docs/update-api-reference` |

```bash
git checkout main
git pull origin main
git checkout -b feature/your-feature-name
```

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/). Each commit message must start with a type prefix:

| Prefix | Description |
|--------|-------------|
| `feat:` | New feature |
| `fix:` | Bug fix |
| `refactor:` | Code restructuring (no behavior change) |
| `docs:` | Documentation changes |
| `chore:` | Build process, tooling, dependency updates |
| `test:` | Adding or updating tests |
| `style:` | Formatting, whitespace (no logic change) |
| `perf:` | Performance improvements |

**Format:**

```
<type>: <short description>

[optional body with more detail]
```

**Examples:**

```
feat: add Shodan integration to recon pipeline

fix: handle WebSocket reconnection on network timeout

refactor: extract tool execution logic into separate module

docs: add API endpoint documentation for recon orchestrator
```

Keep commits **atomic and focused** — each commit should represent a single logical change.

### Pull Requests

When your work is ready:

1. **Push** your branch to your fork:

   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** against the `main` branch.

3. **In your PR description**, include:
   - **Summary** — what changed and why (1-3 bullet points)
   - **How to test** — steps to verify the change
   - **Screenshots** — if there are UI changes
   - **Related issues** — link any relevant issues with `Closes #123`

4. **Keep PRs focused.** Large features should be broken into smaller, reviewable PRs when possible.

5. **Ensure your branch is up to date** with `main` before requesting review:

   ```bash
   git fetch origin
   git rebase origin/main
   ```

---

## Code Style Guidelines

### Python

All Python code lives in Docker containers. Follow these conventions:

- **PEP 8** for general style
- **4 spaces** for indentation (no tabs)
- **Snake case** for functions and variables (`get_scan_results`)
- **Pascal case** for classes (`ReconOrchestrator`)
- **UPPER_SNAKE_CASE** for constants (`DEFAULT_SETTINGS`)
- **Type hints** for function signatures
- **Docstrings** for public functions and classes (Google style)
- Prefer **f-strings** over `.format()` or `%` formatting
- Use **Pydantic models** for data validation (API inputs/outputs)
- Use **`async`/`await`** for I/O-bound operations in FastAPI services

**Example:**

```python
async def get_scan_results(project_id: str, include_vulns: bool = True) -> ScanResults:
    """Fetch scan results for a project from the graph database.

    Args:
        project_id: The unique project identifier.
        include_vulns: Whether to include vulnerability data.

    Returns:
        Aggregated scan results for the project.
    """
    ...
```

### TypeScript / React

The webapp follows strict conventions documented in [.claude/webapp.md](.claude/webapp.md). Key points:

- **TypeScript strict mode** — no `any` types unless absolutely necessary
- **Functional components** with hooks
- **Named exports** over default exports
- **TanStack Query** for server state management
- **Lucide React** for all icons (no other icon libraries)
- **Server Components** by default; add `"use client"` only when needed
- Run `npm run lint` and `npm run type-check` before committing

**Component structure:**

```
components/
└── MyComponent/
    ├── MyComponent.tsx        # Component logic
    ├── MyComponent.module.css # Scoped styles
    └── index.ts               # Re-export
```

### CSS

- **CSS Modules** exclusively — no global CSS, no CSS-in-JS, no Tailwind
- Use **semantic design tokens** from the token system (no raw hex values)
- Follow the **spacing scale** and **typography tokens** defined in the project
- See [.claude/webapp.md](.claude/webapp.md) for the full token reference

**Example:**

```css
.container {
  padding: var(--space-4);
  background: var(--color-bg-primary);
  border: 1px solid var(--color-border-primary);
  border-radius: var(--radius-md);
}
```

---

## Working with Docker

All security tools run inside Docker containers. **Never install scanning tools directly on the host.**

Each module has its own `Dockerfile` and `docker-compose.yml`. To work on a specific service:

```bash
# Rebuild a single service after code changes
docker compose build <service-name>

# Restart a service
docker compose restart <service-name>

# View logs for a service
docker compose logs -f <service-name>

# Access a running container's shell
docker compose exec <service-name> bash
```

When adding new services:
- Create a `Dockerfile` in the module directory
- Add the service to the root `docker-compose.yml`
- Document environment variables in `.env.example`
- Ensure the service has a health check endpoint

---

## Adding New Features

### Adding Configuration Fields

When adding a new configurable setting (e.g., a tool toggle or scan parameter), **four files must be updated**:

| Step | File | Action |
|------|------|--------|
| 1 | `webapp/prisma/schema.prisma` | Add field with `@default()` value |
| 2 | `recon/project_settings.py` | Add to `DEFAULT_SETTINGS` dict and mapping in `get_project_settings()` |
| 3 | `webapp/src/components/projects/ProjectForm/sections/*.tsx` | Add UI control |
| 4 | `recon/<module>.py` | Load with `settings.get('SETTING_NAME', default)` |

Then apply the schema change:

```bash
cd webapp && npx prisma db push && npx prisma generate
```

**Defaults flow (single source of truth):**

```
recon/project_settings.py (DEFAULT_SETTINGS)
         |
recon_orchestrator /defaults endpoint
         |
webapp /api/projects/defaults
         |
ProjectForm.tsx (fetches on create)
```

### Adding WebSocket Message Types

When adding a new real-time message type between the agent and webapp:

1. **Python** — Add to `MessageType` enum and create a Pydantic model in `agentic/websocket_api.py`
2. **TypeScript** — Add the matching value to the enum and payload interface in `webapp/src/lib/websocket-types.ts`

The enum values must match exactly between Python and TypeScript.

### Adding MCP Tools

To expose a new security tool to the AI agent:

1. Create a new MCP server in `mcp/servers/`
2. Register it in `mcp/servers/run_servers.py`
3. Add the tool to the Kali sandbox container if it requires specific binaries
4. Update `agentic/tools.py` to include the new tool definition
5. Document the tool in the MCP README

---

## Testing

Before submitting a PR, verify your changes work correctly:

**For backend changes:**

```bash
# Rebuild and restart the affected service
docker compose build <service>
docker compose restart <service>

# Check logs for errors
docker compose logs -f <service>

# Test API endpoints manually
curl http://localhost:<port>/health
```

**For frontend changes:**

```bash
cd webapp

# Type checking
npm run type-check

# Linting
npm run lint

# Development server (if not using Docker)
npm run dev
```

**For end-to-end verification:**

1. Start the full stack with `docker compose up -d`
2. Open the webapp at http://localhost:3000
3. Create a test project targeting a safe environment (e.g., `guinea_pigs/`)
4. Verify the feature works through the UI

---

## Documentation

Good documentation is valued. When contributing:

- **Update the CHANGELOG** — Add your changes under an `[Unreleased]` section in [CHANGELOG.md](CHANGELOG.md) following [Keep a Changelog](https://keepachangelog.com/) format
- **Update component READMEs** — If you change a module's interface or behavior, update its README
- **Add code comments** — Only where the logic is non-obvious; don't over-comment clear code
- **Update `.claude/CLAUDE.md`** — If you change project conventions, architecture, or file relationships

---

## Reporting Issues

When opening an issue, include:

- **Clear title** describing the problem
- **Steps to reproduce** the issue
- **Expected behavior** vs. actual behavior
- **Environment details** — OS, Docker version, browser (if relevant)
- **Logs** — Relevant container logs (`docker compose logs <service>`)
- **Screenshots** — For UI issues

---

## Security Vulnerabilities

If you discover a security vulnerability in RedAmon itself (not in target systems being scanned), **do not open a public issue**. Instead:

1. Contact the maintainer directly (see [Maintainer](#maintainer) below) with details of the vulnerability
2. Include steps to reproduce
3. Allow reasonable time for a fix before any public disclosure

We follow responsible disclosure practices and appreciate your help keeping RedAmon secure.

---

## Maintainer

**Samuele Giampieri** — creator and lead maintainer of RedAmon.

- [LinkedIn](https://www.linkedin.com/in/samuele-giampieri-b1b67597/)
- [Devergo Labs](https://www.devergolabs.com/)
- [GitHub](https://github.com/samugit83)

---

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub, or reach out to the maintainer. We're happy to help you get started.

Thank you for helping make RedAmon better!
