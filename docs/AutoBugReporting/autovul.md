Now I have deep research on the competitive landscape. Let me build you the complete **ZeroShield** system — the brand, the full architecture for zero-day discovery (not just known CVE scanning), the GitHub publishing workflow, and a live ZeroShield landing page mockup.

---

## The Competitive Landscape You're Entering

ZAST.AI discovered hundreds of zero-day vulnerabilities across dozens of popular open-source projects in 2025, submitting findings through platforms like VulDB and resulting in 119 CVE assignments across projects including Microsoft Azure SDK, Apache Struts, Koa, and node-formidable.

AI-driven vulnerability research is already landing real CVEs in software that millions of people run every day. Two CVEs — one in Node.js's Permission Model (CVE-2026-21636) and one in React Server Components (CVE-2026-23864) — came from the same automated research loop. The old dismissive move of "this is just AI slop" no longer works as a general answer.

TrendAI's ÆSIR platform combines AI automation with expert oversight to discover zero-day vulnerabilities in AI infrastructure — 21 CVEs across NVIDIA, Tencent, and MLflow since mid-2025. Their platform uses MIMIR for real-time threat intelligence and FENRIR for zero-day discovery, scanning massive codebases in hours.

Your niche and differentiator: **focus exclusively on the npm and Docker Hub ecosystems** — the supply chain layer that every developer touches daily but that no dedicated open-source zero-day scanner publicly reports on.

---

## ZeroShield: Zero-Day vs. Known CVE — The Critical Distinction

Before architecture, you must understand what you're actually building. There are two tiers and both matter:

**Tier 1 — Known CVE Scanner** (fast to build, lower bar, still valuable for the dashboard): Pull existing CVE databases (NVD, OSV, GitHub Advisories), match against npm package versions and Docker image SBOMs. This is what Trivy, Grype, and Snyk do. Your value-add here is the automation, branding, and email/GitHub reporting pipeline.

**Tier 2 — Zero-Day Discovery** (hard, high-value, what makes ZeroShield unique): Use AI + static analysis + fuzzing to find vulnerabilities that have no CVE yet. This is what AISLE and ZAST.AI do. For npm packages this means: analyzing source code for memory safety issues, injection points, prototype pollution, deserialization bugs, path traversal, and logic flaws. For Docker images: analyzing Dockerfiles and entrypoints for privilege escalation, exposed secrets, unsafe base images, and misconfigured capabilities.

Build both. Ship Tier 1 first. Add Tier 2 as your research layer.

---

## Complete Step-by-Step Implementation

### Step 1 — Project Setup & Repository Structure

```
zeroshield/
├── scanner/
│   ├── npm_scanner.py        # npm package scanner
│   ├── docker_scanner.py     # Docker Hub image scanner
│   ├── ai_analyzer.py        # Claude API zero-day analysis
│   ├── fuzzer.py             # Lightweight JS fuzzer
│   └── taint_analyzer.py     # Taint flow analysis
├── reporter/
│   ├── email_reporter.py     # Dedicated email alerts
│   ├── github_reporter.py    # Auto-create GitHub issues
│   ├── dashboard_publisher.py# Publish to ZeroShield page
│   └── cve_requester.py      # Request CVE IDs via MITRE
├── orchestrator/
│   ├── scheduler.py          # Cron + job queue
│   └── watchlist.json        # Target packages
├── db/
│   ├── schema.sql
│   └── models.py
├── dashboard/                # Next.js ZeroShield page
│   ├── pages/
│   ├── components/
│   └── public/
├── .github/
│   └── workflows/
│       ├── scan_npm.yml
│       ├── scan_docker.yml
│       └── publish_report.yml
├── docker-compose.yml
└── README.md
```

### Step 2 — Dedicated Email Setup

Create a dedicated Gmail account: `zeroshield.security@gmail.com`. Enable 2FA, then generate an App Password. This address is used exclusively for: (a) outbound vulnerability alerts, (b) responsible disclosure emails to package maintainers, and (c) inbound CVE confirmation emails from MITRE/NVD.

```python
# reporter/email_reporter.py
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Template
from datetime import datetime

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
FROM_ADDR = "zeroshield.security@gmail.com"
APP_PASSWORD = "your_app_password_here"  # Store in .env

# Three separate email types:

def send_internal_alert(vuln: dict, internal_team: list[str]):
    """Immediate alert to your team when a finding is confirmed."""
    subject = f"[ZeroShield] {'🔴 ZERO-DAY' if vuln['is_zero_day'] else '🟡 CVE'} — {vuln['package']} — {vuln['severity']}"
    body = render_internal_template(vuln)
    _send(subject, body, internal_team)

def send_disclosure_email(vuln: dict, maintainer_email: str):
    """Responsible disclosure to package maintainer. 90-day disclosure window."""
    subject = f"[Security Disclosure] Vulnerability found in {vuln['package']} — ZeroShield Research"
    body = render_disclosure_template(vuln)
    _send(subject, body, [maintainer_email])

def send_public_report(weekly_digest: list[dict], subscribers: list[str]):
    """Weekly public digest of all confirmed findings."""
    subject = f"[ZeroShield Weekly] {len(weekly_digest)} vulnerabilities reported — {datetime.now().strftime('%b %d, %Y')}"
    body = render_digest_template(weekly_digest)
    _send(subject, body, subscribers)

def _send(subject: str, body: str, recipients: list[str]):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = f"ZeroShield Security Research <{FROM_ADDR}>"
    msg['To'] = ", ".join(recipients)
    msg['Reply-To'] = FROM_ADDR
    msg.attach(MIMEText(body, 'html'))
    
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as server:
        server.login(FROM_ADDR, APP_PASSWORD)
        server.sendmail(FROM_ADDR, recipients, msg.as_string())
```

### Step 3 — npm Zero-Day Analysis Pipeline

This is the core of Tier 2 and what separates ZeroShield from a simple CVE scanner. The process for each npm package:

```python
# scanner/ai_analyzer.py
import anthropic, subprocess, json, ast
from pathlib import Path

client = anthropic.Anthropic()

VULN_CLASSES = [
    "Prototype Pollution",
    "Command Injection via child_process/exec",
    "Path Traversal",
    "Deserialization of Untrusted Data",
    "ReDoS (Regular Expression Denial of Service)",
    "Server-Side Request Forgery (SSRF)",
    "Insecure use of eval() or Function()",
    "Timing Side-Channel in crypto operations",
    "Race condition in async file operations",
    "Uncontrolled Resource Consumption"
]

def download_npm_source(package_name: str, version: str) -> Path:
    """Download and extract npm package source for analysis."""
    subprocess.run(
        ["npm", "pack", f"{package_name}@{version}"],
        capture_output=True, check=True
    )
    tarball = f"{package_name.replace('/', '-')}-{version}.tgz"
    subprocess.run(["tar", "-xzf", tarball, "-C", "/tmp/zeroshield/"], check=True)
    return Path(f"/tmp/zeroshield/package/")

def extract_js_functions(source_dir: Path, max_chars: int = 40000) -> str:
    """Extract the most security-relevant JS/TS code for AI analysis."""
    code_chunks = []
    priority_files = []
    
    # Prioritize: index.js, lib/, src/, routes/, api/, middleware/
    for pattern in ["index.js", "*.js", "lib/**/*.js", "src/**/*.js"]:
        priority_files.extend(source_dir.glob(pattern))
    
    for f in priority_files[:20]:  # cap at 20 files
        try:
            content = f.read_text(errors='ignore')
            code_chunks.append(f"// === FILE: {f.name} ===\n{content[:3000]}")
        except Exception:
            continue
    
    return "\n\n".join(code_chunks)[:max_chars]

def ai_zero_day_analysis(package_name: str, source_code: str) -> dict:
    """
    Core AI analysis. This is the AISLE-style approach applied to npm.
    Ask Claude to reason deeply about vulnerability classes in the code.
    """
    prompt = f"""You are an expert security researcher performing a zero-day vulnerability audit.

Package: {package_name}
Source code (partial):
{source_code}

Analyze this code for the following vulnerability classes:
{chr(10).join(f"- {v}" for v in VULN_CLASSES)}

For each potential vulnerability found:
1. Identify the exact file and line/function
2. Describe the attack scenario (what input, what outcome)
3. Estimate exploitability: HIGH / MEDIUM / LOW
4. State confidence: CONFIRMED / LIKELY / SPECULATIVE
5. Suggest a minimal proof-of-concept payload (no full exploit, just the triggering input)
6. Rate severity: CRITICAL (9-10) / HIGH (7-8) / MEDIUM (4-6) / LOW (1-3)

STRICT RULES:
- Do NOT report issues you cannot trace to a specific code path.
- Do NOT report theoretical issues without a clear attack vector.
- If nothing significant found, respond with CLEAN.
- Output as JSON array of findings.

Format each finding as:
{{
  "vuln_class": "...",
  "location": "filename:function_name",
  "attack_scenario": "...",
  "exploitability": "HIGH|MEDIUM|LOW",
  "confidence": "CONFIRMED|LIKELY|SPECULATIVE",
  "poc_hint": "...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cvss_estimate": 0.0
}}
"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4000,
        messages=[{"role": "user", "content": prompt}]
    )
    
    raw = response.content[0].text
    if "CLEAN" in raw:
        return {"findings": [], "package": package_name}
    
    try:
        # Extract JSON from response
        import re
        json_match = re.search(r'\[.*\]', raw, re.DOTALL)
        findings = json.loads(json_match.group()) if json_match else []
    except Exception:
        findings = []
    
    # Only surface CONFIRMED or HIGH-exploitability LIKELY findings
    high_quality = [
        f for f in findings 
        if f.get("confidence") == "CONFIRMED" 
        or (f.get("confidence") == "LIKELY" and f.get("exploitability") == "HIGH")
    ]
    
    return {"findings": high_quality, "package": package_name}
```

### Step 4 — Docker Image Zero-Day Analysis

```python
# scanner/docker_scanner.py
import subprocess, json

def scan_docker_image(image_ref: str) -> dict:
    """
    Multi-layer Docker analysis:
    1. Grype for known CVEs in OS packages
    2. Trivy for misconfigs and secrets
    3. AI analysis of Dockerfile and entrypoint scripts
    """
    results = {}
    
    # Layer 1: Known CVE scan
    grype_out = subprocess.run(
        ["grype", image_ref, "-o", "json", "--add-cpes-if-none"],
        capture_output=True, text=True
    )
    results["known_cves"] = json.loads(grype_out.stdout).get("matches", [])
    
    # Layer 2: Misconfig + secrets scan
    trivy_out = subprocess.run([
        "trivy", "image", image_ref,
        "--scanners", "vuln,misconfig,secret",
        "--format", "json",
        "--ignore-unfixed"
    ], capture_output=True, text=True)
    results["misconfigs"] = json.loads(trivy_out.stdout)
    
    # Layer 3: Pull and analyze Dockerfile
    dockerfile = extract_dockerfile(image_ref)
    if dockerfile:
        results["ai_dockerfile_analysis"] = ai_dockerfile_analysis(dockerfile, image_ref)
    
    return results

def ai_dockerfile_analysis(dockerfile_content: str, image_name: str) -> dict:
    """AI analysis of Dockerfile for zero-day misconfigs."""
    prompt = f"""Analyze this Dockerfile for security issues:

Image: {image_name}
Dockerfile:
{dockerfile_content}

Look for:
- Running as root when unnecessary
- Exposed secrets or API keys in ENV/ARG
- Unsafe base images with known issues
- Missing HEALTHCHECK
- Packages installed without version pinning
- curl | bash patterns
- Excessive capabilities (--privileged)
- Sensitive directories mounted
- Supply chain risks in RUN commands

Output JSON array of issues with severity and remediation.
"""
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text
```

### Step 5 — Automated GitHub Publishing

```yaml
# .github/workflows/scan_npm.yml
name: ZeroShield npm Scan

on:
  schedule:
    - cron: '0 */6 * * *'   # every 6 hours
  workflow_dispatch:          # manual trigger

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install anthropic requests psycopg2-binary jinja2
          npm install -g npm@latest
          curl -sfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

      - name: Run ZeroShield Scanner
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          DB_URL: ${{ secrets.DATABASE_URL }}
          EMAIL_APP_PASSWORD: ${{ secrets.EMAIL_APP_PASSWORD }}
          GITHUB_TOKEN: ${{ secrets.GH_PAT }}
        run: python scanner/run_scan.py --target npm --watchlist watchlist.json

      - name: Publish findings to GitHub Issues
        if: always()
        run: python reporter/github_reporter.py

      - name: Update ZeroShield dashboard data
        run: python reporter/dashboard_publisher.py
        
      - name: Commit updated report data
        run: |
          git config user.name "ZeroShield Bot"
          git config user.email "zeroshield.security@gmail.com"
          git add dashboard/public/data/findings.json
          git diff --staged --quiet || git commit -m "chore: update scan results $(date -u)"
          git push
```

### Step 6 — CVE Request Workflow

When you find a genuine zero-day (AI confirms it, you validate manually), here is the exact responsible disclosure process:

**Day 0:** Send disclosure email to maintainer at `security@package.com` or open a private GitHub Security Advisory. Start 90-day clock.

**Day 90 (or when patched):** Submit CVE request to MITRE at `cve.mitre.org/cve/requests`. Include: vulnerability description, affected versions, CVSS score, proof-of-concept (sanitized), and your contact info. You can also use GitHub's CNA (CVE Numbering Authority) directly via the GitHub Advisory Database if the package is on GitHub.

**After CVE assigned:** Publish to ZeroShield page, send email digest, create public GitHub issue with CVE ID.

---

Now here is the ZeroShield brand and landing page:---

## Full Watchlist — Starting Targets

Your initial `watchlist.json` for ZeroShield should target high-impact, widely-used packages in the AI/ML and infrastructure space — exactly the niche where zero-days are most valuable and least well-covered:

```json
{
  "npm": [
    "litellm", "langchain", "@langchain/core", "openai",
    "@anthropic-ai/sdk", "axios", "express", "fastify",
    "socket.io", "ws", "node-fetch", "got", "superagent",
    "jsonwebtoken", "bcrypt", "passport", "multer",
    "serialize-javascript", "lodash", "moment", "dayjs",
    "sharp", "jimp", "pdf-parse", "mammoth",
    "axiom-node", "@axiomhq/js", "pino", "winston"
  ],
  "docker": [
    "litellm/litellm", "ghcr.io/berriai/litellm",
    "nginx", "node:20-alpine", "node:22-alpine",
    "python:3.11-slim", "redis:7-alpine",
    "postgres:16-alpine", "mongo:7",
    "ollama/ollama", "open-webui/open-webui",
    "qdrant/qdrant", "chromadb/chroma",
    "grafana/grafana", "prom/prometheus"
  ],
  "scan_interval_hours": 6,
  "disclosure_window_days": 90,
  "min_cvss_to_report": 6.0,
  "auto_create_github_issue": true,
  "email_recipients": ["zeroshield.security@gmail.com"],
  "maintainer_notify": true
}
```

---

## Hardware Budget & Timeline

**Phase 1 (Weeks 1–4) — Known CVE scanner + dashboard:** A single $12/month VPS (2 vCPU, 4GB RAM, 80GB SSD on DigitalOcean or Hetzner). Run Trivy + Grype + npm audit on your watchlist. Build the ZeroShield Next.js page. Set up the GitHub Actions workflow and email reporting. This gives you the dashboard, the automated reporting, and real CVE data to show.

**Phase 2 (Weeks 5–10) — AI zero-day layer:** Add the Claude API calls for static code analysis. Budget ~$50–100/month in Claude API costs at the scale of 300 packages scanned every 6 hours (most calls will be short). Upgrade to 4 vCPU / 8GB RAM (~$24/month) for parallel scanning.

**Phase 3 (Weeks 11+) — Publish and claim CVEs:** As findings accumulate, go through responsible disclosure on 3–5 packages, request CVE IDs, and publish your results publicly. This is your research credential and your product's proof of concept.

The most important thing AISLE learned — and what separates quality research from AI slop — is that the vast majority of reported issues don't qualify as security vulnerabilities at all. Even a "low" severity CVE is a higher bar than might be obvious. The quality filter is everything. Build your confidence threshold high: only surface findings where the AI can trace a complete code path from attacker-controlled input to dangerous sink. That discipline is what earns maintainer trust and CVE assignments.