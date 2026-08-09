# DevSecShield — Demo Video Script (spoken)

Say this out loud while you click. Keep it casual. No pitch.

---

## Login

Alright, first we log in.

Email, password, verification code — and we're in.

---

## Home

This is the home page.

Here you can see all your teams, utilization across teams, and credit balance.

I'll pick a team and go in.

---

## Team dashboard + left panel

Okay, this is the main team dashboard.

On the left we have all the scanners.

DevSecShield covers:

- **SAST** — static analysis on source code
- **SCA + SBOM** — dependencies and bill of materials
- **IAC** — infrastructure as code, Terraform and similar
- **DAST** — live running apps and APIs
- **LLM** — LLM / model security scans
- **MCP** — MCP servers and tools
- and under workflow, **CI / CD** integrations

On the main dashboard here you can see scan activity by type, vulnerabilities by severity, scans over time, and integration activity.

Team switcher and credits are up here in the sidebar. Settings at the bottom.

Now let's go into SAST first.

---

## SAST — list / dashboard

Click **SAST** on the left.

This is the SAST page.

Up top you have **New Scan** and **Refresh**.

You can switch between Dashboard and Table.

Here you see all your SAST scans — status, timing, and the key stats: risk, findings counts, that kind of thing.

If I want to run a new one, I hit **New Scan**, give it a repo or a zip, pick the language, submit — it queues and runs async.

Let's open an existing completed scan into results.

---

## SAST — results

Okay, this is the SAST results view.

At the top you get the summary — overall risk, severity breakdown, finding counts.

Below that, charts and the findings table.

Each row is a finding — severity, rule, file, line.

Click one and you get the detail: snippet, location, what failed.

You can filter, sort, export the report from here, and if chat / remediation is on this page you can ask about a finding directly.

Same pattern for the other scanners — list page, new scan, results.

Let's jump to SCA + SBOM.

---

## SCA + SBOM

Left nav → **SCA + SBOM**.

Same layout — dashboard / table, scan list, New Scan.

This one is for dependencies.

Results show vulnerable packages, CVEs, severity, and the SBOM inventory of what's in the project.

You can download the BOM from the results header when it's available.

Next — IAC.

---

## IAC

Left nav → **IAC**.

Same flow.

New Scan — pick the IAC type, Terraform, K8s, whatever, point at the repo or zip.

Results are misconfigurations — open resources, weak policies, that kind of thing — with path and severity.

Next — DAST.

---

## DAST

Left nav → **DAST**.

This is for live targets, not source.

New Scan — give it a URL. If the app needs login, fill the auth fields.

Results are runtime findings against that running app or API.

So quick contrast:

- SAST = source at rest
- DAST = app while it's running

Next — LLM.

---

## LLM

Left nav → **LLM**.

Same idea — start a scan, wait for it to finish, open results.

This one is LLM / model behavior testing — prompt injection style checks, safety findings, scores on the results page.

Next — MCP.

---

## MCP

Left nav → **MCP**.

Scans MCP servers and tools.

Results give you exposure / risk on those tools — severity, categories, charts, findings table. Same click-through: row → detail.

---

## CI / CD

Left nav → **CI / CD**.

This is integrations, not a scan list.

You create an integration, open it, wire tokens / pipeline config.

Once it's set up, scans can be triggered from CI and then show up under the normal scanner pages — SAST, SCA, etc. — with the same status and results.

---

## Settings

Bottom of the sidebar → **Settings**.

Team-level stuff — members, credits, Jira / ticketing if configured.

That's where ownership and integrations for the team live.

---

## Wrap (10 seconds)

So that's the walkthrough.

Left panel = scanners.  
Each scanner = list → new scan → results.  
SAST for source, DAST for live, SCA for deps, IAC for infra, LLM and MCP for AI surfaces, CI/CD to hook it into pipelines.

That's the product.
