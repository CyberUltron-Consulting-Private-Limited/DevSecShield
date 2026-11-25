/**
 * (i) tip text of the "llm" area (ids: llm.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── LLM red teaming: scan configuration (components/llm-options-sidebar.tsx)
  // src: backend/utilities/db/schemas.py:176-186 — openai, anthropic, gemini or custom
  "llm.cfg.model_type": {
    what: "Where the model under test is hosted: OpenAI, Anthropic, Google Gemini, or Custom (any HTTP endpoint you describe below).",
    why: "The scan must speak the provider's API to send its attack prompts.",
    example: "Custom for your own chatbot API.",
  },
  // src: backend/utilities/db/schemas.py:178, backend/utilities/db/scan_list_item.py:355 — the provider's model id
  "llm.cfg.model_name": {
    what: "The model id the provider expects, exactly as in its API, or a name for your custom model. It also labels the scan in the Model Risk Comparison chart.",
    why: "Each model behaves differently; results apply only to the model tested.",
    example: "gpt-4o-mini.",
  },
  // src: backend/utilities/db/schemas.py:181 — secret field, never printed
  "llm.cfg.api_key": {
    what: "The provider API key the red-team prompts are sent with. Every test prompt is billed by your provider on this key. It is never printed in logs.",
    why: "Prompts are sent with this key, so your provider bills them; use a key with limits.",
    example: "An OpenAI key from a project with a spending limit.",
  },
  // src: backend/utilities/db/schemas.py:179, RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155 — answers per prompt; not part of the credit price
  "llm.cfg.generations": {
    what: "How many answers the model is asked to give for each attack prompt. More generations catch inconsistent behaviour but send more requests to your provider; the credit price does not change.",
    why: "More answers per prompt catch inconsistent behaviour at the cost of more provider calls.",
    example: "3 sends each prompt three times.",
  },
  // src: backend/utilities/db/schemas.py:185 — the endpoint of a custom model
  "llm.cfg.model_uri": {
    what: "The URL the scan calls to talk to your custom model (POST by default).",
    why: "The scan sends every attack prompt to this address.",
    example: "https://chat.example.com/api/v1/complete.",
  },
  // src: backend/utilities/db/schemas.py:182 — HTTP headers of the custom request
  "llm.cfg.headers": {
    what: "HTTP headers sent with every request to the custom model, as a JSON object, usually for authentication.",
    why: "Endpoints that require authentication refuse the scan without them.",
    example: "{\"Authorization\": \"Bearer <token>\"}.",
  },
  // src: backend/utilities/db/schemas.py:183 — the JSON body with the prompt placeholder
  "llm.cfg.request_template": {
    what: "The JSON body sent to your model, with a placeholder where each attack prompt goes.",
    why: "A wrong template means the model never receives the attack prompts.",
    example: "{\"message\": \"$INPUT\"}.",
  },
  // src: backend/utilities/db/schemas.py:184 — where the answer is in the response
  "llm.cfg.response_field": {
    what: "The field of your model's JSON response that holds the answer text, which the detectors then judge.",
    why: "Without the right field the detectors judge an empty answer.",
    example: "reply for a response {\"reply\": \"…\"}.",
  },
  // src: backend/utilities/db/schemas.py:180, RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155 — garak probes; 0.002 credits each
  "llm.cfg.probes": {
    what: "The attack families (garak probes) to run against the model, such as jailbreaks, prompt injection, data leakage or toxicity. Each selected benchmark costs 0.002 credits.",
    why: "Each benchmark tests a different way a model can be misused.",
    example: "promptinject and dan for a customer-facing chatbot.",
  },
  // src: RabbitMQ/worker/helpers/tools/llm_agent/main.py:142-155, backend/utilities/scan/estimate_scan.py:210 — number of probes x 0.002
  "llm.cfg.estimate": {
    what: "Prices the scan at 0.002 credits per selected benchmark, rounded to 0.01. Your model provider bills its own usage separately. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "10 benchmarks: 0.02 credits.",
  },

  // ────────────────────────────────────────────────────────────── LLM red teaming: list page (app/[team_id]/llm/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1500-1518 — the same status counters as SAST (UTC day for today); last_updated also moves on status polls and chat messages (#47)
  "llm.kpi.status": {
    what: "LLM scans of this team per status (Not started, Pending, Started, Success, Failure), and how many were created or updated since 00:00 UTC today. A status check of a running scan or a chat message also counts as an update.",
    why: "Shows how many tests ran and how many are stuck or failed.",
    example: "Updated today 2: two scans started or finished today (UTC).",
  },
  // src: backend/utilities/dashboard/scan_list.py:1553-1555, backend/utilities/dashboard/scan_list.py:1638 — successful scans
  "llm.kpi.success": {
    what: "LLM scans that finished successfully. Only these feed the risk cards and charts.",
    why: "Only these scans contribute to the risk numbers on this page.",
    example: "5 scans succeeded.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1658-1660, backend/utilities/dashboard/risk_scale.py:76-95, frontend/utils/riskPosture.ts:22-28, frontend/app/[team_id]/llm/page.tsx:304-307 — risk_scale.posture over the findings of successful LLM scans
  "llm.kpi.avg_risk": {
    what: "The one risk score over all findings of successful LLM scans, as on each scan's row, results page and PDF: 0-100: 4 × (10 per Critical, 5 per High, 2 per Medium, 1 per Low), capped by the worst severity (no Critical: 69 at most, no High either: 49, Low only: 29). Grades: A <15, B 15–29, C 30–49, D 50–69, F 70+.",
    why: "One number and grade to compare model risk over time, as every product shows it.",
    example: "One Critical and one Low finding: 4 × 11 = 44, grade C (Elevated risk).",
  },
  // src: backend/utilities/dashboard/scan_list.py:1564-1567, backend/utilities/dashboard/scan_list.py:1617-1618 — findings of successful scans
  "llm.kpi.vulns": {
    what: "Findings of successful LLM scans: all of them (Total Vulns), and those rated Critical (Critical Vulns).",
    why: "Sizes how often your models can be misused.",
    example: "Total 12, Critical 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1532-1543, backend/utilities/dashboard/scan_list.py:1628-1631 — 10 minus the number of OWASP LLM categories with a finding
  "llm.kpi.owasp": {
    what: "10 minus the number of OWASP Top 10 for LLM categories that have at least one finding. 10 means no category was hit; it does not weigh how many findings each has.",
    why: "A quick read of how many OWASP LLM risk areas are affected.",
    example: "Findings in LLM01 and LLM06 only: 8.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1602-1606, backend/utilities/dashboard/scan_list.py:1633-1635 — (tests - hits) / tests over successful scans
  "llm.kpi.passed_rate": {
    what: "Share of attack attempts the models resisted, over all successful scans: attempts that did not trigger a detector divided by all attempts.",
    why: "Shows how well your models resist attacks overall.",
    example: "1,000 attempts, 80 hits: 92.0%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1564-1567 — findings by impact
  "llm.chart.risk_level": {
    what: "Findings of successful LLM scans by severity: Critical, High, Medium, Low.",
    why: "Critical and High findings are the ones to address first.",
    example: "High 4, Medium 6, Low 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1592-1601 — per probe: passed and failed attempts
  "llm.chart.attack_vectors": {
    what: "For each benchmark (garak probe), how many attack attempts the models resisted (passed) and how many succeeded (failed), over all successful scans.",
    why: "Shows which kinds of attack your models fail most.",
    example: "dan: 45 passed, 5 failed.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1581-1590, backend/utilities/dashboard/scan_list.py:1653-1656 — per model name: findings-weighted 0-10 score
  "llm.chart.model_risk": {
    what: "The average risk score (0 to 10, weights Critical 4, High 3, Medium 2, Low 1) of each model's findings, across its successful scans.",
    why: "Helps you choose the safer model for a use case.",
    example: "gpt-4o-mini 5.0, my-chatbot 7.5.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1544-1551, backend/utilities/dashboard/scan_list.py:1607-1613, backend/utilities/dashboard/scan_list.py:1659-1665 — average of each scan's resistance scores
  "llm.chart.posture": {
    what: "Average of the scans' resistance scores in six areas: jailbreak resistance, injection resistance, hallucination resistance, bias resistance, content safety and data privacy. 0 where no scan reported one.",
    why: "Shows the weakest areas of your models' defences.",
    example: "Jailbreak resistance 7.2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1532-1543, backend/utilities/dashboard/scan_list.py:1568-1580, backend/utilities/dashboard/scan_list.py:1666-1669 — findings per OWASP LLM category
  "llm.chart.owasp": {
    what: "Findings per OWASP Top 10 for LLM Applications category (LLM01 Prompt Injection to LLM10). A finding mapped to two categories counts in both.",
    why: "Lets you report findings in the OWASP LLM framework.",
    example: "LLM01 6, LLM06 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1502-1519 — every LLM scan by its UTC creation date
  "llm.chart.scans_per_day": {
    what: "How many LLM scans were created on each day (UTC), whatever their status.",
    why: "Shows how regularly models are tested.",
    example: "3 scans created on 10 Nov.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1500-1512 — counts by status
  "llm.chart.status": {
    what: "All LLM scans of this team by their current status.",
    why: "Failures point to configuration or provider problems.",
    example: "5 Success, 1 Failure.",
  },
  // src: backend/utilities/db/scan_list_item.py:371 — model type from the scan's settings
  "llm.table.model_type": {
    what: "Where the tested model is hosted: openai, anthropic, gemini or custom.",
    why: "Tells you where the tested model runs.",
    example: "openai.",
  },
  // src: backend/utilities/db/scan_list_item.py:355, backend/utilities/db/scan_list_item.py:372 — model name from the settings or the results
  "llm.table.model_name": {
    what: "The model id that was tested.",
    why: "Results apply only to this model.",
    example: "gpt-4o-mini.",
  },
  // src: backend/utilities/db/scan_list_item.py:374 — number of selected probes
  "llm.table.probes": {
    what: "How many security benchmarks (garak probes) the scan was configured with.",
    why: "More benchmarks mean a broader test.",
    example: "10 probes selected.",
  },
  // src: backend/utilities/db/scan_list_item.py:343-351, backend/utilities/db/scan_list_item.py:377 — distinct MITRE ATLAS tactics of the findings
  "llm.table.mitre": {
    what: "How many different MITRE ATLAS tactics (the adversarial-AI attack stages) the scan's findings map to.",
    why: "Shows how many adversarial-AI attack stages the findings cover.",
    example: "3: initial access, ML model access and exfiltration.",
  },
  // src: backend/utilities/db/scan_list_item.py:298-315 — counts per impact of a successful scan
  "llm.table.vulns": {
    what: "This scan's findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "1 red, 0 orange, 3 amber, 2 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:371,563-567, backend/utilities/dashboard/risk_scale.py:76-95, frontend/utils/riskPosture.ts:22-28, frontend/app/[team_id]/llm/page.tsx:115-118,928 — the row's risk_posture
  "llm.table.risk": {
    what: "This scan's one risk score and grade, as on its results page and PDF: 0-100: 4 × (10 per Critical, 5 per High, 2 per Medium, 1 per Low), capped by the worst severity (no Critical: 69 at most, no High either: 49, Low only: 29). Grades: A <15, B 15–29, C 30–49, D 50–69, F 70+. Empty (—) when the scan did not succeed.",
    why: "Lets you compare scans by overall risk on the scale every product uses.",
    example: "1 Critical and 1 Medium finding: 4 × 12 = 48, grade C, shown 48 · C.",
  },
} as const satisfies TipAreaText;

export default TEXT;
