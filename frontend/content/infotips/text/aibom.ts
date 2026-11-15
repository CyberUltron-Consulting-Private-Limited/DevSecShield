/**
 * (i) tip text of the "aibom" area (ids: aibom.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── AI BOM: scan configuration (components/ai-bom-options-sidebar.tsx)
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:391-394, RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:426-447 — repository: model and source files; AI BOM file: AI summariser
  "aibom.cfg.repository": {
    what: "Finds the AI in your code: model files, embedding models, Hugging Face models, AI SDKs and external AI providers, datasets, and their licenses, and builds a CycloneDX AI bill of materials.",
    why: "You cannot govern AI you do not know you use; this finds it in the code.",
    example: "A service that imports the OpenAI SDK and loads a local .onnx model.",
  },
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:122-150 — an existing AI-BOM JSON analysed by the AI model (map-reduce)
  "aibom.cfg.file": {
    what: "An AI bill of materials you already have, as a JSON file. No code is cloned: the file's contents are analysed by the scan's AI model to list risks. Choosing a file clears the repository or zip.",
    why: "Reuses an AI BOM you already produce, so no code has to be cloned.",
    example: "aibom.cdx.json exported from another tool.",
  },
  // src: RabbitMQ/worker/helpers/tools/ai_bom_agent/main.py:426-447, backend/utilities/scan/estimate_scan.py:210 — 2 credits per MB of model/source files + ~0.05; a file is ~0.01
  "aibom.cfg.estimate": {
    what: "A repository or zip costs 2 credits per MB of model and source files plus about 0.05; an uploaded AI BOM file about 0.01. Rounded to 0.01. Nothing is charged until you start the scan.",
    why: "Shows the price before any credits are charged.",
    example: "4 MB of Python and model files: about 8.05 credits.",
  },

  // ────────────────────────────────────────────────────────────── AI BOM: list page (app/[team_id]/ai_bom/page.tsx)
  // src: backend/utilities/dashboard/scan_list.py:1853-1860 — detections of successful scans
  "aibom.kpi.assets": {
    what: "Every AI component detection in successful AI BOM scans: models, datasets, AI libraries and external AI providers, added up across scans.",
    why: "Sizes your AI footprint, the starting point for AI governance.",
    example: "The OpenAI SDK found in 4 files counts 4 here.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1821, backend/utilities/dashboard/scan_list.py:1884-1886, backend/utilities/dashboard/scan_list.py:1956 — distinct (provider, name) of model components
  "aibom.kpi.models": {
    what: "Distinct models (local model files, Hugging Face models, embedding models), counted once per provider and name across all scans.",
    why: "Each model is something to license, document and monitor.",
    example: "bert-base-uncased found in two repositories counts 1.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1890-1892, backend/utilities/dashboard/scan_list.py:1957 — distinct dataset names
  "aibom.kpi.datasets": {
    what: "Distinct datasets the code loads, counted once per name.",
    why: "Datasets carry privacy and licensing obligations.",
    example: "squad loaded by two notebooks counts 1.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1887-1889, backend/utilities/dashboard/scan_list.py:1958 — distinct providers of external_provider detections
  "aibom.kpi.providers": {
    what: "Distinct external AI services your code calls, such as OpenAI or Anthropic, counted once each.",
    why: "Each external AI provider receives your data and is a third-party risk.",
    example: "OpenAI used in 4 files and Anthropic in 1: 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1894-1896 — impact critical or high
  "aibom.kpi.high_risk": {
    what: "AI asset detections rated Critical or High.",
    why: "These AI components need review first.",
    example: "A model downloaded without a pinned revision, rated High.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1898-1904, backend/utilities/dashboard/aibom_license.py:83-92 — libraries without a usable license
  "aibom.kpi.unlicensed": {
    what: "AI libraries with no usable open-source license declared. Models and external providers are not counted here.",
    why: "Using code without a clear license is a legal risk.",
    example: "An internal AI package with no license field.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1906-1910, backend/utilities/dashboard/scan_list.py:1960-1963 — assets with a declared license and a model card / total
  "aibom.kpi.governance": {
    what: "Share of AI asset detections that have both a declared license and a model card: the documentation an AI governance review asks for.",
    why: "Regulations such as the EU AI Act expect licenses and model documentation.",
    example: "10 assets, 4 with license and model card: 40%.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1965-1971 — 0-10, weights 4/3/2/1
  "aibom.kpi.avg_risk": {
    what: "Severity-weighted average of all AI asset findings, 0 to 10: Critical 4, High 3, Medium 2, Low 1, the average weight divided by 4 and multiplied by 10.",
    why: "One number to compare AI risk over time.",
    example: "2 High and 2 Low: (3+3+1+1)/4 = 2, so 5.0.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1979-2018, backend/utilities/dashboard/finding_metrics.py:18-40 — stored findings of successful scans by status
  "aibom.chart.remediation": {
    what: "Stored findings of successful AI BOM scans by the status your team set: Fixed, In progress, Not started, Ignored.",
    why: "Shows how far the team has got with AI findings.",
    example: "12 findings: 3 Fixed, 9 Not started.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1862-1866 — impact per detection
  "aibom.chart.severity": {
    what: "AI asset detections by severity: Critical, High, Medium, Low.",
    why: "Critical and High detections are the ones to review first.",
    example: "High 3, Medium 7, Low 20.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1868-1869 — component_type per detection
  "aibom.chart.asset_type": {
    what: "Detections by kind of AI component: local model file, Hugging Face model, embedding model, dataset, AI library, external provider and others.",
    why: "Shows what kind of AI your code depends on most.",
    example: "external_provider 5, huggingface_model 2.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1871-1872 — resolved provider per detection
  "aibom.chart.provider": {
    what: "Detections by the AI vendor or source behind them, such as openai, anthropic or huggingface.",
    why: "Shows which vendors your AI use depends on.",
    example: "openai 6, huggingface 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1874-1875 — resolved license per detection
  "aibom.chart.license": {
    what: "Detections by license, as declared or resolved for each component (for example MIT, Apache-2.0, a proprietary API's terms, or not declared).",
    why: "Shows the license obligations attached to your AI components.",
    example: "Apache-2.0 8, NOASSERTION 3.",
  },
  // src: backend/utilities/dashboard/scan_list.py:1930-1936, backend/utilities/dashboard/scan_list.py:1973-1977 — the 10 most severe detections
  "aibom.chart.top_risks": {
    what: "The 10 most severe AI asset detections (Critical first), with their type, provider, license and impact.",
    why: "These are the AI components to review first.",
    example: "gpt-4o · external_provider · openai · proprietary · High.",
  },
  // src: backend/utilities/db/scan_list_item.py:489-510 — counts per impact of a successful scan
  "aibom.table.risks": {
    what: "This scan's AI asset findings by severity: Critical (red), High (orange), Medium (amber), Low (blue). Counted once the scan succeeded.",
    why: "Shows at a glance how serious this scan's findings are.",
    example: "0 red, 2 orange, 5 amber, 11 blue.",
  },
  // src: backend/utilities/db/scan_list_item.py:526-529 — weighted 4/3/2/1 average, /4 *10
  "aibom.table.risk": {
    what: "This scan's severity-weighted average, 0 to 10: Critical 4, High 3, Medium 2, Low 1, averaged over its findings, divided by 4 and multiplied by 10.",
    why: "Lets you compare scans by overall severity.",
    example: "1 High and 1 Low: (3+1)/2 = 2, so 5.0.",
  },
} as const satisfies TipAreaText;

export default TEXT;
