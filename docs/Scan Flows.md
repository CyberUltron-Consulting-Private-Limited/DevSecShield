I’ve explained the storage layer; now I’m tracing each scan path end-to-end so I can give you the exact sequence of scanner execution, vector-store usage, and LLM usage for each scan type instead of a generic RAG summary.

Searched for regex `@router|celery|task|scan_worker|dast_worker|guardrail_worker|llm_benchmark|sbom_sca|iac|mcp|leakage|agent_discovery|semgrep|grype|trivy|wapiti|zap|nuclei|garak` (`**/backend/**|RabbitMQ/**`), no results

Search complete: Trace scan flows

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/scan_worker.py#1-1), lines 1 to 320

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/dast_worker.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/guardrail_worker/guardrail_worker.py)

Searched for files matching `**/backend/**`, 103 matches

Searched for files matching `**/*celery*`, 4 matches

Searched for files matching `**/*task*`, no matches

Searched for files matching `**/*fastapi*`, no matches

Searched for files matching `**/*.py`, 316 matches

Searched for regex `sast|dast|iac|sbom|sca|mcp|llm|leak|agent discovery|guardrail|cicd` (`**/backend/routers/**`), 200 results

Searched for regex `@router|def .*scan|start_scan|estimate_scan|celery|send_task|apply_async|delay` (`**/backend/**/*.py`), 200 results

Searched for regex `MongoClient|motor|pymongo|get_database|mongo|qdrant|chroma|vector|OpenAI|Anthropic|ChatOpenAI|AzureOpenAI|langchain|llm` (`**/backend/**/*.py`), 200 results

Searched for regex `task\(|@shared_task|@celery|Celery\(|send_task|apply_async|delay|basic_publish|pika` (`**/RabbitMQ/**/*.py`), 36 results

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/scan_worker.py#1-1), lines 1 to 260

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/scan_worker.py#261-261), lines 261 to 620

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/dast_worker.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/guardrail_worker/guardrail_worker.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/backend/utilities/scan/start_scan.py)

Searched for regex `def start_scan_and_update_db|send_task\(|scan_worker\.sast|scan_worker\.iac|scan_worker\.sbom_sca|scan_worker\.mcp_scan|scan_worker\.llm_benchmark_scan|dast_worker\.dast` (`**/backend/utilities/scan/start_scan.py`), 13 results

Searched for regex `@router.post\("/\{team_id\}/\{type\}/scan|@router.get\("/\{team_id\}/\{type\}/scan/\{scan_id\}|start_scan_and_update_db|get_status_and_update_db|create_ticket|finding` (`**/backend/routers/scans.py`), 54 results

Searched for regex `def get_status_and_update_db|AsyncResult|create_findings_in_mongo_db|scan_findings|message_log|active_context` (`**/backend/utilities/celery/celery_connection.py`), 7 results

Searched for regex `def create_findings_in_mongo_db|scan_type ==|insert_one|insert_many|ScanFindings|owasp_top_10` (`**/backend/utilities/celery/create_findings.py`), 18 results

Searched for regex `def format_input_for_scan|repo_dict_context|zip_dict_context|file_dict_context|mcp_dict_context|llm_benchmark_dict_context|dast_dict_context` (`**/backend/utilities/scan/format_input.py`), 11 results

Searched for regex `def estimate_credits|send_task\(|_estimation|scan_worker|dast_worker` (`**/backend/utilities/scan/estimate_scan.py`), 25 results

I’ve got the worker entry points; next I’m drilling into each agent implementation to separate the deterministic scanner steps from the LLM/RAG layers and to see which scan types do not use vectors at all.

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/scan_worker.py#320-320), lines 320 to 620

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/helpers/tools/llm_agent/main.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/helpers/tools/iac_agent/main.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/helpers/tools/mcp_agent/main.py)

I’ve separated worker-level orchestration from agent logic; the last missing piece is how API requests create/poll scans and how DAST works internally, then I can lay out the full request-to-result timeline for every scan family.

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/backend/routers/scans.py#1-1), lines 1 to 360

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/agent/main.py)

I have the main DAST agent, but some helper paths differ from what I expected; I’m listing that subtree to resolve the actual XSS/SQLi/check modules before I summarize the DAST internals.

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/agent)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/checks)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/crawler)

I found the actual DAST helper layout; the next read is focused on whether those DAST checks use LLMs, rule engines, or plain heuristics so I can explain the split accurately.

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/agent/BaseUtilities.py#1-1), lines 1 to 260

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/agent/xss_agent.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/agent/sqli_agent.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/checks/page_analysis.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/checks/security_headers.py)

The remaining gap is the dispatch layer from API to Celery and the scanner helper implementations like Grype and Garak; after that I can give you a precise “scanner first, LLM second” breakdown with examples.

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/backend/utilities/scan/start_scan.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/backend/utilities/celery/celery_connection.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/helpers/tools/llm_agent/llm_runner.py#1-1), lines 1 to 280

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/worker/helpers/tools/sca_sbom_agent/grype.py)

Read [](file:///Users/anshsinghal/Library/Application%20Support/Code/User/workspaceStorage/b9d13f7650824c77697ac63e3f90af57/GitHub.copilot-chat/chat-session-resources/0afdb5d1-64c9-4ade-ad41-e187b632908c/call_OHbRRU5h5sohwsZZM7VACgZO__vscode-1775101016705/content.txt#1-1), lines 1 to 260

I’ve pinned down the main scan families. I’m doing one final read of the DAST agent graph because that path is the most LLM-heavy and the exact sequence matters for explaining why the model is there at all.

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/checks/nuclei/run_nuclei.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/agent/agent_graph.py)

Read [](file:///Users/anshsinghal/Desktop/DevSecShield/RabbitMQ/dast_worker/helpers/agent/utils.py)

I traced the codebase from API route to Celery worker to tool runner to result storage, and the cleanest way to understand it is this:

This project is not using one single “AI scan engine.” It has three different patterns.

1. Tool-first, then LLM interpretation
2. LLM-first or LLM-agentic generation of test logic
3. Pure metadata/schema reasoning with LLM

The important part is that embeddings and the vector store are not used everywhere. In the code I found, they are used mainly in the SAST pipeline, not across all scan types.

**Big Picture**
A scan normally follows this lifecycle:

1. The frontend creates a scan record through scans.py.
2. The backend starts the worker task through start_scan.py.
3. That function dispatches a Celery task by scan type:
   SAST, IaC, SBOM/SCA, MCP, LLM benchmark go to scan_worker.py.
   DAST goes to dast_worker.py.
   Guardrails goes to guardrail_worker.py.
4. Celery stores task state and final result in Mongo because the Celery backend is Mongo in celery_connection.py.
5. When the frontend polls scan status, celery_connection.py reads the Celery result, copies the result into the main Scan row in Postgres, and creates findings in Mongo.
6. Post-scan chat messages are stored in Mongo in message_log and active_context via scans.py.

So the storage roles are:

- Postgres: main scan record, team/user ownership, scan lifecycle
- MongoDB: Celery result backend, chat history, active context, findings/log-style documents
- Qdrant: temporary vector retrieval store for scan-time retrieval

**The Most Important Concept: Why Embeddings Exist Here**
Embeddings are only useful if you want semantic retrieval.

In this code, embeddings are created in base_utilities.py using OpenAI text-embedding-3-small.

The reason is:

A logical component like “authentication and session flow” may be described in natural language. The exact relevant code may be spread across:
- an auth router
- a JWT helper
- a middleware
- maybe a password utility

Keyword matching is weak for that. Embeddings let the system search semantically, not just by exact words.

So the low-level purpose of embeddings in this project is:

- convert code chunks or scan-result chunks into vectors
- put them into Qdrant
- later ask for the chunks most relevant to a logical component description
- give only those chunks to the LLM

That is the RAG part.

Without embeddings, the model would either:
- get the whole repo dumped into the prompt, which is too large and noisy
- or rely on naive string matching, which misses related code

**Where The Vector Store Is Actually Used**
The vector store is created in base_utilities.py through QdrantVectorStore.

The active collections I verified are:

- codebase_context
- open_source_context

Those are created and used in:
- codebase_context.py
- open_source_context.py

The retrieval query happens in base_agent.py.

The code filters by context_id, which means each scan run gets its own temporary retrieval space. This is not a big permanent knowledge base. It is a per-scan retrieval cache.

That is why I would describe Qdrant here as:
“temporary semantic context storage for active scans.”

**Exact Flow Of Each Scan Type**

**1. SAST**
This is the most RAG-heavy pipeline in the repo.

Main files:
- scan_worker.py
- main.py
- semgrep_util.py
- codebase_context.py
- open_source_context.py
- base_context.py
- base_agent.py

Low-level flow:

1. API starts scan.
2. Celery task sast in scan_worker.py validates repo or zip input.
3. SASTAgent is created in main.py.
4. The repo is cloned or zip extracted.
5. First, it builds the “open source context”:
   it calls Semgrep through semgrep_util.py.
6. Semgrep returns JSON results.
7. Those results are chunked and saved into Qdrant as open_source_context through open_source_context.py.
8. Then it builds the “codebase context”:
   source files are loaded, filtered, chunked in codebase_context.py.
9. Those code chunks are embedded and stored in Qdrant as codebase_context.
10. Then it runs a map-reduce summary on the codebase through base_context.py to create logical components.
11. For each logical component, it creates a natural-language query like:
   “Find the code snippets corresponding to the logical component given below”
12. That query is run against:
   - the codebase_context collection
   - the open_source_context collection
13. The relevant retrieved chunks are formatted into prompt context.
14. Then the LLM is called to generate structured vulnerabilities for that logical component.
15. Results are aggregated, cleaned up, and Qdrant documents are deleted.

Why Semgrep is used:
Semgrep is the raw static scanner. It finds suspicious patterns quickly and deterministically.

Why the vector store is used:
Because the LLM should not read the entire repository every time it analyzes one component. Qdrant helps fetch only the most relevant code and Semgrep findings.

Why the LLM is used:
Two reasons.
- First, to summarize the whole codebase into logical components.
- Second, to reason over “code snippets + Semgrep findings + component description” and produce structured human-usable vulnerability output.

Example:
Suppose the repo has an auth module split across multiple files.
Semgrep might flag one dangerous pattern in a token helper.
But the real issue may depend on how the router, middleware, and helper work together.
The RAG step retrieves those related files.
The LLM then says something like:
“This is an authentication flow vulnerability because token validation is missing in this middleware path and Semgrep also found weak usage in the helper.”

So in SAST:
- Semgrep = raw signal
- Embeddings = semantic indexing
- Qdrant = retrieval store
- LLM = architectural reasoning + final vulnerability writing

This is the clearest example of actual RAG in the repo.

**2. SBOM / SCA**
Main files:
- scan_worker.py
- main.py
- grype.py

Low-level flow:

1. API dispatches the sbom_sca task.
2. SCASBOMAgent clones a repo, extracts zip, or reads an SBOM file.
3. If scanning a directory, it runs Grype in grype.py.
4. Grype returns dependency vulnerability JSON.
5. The agent parses those results into strings.
6. It groups findings into text documents.
7. It runs map-reduce summarization with the LLM.
8. The output is structured dependency vulnerabilities.

Important difference from SAST:
This path does not actively use the vector store in the normal flow I verified.

It uses OpenSourceContext as a convenience wrapper for running the tool and holding documents, but it does not rely on Qdrant retrieval in the main SBOM path.

Why Grype is used:
Grype is the actual package vulnerability engine.

Why the LLM is used:
Not to discover CVEs from scratch.
It is used to:
- compress many raw Grype findings
- rewrite them into structured vulnerability objects
- merge duplicate or related dependency issues into cleaner reporting

Example:
Grype may return ten package findings with CVEs and versions.
The LLM turns that into a higher-level report like:
“Your Python dependency graph contains vulnerable versions of package X and Y, creating remote code execution and deserialization risk.”

So in SBOM/SCA:
- Grype = raw scanner
- No meaningful RAG step in current active flow
- LLM = summarization and structuring

**3. IaC**
Main files:
- scan_worker.py
- main.py
- codebase_context.py

Low-level flow:

1. API dispatches iac.
2. IACAgent clones or extracts repo input.
3. It builds include rules for Terraform, Kubernetes YAML, Helm, Pulumi, CloudFormation, CDK, and similar depending on context.
4. It loads only matching IaC files through CodebaseContext.
5. It does not store them in Qdrant in the main path.
   The code explicitly calls prepare_context with load_documents_to_vector_store set to False.
6. It runs an LLM map-reduce summary through IACSummaryManager to produce IaC vulnerabilities.
7. It runs a second LLM summary through IACDiagramSummaryManager to generate an architecture description.
8. That description is turned into a dependency diagram.

So IaC in this repo is not “run tfsec and then summarize.”
It is much more LLM-led on the file contents themselves.

Why no vector store here:
The implementation is not doing semantic retrieval per component. It just loads the relevant IaC files and sends them through map-reduce summarization.

Why the LLM is used:
- detect misconfiguration patterns in the IaC text
- summarize risk
- infer architecture and dependency relationships for the diagram

Example:
For Terraform files, the model may read:
- S3 bucket config
- IAM policy
- security group
and output:
“Public bucket exposure with permissive security group and missing encryption.”

So in IaC:
- File filtering is deterministic
- No active embeddings/vector retrieval in the main path
- LLM does the actual analysis and architecture summarization

**4. LLM Benchmark**
Main files:
- scan_worker.py
- main.py
- llm_runner.py

Low-level flow:

1. API dispatches llm_benchmark_scan.
2. LLMBenchmarkingAgent creates an OpenSourceContext around the Garak runner.
3. Garak is run by llm_runner.py.
4. Garak sends adversarial probes to the target model endpoint.
5. Garak outputs summary metrics like hit rate, probes used, risk level, total tests, and per-probe results.
6. The agent then sends those Garak results to the LLM summarizer.
7. The LLM produces:
   - a vulnerability list
   - a model_vulnerabilities summary

Important conceptual point:
In this pipeline, there are two LLMs involved in two very different roles.

- The target model being attacked by Garak
- Your own OpenAI-based LLM that summarizes Garak’s results

So this scan is “LLM scanning another LLM system,” but the scanner itself is Garak first, summarizer second.

Why Garak is used:
Garak is the actual adversarial probe engine.

Why the LLM is used:
To turn Garak’s raw measurements into a readable vulnerability report.

Why no vector store:
This path does not need code retrieval. It is summarizing benchmark output.

Example:
Garak may show high hit rate on prompt injection probes and low rate on benign probes.
The summarizer then writes:
“This target model is vulnerable to prompt injection and malware-generation probes at a high rate.”

So in LLM Benchmark:
- Garak = actual test runner
- No Qdrant
- No embeddings
- LLM = result summarizer

**5. MCP Scan**
Main files:
- scan_worker.py
- main.py

Low-level flow:

1. API dispatches mcp_scan.
2. MCPAgent connects to the MCP server via MCPClient.
3. It fetches recon context:
   tools, prompts, resources.
4. For each tool, prompt, and resource, it calls the LLM to:
   - generate vulnerabilities
   - classify category and risk level
5. It returns structured findings grouped by tools, prompts, and resources.

There is no vector store here.
There are no embeddings in the active path.

Why the LLM is used:
Because this is a schema- and metadata-reasoning problem.
The model reads:
- tool description
- input schema
- output schema
- resource properties
and then infers the security risks.

Example:
If an MCP tool allows arbitrary file read or shell execution with permissive input schema, the model can flag dangerous capability exposure.

So in MCP:
- MCP client = recon collector
- No scanner like Semgrep or Grype
- No embeddings
- LLM = primary analysis engine

**6. DAST**
Main files:
- dast_worker.py
- main.py
- agent_graph.py
- security_headers.py
- page_analysis.py
- run_nuclei.py
- xss_agent.py
- sqli_agent.py
- utils.py

This is the most agentic scan in the repo.

Low-level flow:

1. API dispatches dast.
2. DASTAgent validates auth and target config.
3. It crawls the site to get URLs.
4. For each URL it runs several checks.

The checks are different in character.

Security headers check:
- uses Playwright to load the page
- reads HTTP response headers
- produces a raw list of findings
- then sends those findings to the LLM to generate structured vulnerabilities

Page analysis check:
- creates a Nuclei login and navigation template
- runs Nuclei headless
- loads the resulting page/HTML artifacts as documents
- sends them to the LLM map-reduce summarizer
- gets structured page-level vulnerabilities

XSS agent:
- gets page content using Nuclei-assisted page fetch logic
- builds an auth-and-navigation template
- asks the LLM to generate an attack strategy
- asks the LLM to generate a headless Nuclei template
- asks the LLM to validate that YAML template
- executes the template with Nuclei
- summarizes resulting evidence with the LLM

SQLi agent:
- same pattern as XSS but for SQL injection

This is not classic ZAP-only DAST.
This is:
- crawler + browser
- Nuclei execution
- LLM-generated exploit strategy
- LLM-generated test templates
- LLM-generated vulnerability summaries

Why the LLM is used here:
Because the system is dynamically creating test logic from page content.

Why no vector store:
The scan is acting on live page state, HTML, and generated templates, not on a reusable semantic code corpus.

Example:
Suppose a page has a comment form and weak output escaping.
The XSS agent:
- captures page HTML
- asks the LLM how to attack it
- asks the LLM to generate a Nuclei headless template that logs in, navigates, injects alert payload, waits for reflection, and verifies impact
- runs that template
- summarizes the evidence as an XSS vulnerability

So in DAST:
- crawler/browser/Nuclei = execution layer
- LLM = strategy generator, template generator, validator, summarizer
- no embeddings
- no Qdrant

**7. Guardrails**
Main file:
- guardrail_worker.py

This one is different again.

Low-level flow:

1. Input prompt and guardrail config arrive.
2. Guardrail worker validates context.
3. It runs llm-guard based checks.
4. Optionally creates ticketing issues.

This path is not a vector pipeline.
It is also not primarily an OpenAI reasoning pipeline in the same way as SAST or DAST.

It is more like:
policy/security filter execution on prompts.

So guardrails is:
- deterministic guard layer
- Mongo-backed logs
- optional Jira ticketing
- not RAG

**What Is Actually Using Embeddings Right Now**
Based on the active code paths I verified:

- SAST: yes
- SBOM/SCA: no active vector retrieval in the normal path
- IaC: no
- LLM benchmark: no
- MCP: no
- DAST: no
- Guardrails: no

So if you are trying to understand “where embeddings are used,” the real answer is:
mostly the SAST pipeline.

That is the place where semantic retrieval matters because the project is trying to connect:
- a logical component description
- code snippets
- Semgrep findings

**Why LLM Is Used In So Many Different Places**
The project uses LLMs for four different jobs.

1. Summarization
Used in SBOM/SCA, IaC, LLM benchmark, DAST page analysis.
Purpose:
turn lots of raw raw output into structured vulnerability objects.

2. Structural decomposition
Used in SAST.
Purpose:
break the codebase into logical components before detailed analysis.

3. Semantic reasoning over retrieved context
Used in SAST.
Purpose:
take code snippets plus Semgrep results and infer deeper vulnerability relationships.

4. Agentic test generation
Used in DAST XSS and SQLi.
Purpose:
generate strategies and Nuclei templates tailored to the actual page.

That is why the code can feel confusing. “LLM” is not one thing in this repo. It plays several roles.

**The Exact Role Of Qdrant In One Sentence**
Qdrant is not being used as permanent memory for the product.
It is being used as temporary semantic lookup storage so the SAST agent can fetch the most relevant code and Semgrep chunks for one scan run.

**The Exact Role Of MongoDB In One Sentence**
MongoDB is being used as the flexible document/log/result store and as Celery’s result backend, not as the main vector store.

**Two Scan Types Exist In Schema But Are Not Fully Wired In The Active Flow**
I also found that new_models.py declares scan types including leakage and agent_discovery, but the active task dispatch in start_scan.py only routes:
- sast
- iac
- sbom_sca
- mcp
- llm
- dast

And in scan_worker.py, the discovery task is commented out. So those two appear declared in the data model but not fully active in the current worker flow.

**If You Want The Simplest Mental Model**
Use this:

- SAST = Semgrep + Qdrant + embeddings + LLM
- SBOM/SCA = Grype + LLM
- IaC = file filtering + LLM
- LLM benchmark = Garak scans a target model + LLM summarizes results
- MCP = schema recon + LLM reasoning
- DAST = crawler/browser/Nuclei + LLM-generated exploit logic
- Guardrails = prompt-policy checks, mostly not RAG

**One Concrete Example End To End: SAST**
1. User starts a Python SAST scan.
2. Repo is cloned.
3. Semgrep scans the repo.
4. Semgrep JSON is chunked and embedded into Qdrant.
5. Python files are loaded, chunked, and embedded into Qdrant.
6. LLM summarizes the repo into logical components, for example:
   Authentication
   Billing
   File upload
7. For Authentication, the system builds a semantic query from that component description.
8. Qdrant returns the most relevant code chunks plus the most relevant Semgrep chunks.
9. LLM reads those and outputs structured vulnerabilities.
10. Results go back through Celery, then are stored in Postgres and findings in Mongo.

**One Concrete Example End To End: DAST**
1. User starts a DAST scan against a login-protected site.
2. Crawler discovers URLs.
3. For one page, the system fetches page content.
4. LLM writes an XSS attack strategy from the HTML.
5. LLM writes a Nuclei headless template using that strategy plus the login/navigation template.
6. LLM validates the YAML.
7. Nuclei executes the template.
8. Result documents are summarized by the LLM into vulnerabilities.
9. Findings return through Celery and are surfaced in the scan result.

If you want the next best step, I can do one of these:

1. Draw a single end-to-end flowchart for the whole system.
2. Draw separate sequence diagrams for SAST, DAST, SBOM/SCA, IaC, MCP, and LLM benchmark.
3. Make a “which parts are deterministic tool logic vs which parts are LLM logic” matrix for the whole project.