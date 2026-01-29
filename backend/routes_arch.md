## Routes to Restructure

note: add /{team_id}/ to the routes to make them org specific . 

**Conversations** *( major changes in database structure )*

Path param `{type}`: sast, llm, mcp, iac, leakage, sbom_sca, agent_discovery, dast.
- GET `/{type}/conversations` — List all scan conversations
- POST `/{type}/conversation` — Create a new scan conversation
- POST `/{type}/conversation/{conversation_id}/message` — Send a message to a scan conversation
- GET `/{type}/conversation/{conversation_id}` — Get the scan status of a scan conversation
- POST `/{type}/conversation/{conversation_id}/scan` — Start a scan
- DELETE `/{type}/conversation/{conversation_id}` — Delete a scan conversation
- PUT `/{type}/conversation/{conversation_id}` — Update a scan conversation (e.g. rename)
- GET `/{type}/conversation/{conversation_id}/export` — Export the results of a scan conversation
- POST `/{type}/conversation/{conversation_id}/reinitialize` — Reinitialize a scan

**Guardrails**  *( no major changes in database structure , only need to use the APIRouter for these routes )*

- GET `/guardrails/integrations` — List all guardrails integrations
- POST `/guardrails/integration` — Create a new guardrails integration
- GET `/guardrails/integration/{integration_id}` — Get a guardrails integration
- PUT `/guardrails/integration/{integration_id}` — Update a guardrails integration
- DELETE `/guardrails/integration/{integration_id}` — Delete a guardrails integration
- GET `/guardrails/integration/{integration_id}/settings` — Get the integration settings of all the scanners in the integration

**Guardrails public**  *( no major changes in database structure , only need to use the APIRouter for these routes )*

- POST `/public/guardrails/start_scan` — Start a new guardrails scan
- GET `/public/guardrails/{scan_id}` — Get the status of a guardrails scan

**CI/CD**  *( no major changes in database structure , only need to use the APIRouter for these routes and need to handle the changes with respect to the worker outputs , no actual changes in architecture  )*

Path param `{type}`: sast, llm, mcp, iac, leakage, sbom_sca, agent_discovery.
- POST `/cicd/{type}/scan` — Run a new cicd scan
- GET `/cicd/log/{log_id}` — Get a cicd log
- GET `/cicd/integrations` — List all cicd integrations
- POST `/cicd/integration` — Create a new cicd integration
- GET `/cicd/integration/{integration_id}` — Get a cicd integration
- PUT `/cicd/integration/{integration_id}` — Update a cicd integration
- DELETE `/cicd/integration/{integration_id}` — Delete a cicd integration 



## Routes to Add 

**Team**  


