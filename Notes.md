## Use these Repos:

1. SAST and IAC Scanning:

SAST
- https://github.com/semgrep/semgrep 🟩 ✔️✔️ Implemented function ✔️✔️ Docker tested

```semgrep --config "p/python" --verbose --json --output semgrep_result.json backend```

    app rulesets supported :
    1. c
    2. java 
    3. php
    4. ruby 
    5. rust 
    6. swift
    7. python
    8. csharp 
    9. kotlin
    10. javascript

IAC 
- https://github.com/bridgecrewio/checkov
- https://github.com/aquasecurity/tfsec 🟩 ✔️✔️ Implemented function ✔️✔️ Docker tested

```tfsec . --format json --out tfsec_output.json```
https://github.com/aquasecurity/tfsec/blob/master/tfsec-to-trivy-migration-guide.md  (tfsec to trivy migration)


2. Code and Data leakage monitoring:
- https://github.com/gitleaks

3. Web Vulnerability Detection :
- https://github.com/usestrix/strix

4. SBOM Scanning :
- https://github.com/anchore/grype 🟩  ✔️✔️ Implemented function ✔️✔️ Docker tested

```grype dir:. --output json --file test.json```

5. Agent discovery:
- https://github.com/yacwagh/double-trust

6. LLM Benchmarking:
- https://github.com/NVIDIA/garak 🟩 ✔️✔️ Implemented function ✔️✔️ Docker tested
- Python 3.13.5 only works for this godamn thing 🔴



7. MCP Scanning ( remote and local )
- https://github.com/invariantlabs-ai/mcp-scan 🟩 ✔️✔️ Implemented function ✔️✔️ Docker tested

```uvx mcp-scan C:\Users\HP\Desktop\MCPTest\time_mcp.json --json --opt-out --verbose  --storage-file mcp_results```

Notes:
- MCP Severs have a server config file in JSON , that gets run in order to start an MCP server
- this JSON file is what gets extracted by the scanner and then it runs the server using this config and makes requests to it , to get information about the tools available and some metadata about them.
- for local MCP server scans , they must have a config file in their repo , that the scanner will detect and scan 
- for remote scans ( MCP Servers listed in MCP.so ), the server configs for each server is listed on their site MCP.so . We need to find a way to give this config file to the scanner to start the server and scan it . The most probable way would be to ask the user to copy and paste the config file into the text area . 

Lable values 
1 -> low 
2 -> High 
3 -> Critical

Sidenotes:
- those weird characters that show up in the description fields as strings , is somethign you cannot solve because that was present in the raw string that was read too .




## Notes:
- A project must can be associated to atleast 1 editor users and optionally viewer users ( just send a mail to the user saying they have a project waiting for them )