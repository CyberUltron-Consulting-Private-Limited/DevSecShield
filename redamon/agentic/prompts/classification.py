"""
RedAmon Attack Path Classification Prompt

LLM-based classification of user intent to select the appropriate attack path and phase.
Determines both the attack methodology AND the required phase (informational/exploitation).
"""


ATTACK_PATH_CLASSIFICATION_PROMPT = """You are classifying a penetration testing request to determine:
1. The required PHASE (informational vs exploitation)
2. The ATTACK PATH TYPE (for exploitation requests only)

## Phase Types

### informational
- Reconnaissance, OSINT, information gathering
- Querying the graph database for targets, vulnerabilities, services
- Scanning and enumeration without exploitation
- Example requests:
  - "What vulnerabilities exist on 10.0.0.5?"
  - "Show me all open ports on the target"
  - "What services are running?"
  - "Query the graph for CVEs"
  - "Scan the network"
  - "What technologies are used?"

### exploitation
- Active exploitation of vulnerabilities
- Brute force / credential attacks
- Any request that involves gaining unauthorized access
- Example requests:
  - "Exploit CVE-2021-41773"
  - "Brute force SSH"
  - "Try to crack the password"
  - "Pwn the target"
  - "Try SQL injection on the web app"

## Attack Path Types (ONLY for exploitation phase)

### cve_exploit
- Exploiting known CVE vulnerabilities
- Using Metasploit exploit modules (`exploit/*`)
- Keywords: CVE-XXXX-XXXX, MS17-XXX, vulnerability, exploit, RCE, remote code execution, pwn, hack
- Requires: TARGET selection, PAYLOAD selection
- Command: `exploit`
- Example requests:
  - "Exploit CVE-2021-41773 on 10.0.0.5"
  - "Use the Apache path traversal vulnerability"
  - "Attack the target using MS17-010"
  - "Test if the server is vulnerable to Log4Shell"

### brute_force_credential_guess
- Password guessing / credential attacks
- Using THC Hydra for password brute-forcing (`execute_hydra`)
- Keywords: brute force, crack password, credential attack, dictionary attack, password spray, guess password, wordlist, login attack
- Services: SSH, FTP, RDP, VNC, SMB, MySQL, MSSQL, PostgreSQL, Telnet, POP3, IMAP, HTTP login, Tomcat
- Requires: wordlists/credential files
- Tool: `execute_hydra` (NOT metasploit_console)
- Example requests:
  - "Brute force SSH on 10.0.0.5"
  - "Try to crack the MySQL password"
  - "Password spray against the FTP server"
  - "Guess credentials for the Tomcat manager"
  - "Dictionary attack on the SSH service"
  - "Try default credentials on PostgreSQL"
  - "Try to get access to SSH guessing password"

### phishing_social_engineering
- Social engineering attacks, phishing campaigns, payload delivery to humans
- Generating malicious payloads, documents, or links for delivery to targets
- Using msfvenom for payload generation (exe, elf, apk, war, python, powershell, bash)
- Generating malicious documents (Word macro, Excel macro, PDF exploit, RTF, LNK, HTA)
- Web delivery attacks (exploit/multi/script/web_delivery)
- Email phishing campaigns with crafted payloads or links
- Keywords: phish, phishing, social engineering, spear phishing, payload generation, malicious document, macro, msfvenom, trojan, dropper, email attack, fake email, web delivery, hta, office macro, backdoor, implant, campaign, lure, bait, send email, craft email, generate payload, malicious file, reverse shell payload, create backdoor
- Tools: `kali_shell` (msfvenom), `metasploit_console` (fileformat modules, handler, web_delivery), `execute_code` (email sending)
- Example requests:
  - "Generate a phishing payload for Windows"
  - "Create a malicious Word document with a macro"
  - "Set up a web delivery attack"
  - "Send a phishing email with a backdoor to target@example.com"
  - "Create an HTA delivery server"
  - "Generate an APK backdoor for Android"
  - "Craft a spear phishing campaign"
  - "Create a trojanized PDF"
  - "Generate a reverse shell executable"
  - "Create a malicious Excel file with a macro"

### <descriptive_term>-unclassified
- ANY exploitation request that does NOT clearly fit cve_exploit or brute_force_credential_guess
- The agent has no specialized workflow for these — it will use available tools generically
- You MUST create a short, descriptive snake_case term followed by "-unclassified"
- Format: `<term>-unclassified` where term is 1-4 lowercase words joined by underscores
- Example values: "sql_injection-unclassified", "dos_attack-unclassified", "ssrf-unclassified", "xss-unclassified", "file_upload-unclassified", "command_injection-unclassified", "directory_traversal-unclassified"
- Keywords: SQL injection, XSS, cross-site scripting, directory traversal, path traversal, DoS, denial of service, SSRF, file upload, command injection, LFI, RFI, deserialization, XXE, privilege escalation
- Example requests:
  - "Try SQL injection on the web app" -> "sql_injection-unclassified"
  - "Test for SSRF on the API" -> "ssrf-unclassified"
  - "Try to upload a web shell" -> "file_upload-unclassified"
  - "Test for XSS on the login page" -> "xss-unclassified"
  - "Attempt directory traversal" -> "directory_traversal-unclassified"

## User Request
{objective}

## Instructions
Classify the user's request:

1. First determine the REQUIRED PHASE:
   - Is this a reconnaissance/information gathering request? -> "informational"
   - Is this an active attack/exploitation request? -> "exploitation"

2. If exploitation, determine the ATTACK PATH TYPE:
   - Does the request mention a CVE or specific vulnerability ID? -> "cve_exploit"
   - Does the request mention password guessing, brute force, or credential attacks? -> "brute_force_credential_guess"
   - Does the request target a login service (SSH, FTP, MySQL, etc.) with credential-based attack? -> "brute_force_credential_guess"
   - Does the request mention exploit modules or payloads? -> "cve_exploit"
   - Does the request mention wordlists or dictionaries? -> "brute_force_credential_guess"
   - Does the request mention phishing, social engineering, payload generation, malicious documents, msfvenom, trojans, backdoors, email attacks, or crafting bait? -> "phishing_social_engineering"
   - Does the request describe a specific attack technique (SQLi, XSS, SSRF, DoS, file upload, etc.) that doesn't fit cve_exploit, brute_force, or phishing? -> "<descriptive_term>-unclassified"
   - Default to "cve_exploit" if truly unclear (e.g., vague "hack the target")

3. If informational, set attack_path_type to "cve_exploit" (default, won't be used)

4. Extract TARGET HINTS from the request (best-effort, used for graph linking):
   - target_host: IP address or hostname mentioned (e.g., "10.0.0.5", "www.example.com"). null if none found.
   - target_port: port number mentioned (e.g., 8080, 443). null if none found.
   - target_cves: list of CVE IDs mentioned (e.g., ["CVE-2021-41773"]). Empty list if none found.

Output valid JSON matching this schema:

```json
{{
  "required_phase": "informational" | "exploitation",
  "attack_path_type": "cve_exploit" | "brute_force_credential_guess" | "phishing_social_engineering" | "<descriptive_term>-unclassified",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of the classification",
  "detected_service": "ssh" | "ftp" | "mysql" | "mssql" | "postgres" | "smb" | "rdp" | "vnc" | "telnet" | "tomcat" | "http" | null,
  "target_host": "10.0.0.5" | "www.example.com" | null,
  "target_port": 8080 | null,
  "target_cves": ["CVE-2021-41773"] | []
}}
```

Notes:
- `required_phase` determines if this is reconnaissance ("informational") or active attack ("exploitation")
- `attack_path_type` is only relevant when required_phase is "exploitation"
- For unclassified paths, the term MUST be lowercase snake_case followed by "-unclassified" (e.g., "sql_injection-unclassified")
- `detected_service` should only be set for brute_force_credential_guess, null otherwise
- `confidence` should be 0.9+ if the intent is very clear, 0.6-0.8 if somewhat ambiguous
- `target_host`, `target_port`, `target_cves` are best-effort extraction — null/empty if not mentioned
"""
