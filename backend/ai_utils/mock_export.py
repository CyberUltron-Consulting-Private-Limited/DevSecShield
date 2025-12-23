mock_export_results = {
    "vulnerabilities": [
        {
            "name": "Path Traversal Vulnerability in File Upload",
            "description": "The application builds a file path from potentially untrusted user input without proper validation. An attacker can manipulate the path to access files outside the intended directory, potentially leading to unauthorized file access, data exfiltration, or arbitrary file overwrites.",
            "cves": [
                {
                    "cve_id": "CVE-2021-44228",
                    "description": "Path traversal vulnerability allowing unauthorized file system access through user-controlled input.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-22",
                    "description": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_normal_sys.py:79\n            with open(path, \"wb\") as file:",
            "severity": "High",
            "fix": "Implement proper path validation using os.path.abspath() and os.path.commonpath() to ensure the resolved path stays within the allowed directory. Use secure_filename() from werkzeug.utils or similar sanitization functions. Consider using FastAPI's :path annotation for automatic path sanitization."
        },
        {
            "name": "SQL Injection in User Authentication",
            "description": "The application constructs SQL queries by directly concatenating user input without parameterization. This allows attackers to inject malicious SQL code that can bypass authentication, extract sensitive data, or modify database contents.",
            "cves": [
                {
                    "cve_id": "CVE-2023-12345",
                    "description": "SQL injection vulnerability in authentication mechanism allowing unauthorized access.",
                    "severity": "Critical"
                },
                {
                    "cve_id": "CWE-89",
                    "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    "severity": "Critical"
                }
            ],
            "code_snippet_or_location": "backend/auth_utils.py:45\n            query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
            "severity": "Critical",
            "fix": "Use parameterized queries or prepared statements. Replace string concatenation with ORM methods or parameterized SQL queries. Example: Use SQLAlchemy's session.query() with filter() or execute() with named parameters."
        },
        {
            "name": "Cross-Site Scripting (XSS) in User Comments",
            "description": "User-supplied input is rendered in HTML responses without proper sanitization or encoding. Attackers can inject malicious JavaScript code that executes in other users' browsers, potentially stealing session cookies, performing actions on behalf of users, or defacing the application.",
            "cves": [
                {
                    "cve_id": "CVE-2022-23456",
                    "description": "Stored Cross-Site Scripting vulnerability allowing persistent script injection.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-79",
                    "description": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "frontend/components/comment.tsx:23\n            <div dangerouslySetInnerHTML={{__html: comment.content}} />",
            "severity": "High",
            "fix": "Escape all user input before rendering. Use React's built-in escaping (default behavior) or libraries like DOMPurify for sanitization. Never use dangerouslySetInnerHTML with user-controlled content. Implement Content Security Policy (CSP) headers."
        },
        {
            "name": "Insecure Direct Object Reference (IDOR)",
            "description": "The application exposes internal object references (such as database IDs) in URLs or API endpoints without proper authorization checks. Attackers can manipulate these references to access resources belonging to other users.",
            "cves": [
                {
                    "cve_id": "CVE-2023-34567",
                    "description": "Insecure direct object reference allowing unauthorized resource access.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-639",
                    "description": "Authorization Bypass Through User-Controlled Key",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_admin.py:112\n            user_data = db.get_user_by_id(user_id)",
            "severity": "High",
            "fix": "Implement proper authorization checks before accessing resources. Verify that the authenticated user has permission to access the requested resource. Use indirect object references or access control lists (ACLs) instead of direct database IDs."
        },
        {
            "name": "Hardcoded API Keys and Secrets",
            "description": "Sensitive credentials such as API keys, database passwords, and secret tokens are hardcoded directly in the source code. These secrets can be exposed through version control systems, code repositories, or reverse engineering.",
            "cves": [
                {
                    "cve_id": "CVE-2022-45678",
                    "description": "Exposure of sensitive credentials in source code.",
                    "severity": "Critical"
                },
                {
                    "cve_id": "CWE-798",
                    "description": "Use of Hard-coded Credentials",
                    "severity": "Critical"
                }
            ],
            "code_snippet_or_location": "backend/config.py:8\n            API_KEY = \"sk_live_1234567890abcdef\"",
            "severity": "Critical",
            "fix": "Move all secrets to environment variables or secure secret management systems (AWS Secrets Manager, HashiCorp Vault, etc.). Use .env files for local development (and ensure they're in .gitignore). Never commit secrets to version control."
        },
        {
            "name": "Weak Password Hashing Algorithm",
            "description": "The application uses weak hashing algorithms (MD5, SHA1) or plain text storage for passwords. Weak hashing makes passwords vulnerable to rainbow table attacks and brute force attempts.",
            "cves": [
                {
                    "cve_id": "CVE-2023-56789",
                    "description": "Use of cryptographically weak password hashing algorithm.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-916",
                    "description": "Use of Password Hash With Insufficient Computational Effort",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/auth_utils.py:78\n            password_hash = hashlib.md5(password.encode()).hexdigest()",
            "severity": "High",
            "fix": "Use bcrypt, argon2, or scrypt for password hashing with appropriate cost factors. Use libraries like passlib or werkzeug.security.generate_password_hash() which use bcrypt by default. Never use MD5, SHA1, or SHA256 for password hashing."
        },
        {
            "name": "Missing CSRF Protection",
            "description": "State-changing operations (POST, PUT, DELETE requests) lack Cross-Site Request Forgery (CSRF) protection. Attackers can trick authenticated users into performing unintended actions by crafting malicious requests.",
            "cves": [
                {
                    "cve_id": "CVE-2022-67890",
                    "description": "Missing CSRF token validation in state-changing operations.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-352",
                    "description": "Cross-Site Request Forgery (CSRF)",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_admin.py:45\n            @app.post(\"/admin/delete_user\")",
            "severity": "Medium",
            "fix": "Implement CSRF tokens for all state-changing operations. Use frameworks' built-in CSRF protection (FastAPI-CSRF, Flask-WTF). Validate CSRF tokens on the server side for every POST, PUT, DELETE request. Use SameSite cookie attributes."
        },
        {
            "name": "Command Injection in System Calls",
            "description": "User input is directly passed to system commands or shell execution functions without proper sanitization. Attackers can inject arbitrary commands that execute with the application's privileges.",
            "cves": [
                {
                    "cve_id": "CVE-2023-78901",
                    "description": "Command injection vulnerability allowing arbitrary command execution.",
                    "severity": "Critical"
                },
                {
                    "cve_id": "CWE-78",
                    "description": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                    "severity": "Critical"
                }
            ],
            "code_snippet_or_location": "backend/utils.py:34\n            os.system(f\"ping {hostname}\")",
            "severity": "Critical",
            "fix": "Avoid using os.system(), subprocess with shell=True, or os.popen(). Use subprocess.run() with a list of arguments instead of shell commands. Validate and sanitize all input. Use allowlists for permitted commands and arguments."
        },
        {
            "name": "Insecure Deserialization",
            "description": "The application deserializes untrusted data without proper validation or sanitization. Attackers can craft malicious serialized objects that execute arbitrary code during deserialization.",
            "cves": [
                {
                    "cve_id": "CVE-2023-89012",
                    "description": "Insecure deserialization of untrusted data leading to remote code execution.",
                    "severity": "Critical"
                },
                {
                    "cve_id": "CWE-502",
                    "description": "Deserialization of Untrusted Data",
                    "severity": "Critical"
                }
            ],
            "code_snippet_or_location": "backend/serialization.py:12\n            data = pickle.loads(user_input)",
            "severity": "Critical",
            "fix": "Avoid deserializing untrusted data. Use JSON or other safe serialization formats. If deserialization is necessary, implement strict validation, use allowlists for permitted classes, and run deserialization in isolated environments with restricted permissions."
        },
        {
            "name": "Sensitive Data Exposure in Logs",
            "description": "The application logs sensitive information such as passwords, API keys, credit card numbers, or personal identifiable information (PII). This data can be exposed through log files, monitoring systems, or log aggregation services.",
            "cves": [
                {
                    "cve_id": "CVE-2022-90123",
                    "description": "Exposure of sensitive information in application logs.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-532",
                    "description": "Insertion of Sensitive Information into Log File",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": "backend/auth_utils.py:56\n            logger.info(f\"User login attempt: {username}, password: {password}\")",
            "severity": "Medium",
            "fix": "Never log sensitive data. Implement log sanitization functions to redact passwords, tokens, credit card numbers, and PII. Use structured logging with field-level filtering. Review all logging statements and remove sensitive data."
        },
        {
            "name": "Missing Security Headers",
            "description": "The application does not set important security headers such as Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security. This leaves the application vulnerable to various client-side attacks.",
            "cves": [
                {
                    "cve_id": "CVE-2023-01234",
                    "description": "Missing security headers exposing application to client-side attacks.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-693",
                    "description": "Protection Mechanism Failure",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": None,
            "severity": "Medium",
            "fix": "Implement security headers middleware. Set Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security, and Referrer-Policy. Use libraries like secure or helmet for automatic header configuration."
        },
        {
            "name": "Broken Authentication - Session Fixation",
            "description": "The application does not regenerate session identifiers after user authentication. This allows attackers to fixate a session ID and hijack user sessions after login.",
            "cves": [
                {
                    "cve_id": "CVE-2023-12345",
                    "description": "Session fixation vulnerability allowing session hijacking.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-384",
                    "description": "Session Fixation",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/auth_utils.py:89\n            # Session ID not regenerated after login",
            "severity": "High",
            "fix": "Regenerate session ID after successful authentication and privilege changes. Invalidate old session tokens. Use secure, random session identifiers. Implement proper session timeout and expiration mechanisms."
        },
        {
            "name": "XML External Entity (XXE) Injection",
            "description": "The application processes XML input without disabling external entity resolution. Attackers can exploit this to read local files, perform SSRF attacks, or cause denial of service.",
            "cves": [
                {
                    "cve_id": "CVE-2022-23456",
                    "description": "XML External Entity injection allowing local file disclosure.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-611",
                    "description": "Improper Restriction of XML External Entity Reference",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/xml_parser.py:15\n            tree = ET.parse(xml_string)",
            "severity": "High",
            "fix": "Disable external entity processing in XML parsers. Use defusedxml library for Python. Set resolve_entities=False and forbid_external=True. Prefer JSON or other safe data formats over XML when possible."
        },
        {
            "name": "Insecure Random Number Generation",
            "description": "The application uses cryptographically weak random number generators (like random.randint()) for security-sensitive operations such as session tokens, password reset tokens, or cryptographic keys.",
            "cves": [
                {
                    "cve_id": "CVE-2023-34567",
                    "description": "Use of cryptographically weak random number generator.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-330",
                    "description": "Use of Insufficiently Random Values",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": "backend/utils.py:22\n            token = ''.join(random.choices(string.ascii_letters, k=32))",
            "severity": "Medium",
            "fix": "Use cryptographically secure random number generators. In Python, use secrets.token_urlsafe(), secrets.token_hex(), or os.urandom(). Never use random module for security-sensitive operations. Use secrets module for tokens, passwords, and keys."
        },
        {
            "name": "Server-Side Request Forgery (SSRF)",
            "description": "The application makes HTTP requests to user-supplied URLs without proper validation. Attackers can exploit this to access internal services, perform port scanning, or access cloud metadata endpoints.",
            "cves": [
                {
                    "cve_id": "CVE-2023-45678",
                    "description": "Server-side request forgery allowing access to internal resources.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-918",
                    "description": "Server-Side Request Forgery (SSRF)",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/webhook.py:28\n            response = requests.get(user_provided_url)",
            "severity": "High",
            "fix": "Validate and sanitize all URLs before making requests. Use allowlists for permitted domains and protocols. Block access to private IP ranges (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Use URL parsing libraries to validate scheme and hostname."
        },
        {
            "name": "Insufficient Rate Limiting",
            "description": "The application does not implement rate limiting on authentication endpoints, API endpoints, or resource-intensive operations. This allows attackers to perform brute force attacks, credential stuffing, or denial of service.",
            "cves": [
                {
                    "cve_id": "CVE-2022-56789",
                    "description": "Missing rate limiting allowing brute force attacks.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-307",
                    "description": "Improper Restriction of Excessive Authentication Attempts",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_auth.py:34\n            @app.post(\"/login\")",
            "severity": "Medium",
            "fix": "Implement rate limiting on all authentication endpoints, API endpoints, and sensitive operations. Use libraries like slowapi, flask-limiter, or fastapi-limiter. Implement exponential backoff and account lockout mechanisms. Monitor and alert on suspicious activity."
        },
        {
            "name": "Unvalidated Redirects and Forwards",
            "description": "The application redirects users to URLs based on user-controlled input without validation. Attackers can craft malicious redirects to phishing sites or malicious domains.",
            "cves": [
                {
                    "cve_id": "CVE-2023-67890",
                    "description": "Unvalidated redirect allowing phishing attacks.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-601",
                    "description": "URL Redirection to Untrusted Site ('Open Redirect')",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_auth.py:67\n            return redirect(request.args.get('next'))",
            "severity": "Medium",
            "fix": "Validate all redirect URLs against an allowlist of permitted domains. Use relative URLs or internal route names instead of external URLs when possible. Implement a redirect token system that validates redirect destinations server-side."
        },
        {
            "name": "Insecure File Permissions",
            "description": "The application creates files or directories with overly permissive access controls (world-readable or world-writable). This can expose sensitive data or allow unauthorized modifications.",
            "cves": [
                {
                    "cve_id": "CVE-2022-78901",
                    "description": "Insecure file permissions exposing sensitive data.",
                    "severity": "Low"
                },
                {
                    "cve_id": "CWE-276",
                    "description": "Incorrect Default Permissions",
                    "severity": "Low"
                }
            ],
            "code_snippet_or_location": "backend/file_utils.py:45\n            os.chmod(file_path, 0o777)",
            "severity": "Low",
            "fix": "Set appropriate file permissions (typically 0o600 for files, 0o700 for directories). Use umask to restrict default permissions. Review all file creation operations and ensure sensitive files are not world-readable or writable."
        },
        {
            "name": "Missing Input Validation",
            "description": "User input is not properly validated before processing. This can lead to various injection attacks, buffer overflows, or application crashes when unexpected data formats are provided.",
            "cves": [
                {
                    "cve_id": "CVE-2023-89012",
                    "description": "Missing input validation allowing injection attacks.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-20",
                    "description": "Improper Input Validation",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_admin.py:123\n            user_id = request.json.get('user_id')",
            "severity": "High",
            "fix": "Implement comprehensive input validation using Pydantic models, JSON Schema, or similar validation frameworks. Validate data types, ranges, formats, and lengths. Reject invalid input rather than attempting to sanitize. Use allowlists over denylists."
        },
        {
            "name": "Insecure Cryptographic Storage",
            "description": "Sensitive data such as passwords, credit card numbers, or personal information is stored using weak encryption or without encryption at all. This exposes data if the storage is compromised.",
            "cves": [
                {
                    "cve_id": "CVE-2022-90123",
                    "description": "Insecure storage of sensitive data without proper encryption.",
                    "severity": "Critical"
                },
                {
                    "cve_id": "CWE-312",
                    "description": "Cleartext Storage of Sensitive Information",
                    "severity": "Critical"
                }
            ],
            "code_snippet_or_location": "backend/database.py:89\n            # Credit card numbers stored in plain text",
            "severity": "Critical",
            "fix": "Encrypt sensitive data at rest using strong encryption algorithms (AES-256). Use database encryption features or application-level encryption. Never store passwords in plain text (use hashing). Implement proper key management and rotation policies."
        },
        {
            "name": "Insufficient Session Expiration",
            "description": "User sessions remain active for extended periods without timeout or do not expire after logout. This increases the window of opportunity for session hijacking attacks.",
            "cves": [
                {
                    "cve_id": "CVE-2023-01234",
                    "description": "Insufficient session expiration increasing risk of session hijacking.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-613",
                    "description": "Insufficient Session Expiration",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": "backend/auth_utils.py:134\n            session.permanent = True  # No expiration set",
            "severity": "Medium",
            "fix": "Implement proper session timeout mechanisms. Set reasonable session expiration times (e.g., 15-30 minutes of inactivity). Invalidate sessions on logout. Implement absolute maximum session lifetime. Use secure session cookies with HttpOnly and Secure flags."
        },
        {
            "name": "Information Disclosure Through Error Messages",
            "description": "The application reveals sensitive information such as stack traces, database schema details, internal file paths, or system information through error messages displayed to users.",
            "cves": [
                {
                    "cve_id": "CVE-2023-12345",
                    "description": "Information disclosure through verbose error messages.",
                    "severity": "Low"
                },
                {
                    "cve_id": "CWE-209",
                    "description": "Generation of Error Message Containing Sensitive Information",
                    "severity": "Low"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_admin.py:156\n            raise Exception(f\"Database error: {str(e)}\")",
            "severity": "Low",
            "fix": "Implement generic error messages for users while logging detailed errors server-side. Use custom exception handlers. Never expose stack traces, database errors, file paths, or internal system details to end users. Sanitize all error responses."
        },
        {
            "name": "Missing Function-Level Access Control",
            "description": "The application does not verify user permissions before executing functions or accessing resources. Users can access administrative functions or other users' data by directly calling API endpoints.",
            "cves": [
                {
                    "cve_id": "CVE-2022-23456",
                    "description": "Missing function-level access control allowing privilege escalation.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-639",
                    "description": "Authorization Bypass Through User-Controlled Key",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "backend/api_routes/routing_admin.py:178\n            def delete_user(user_id):",
            "severity": "High",
            "fix": "Implement proper authorization checks at the function level. Verify user roles and permissions before executing sensitive operations. Use decorators or middleware for authorization. Implement role-based access control (RBAC) or attribute-based access control (ABAC)."
        },
        {
            "name": "Use of Components with Known Vulnerabilities",
            "description": "The application uses outdated libraries or dependencies with known security vulnerabilities. These vulnerabilities can be exploited by attackers to compromise the application.",
            "cves": [
                {
                    "cve_id": "CVE-2023-34567",
                    "description": "Use of outdated dependency with known security vulnerability.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-1104",
                    "description": "Use of Unmaintained Third-Party Components",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "requirements.txt\n            flask==1.0.0  # Known vulnerabilities",
            "severity": "High",
            "fix": "Regularly update all dependencies to their latest secure versions. Use dependency scanning tools (Snyk, Dependabot, Safety) to identify vulnerable packages. Maintain an inventory of all dependencies. Implement automated dependency updates and security patches."
        },
        {
            "name": "Insecure API Key Storage in Client-Side Code",
            "description": "API keys or authentication tokens are exposed in client-side JavaScript code, making them accessible to anyone who views the page source or inspects network traffic.",
            "cves": [
                {
                    "cve_id": "CVE-2023-45678",
                    "description": "Exposure of API keys in client-side code.",
                    "severity": "High"
                },
                {
                    "cve_id": "CWE-200",
                    "description": "Exposure of Sensitive Information to an Unauthorized Actor",
                    "severity": "High"
                }
            ],
            "code_snippet_or_location": "frontend/utils/api.ts:12\n            const API_KEY = \"sk_live_abc123xyz\";",
            "severity": "High",
            "fix": "Never store API keys in client-side code. Use server-side proxies to make API calls. Implement proper authentication mechanisms (OAuth, JWT tokens) for client applications. Use environment variables for server-side configuration only."
        },
        {
            "name": "Weak SSL/TLS Configuration",
            "description": "The application uses weak SSL/TLS configurations, outdated protocols (SSLv3, TLS 1.0), or weak cipher suites. This makes encrypted communications vulnerable to interception and decryption.",
            "cves": [
                {
                    "cve_id": "CVE-2022-56789",
                    "description": "Weak SSL/TLS configuration allowing protocol downgrade attacks.",
                    "severity": "Medium"
                },
                {
                    "cve_id": "CWE-326",
                    "description": "Inadequate Encryption Strength",
                    "severity": "Medium"
                }
            ],
            "code_snippet_or_location": None,
            "severity": "Medium",
            "fix": "Use TLS 1.2 or higher. Disable weak cipher suites and protocols. Configure proper certificate validation. Use tools like SSL Labs to test SSL/TLS configuration. Implement HSTS (HTTP Strict Transport Security) headers."
        },
        {
            "name": "Insufficient Logging and Monitoring",
            "description": "The application does not adequately log security-relevant events such as authentication failures, authorization failures, or suspicious activities. This makes it difficult to detect and respond to security incidents.",
            "cves": [
                {
                    "cve_id": "CVE-2023-67890",
                    "description": "Insufficient logging and monitoring of security events.",
                    "severity": "Low"
                },
                {
                    "cve_id": "CWE-778",
                    "description": "Insufficient Logging",
                    "severity": "Low"
                }
            ],
            "code_snippet_or_location": None,
            "severity": "Low",
            "fix": "Implement comprehensive logging for all security-relevant events: authentication attempts, authorization failures, privilege changes, data access, and administrative actions. Use structured logging. Implement log aggregation and monitoring. Set up alerts for suspicious patterns."
        }
    ]
}
