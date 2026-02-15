from backend.get_db import get_db , get_mongo_db
from backend.new_models import Scan 
from sqlmodel import Session , select
from backend.mongo_models import ScanFindings
from rich.console import Console
from sqlalchemy import or_

console = Console()


DEV_ENVIRONMENT = True
def migrate_findings_to_mongo_db():
    engine = get_db(dev_environment=DEV_ENVIRONMENT)
    mongo_db = get_mongo_db(dev_environment=DEV_ENVIRONMENT)

    # SAST scans 
    with Session(engine) as session:
        scans_1 = session.exec(select(Scan).where(Scan.scan_type == "sast")).all()

        for scan in scans_1:
            results = scan.scan_data
            if results is None or len(results) == 0 or results == {}:
                continue # skip if no results

            """
            results will look like this : 

            [
                 {
                    "logical_component_title": "Database Backup Workflow (Postgres to SQLite backup)",
                    "vulnerabilities": [
                        {
                            "title": "Exposed Database URL in logs",
                            "description": "The backup script prints the full DATABASE_URL to stdout after loading environment variables (print(db_url)). This can reveal database credentials and connection details in logs or process listings.",
                            "impact": "High",
                            "owasp_top_10": {
                            "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                                            },
                            "compliance_controls": {
                            "ISO27001_A12_OPERATIONS_SECURITY": "ISO 27001 - A.12 Operations Security",
                            "NIST_CSF_PROTECT": "NIST CSF - Protect"
                                                },
                            "suggested_fix": "Remove or redact prints of the DATABASE_URL. Use a secure logger with redaction. Do not expose credentials in logs or stdout.",
                            "location": "backup.py",
                            "snippet": "print(db_url)",
                            "cves": {}
                        },
                    ]
                }
            
            ]
            """
            for item in results: 
                logical_component_title = item["logical_component_title"]
                vulnerabilities = item["vulnerabilities"]   
                for vulnerability in vulnerabilities:
                    vulnerability["logical_component_title"] = logical_component_title
                    scan_finding = ScanFindings(
                        scan_id = scan.id,
                        finding_data = vulnerability,
                        fixed = False,
                        fixed_date = None,
                        info = None
                    )
                    mongo_db["scan_findings"].insert_one(scan_finding)
    

    # IAC , SCA SBOM  scans 
    or_statements = []
    or_statements.append(Scan.scan_type == "iac")
    or_statements.append(Scan.scan_type == "sbom_sca")
    or_statements.append(Scan.scan_type == "llm")
    with Session(engine) as session:
        scans_2 = session.exec(select(Scan).where(or_(*or_statements))).all()

        for scan in scans_2:
            results = scan.scan_data
            if results is None or len(results) == 0 or results == {}:
                continue # skip if no results

            """
            results will look like this : 

            [
                    {
                        "title": "Publicly accessible S3 bucket with unencrypted data and no versioning",
                        "description": "The Terraform configuration defines an S3 bucket (aws_s3_bucket.public_data) with acl set to public-read-write, which makes the bucket publicly accessible for both reading and writing. There is no encryption configured for objects in the bucket (no server-side encryption block), and versioning is disabled (versioning_configuration { status = \"Disabled\" }). This combination enables any internet user to read, modify, or delete bucket contents, and prevents recoverability of deleted or overwritten objects. The lack of encryption also means data at rest is not protected against unauthorized access if the bucket is compromised. The public access is not restricted by a bucket policy, increasing the risk surface and making data exfiltration or tampering trivial for attackers who discover the bucket.",
                        "impact": "Critical",
                        "owasp_top_10": {
                        "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                        },
                        "compliance_controls": {
                        "NIST80053_AC": "NIST 800-53 - Access Control",
                        "ISO27001_A9_ACCESS_CONTROL": "ISO 27001 - A.9 Access Control"
                        },
                        "suggested_fix": "Mitigate by enforcing least privilege and protective controls for S3 data: 1) Change acl from public-read-write to private or use a restrictive policy that grants access only to specific IAM principals or roles. 2) Enable server-side encryption (SSE-S3 or SSE-KMS) for all objects to protect data at rest. 3) Enable bucket versioning to retain previous object versions and enable MFA Delete where appropriate for critical data. 4) Enforce a bucket policy to block public access and require HTTPS (e.g., StringEquals or IpAddress conditions) where feasible. 5) Consider enabling access logging and S3 Object Lock if compliance requires immutability. 6) Use IAM roles or presigned URLs for controlled access instead of exposing bucket publicly.",
                        "location": "terraform/main.tf -> resource aws_s3_bucket.public_data",
                        "snippet": "resource \"aws_s3_bucket\" \"public_data\" {\n  bucket = \"my-public-data-bucket-12345\"\n  \n  # VULNERABILITY: Public access enabled\n  acl = \"public-read-write\"\n}\n\n# VULNERABILITY: No versioning, no encryption\nresource \"aws_s3_bucket_versioning\" \"public_data\" {\n  bucket = aws_s3_bucket.public_data.id\n  versioning_configuration {\n    status = \"Disabled\"\n  }\n}",
                        "cves": {}
                    },

            ]
            """  
            for vulnerability in results:
                scan_finding = ScanFindings(
                    scan_id = scan.id,
                    finding_data = vulnerability,
                    fixed = False,
                    fixed_date = None,
                    info = None
                )
                mongo_db["scan_findings"].insert_one(scan_finding)
    


    # MCP  scans 
    with Session(engine) as session:
        scans_3 = session.exec(select(Scan).where(Scan.scan_type == "mcp")).all()

        for scan in scans_3:
            results = scan.scan_data
            if results is None or len(results) == 0 or results == {}:
                continue # skip if no results

            """
            results will look like this : 
            {
            "tools": [
                {
                "tool_name": "read_wiki_structure",
                "tool_description": "Get a list of documentation topics for a GitHub repository.\n\nArgs:\n    repoName: GitHub repository in owner/repo format (e.g. \"facebook/react\")",
                "tool_input_schema": {
                    "properties": {
                    "repoName": {
                        "type": "string"
                    }
                    },
                    "required": [
                    "repoName"
                    ],
                    "type": "object"
                },
                "tool_output_schema": {
                    "properties": {
                    "result": {
                        "type": "string"
                    }
                    },
                    "required": [
                    "result"
                    ],
                    "type": "object",
                    "x-fastmcp-wrap-result": true
                },
                "vulnerabilities": [
                    {
                    "title": "Unauthorized Access to Private Wiki Contents via read_wiki_structure",
                    "description": "The tool read_wiki_structure may fetch documentation topics across any GitHub repository using only the repoName input. If used against private repositories or with insufficient authorization checks, this could expose private wiki pages and docs to unauthorized callers.",
                    "impact": "High",
                    "owasp_top_10": {
                        "BROKEN_ACCESS_CONTROL": "A01:2021 - Broken Access Control"
                    },
                    "owasp_top_10_llm": {
                        "SENSITIVE_INFORMATION_DISCLOSURE": "LLM06:2025 - Sensitive Information Disclosure"
                    },
                    "compliance_controls": {
                        "NIST80053_AC": "NIST 800-53 - Access Control",
                        "ISO27001_A9_ACCESS_CONTROL": "ISO 27001 - A.9 Access Control",
                        "GDPR_DATA_MINIMIZATION": "GDPR - Data minimization",
                        "GDPR_LAWFULNESS": "GDPR - Lawfulness, fairness, and transparency"
                    },
                    "suggested_fix": "Enforce per-repo access controls by tying authorization to the caller's credentials and repository permissions. Validate that the requesting user is allowed to view private repository wiki topics before returning results. Avoid leaking private content in error messages or logs; implement least privilege for API calls; consider scoping GitHub API requests to the caller's authenticated session."
                    },
                ] 
            } , 

            "prompts": [],
            "resources": []

            """  
            for tool in results["tools"]:
                tool_name = tool["tool_name"]
                tool_description = tool["tool_description"]
                tool_input_schema = tool["tool_input_schema"]
                tool_output_schema = tool["tool_output_schema"]
                tool_metadata = {
                    "tool_name": tool_name,
                    "tool_description": tool_description,
                    "tool_input_schema": tool_input_schema,
                    "tool_output_schema": tool_output_schema
                }
                vulnerabilities = tool["vulnerabilities"]
                for vulnerability in vulnerabilities:
                    vulnerability["resource_type"] = "tool"
                    vulnerability["metadata"] = tool_metadata
                    scan_finding = ScanFindings(
                        scan_id = scan.id,
                        finding_data = vulnerability,
                        fixed = False,
                        fixed_date = None,
                        info = None
                    )
                    mongo_db["scan_findings"].insert_one(scan_finding)
    

if __name__ == "__main__":
    migrate_findings_to_mongo_db()