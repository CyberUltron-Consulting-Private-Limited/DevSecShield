## Data Returned by the Celery Tasks 

### Common fields : 

- "results" will always have the findings data for the scan

### SAST : 

example : 

```json
{
    "results" :  [
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
                }, //...( multiple vulnerabilities for the logical component )
                ]
            }, //...( multiple logical components )
        ] , 
    
    "metadata": {
        "excluded_documents" : [ "file_path.extension" , "file_path.extension" , ...( multiple files ) ],
        "included_documents" : [ "file_path.extension" , "file_path.extension" , ...( multiple files ) ],
    }
    "duration_of_scan": 10.5, // duration in seconds
}
```

### IAC : 

example : 

```json
{

    "results" : [ 
            {
                "title": "Publicly accessible S3 bucket with unencrypted data and no versioning",
                "description": "The Terraform configuration defines ........",
                "owasp_top_10": {
                "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                },
                "compliance_controls": {
                "NIST80053_AC": "NIST 800-53 - Access Control",
                "ISO27001_A9_ACCESS_CONTROL": "ISO 27001 - A.9 Access Control"
                },
                "suggested_fix": "Mitigate by enfo.......",
                "location": "terraform/main.tf",
                "snippet": "print(aws_s3_bucket.public_data)",
                "category": "Access Control",
                "resource": "aws_s3_bucket.public_data",
                "cves": {}
            }, // ...( multiple findings )
        ] , 
    
    "dependency_diagram": "dependency_diagram_string",
    "metadata": {
        "excluded_documents" : [ "file_path.extension" , "file_path.extension" , ...( multiple files ) ],
        "included_documents" : [ "file_path.extension" , "file_path.extension" , ...( multiple files ) ],
    }
    "duration_of_scan": 10.5, // duration in seconds
}

```