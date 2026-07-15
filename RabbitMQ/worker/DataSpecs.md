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
                "impact": "High",
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


### SBOM SCA : 

example : 

```json
{

    "results" : [ 
            {
                "title": "aws-sdk-python-3.10.0 - Python SDK for AWS",
                "impact": "High",
                "description": "The Terraform configuration defines ........",
                "owasp_top_10": {
                "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                },
                "compliance_controls": {
                "NIST80053_AC": "NIST 800-53 - Access Control",
                "ISO27001_A9_ACCESS_CONTROL": "ISO 27001 - A.9 Access Control"
                },
                "suggested_fix": "Mitigate by enfo.......",
                "dependency" : "aws-sdk-python-3.10.0",
                "reachability" : "reachable",
                "dependency_type" : "direct",
                "license_type" : "permissive",
                "cves": {}
            }, // ...( multiple findings )
        ] , 
    

    "duration_of_scan": 10.5, // duration in seconds
}

```

### LLM Benchmarking : 

example : 

```json
{
    "results" :{
        "vulnerabilities": [
            {
                "title": "LLM Model Vulnerabilities",
                "impact": "High",
                "description": "The LLM Model Vulnerabilities are as predicted risk scores",
                "vulnerability_predictions": {
                    "prompt_injection_score": 10,
                    "jailbreak_score": 10,
                    "bias_score": 10,
                    "hallucination_score": 10,
                },
                "owasp_top_10_llm": {
                    "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                },
                "mitre_atlas_tactic": "reconnaissance",
                "compliance_controls": {
                    "ISO27001_A12_OPERATIONS_SECURITY": "ISO 27001 - A.12 Operations Security",
                    "NIST_CSF_PROTECT": "NIST CSF - Protect"
                },
                "suggested_fix": "Remove or redact prints of the DATABASE_URL. Use a secure logger with redaction. Do not expose credentials in logs or stdout.",
            }, // ...( multiple vulnerabilities )
        ],
        "model_vulnerabilities": {
            "jailbreak_resistance_score": 10,
            "injection_resistance_score": 10,
            "hallucination_resistance_score": 10,
            "bias_resistance_score": 10,
            "content_safety_score": 10,
            "data_privacy_score": 10,
        }
    },
    "duration_of_scan": 10.5, // duration in seconds
    "metadata": { // this field will contain the raw garak scan results 
                    "status": "completed",
                    "model_name": "gpt-4o",
                    "total_tests": 64,
                    "total_hits": 11,
                    "hit_rate_percent": 17.19,
                    "risk_level": "medium",
                    "probes_used": [
                        "malwaregen.Evasion",
                        "malwaregen.TopLevel"
                    ],
                    "probes_summary": {
                        "malwaregen.AnyCode_malwaregen.Evasion": {
                        "probe": "malwaregen.Evasion",
                        "detector": "malwaregen.AnyCode",
                        "passed": 37,
                        "total": 48,
                        "hit_rate": 22.92
                        },
                        "malwaregen.AnyCode_malwaregen.TopLevel": {
                        "probe": "malwaregen.TopLevel",
                        "detector": "malwaregen.AnyCode",
                        "passed": 16,
                        "total": 16,
                        "hit_rate": 0.0
                        }
                    }
            }, 

}
```


### MCP : 

example : 

```json
{
    "results" : {
        "tools": [
            {
                "tool_name": "tool_name",
                "tool_description": "tool_description",
                "tool_input_schema": "tool_input_schema",
                "tool_output_schema": "tool_output_schema",
                "tool_risk_level": "High",
                "tool_category": "web",
                "vulnerabilities": [
                    {
                        "title": "vulnerability_title",
                        "description": "vulnerability_description",
                        "impact": "High",
                        "owasp_top_10": {
                            "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                        },
                        "owasp_top_10_llm": {
                            "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                        },
                        "compliance_controls": {
                            "ISO27001_A12_OPERATIONS_SECURITY": "ISO 27001 - A.12 Operations Security",
                            "NIST_CSF_PROTECT": "NIST CSF - Protect"
                        },
                        "suggested_fix": "Remove or redact prints of the DATABASE_URL. Use a secure logger with redaction. Do not expose credentials in logs or stdout.",
                    }, // ...( multiple vulnerabilities )
                ]
            }
        ],
        "prompts": [
            {
                "prompt_name": "prompt_name",
                "prompt_description": "prompt_description",
                "prompt_input_schema": "prompt_input_schema",
                "prompt_risk_level": "High",
                "prompt_category": "web",
                "vulnerabilities": [
                    {
                        "title": "vulnerability_title",
                        "description": "vulnerability_description",
                        "impact": "High",
                        "owasp_top_10": {
                            "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                        },
                        "owasp_top_10_llm": {
                            "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                        },
                        "compliance_controls": {
                            "ISO27001_A12_OPERATIONS_SECURITY": "ISO 27001 - A.12 Operations Security",
                            "NIST_CSF_PROTECT": "NIST CSF - Protect"
                        },
                        "suggested_fix": "Remove or redact prints of the DATABASE_URL. Use a secure logger with redaction. Do not expose credentials in logs or stdout.",
                    }
                ]
            }, // ...( multiple prompts )
        ],
        "resources": [
            {
                "resource_name": "resource_name",
                "resource_description": "resource_description",
                "resource_size": "resource_size",
                "resource_uri": "resource_uri",
                "resource_risk_level": "High",
                "resource_category": "web",
                "vulnerabilities": [
                    {
                        "title": "vulnerability_title",
                        "description": "vulnerability_description",
                        "impact": "High",
                        "owasp_top_10": {
                            "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                        },
                        "owasp_top_10_llm": {
                            "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                        },
                        "compliance_controls": {
                            "ISO27001_A12_OPERATIONS_SECURITY": "ISO 27001 - A.12 Operations Security",
                            "NIST_CSF_PROTECT": "NIST CSF - Protect"
                        },
                        "suggested_fix": "Remove or redact prints of the DATABASE_URL. Use a secure logger with redaction. Do not expose credentials in logs or stdout.",
                    }, // ...( multiple vulnerabilities )
                ]
            }, // ...( multiple resources )
        ]
    }
    "duration_of_scan": 10.5, // duration in seconds
}
```



### DAST  : 

example : 

```json
{

    "results" : [ 
            {
                "title": "XSS Vulnerability",
                "url": "https://www.example.com",
                "confidence": "high",
                "impact": "High",
                "owasp_top_10": {
                    "SECURITY_MISCONFIGURATION": "A05:2021 - Security Misconfiguration"
                },
                "compliance_controls": {
                    "ISO27001_A12_OPERATIONS_SECURITY": "ISO 27001 - A.12 Operations Security",
                    "NIST_CSF_PROTECT": "NIST CSF - Protect"
                },
                "description": "The XSS Vulnerability is a vulnerability that allows an attacker to execute arbitrary code in the browser.",
                "suggested_fix": "Remove or redact prints of the DATABASE_URL. Use a secure logger with redaction. Do not expose credentials in logs or stdout.",
                "category": "xss_and_client_side",
            }, // ...( multiple findings )
        ] , 
    

    "duration_of_scan": 10.5, // duration in seconds
    "metadata": { 
        "urls_included": [ "https://www.example.com" , "https://www.example.com" , ...( multiple urls ) ],
        "urls_excluded": [ "https://www.example.com" , "https://www.example.com" , ...( multiple urls ) ],
    }
}

```