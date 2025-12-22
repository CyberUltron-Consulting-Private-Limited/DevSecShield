"""
Parser for SAST scan results.
Converts raw SAST scan JSON into human-readable format.
"""

from typing import Dict, List, Any, Optional


def parse_sast_results(raw_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse SAST scan results into a human-readable format.
    
    Args:
        raw_results: Raw SAST scan results dictionary
        
    Returns:
        Dictionary with parsed, human-readable results
    """
    parsed = {
        "summary": {
            "total_vulnerabilities": 0,
            "total_errors": 0,
            "total_files_scanned": 0,
            "total_files_skipped": 0,
            "by_severity": {},
            "by_check": {},
            "by_file": {},
            "by_cwe": {},
            "by_owasp": {},
            "by_vulnerability_class": {},
            "by_category": {},
            "by_technology": {},
            "by_engine": {},
            "ignored_count": 0,
            "unique_files": set(),
            "scan_version": raw_results.get("version", "Unknown"),
            "engine_requested": raw_results.get("engine_requested", "Unknown")
        },
        "vulnerabilities": [],
        "errors": [],
        "skipped_files": [],
        "scan_statistics": {}
    }
    
    results = raw_results.get("results", [])
    parsed["summary"]["total_vulnerabilities"] = len(results)
    
    # Process errors
    errors = raw_results.get("errors", [])
    parsed["summary"]["total_errors"] = len(errors)
    for error in errors:
        parsed_error = {
            "type": error.get("type", "Unknown"),
            "level": error.get("level", "unknown"),
            "message": error.get("message", "No message"),
            "file": error.get("path", "Unknown")
        }
        parsed["errors"].append(parsed_error)
    
    # Process paths
    paths = raw_results.get("paths", {})
    scanned = paths.get("scanned", [])
    skipped = paths.get("skipped", [])
    parsed["summary"]["total_files_scanned"] = len(scanned)
    parsed["summary"]["total_files_skipped"] = len(skipped)
    
    # Process skipped files with reasons
    for skipped_file in skipped:
        if isinstance(skipped_file, dict):
            parsed["skipped_files"].append({
                "file": skipped_file.get("path", "Unknown"),
                "reason": skipped_file.get("reason", "Unknown")
            })
        else:
            parsed["skipped_files"].append({
                "file": skipped_file if isinstance(skipped_file, str) else "Unknown",
                "reason": "Not specified"
            })
    
    # Process scan statistics
    time_info = raw_results.get("time", {})
    if time_info:
        profiling = time_info.get("profiling_times", {})
        scanning_time = time_info.get("scanning_time", {})
        parsing_time = time_info.get("parsing_time", {})
        matching_time = time_info.get("matching_time", {})
        tainting_time = time_info.get("tainting_time", {})
        
        parsed["scan_statistics"] = {
            "total_scan_time_seconds": round(profiling.get("total_time", 0), 2),
            "config_time_seconds": round(profiling.get("config_time", 0), 2),
            "core_time_seconds": round(profiling.get("core_time", 0), 2),
            "scanning_time_seconds": round(scanning_time.get("total_time", 0), 2),
            "parsing_time_seconds": round(parsing_time.get("total_time", 0), 2),
            "matching_time_seconds": round(matching_time.get("total_time", 0), 2),
            "tainting_time_seconds": round(taining_time.get("total_time", 0), 2),
            "rules_parse_time_seconds": round(time_info.get("rules_parse_time", 0), 2),
            "files_scanned": len(scanned),
            "files_skipped": len(skipped),
            "average_scan_time_per_file": round(
                scanning_time.get("per_file_time", {}).get("mean", 0), 3
            ) if scanning_time.get("per_file_time") else None,
            "max_memory_bytes": raw_results.get("time", {}).get("max_memory_bytes", 0)
        }
    
    # Process each vulnerability
    for result in results:
        check_id = result.get("check_id", "Unknown")
        path = result.get("path", "Unknown")
        start = result.get("start", {})
        end = result.get("end", {})
        extra = result.get("extra", {})
        snippet = result.get("snippet", "")
        dataflow_trace = result.get("dataflow_trace", {})
        
        # Extract from extra
        message = extra.get("message", "No message available")
        metadata = extra.get("metadata", {})
        metavars = extra.get("metavars", {})
        severity = extra.get("severity", "UNKNOWN")
        lines = extra.get("lines", "")
        fingerprint = result.get("fingerprint", "")
        is_ignored = result.get("is_ignored", False)
        validation_state = result.get("validation_state", "UNKNOWN")
        engine_kind = result.get("engine_kind", "Unknown")
        
        # Extract metadata fields
        likelihood = metadata.get("likelihood", "Unknown")
        impact = metadata.get("impact", "Unknown")
        confidence = metadata.get("confidence", "Unknown")
        category = metadata.get("category", "Unknown")
        subcategory = metadata.get("subcategory", [])
        cwe_list = metadata.get("cwe", [])
        owasp_list = metadata.get("owasp", [])
        references = metadata.get("references", [])
        display_name = metadata.get("display-name", check_id)
        vulnerability_class = metadata.get("vulnerability_class", [])
        functional_categories = metadata.get("functional-categories", [])
        technology = metadata.get("technology", [])
        source_url = metadata.get("source", "")
        shortlink = metadata.get("shortlink", "")
        cwe_top25_2020 = metadata.get("cwe2020-top25", False)
        cwe_top25_2021 = metadata.get("cwe2021-top25", False)
        cwe_top25_2022 = metadata.get("cwe2022-top25", False)
        
        # Extract semgrep info
        semgrep_info = metadata.get("semgrep.dev", {})
        rule_info = semgrep_info.get("rule", {}) if semgrep_info else {}
        
        # Location info
        start_line = start.get("line", 0)
        start_col = start.get("col", 0)
        start_offset = start.get("offset", 0)
        end_line = end.get("line", 0)
        end_col = end.get("col", 0)
        end_offset = end.get("offset", 0)
        
        # Parse metavars
        parsed_metavars = parse_metavars(metavars)
        
        # Count by severity
        parsed["summary"]["by_severity"][severity] = parsed["summary"]["by_severity"].get(severity, 0) + 1
        
        # Count by check
        parsed["summary"]["by_check"][check_id] = parsed["summary"]["by_check"].get(check_id, 0) + 1
        
        # Count by file
        parsed["summary"]["by_file"][path] = parsed["summary"]["by_file"].get(path, 0) + 1
        
        # Count by CWE
        for cwe in cwe_list:
            cwe_id = cwe.split(":")[0] if ":" in cwe else cwe
            parsed["summary"]["by_cwe"][cwe_id] = parsed["summary"]["by_cwe"].get(cwe_id, 0) + 1
        
        # Count by OWASP
        for owasp in owasp_list:
            owasp_id = owasp.split(":")[0] if ":" in owasp else owasp
            parsed["summary"]["by_owasp"][owasp_id] = parsed["summary"]["by_owasp"].get(owasp_id, 0) + 1
        
        # Count by vulnerability class
        for vuln_class in vulnerability_class:
            parsed["summary"]["by_vulnerability_class"][vuln_class] = parsed["summary"]["by_vulnerability_class"].get(vuln_class, 0) + 1
        
        # Count by category
        parsed["summary"]["by_category"][category] = parsed["summary"]["by_category"].get(category, 0) + 1
        
        # Count by technology
        for tech in technology:
            parsed["summary"]["by_technology"][tech] = parsed["summary"]["by_technology"].get(tech, 0) + 1
        
        # Count by engine
        parsed["summary"]["by_engine"][engine_kind] = parsed["summary"]["by_engine"].get(engine_kind, 0) + 1
        
        # Count ignored
        if is_ignored:
            parsed["summary"]["ignored_count"] += 1
        
        # Track unique files
        parsed["summary"]["unique_files"].add(path)
        
        # Parse dataflow trace
        dataflow_info = parse_dataflow_trace(dataflow_trace)
        
        # Create human-readable vulnerability entry
        parsed_vuln = {
            "check_id": check_id,
            "display_name": display_name,
            "message": message,
            "severity": severity.upper(),
            "fingerprint": fingerprint,
            "is_ignored": is_ignored,
            "validation_state": validation_state,
            "engine_kind": engine_kind,
            "file": path,
            "location": {
                "start_line": start_line,
                "start_column": start_col,
                "start_offset": start_offset,
                "end_line": end_line,
                "end_column": end_col,
                "end_offset": end_offset
            },
            "risk_assessment": {
                "likelihood": likelihood,
                "impact": impact,
                "confidence": confidence,
                "category": category,
                "subcategory": subcategory
            },
            "security_classification": {
                "cwe": cwe_list,
                "owasp": owasp_list,
                "vulnerability_class": vulnerability_class,
                "cwe_top25": {
                    "2020": cwe_top25_2020,
                    "2021": cwe_top25_2021,
                    "2022": cwe_top25_2022
                }
            },
            "code": {
                "snippet": snippet.strip() if snippet else "No snippet available",
                "vulnerable_line": lines.strip() if lines else "N/A"
            },
            "metadata": {
                "functional_categories": functional_categories,
                "technology": technology,
                "metavars": parsed_metavars
            },
            "references": references,
            "dataflow": dataflow_info,
            "semgrep": {
                "source_url": source_url,
                "shortlink": shortlink,
                "rule_id": rule_info.get("rule_id", "N/A"),
                "rule_origin": rule_info.get("origin", "N/A"),
                "rule_version_id": rule_info.get("version_id", "N/A"),
                "rule_r_id": rule_info.get("r_id", "N/A"),
                "rule_rv_id": rule_info.get("rv_id", "N/A"),
                "playground_url": rule_info.get("url", "N/A")
            } if source_url else None
        }
        
        parsed["vulnerabilities"].append(parsed_vuln)
    
    # Convert set to count
    parsed["summary"]["unique_files"] = len(parsed["summary"]["unique_files"])
    
    return parsed


def parse_dataflow_trace(dataflow_trace: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse dataflow trace information into human-readable format.
    
    Args:
        dataflow_trace: Raw dataflow trace dictionary
        
    Returns:
        Dictionary with parsed dataflow information
    """
    if not dataflow_trace:
        return None
    
    parsed_trace = {
        "taint_source": None,
        "taint_sink": None,
        "intermediate_variables": []
    }
    
    # Parse taint source
    taint_source = dataflow_trace.get("taint_source", [])
    if taint_source and len(taint_source) >= 2:
        source_location = taint_source[1]
        if isinstance(source_location, list) and len(source_location) >= 2:
            location_info = source_location[0] if isinstance(source_location[0], dict) else {}
            var_name = source_location[1] if len(source_location) > 1 else "Unknown"
            parsed_trace["taint_source"] = {
                "variable": var_name,
                "file": location_info.get("path", "Unknown"),
                "line": location_info.get("start", {}).get("line", 0),
                "column": location_info.get("start", {}).get("col", 0)
            }
    
    # Parse taint sink
    taint_sink = dataflow_trace.get("taint_sink", [])
    if taint_sink and len(taint_sink) >= 2:
        sink_location = taint_sink[1]
        if isinstance(sink_location, list) and len(sink_location) >= 2:
            location_info = sink_location[0] if isinstance(sink_location[0], dict) else {}
            var_name = sink_location[1] if len(sink_location) > 1 else "Unknown"
            parsed_trace["taint_sink"] = {
                "variable": var_name,
                "file": location_info.get("path", "Unknown"),
                "line": location_info.get("start", {}).get("line", 0),
                "column": location_info.get("start", {}).get("col", 0)
            }
    
    # Parse intermediate variables
    intermediate_vars = dataflow_trace.get("intermediate_vars", [])
    for var in intermediate_vars[:5]:  # Limit to first 5
        location = var.get("location", {})
        parsed_trace["intermediate_variables"].append({
            "variable": var.get("content", "Unknown"),
            "file": location.get("path", "Unknown"),
            "line": location.get("start", {}).get("line", 0),
            "column": location.get("start", {}).get("col", 0)
        })
    
    return parsed_trace if parsed_trace["taint_source"] or parsed_trace["taint_sink"] else None


def parse_metavars(metavars: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse metavars (metadata variables) into human-readable format.
    
    Args:
        metavars: Raw metavars dictionary
        
    Returns:
        Dictionary with parsed metavar information
    """
    if not metavars:
        return {}
    
    parsed_metavars = {}
    
    for var_name, var_data in metavars.items():
        if isinstance(var_data, dict):
            location = var_data.get("start", {})
            end_location = var_data.get("end", {})
            abstract_content = var_data.get("abstract_content", "")
            propagated_value = var_data.get("propagated_value", {})
            
            parsed_var = {
                "name": var_name,
                "content": abstract_content,
                "location": {
                    "start_line": location.get("line", 0),
                    "start_column": location.get("col", 0),
                    "start_offset": location.get("offset", 0),
                    "end_line": end_location.get("line", 0),
                    "end_column": end_location.get("col", 0),
                    "end_offset": end_location.get("offset", 0)
                }
            }
            
            # Parse propagated value if present
            if propagated_value:
                svalue_start = propagated_value.get("svalue_start", {})
                svalue_end = propagated_value.get("svalue_end", {})
                svalue_content = propagated_value.get("svalue_abstract_content", "")
                
                parsed_var["propagated_value"] = {
                    "content": svalue_content,
                    "start_line": svalue_start.get("line", 0),
                    "start_column": svalue_start.get("col", 0),
                    "end_line": svalue_end.get("line", 0),
                    "end_column": svalue_end.get("col", 0)
                }
            
            parsed_metavars[var_name] = parsed_var
    
    return parsed_metavars

