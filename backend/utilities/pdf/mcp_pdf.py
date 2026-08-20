"""
MCP Scan Results PDF Generator
Human-readable enterprise report from MCP scan results.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

from backend.utilities.pdf.report_branding import (
    append_executive_summary,
    append_findings_catalog,
    build_finding_section,
    count_label,
    escape_html,
    finding_location,
    format_scan_duration,
    get_report_styles,
    make_cover_callback,
    make_footer_callback,
    mapping_rows,
    severity_color,
    split_scan_payload,
)


def get_severity_color(severity: str):
    return severity_color(severity)


def _is_agent_format(scan_results: Any) -> bool:
    return (
        isinstance(scan_results, dict)
        and (
            "tools" in scan_results
            or "prompts" in scan_results
            or "resources" in scan_results
        )
    )


def _flatten_agent_vulnerabilities(scan_results: dict) -> list:
    """Return list of (resource_type, resource_name, vuln_dict)."""
    out = []
    for tool in scan_results.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        name = tool.get("tool_name", "Unknown")
        for v in tool.get("vulnerabilities") or []:
            if isinstance(v, dict):
                out.append(("Tool", name, v))
    for prompt in scan_results.get("prompts") or []:
        if not isinstance(prompt, dict):
            continue
        name = prompt.get("prompt_name", "Unknown")
        for v in prompt.get("vulnerabilities") or []:
            if isinstance(v, dict):
                out.append(("Prompt", name, v))
    for resource in scan_results.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        name = resource.get("resource_name", "Unknown")
        for v in resource.get("vulnerabilities") or []:
            if isinstance(v, dict):
                out.append(("Resource", name, v))
    return out


def generate_pdf(scan_results: dict, output_path: Optional[str] = None) -> str:
    """
    Generate a PDF report from MCP scan results.
    Supports agent format { tools, prompts, resources } or legacy { final_issues, error_messages }.
    """
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"mcp_scan_report_{timestamp}.pdf"

    inner, duration, _raw = split_scan_payload(scan_results)
    if isinstance(inner, dict):
        scan_results = inner
    elif isinstance(inner, list):
        scan_results = {"final_issues": inner}
    else:
        scan_results = {}

    if not isinstance(scan_results, dict):
        scan_results = {}

    use_agent_format = _is_agent_format(scan_results)
    if use_agent_format:
        flat_vulns = _flatten_agent_vulnerabilities(scan_results)
        tools_list = scan_results.get("tools") or []
        prompts_list = scan_results.get("prompts") or []
        resources_list = scan_results.get("resources") or []
        total_issues = len(flat_vulns)
        by_severity: Dict[str, int] = {}
        for _rt, _rn, v in flat_vulns:
            imp = count_label(v.get("impact") or "Unknown")
            by_severity[imp] = by_severity.get(imp, 0) + 1
        final_issues: List[Dict[str, Any]] = []
        error_messages = scan_results.get("error_messages", []) or []
        num_tools = len(tools_list)
        num_prompts = len(prompts_list)
        num_resources = len(resources_list)
        by_issue_code: Dict[str, int] = {}
        by_server: Dict[str, int] = {}
        unique_tools: set = set()
    else:
        flat_vulns = []
        final_issues = scan_results.get("final_issues", []) or []
        error_messages = scan_results.get("error_messages", []) or []
        total_issues = len(final_issues)
        by_severity = {}
        by_issue_code = {}
        by_server = {}
        unique_tools = set()
        for issue in final_issues:
            severity = count_label(issue.get("issue_severity", "unknown"))
            by_severity[severity] = by_severity.get(severity, 0) + 1
            issue_code = issue.get("issue_code", "Unknown")
            by_issue_code[issue_code] = by_issue_code.get(issue_code, 0) + 1
            server = issue.get("server", "Unknown")
            by_server[server] = by_server.get(server, 0) + 1
            tool = issue.get("tool")
            if tool and isinstance(tool, dict) and tool.get("name"):
                unique_tools.add(tool["name"])
        num_tools = len(unique_tools)
        num_prompts = 0
        num_resources = 0

    styles = get_report_styles()
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=56,
        bottomMargin=52,
    )
    story: List[Any] = []

    if use_agent_format:
        overview = [
            ("Scan type", "Model Context Protocol (MCP)"),
            ("Tools", str(num_tools)),
            ("Prompts", str(num_prompts)),
            ("Resources", str(num_resources)),
            ("Total vulnerabilities", str(total_issues)),
            ("Scan errors", str(len(error_messages))),
            ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
        ]
    else:
        overview = [
            ("Scan type", "Model Context Protocol (MCP)"),
            ("Total issues found", str(total_issues)),
            ("Unique tools affected", str(len(unique_tools))),
            ("Unique servers scanned", str(len(by_server))),
            ("Scan errors", str(len(error_messages))),
            ("Report generated", datetime.now().strftime("%B %d, %Y at %I:%M %p")),
        ]

    extra_tables = []
    if by_issue_code:
        extra_tables.append(
            (
                "Issues by issue code",
                ["Issue code", "Count"],
                [[str(code), str(count)] for code, count in sorted(by_issue_code.items(), key=lambda x: -x[1])],
                [4.0 * inch, 1.5 * inch],
            )
        )
    if by_server:
        extra_tables.append(
            (
                "Issues by server",
                ["Server", "Count"],
                [[str(server), str(count)] for server, count in sorted(by_server.items(), key=lambda x: -x[1])],
                [4.0 * inch, 1.5 * inch],
            )
        )

    append_executive_summary(
        story,
        report_key="mcp",
        overview_rows=overview,
        severity_counts=by_severity,
        styles=styles,
        extra_tables=extra_tables or None,
        project_name="MCP Findings",
        scan_time=format_scan_duration(duration),
        meta_chips=[
            ("Scan type", "MCP"),
            ("Total issues", str(total_issues)),
            ("Report generated", datetime.now().strftime("%b %d, %Y · %I:%M %p")),
            ("Platform", "zeroshield.ai"),
        ],
    )
    story.append(PageBreak())

    catalog: List[List[Any]] = []
    if use_agent_format:
        for idx, (resource_type, resource_name, vuln) in enumerate(flat_vulns, 1):
            title = vuln.get("title") or "Untitled"
            impact = count_label(vuln.get("impact") or "Unknown")
            location = finding_location(vuln)
            if location == "—":
                location = f"{resource_type}: {resource_name}"
            catalog.append(
                [
                    str(idx),
                    impact,
                    Paragraph(escape_html(str(title)), styles["table_cell"]),
                    Paragraph(escape_html(location), styles["mono_cell"]),
                ]
            )
    else:
        for idx, issue in enumerate(final_issues, 1):
            issue_code = issue.get("issue_code", "Unknown")
            severity = count_label(issue.get("issue_severity", "unknown"))
            server = issue.get("server", "Unknown")
            catalog.append(
                [
                    str(idx),
                    severity,
                    Paragraph(escape_html(str(issue_code)), styles["table_cell"]),
                    Paragraph(escape_html(str(server)), styles["mono_cell"]),
                ]
            )
    append_findings_catalog(story, catalog_rows=catalog, styles=styles)
    story.append(PageBreak())

    story.append(Paragraph("Detailed Findings", styles["title"]))
    story.append(
        Paragraph(
            "Each card includes the affected MCP resource, description, and remediation.",
            styles["muted"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))

    if total_issues == 0:
        story.append(Paragraph("No security issues were identified in this scan.", styles["body"]))
    elif use_agent_format:
        for idx, (resource_type, resource_name, vuln) in enumerate(flat_vulns, 1):
            title = vuln.get("title") or "Untitled"
            impact = count_label(vuln.get("impact") or "Unknown")
            suggested_fix = vuln.get("suggested_fix")
            if suggested_fix is not None and not isinstance(suggested_fix, str):
                suggested_fix = str(suggested_fix)
            standards: List[List[str]] = []
            standards.extend(mapping_rows(vuln.get("owasp_top_10"), label="OWASP Top 10"))
            standards.extend(mapping_rows(vuln.get("owasp_top_10_llm"), label="OWASP Top 10 (LLM)"))
            standards.extend(mapping_rows(vuln.get("compliance_controls"), label="Compliance"))
            story.append(
                build_finding_section(
                    index=idx,
                    title=str(title),
                    severity=impact,
                    detail_rows=[
                        ("Severity", impact),
                        ("Resource", f"{resource_type}: {resource_name}"),
                    ],
                    description=str(vuln.get("description") or ""),
                    evidence="",
                    recommended_fix=str(suggested_fix or ""),
                    standards_rows=standards or None,
                    styles=styles,
                )
            )
    else:
        for idx, issue in enumerate(final_issues, 1):
            issue_code = issue.get("issue_code", "Unknown")
            issue_message = issue.get("issue_message", "No message available")
            issue_type = issue.get("issue_type", "unknown")
            server = issue.get("server", "Unknown")
            tool = issue.get("tool")
            severity = count_label(issue.get("issue_severity", "unknown"))
            tool_name = "N/A"
            tool_description = ""
            if tool and isinstance(tool, dict):
                tool_name = tool.get("name", "N/A")
                tool_description = tool.get("description", "") or ""
            issue_type_display = issue_type.replace("_", " ").title() if issue_type != "unknown" else "Unknown"
            description = str(issue_message)
            if tool_description:
                description = f"{description}\n\nTool details: {tool_description}"
            story.append(
                build_finding_section(
                    index=idx,
                    title=str(issue_code),
                    severity=severity,
                    detail_rows=[
                        ("Severity", severity),
                        ("Issue type", issue_type_display),
                        ("Server", str(server)),
                        ("Tool name", str(tool_name)),
                    ],
                    description=description,
                    evidence="",
                    recommended_fix="",
                    styles=styles,
                )
            )

    if error_messages:
        story.append(PageBreak())
        story.append(Paragraph("Scan Errors", styles["title"]))
        for idx, error_msg in enumerate(error_messages, 1):
            story.append(
                build_finding_section(
                    index=idx,
                    title="Scan error",
                    severity="ERROR",
                    detail_rows=[("Source", "MCP scan")],
                    description=str(error_msg),
                    styles=styles,
                )
            )

    doc.build(
        story,
        onFirstPage=make_cover_callback("mcp"),
        onLaterPages=make_footer_callback("mcp"),
    )
    return output_path


def create_title_page(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_enterprise_cover_page

    draw_enterprise_cover_page(canvas_obj, doc, report_key="mcp")


def create_header_footer(canvas_obj, doc):
    from backend.utilities.pdf.report_branding import draw_standard_footer

    draw_standard_footer(canvas_obj, doc, report_key="mcp")


if __name__ == "__main__":
    test_file_path = os.path.normpath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "..",
            "RabbitMQ",
            "worker",
            "mcp_results_testing.json",
        )
    )
    out_dir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "generated_reports"))
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "MCP_Enterprise_Report.pdf")
    if os.path.exists(test_file_path):
        with open(test_file_path, "r", encoding="utf-8") as f:
            scan_results = json.load(f)
        print(generate_pdf(scan_results, out))
    else:
        print(
            generate_pdf(
                {
                    "tools": [
                        {
                            "tool_name": "search",
                            "vulnerabilities": [
                                {
                                    "title": "Unrestricted tool invocation",
                                    "impact": "High",
                                    "description": "Tool accepts unsanitized arguments.",
                                    "suggested_fix": "Validate and authorize tool arguments.",
                                    "owasp_top_10": {"A01:2021": "Broken Access Control"},
                                }
                            ],
                        }
                    ]
                },
                out,
            )
        )
