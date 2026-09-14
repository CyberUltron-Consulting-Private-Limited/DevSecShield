from atlassian import Jira
from rich.console import Console
from requests.exceptions import HTTPError, Timeout, RequestException
import requests
from requests.auth import HTTPBasicAuth
import json
import ipaddress
from urllib.parse import urlparse
import socket
console = Console()


# SECURITY: Request timeout configuration (connect_timeout, read_timeout)
REQUEST_TIMEOUT = (5, 30)  # 5 seconds to connect, 30 seconds to read


def validate_jira_url(url: str) -> bool:
    """
    Validate that a Jira URL is safe to connect to.
    Prevents SSRF attacks by blocking internal/private IP addresses.
    
    Returns:
        True if URL is safe, raises ValueError if unsafe
    """
    if not url:
        raise ValueError("Jira URL cannot be empty")
    
    # Parse the URL
    try:
        parsed = urlparse(url)
    except Exception:
        raise ValueError(f"Invalid URL format: {url}")
    
    # Must be HTTPS in production (allow HTTP only for localhost in dev)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}. Must be http or https")
    
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must have a hostname")
    
    # Block localhost and loopback
    if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0'):
        raise ValueError("Cannot connect to localhost or loopback addresses")
    
    # Resolve hostname and check IP
    try:
        # Get all IP addresses for the hostname
        ip_addresses = socket.getaddrinfo(hostname, None)
        for family, type, proto, canonname, sockaddr in ip_addresses:
            ip = sockaddr[0]
            ip_obj = ipaddress.ip_address(ip)
            
            # Block private, loopback, link-local, and reserved addresses
            if ip_obj.is_private:
                raise ValueError(f"Cannot connect to private IP address: {ip}")
            if ip_obj.is_loopback:
                raise ValueError(f"Cannot connect to loopback address: {ip}")
            if ip_obj.is_link_local:
                raise ValueError(f"Cannot connect to link-local address: {ip}")
            if ip_obj.is_reserved:
                raise ValueError(f"Cannot connect to reserved address: {ip}")
            if ip_obj.is_multicast:
                raise ValueError(f"Cannot connect to multicast address: {ip}")
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")
    
    # Block common internal domain patterns
    blocked_patterns = [
        '.internal', '.local', '.localhost', '.intranet',
        '.corp', '.private', '.lan', '.home',
        'metadata.google.internal',  # GCP metadata
        '169.254.169.254',  # AWS/Azure/GCP metadata
        'metadata.azure.com',  # Azure metadata
    ]
    hostname_lower = hostname.lower()
    for pattern in blocked_patterns:
        if pattern in hostname_lower:
            raise ValueError(f"Cannot connect to internal domain: {hostname}")
    
    # Must end with atlassian.net or be a known Jira domain
    allowed_domains = ['.atlassian.net', '.atlassian.com', '.jira.com']
    is_allowed = any(hostname_lower.endswith(domain) for domain in allowed_domains)
    
    # For custom Jira Server deployments, require explicit configuration
    # This can be overridden by an environment variable for self-hosted Jira
    import os
    if not is_allowed:
        custom_jira_hosts = os.getenv('ALLOWED_JIRA_HOSTS', '').split(',')
        custom_jira_hosts = [h.strip().lower() for h in custom_jira_hosts if h.strip()]
        if hostname_lower not in custom_jira_hosts:
            console.print(f"[SECURITY] Jira URL '{hostname}' not in allowed list. Add to ALLOWED_JIRA_HOSTS env var if needed.", style="bold yellow")
            # Note: Currently allowing for backward compatibility, but log a warning
            # In strict mode, uncomment the next line:
            # raise ValueError(f"Jira host not in allowed list: {hostname}")
    
    return True


def list_projects(jira_url: str, jira_token: str, jira_email: str = "support@zeroshield.ai"):
    """
    List all Jira projects visible to the authenticated user.
    """
    # SECURITY: Validate Jira URL to prevent SSRF
    validate_jira_url(jira_url)
    
    url = f"{jira_url}/rest/api/3/project/search"

    auth = HTTPBasicAuth(jira_email, jira_token)

    headers = {
    "Accept": "application/json"
    }

    try:
        response = requests.request(
            "GET",
            url,
            headers=headers,
            auth=auth,
            timeout=REQUEST_TIMEOUT  # SECURITY: Request timeout
        )
        response.raise_for_status()
        return response.json()
    except Timeout:
        console.print(f"[ERROR] Jira request timed out for URL: {jira_url}", style="bold red")
        raise Exception("Jira request timed out. Please try again.")
    except RequestException as e:
        console.print(f"[ERROR] Jira request failed: {e}", style="bold red")
        raise


def create_issue_in_project(
    jira_url: str,
    jira_token: str,
    project_id: str,
    summary: str,
    description: str,
    jira_email: str = "support@zeroshield.ai",
    issue_type: str = "Task",
):
    """
    Create an issue in the specified Jira project (by project ID).
    """
    # SECURITY: Validate Jira URL to prevent SSRF
    validate_jira_url(jira_url)
    
    url = f"{jira_url}/rest/api/3/issue"

    auth = HTTPBasicAuth(jira_email, jira_token)

    headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
    }

    payload = json.dumps({
        "fields": {
            "project": {"id": project_id},
            "issuetype": {"name": issue_type},
            "summary": summary,
            "description": {
                "content": [
                    {
                        "content": [
                            {"text": description, "type": "text"}
                        ],
                        "type": "paragraph"
                    }
                ],
                "type": "doc",
                "version": 1
            }
        }
    })

    try:
        response = requests.request(
            "POST",
            url,
            data=payload,
            headers=headers,
            auth=auth,
            timeout=REQUEST_TIMEOUT  # SECURITY: Request timeout
        )
        
        print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))

        if response.status_code not in [200, 201]:
            raise Exception(f"Failed to create issue in Jira: {response.text}")
            
        return response.json()
    except Timeout:
        console.print(f"[ERROR] Jira request timed out for URL: {jira_url}", style="bold red")
        raise Exception("Jira request timed out. Please try again.")
    except RequestException as e:
        console.print(f"[ERROR] Jira request failed: {e}", style="bold red")
        raise


def list_issue_transitions(
    jira_url: str,
    jira_token: str,
    issue_key: str,
    jira_email: str = "support@zeroshield.ai",
) -> list[dict]:
    validate_jira_url(jira_url)
    url = f"{jira_url.rstrip('/')}/rest/api/3/issue/{issue_key}/transitions"
    auth = HTTPBasicAuth(jira_email, jira_token)
    headers = {"Accept": "application/json"}
    try:
        response = requests.request(
            "GET",
            url,
            headers=headers,
            auth=auth,
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        return response.json().get("transitions") or []
    except Timeout:
        raise Exception("Jira request timed out. Please try again.")
    except RequestException as e:
        console.print(f"[ERROR] Jira transitions request failed: {e}", style="bold red")
        raise


def transition_issue(
    jira_url: str,
    jira_token: str,
    issue_key: str,
    transition_id: str,
    jira_email: str = "support@zeroshield.ai",
) -> None:
    validate_jira_url(jira_url)
    url = f"{jira_url.rstrip('/')}/rest/api/3/issue/{issue_key}/transitions"
    auth = HTTPBasicAuth(jira_email, jira_token)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    payload = json.dumps({"transition": {"id": str(transition_id)}})
    try:
        response = requests.request(
            "POST",
            url,
            data=payload,
            headers=headers,
            auth=auth,
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code not in (200, 204):
            raise Exception(f"Failed to transition Jira issue {issue_key}: {response.text}")
    except Timeout:
        raise Exception("Jira request timed out. Please try again.")
    except RequestException as e:
        console.print(f"[ERROR] Jira transition failed: {e}", style="bold red")
        raise


if __name__ == "__main__":
    try:
        # Test examples removed - use environment variables
        pass
    except HTTPError as e:
        console.print(f"Error listing projects: {e} with status code {e.response.status_code}",style="bold red")
        console.print(f"Error response: {e.response.text}",style="bold red")