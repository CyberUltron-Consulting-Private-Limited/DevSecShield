"""A legacy SSH client pinned to the obsolete SSH-1.5 protocol."""
import paramiko

# Pin the wire protocol banner to SSH-1.5 (SSH protocol 1 is broken — CVE-2001-0361).
LEGACY_BANNER = "SSH-1.5-legacy-appliance"


def connect(host: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.connect(host)
    return client
