"""Confined file access. Paths stay inside the scanned root."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from aibom.cbom.posture.limits import (
    BYTES_PER_CONFIG_FILE,
    BYTES_PER_LINE,
    BYTES_PER_TLS_RESULT,
    NUL_PROBE_BYTES,
    PATH_MAX_BYTES,
)
from aibom.cbom.rules import LANGUAGE_EXTENSIONS

SKIP_DIRS = frozenset(
    {
        ".git",
        ".terraform",
        ".terragrunt-cache",
        "node_modules",
        "vendor",
        ".venv",
        "venv",
        "site-packages",
        "__pycache__",
        "dist",
        "build",
        "target",
        "cdk.out",
        ".serverless",
        ".aws-sam",
        ".next",
    }
)

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
TlsResultSignature = Literal["testssl_flat", "testssl_pretty", "sslyze", "nmap"]


@dataclass(frozen=True, slots=True)
class IndexedFile:
    rel: str
    cls: str
    size: int


@dataclass(frozen=True, slots=True)
class DecodedFile:
    rel: str
    cls: str
    size: int
    text: str
    encoding: Literal["utf-8", "utf-16"]
    replaced: bool
    capped_line: int


@dataclass(frozen=True, slots=True)
class Skip:
    code: str


def sanitize_path(rel: str) -> str:
    text = rel.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    cleaned = "".join("?" if ord(ch) < 32 else ch for ch in text)
    raw = cleaned.encode("utf-8")
    if len(raw) <= PATH_MAX_BYTES:
        return cleaned
    return raw[:PATH_MAX_BYTES].decode("utf-8", errors="ignore")


def sniff_cloudformation(head: bytes) -> bool:
    text = head.decode("utf-8", errors="ignore")
    return "AWSTemplateFormatVersion" in text or "AWS::" in text


def sniff_kubernetes(head: bytes) -> bool:
    text = head.decode("utf-8", errors="ignore")
    return "apiVersion" in text and "kind" in text


def sniff_compose(head: bytes) -> bool:
    text = head.decode("utf-8", errors="ignore")
    return "\nservices:" in f"\n{text}" or text.startswith("services:")


def sniff_traefik(head: bytes) -> bool:
    text = head.decode("utf-8", errors="ignore")
    return "entryPoints" in text or "\ntls:" in f"\n{text}"


def sniff_tls_result(head: bytes) -> TlsResultSignature | None:
    text = head.decode("utf-8", errors="ignore")
    if "<nmaprun" in text or text.lstrip().startswith("<!DOCTYPE nmaprun"):
        return "nmap"
    if "server_scan_results" in text:
        return "sslyze"
    if '"scanResult"' in text:
        return "testssl_pretty"
    if '"finding"' in text and '"severity"' in text:
        return "testssl_flat"
    return None


def _name_class(rel: str) -> str | None:
    name = Path(rel).name.casefold()
    lower = f"/{rel.casefold()}"
    if name.endswith((".tf", ".tf.json", ".tfvars", ".tfvars.json")):
        return "terraform"
    docker = name in {"dockerfile", "containerfile"}
    if docker or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return "dockerfile"
    compose = name.startswith(("docker-compose", "compose."))
    if compose or name in {"docker-compose.yml", "docker-compose.yaml"}:
        return "compose"
    ssh_dir = "/sshd_config.d/" in lower or "/ssh_config.d/" in lower
    if name in {"sshd_config", "ssh_config"} or ssh_dir:
        return "ssh"
    databases = {
        "postgresql.conf",
        "pg_hba.conf",
        "my.cnf",
        "mongod.conf",
        "elasticsearch.yml",
        "redis.conf",
    }
    if name in databases:
        return "database"
    if name == "crypttab":
        return "disk"
    if name.endswith(".sql"):
        return "sql"
    if name == "codeowners" or name in {"cbom-mapping.yaml", "cbom-mapping.json"}:
        return "business"
    web = {"nginx.conf", "httpd.conf", "apache2.conf", "ssl.conf", "haproxy.cfg"}
    if name in web or name.startswith("envoy"):
        return "web-server"
    app = name in {"server.xml", "ssl.ini"}
    if app or name.startswith(("application.", "jetty")):
        return "application-server"
    suffix = Path(name).suffix
    if suffix in LANGUAGE_EXTENSIONS:
        return "source"
    if name.endswith((".sh", ".bash")) or name == "makefile":
        return "shell"
    return None


def classify_name(rel: str) -> str | None:
    return _name_class(rel)


def file_byte_limit(cls: str) -> int:
    if cls == "tls-result":
        return BYTES_PER_TLS_RESULT
    return BYTES_PER_CONFIG_FILE


def decode_bytes(raw: bytes, rel: str, cls: str) -> DecodedFile | Skip:
    probe = raw[:NUL_PROBE_BYTES]
    utf16 = raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff")
    if b"\x00" in probe and not utf16:
        return Skip("binary_skipped")
    encoding: Literal["utf-8", "utf-16"] = "utf-8"
    replaced = False
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        encoding = "utf-16"
        text = raw.decode("utf-16")
    else:
        body = raw[3:] if raw.startswith(b"\xef\xbb\xbf") else raw
        text = body.decode("utf-8", errors="replace")
        replaced = "\ufffd" in text
    capped = 0
    lines = []
    for number, line in enumerate(text.splitlines(), start=1):
        encoded = line.encode("utf-8")
        if len(encoded) > BYTES_PER_LINE:
            line = encoded[:BYTES_PER_LINE].decode("utf-8", errors="ignore")
            if capped == 0:
                capped = number
        lines.append(line)
    return DecodedFile(
        rel=rel,
        cls=cls,
        size=len(raw),
        text="\n".join(lines),
        encoding=encoding,
        replaced=replaced,
        capped_line=capped,
    )



def _sort_key(name: str, is_dir: bool) -> bytes:
    raw = os.fsencode(name)
    return raw + (b"/" if is_dir else b"")


def iter_entries(root: Path):
    """Yield regular-file candidates as (relative path, DirEntry)."""
    pending = [root]
    while pending:
        current = pending.pop(0)
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        def sort_key(entry: os.DirEntry) -> bytes:
            return _sort_key(entry.name, entry.is_dir(follow_symlinks=False))

        entries.sort(key=sort_key)
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                if entry.name in SKIP_DIRS:
                    continue
                pending.append(Path(entry.path))
                continue
            rel = Path(os.path.relpath(entry.path, root)).as_posix()
            yield rel, entry
