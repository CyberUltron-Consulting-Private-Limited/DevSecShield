from pydantic import BaseModel, Field, model_validator
from rich.console import Console
from git import Repo, GitCommandError
import tempfile     
import shutil
from pathlib import Path
from typing import Literal
import json
from helpers.context import git_hosts
from helpers.context.s3_utils import download_zip_file, download_file
import zipfile
import errno
import os
import logging

logger = logging.getLogger(__name__)

# A cloned repository is attacker-controlled: a committed link such as ``key.pem -> /proc/self/environ`` must never
# become a real link on the worker. ``core.symlinks=false`` makes git check every link out as a plain file holding
# the target path. It is set through git's environment config (git >= 2.31) rather than ``-c`` on the clone command
# line, which GitPython only accepts with its unsafe-options check switched off.
CLONE_GIT_ENV = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.symlinks", "GIT_CONFIG_VALUE_0": "false"}


def clone_repo(
    url: str,
    branch: str = "main") -> Path:

    try:
        # tmp = Path(tempfile.mkdtemp(prefix="repo_"))
        with tempfile.TemporaryDirectory(delete=False,prefix="repo_") as temp_dir:
            tmp = Path(temp_dir)
        # The URL carries the access token: never log or report it.
        Console().print(f":package: Cloning [blue]{git_hosts.redact(url)}[/] → {tmp} Branch:{branch}")

        Repo.clone_from(url, tmp, depth=1, branch=branch, env=CLONE_GIT_ENV)
    except GitCommandError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(git_hosts.redact(f"Clone failed: {e}")) from None
    return tmp

def snippet_with_numbers(fp: Path, start: int, end: int) -> str:
    try:
        lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\n".join(
            f"{i+1:>5}| {lines[i]}" for i in range(start - 1, min(end, len(lines)))
        )
    except Exception as exc:
        Console().print(f"Failed to read code snippet {fp}:{start}-{end} — {exc}",style="bold red")
        return ""


def _is_provider_url(url: str, host: str) -> bool:
    """True when a scan may clone ``url`` as this provider: https on the provider host (or a sub-domain), or a
    self-hosted server listed in GIT_ALLOWED_HOSTS (helpers/context/git_hosts.py)."""
    try:
        git_hosts.check_repo_url(url, host, host)
    except ValueError:
        return False
    return True

def is_github_url(url: str) -> bool:
    return _is_provider_url(url, "github.com")

def is_gitlab_url(url: str) -> bool:
    return _is_provider_url(url, "gitlab.com")

def is_bitbucket_url(url: str) -> bool:
    return _is_provider_url(url, "bitbucket.org")

# The clone URL is rebuilt from the checked scheme, host, port and path (git_hosts.clone_url), so a self-hosted host
# or a sub-domain is kept as it is and nothing in the path can redirect the clone to another host.

class GithubContext(BaseModel):
    mode : Literal["github"] = "github"
    branch: str = Field(description="The branch of the GitHub repository to scan.",default="main")
    repo_url : str = Field(..., description="The URL of the GitHub repository to scan.")
    PAT: str = Field(default="", description="The GitHub token to use for authentication. Empty for public repos.")

    @model_validator(mode='after')
    def check_valid_url_and_add_PAT(self):
        if not self.repo_url:
            raise ValueError("repo_url is required")
        pat = (self.PAT or "").strip()
        # Ignore accidental paste of a repo URL into the PAT field.
        # Using a URL as username produces: https://https://github.com/...@github.com/...
        if pat and ("://" in pat or "github.com" in pat.lower() or "@" in pat):
            Console().print(
                "Ignoring PAT that looks like a URL/host (not a token); cloning as public repo",
                style="bold yellow",
            )
            pat = ""
        try:
            self.repo_url = git_hosts.clone_url(self.repo_url, "github.com", "GitHub", user=pat or None)
        except ValueError as e:
            raise ValueError(f"Invalid GitHub URL: {e}") from None
        return self

class GitlabContext(BaseModel):
    mode : Literal["gitlab"] = "gitlab"
    branch: str = Field(description="The branch of the GitLab repository to scan.",default="main")
    repo_url: str = Field(..., description="The URL of the GitLab repository to scan.")
    PAT: str = Field(..., description="The GitLab token to use for authentication.")

    @model_validator(mode='after')
    def check_valid_url_and_add_PAT(self):
        if not self.PAT or not self.repo_url:
            raise ValueError("PAT and repo_url are required")
        try:
            self.repo_url = git_hosts.clone_url(self.repo_url, "gitlab.com", "GitLab", user="oauth2", secret=self.PAT)
        except ValueError as e:
            raise ValueError(f"Invalid GitLab URL: {e}") from None
        return self

class BitbucketContext(BaseModel):
    mode : Literal["bitbucket"] = "bitbucket"
    branch: str = Field(description="The branch of the Bitbucket repository to scan.",default="main")
    repo_url: str = Field(..., description="The URL of the Bitbucket repository to scan.")
    PAT: str = Field(..., description="The Bitbucket token to use for authentication.")

    @model_validator(mode='after')
    def check_valid_url_and_add_PAT(self):
        if not self.PAT or not self.repo_url:
            raise ValueError("PAT and repo_url are required")
        try:
            self.repo_url = git_hosts.clone_url(self.repo_url, "bitbucket.org", "Bitbucket", user="x-token-auth",
                                                secret=self.PAT)
        except ValueError as e:
            raise ValueError(f"Invalid Bitbucket URL: {e}") from None
        return self

def validate_dict_with_context(dict_context: dict) -> GithubContext | GitlabContext | BitbucketContext:
    
    try:
        json_context = json.dumps(dict_context)
        if dict_context["mode"] == "github":
            context = GithubContext.model_validate_json(json_context)
        elif dict_context["mode"] == "gitlab":
            context = GitlabContext.model_validate_json(json_context)
        elif dict_context["mode"] == "bitbucket":
            context = BitbucketContext.model_validate_json(json_context)
        else:
            raise ValueError(f"Invalid mode: {json_context['mode']}")
        return context
    except Exception as e:
        raise ValueError(f"Invalid context JSON: {e}")


def clone_repo_from_context(context: GithubContext | GitlabContext | BitbucketContext) -> Path:
    if context and isinstance(context, GithubContext):
        return clone_repo(context.repo_url, context.branch)
    elif context and isinstance(context, GitlabContext):
        return clone_repo(context.repo_url, context.branch)
    elif context and isinstance(context, BitbucketContext):
        return clone_repo(context.repo_url, context.branch)
    else:
        raise ValueError(f"Unsupported context: {context}")


class ZipContext(BaseModel):
    bucket_name: str = Field(..., description="The name of the bucket with zip file of the project to scan.")
    object_name: str = Field(..., description="The name of the object with zip file of the project to scan.")


# SECURITY: Safe zip extraction limits
MAX_EXTRACTED_SIZE = 2 * 1024 * 1024 * 1024  # 2GB max total extracted size
MAX_COMPRESSION_RATIO = 100  # Zip bomb detection: 100x compression is suspicious
# Sparse files (SQLite, empty DBs) compress far past 100x while staying small.
# The ratio check only applies once the archive would expand past this size.
# Smaller archives stay bounded by MAX_EXTRACTED_SIZE.
MIN_UNCOMPRESSED_FOR_RATIO = 64 * 1024 * 1024
MAX_FILES_IN_ARCHIVE = 50000  # Prevent file count DoS
# Entries the filesystem cannot hold (a name over 255 bytes, a path over 4096 bytes, or absurd nesting) are skipped
# one by one instead of failing the whole upload: a repository with one such file still gets scanned.
MAX_NAME_BYTES = 255
MAX_PATH_BYTES = 4000
MAX_PATH_DEPTH = 128


def safe_extract_zip(zip_path: str, extract_to: str) -> None:
    """
    Safely extract a zip file with protection against:
    - Path traversal attacks (ZipSlip)
    - Zip bombs (compression ratio and size limits)
    - File count DoS attacks
    """
    from pathlib import Path
    
    extract_path = Path(extract_to).resolve()
    
    with zipfile.ZipFile(zip_path, 'r') as zf:
        # Pre-check: Calculate totals before extraction
        total_uncompressed = sum(info.file_size for info in zf.infolist())
        total_compressed = sum(info.compress_size for info in zf.infolist())
        file_count = len(zf.infolist())
        
        # Check 1: File count limit
        if file_count > MAX_FILES_IN_ARCHIVE:
            raise ValueError(f"Archive contains too many files: {file_count} > {MAX_FILES_IN_ARCHIVE}")
        
        # Check 2: Total size limit
        if total_uncompressed > MAX_EXTRACTED_SIZE:
            raise ValueError(f"Archive uncompressed size exceeds limit: {total_uncompressed} > {MAX_EXTRACTED_SIZE}")
        
        # Check 3: Zip bomb detection via compression ratio.
        # A few megabytes at a high ratio is a sparse file, not a bomb.
        if (
            total_compressed > 0
            and total_uncompressed > MIN_UNCOMPRESSED_FOR_RATIO
            and total_uncompressed / total_compressed > MAX_COMPRESSION_RATIO
        ):
            raise ValueError("Suspicious compression ratio detected (possible zip bomb)")
        
        # Safe extraction with path traversal protection
        skipped = 0
        for info in zf.infolist():
            parts = [p for p in info.filename.replace("\\", "/").split("/") if p]
            if (any(len(p.encode("utf-8", "surrogateescape")) > MAX_NAME_BYTES for p in parts)
                    or len(parts) > MAX_PATH_DEPTH
                    or len(str(extract_path).encode()) + len(info.filename.encode("utf-8", "surrogateescape")) > MAX_PATH_BYTES):
                skipped += 1  # the filesystem cannot hold it; checked before the traversal test so it never mkdirs
                continue
            # Resolve the full target path
            target_path = (extract_path / info.filename).resolve()
            
            # Security check: Ensure target is within extract directory
            if target_path != extract_path and extract_path not in target_path.parents:
                raise ValueError(f"Path traversal detected in archive: {info.filename}")
            
            # Create directory or extract file
            try:
                if info.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                else:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as source, open(target_path, 'wb') as target:
                        target.write(source.read())
            except OSError as exc:
                if exc.errno != errno.ENAMETOOLONG:
                    raise
                skipped += 1
        if skipped:
            logger.warning("zip extraction skipped %d entries whose names the filesystem cannot hold", skipped)


def get_directory_from_zip_context(zip_context: ZipContext) -> Path:
    directory = zip_file_path = None
    try:
        # Download the zip file from the s3 bucket 
        zip_file_path = download_zip_file(zip_context.bucket_name, zip_context.object_name)

        
        # create a temporary directory
        directory = tempfile.mkdtemp(prefix="repo_")
        
        # SECURITY: Use safe extraction instead of extractall()
        safe_extract_zip(zip_file_path, directory)
        
        return directory
    except Exception as e:
        if directory:  # a refused archive (bomb, traversal, corrupt) must not leave its partial tree behind
            shutil.rmtree(directory, ignore_errors=True)
        raise ValueError(f"Error in getting directory from zip context: {e}")
    finally:  # the downloaded archive is only needed for the extraction
        if zip_file_path:
            try:
                os.remove(zip_file_path)
            except OSError:
                pass
    
def validate_dict_with_zip_context(dict_context: dict) -> ZipContext:
    try:
        json_context = json.dumps(dict_context)
        context = ZipContext.model_validate_json(json_context)
        return context
    except Exception as e:
        raise ValueError(f"Invalid zip context JSON: {e}")


class FileContext(BaseModel):
    bucket_name: str = Field(..., description="The name of the bucket with file to download.")
    object_name: str = Field(..., description="The name of the object with file to download.")

def get_file_from_file_context(file_context: FileContext) -> str | Path | None:
    try:
        return download_file(file_context.bucket_name, file_context.object_name)
    except Exception as e:
        raise ValueError(f"Error in getting file from file context: {e}")

def validate_dict_with_file_context(dict_context: dict) -> FileContext:
    try:
        json_context = json.dumps(dict_context)
        context = FileContext.model_validate_json(json_context)
        return context
    except Exception as e:
        raise ValueError(f"Invalid file context JSON: {e}")