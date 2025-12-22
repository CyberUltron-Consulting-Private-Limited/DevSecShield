from pydantic import BaseModel, Field, model_validator
from rich.console import Console
from git import Repo, GitCommandError
import tempfile
import shutil
from pathlib import Path
from typing import Literal
import json

def clone_repo(url: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="repo_"))
    Console().print(f":package: Cloning [blue]{url}[/] → {tmp}")
    try:
        Repo.clone_from(url, tmp, depth=1)
    except GitCommandError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"Clone failed: {e}") from e
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

def is_github_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "github.com" in url

def is_gitlab_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "gitlab.com" in url

def is_bitbucket_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "bitbucket.org" in url

class GithubContext(BaseModel):
    mode : Literal["github"] = "github"
    repo_url : str = Field(..., description="The URL of the GitHub repository to scan.")
    PAT: str = Field(..., description="The GitHub token to use for authentication.")

    @model_validator(mode='after')
    def check_valid_url_and_add_PAT(self):
        if not self.PAT or not self.repo_url:
            raise ValueError("PAT and repo_url are required")
        if is_github_url(self.repo_url):
            ind = self.repo_url.find("github.com")
            repo = self.repo_url[ind:]
            repo = f"https://{self.PAT}@{repo}"
            self.repo_url = repo
        else:
            raise ValueError(f"Invalid GitHub URL: {self.repo_url}")
        return self

class GitlabContext(BaseModel):
    mode : Literal["gitlab"] = "gitlab"
    repo_url: str = Field(..., description="The URL of the GitLab repository to scan.")
    PAT: str = Field(..., description="The GitLab token to use for authentication.")

    @model_validator(mode='after')
    def check_valid_url_and_add_PAT(self):
        if not self.PAT or not self.repo_url:
            raise ValueError("PAT and repo_url are required")
        if is_gitlab_url(self.repo_url):
            ind = self.repo_url.find("gitlab.com")
            repo = self.repo_url[ind:]
            repo = f"https://oauth2:{self.PAT}@{repo}"
            self.repo_url = repo
        else:
            raise ValueError(f"Invalid GitLab URL: {self.repo_url}")
        return self

class BitbucketContext(BaseModel):
    mode : Literal["bitbucket"] = "bitbucket"
    repo_url: str = Field(..., description="The URL of the Bitbucket repository to scan.")
    PAT: str = Field(..., description="The Bitbucket token to use for authentication.")

    @model_validator(mode='after')
    def check_valid_url_and_add_PAT(self):
        if not self.PAT or not self.repo_url:
            raise ValueError("PAT and repo_url are required")
        if is_bitbucket_url(self.repo_url):
            ind = self.repo_url.find("bitbucket.org")
            repo = self.repo_url[ind:]
            repo = f"https://x-token-auth:{self.PAT}@{repo}"
            self.repo_url = repo
        else:
            raise ValueError(f"Invalid Bitbucket URL: {self.repo_url}")
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