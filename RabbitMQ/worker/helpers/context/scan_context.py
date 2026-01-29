from pydantic import BaseModel, Field, model_validator
from rich.console import Console
from git import Repo, GitCommandError
import tempfile     
import shutil
from pathlib import Path
from typing import Literal
import json
from helpers.context.s3_utils import download_zip_file, download_file
import zipfile

def clone_repo(
    url: str,
    branch: str = "main") -> Path:

    try:
        # tmp = Path(tempfile.mkdtemp(prefix="repo_"))
        with tempfile.TemporaryDirectory(delete=False,prefix="repo_") as temp_dir:
            tmp = Path(temp_dir)
        Console().print(f":package: Cloning [blue]{url}[/] → {tmp} Branch:{branch}")

        Repo.clone_from(url, tmp, depth=1 , branch=branch)
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
    branch: str = Field(description="The branch of the GitHub repository to scan.",default="main")
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
    branch: str = Field(description="The branch of the GitLab repository to scan.",default="main")
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
    branch: str = Field(description="The branch of the Bitbucket repository to scan.",default="main")
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


def get_directory_from_zip_context(zip_context: ZipContext) -> Path:
    try:
        # Download the zip file from the s3 bucket 
        zip_file_path = download_zip_file(zip_context.bucket_name, zip_context.object_name)

        
        # create a temporary directory
        directory = tempfile.mkdtemp(prefix="repo_")
        
        # extract the zip file to a temporary directory
        with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
            zip_ref.extractall(directory)
        
        return directory
    except Exception as e:
        raise ValueError(f"Error in getting directory from zip context: {e}")
    
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