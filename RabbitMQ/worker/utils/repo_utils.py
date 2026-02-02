import tempfile
from pathlib import Path
import shutil
from git import Repo, GitCommandError
from rich.console import Console


def is_github_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "github.com" in url

def is_gitlab_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "gitlab.com" in url

def is_bitbucket_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and "bitbucket.org" in url



def clone_repo(url: str) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="repo_"))
    Console().print(f":package: Cloning [blue]{url}[/] → {tmp}")
    try:
        Repo.clone_from(url, tmp, depth=1)
    except GitCommandError as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"Clone failed: {e}") from e
    return tmp

def clone_and_return_directory(repo_url: str, PAT: str) -> Path:
    if repo_url and is_github_url(repo_url):
        ind = repo_url.find("github.com")
        repo = repo_url[ind:]
        repo = f"https://{PAT}@{repo}"
        return clone_repo(repo)
    elif repo_url and is_gitlab_url(repo_url):
        ind = repo_url.find("gitlab.com")
        repo = repo_url[ind:]
        repo = f"https://oauth2:{PAT}@{repo}"
        return clone_repo(repo)
    elif repo_url and is_bitbucket_url(repo_url):
        ind = repo_url.find("bitbucket.org")
        repo = repo_url[ind:]
        repo = f"https://x-token-auth:{PAT}@{repo}"
        return clone_repo(repo)
    else:
        raise ValueError(f"Unsupported URL: {repo_url}")