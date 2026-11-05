"""S3 cleanup must succeed on an empty listing, and zip rejects must not look like a credit outage."""

import os

import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

from backend.utilities.db.s3_utils import delete_file  # noqa: E402
from backend.utilities.scan.estimate_scan import _estimation_failure  # noqa: E402


class _Result:
    def __init__(self, result):
        self.result = result


def test_zip_bomb_is_not_reported_as_a_credit_failure() -> None:
    exc = _estimation_failure(
        _Result("Suspicious compression ratio detected (possible zip bomb)")
    )
    assert exc.status_code == 400
    assert "zip bomb" in exc.detail


@pytest.mark.parametrize("worker_error", [
    "Error in initializing CBOMAgent: Error in getting directory from zip context: File is not a zip file",
    "Error in initializing CBOMAgent: Error in getting directory from zip context: Bad magic number for file header",
    "Error in initializing CBOMAgent: File <ZipInfo a.py> is encrypted, password required for extraction",
])
def test_an_unreadable_archive_is_bad_input_not_an_outage(worker_error) -> None:
    exc = _estimation_failure(_Result(worker_error))
    assert exc.status_code == 400 and exc.detail.startswith("The uploaded file is not a readable zip archive (")


# The worker's own messages from the lab UI run (u2, round 5): a typo in the branch and a repository that does not
# exist (GitHub answers a missing or private repository with a credential prompt) both came back as
# "Internal server error. Please try again later."
_CLONE = ("Error in initializing CBOMAgent: Clone failed: Cmd('git') failed due to: exit code(128)\n"
          "  cmdline: git clone -v --depth=1 --branch={branch} -- https://github.com/{repo} /tmp/repo_9z7m403x\n"
          "  stderr: 'Cloning into '/tmp/repo_9z7m403x'...\n{fatal}'")


def test_a_missing_branch_names_the_branch() -> None:
    exc = _estimation_failure(_Result(_CLONE.format(
        branch="no-such-branch-u2", repo="ricmoo/pyaes",
        fatal="warning: Could not find remote branch no-such-branch-u2 to clone.\n"
              "fatal: Remote branch no-such-branch-u2 not found in upstream origin")))
    assert exc.status_code == 400
    assert exc.detail.startswith("The branch 'no-such-branch-u2' was not found in the repository.")


@pytest.mark.parametrize("fatal", [
    "fatal: could not read Username for 'https://github.com': No such device or address",
    "remote: Repository not found.\nfatal: repository 'https://github.com/x/y/' not found",
    "remote: Invalid username or token. Password authentication is not supported for Git operations.\n"
    "fatal: Authentication failed for 'https://github.com/x/y/'",
    "fatal: unable to access 'https://bitbucket.org/x/y/': The requested URL returned error: 403",
])
def test_a_missing_or_private_repository_says_so(fatal) -> None:
    exc = _estimation_failure(_Result(_CLONE.format(branch="main", repo="zs-lab-u2-nonexistent/nope-nope",
                                                    fatal=fatal)))
    assert exc.status_code == 400
    assert exc.detail.startswith("The repository was not found or cannot be read with the given access.")
    assert "github.com" not in exc.detail and "/tmp/" not in exc.detail, "git's output is never echoed"


def test_an_unreachable_git_host_is_not_blamed_on_the_customer() -> None:
    exc = _estimation_failure(_Result(_CLONE.format(
        branch="main", repo="x/y", fatal="fatal: unable to access 'https://github.com/x/y/': Could not resolve host: "
                                         "github.com")))
    assert exc.status_code == 400 and "could not reach the repository host" in exc.detail


def test_other_estimation_failures_stay_credit_errors() -> None:
    exc = _estimation_failure(_Result("broker connection refused"))
    assert exc.status_code == 500
    assert exc.detail == "Credit estimation failed, please try again later"


@mock_aws
def test_delete_file_returns_true_when_the_bucket_listing_has_no_contents(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_ENDPOINT_URL_S3", raising=False)

    client = boto3.client("s3", region_name="us-east-1")
    client.create_bucket(Bucket="devsecshield-storage")
    client.put_object(Bucket="devsecshield-storage", Key="scan.zip", Body=b"PK\x03\x04")

    assert delete_file("devsecshield-storage", "scan.zip") is True
    assert delete_file("devsecshield-storage", "already-gone.zip") is True
