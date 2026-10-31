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
