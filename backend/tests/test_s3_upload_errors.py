"""Storage upload failures surface as a clear 503, never a generic 500, and the AWS error code is logged (G-X-1, D-S1-1).

Found on staging (audit-C G-X-1, audit-D D-S1-1): every archive upload (UI scans, the CBOM estimate and the hosted
CI/CD gate) answered 500 "Failed to upload file to storage". ``upload_file`` swallowed the boto error, printed it to
stdout only and returned None, so neither the API, the UI nor the pipeline could tell a storage outage from a scan
failure, and the logs carried no AWS error code. The bucket was also hard-coded.

S3 is stubbed with moto (no network); the credentials are dummies.

Run (repo root): PYTHONPATH=. backend/.venv/bin/python -m pytest backend/tests/test_s3_upload_errors.py -q
"""
from __future__ import annotations

import asyncio
import io
import logging
import zipfile

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from fastapi import HTTPException
from moto import mock_aws

from backend.utilities.cicd import format_input as cicd_format
from backend.utilities.db import s3_utils
from backend.utilities.db import schemas
from backend.utilities.scan import format_input as scan_format

SECRET = "ci-only-dummy-secret-value"


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ci-only-dummy")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SECRET)
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for name in ("S3_BUCKET", "S3_REGION", "AWS_ENDPOINT_URL_S3"):
        monkeypatch.delenv(name, raising=False)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "import hashlib\n")
    return buf.getvalue()


class Upload:
    filename = "repo.zip"

    def __init__(self, data: bytes):
        self.data = data

    async def read(self) -> bytes:
        return self.data


def _assert_safe(err: HTTPException, code: str) -> None:
    assert err.status_code == 503
    assert f"(code: {code})" in err.detail and "not stored" in err.detail
    assert SECRET not in err.detail and "ci-only-dummy" not in err.detail
    assert err.headers.get("Retry-After")


def test_missing_bucket_is_a_503_with_the_aws_code_logged(caplog):
    with mock_aws(), caplog.at_level(logging.ERROR, logger=s3_utils.__name__):
        with pytest.raises(HTTPException) as err:  # the bucket was never created
            s3_utils.upload_file(io.BytesIO(b"zip"))
    _assert_safe(err.value, "NoSuchBucket")
    assert "does not exist" in err.value.detail
    assert "aws_code=NoSuchBucket" in caplog.text and "bucket=devsecshield-storage" in caplog.text
    assert SECRET not in caplog.text


def test_rejected_credentials_and_unreachable_endpoint_name_their_cause(monkeypatch, caplog):
    class Client:
        def __init__(self, exc):
            self.exc = exc

        def upload_fileobj(self, **_kw):
            raise self.exc

    denied = ClientError({"Error": {"Code": "InvalidAccessKeyId", "Message": "nope"},
                          "ResponseMetadata": {"HTTPStatusCode": 403}}, "PutObject")
    monkeypatch.setattr(s3_utils, "_s3_client", lambda: Client(denied))
    with caplog.at_level(logging.ERROR, logger=s3_utils.__name__), pytest.raises(HTTPException) as err:
        s3_utils.upload_file(io.BytesIO(b"zip"))
    _assert_safe(err.value, "InvalidAccessKeyId")
    assert "credentials were rejected" in err.value.detail
    assert "aws_code=InvalidAccessKeyId http_status=403" in caplog.text

    monkeypatch.setattr(s3_utils, "_s3_client",
                        lambda: Client(EndpointConnectionError(endpoint_url="https://minio.invalid")))
    with pytest.raises(HTTPException) as err:
        s3_utils.upload_file(io.BytesIO(b"zip"))
    _assert_safe(err.value, "EndpointConnectionError")


def test_storage_not_configured_is_a_503(monkeypatch):
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    with pytest.raises(HTTPException) as err:
        s3_utils.upload_file(io.BytesIO(b"zip"))
    _assert_safe(err.value, "NotConfigured")


def test_bucket_region_and_endpoint_come_from_the_environment(monkeypatch):
    assert s3_utils.storage_bucket() == "devsecshield-storage"  # the historic default
    monkeypatch.setenv("S3_BUCKET", "staging-uploads")
    monkeypatch.setenv("S3_REGION", "ap-south-1")
    with mock_aws():
        boto3.client("s3", region_name="ap-south-1").create_bucket(
            Bucket="staging-uploads", CreateBucketConfiguration={"LocationConstraint": "ap-south-1"})
        stored = s3_utils.upload_file(io.BytesIO(b"zip"))
        assert stored["bucket"] == "staging-uploads"
        body = boto3.client("s3", region_name="ap-south-1").get_object(Bucket="staging-uploads",
                                                                       Key=stored["object_name"])["Body"].read()
    assert body == b"zip"
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "http://minio:9000")
    assert s3_utils.storage_endpoint() == "http://minio:9000"


def test_ui_scan_upload_answers_503_not_500():
    payload = schemas.StartScanPayload.model_validate({"cbom": {"zip_file_used": True}})
    with mock_aws(), pytest.raises(HTTPException) as err:
        asyncio.run(scan_format.format_input_for_scan(scan_type="cbom", start_scan_payload=payload,
                                                      uploaded_file=Upload(_zip())))
    _assert_safe(err.value, "NoSuchBucket")


def test_cicd_gate_upload_answers_503_not_500(monkeypatch):
    async def valid(_file):
        return _zip()

    monkeypatch.setattr(cicd_format, "validate_zip_file", valid)
    with mock_aws(), pytest.raises(HTTPException) as err:
        asyncio.run(cicd_format.format_cicd_input(uploaded_file=Upload(_zip()), scan_type="cbom", scan_settings={}))
    _assert_safe(err.value, "NoSuchBucket")
