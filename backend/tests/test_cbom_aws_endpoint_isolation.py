"""CBOM AWS collection never follows an endpoint configured for something else (PR #92 review 5875247534).

The local stack (deploy/local) and the staging stack with MinIO give every backend-image container
AWS_ENDPOINT_URL_S3=http://minio:9000 for the product's own uploads. botocore applies that service-specific variable
(and AWS_ENDPOINT_URL, and endpoint_url in ~/.aws/config) to every S3 client created without an endpoint_url, so the
collector's S3 calls for a CUSTOMER account went to MinIO with the assumed role's keys: every bucket was missing
from the CBOM and the run showed an access-denied coverage gap. ``aws_validate._boto`` already refuses ambient
credentials; its client config must refuse ambient endpoints the same way. No network call is made here.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

import pytest

boto3 = pytest.importorskip("boto3")

from backend.utilities.cbom_sources import aws_collect, aws_validate  # noqa: E402


@pytest.fixture
def ambient_endpoints(monkeypatch):
    # Placeholder values only: nothing is sent anywhere.
    monkeypatch.setenv("CBOM_AWS_ACCESS_KEY_ID", "placeholder-id")
    monkeypatch.setenv("CBOM_AWS_SECRET_ACCESS_KEY", "placeholder-secret")
    monkeypatch.delenv("CBOM_AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_ENDPOINT_URL_S3", "http://minio:9000")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://ambient.invalid:4566")
    monkeypatch.setenv("AWS_ENDPOINT_URL_STS", "http://ambient-sts.invalid:4566")
    return monkeypatch


def _host(client) -> str:
    return urlparse(client.meta.endpoint_url).hostname or ""


def _account() -> aws_collect._Account:
    base, cfg = aws_validate._boto()
    acct = aws_collect._Account(base, cfg, "arn:aws:iam::123456789012:role/ZeroShieldCBOMReader",
                                "zs-ext-AAAA-BBBB-CCCC-DDDD", team_id=1)
    # What assume() builds from the STS answer, without calling STS.
    acct.session = boto3.session.Session(aws_access_key_id="placeholder-id", aws_secret_access_key="placeholder-secret",
                                         aws_session_token="placeholder-token")
    acct.expires = time.monotonic() + 3600
    return acct


def test_customer_s3_calls_go_to_aws_not_to_the_configured_minio(ambient_endpoints):
    client = _account().client("s3", "global")
    assert client.meta.endpoint_url.startswith("https://")
    assert _host(client).endswith(".amazonaws.com"), client.meta.endpoint_url


@pytest.mark.parametrize("service,region", [("kms", "ap-south-1"), ("ec2", "us-east-1"), ("acm", "eu-west-1"),
                                            ("secretsmanager", "ap-south-1"), ("sts", "us-east-1")])
def test_every_collector_client_ignores_ambient_endpoints(ambient_endpoints, service, region):
    host = _host(_account().client(service, region))
    assert host.endswith(".amazonaws.com") and "invalid" not in host, host


def test_the_zeroshield_principal_calls_sts_at_aws(ambient_endpoints):
    base, cfg = aws_validate._boto()
    assert _host(base.client("sts", region_name="us-east-1", config=cfg)).endswith(".amazonaws.com")


def test_the_config_says_so(ambient_endpoints):
    _, cfg = aws_validate._boto()
    assert cfg.ignore_configured_endpoint_urls is True
