"""The worker downloads uploads from the region the backend stored them in (review of #487 m4).

The backend uploader reads ``S3_REGION`` (else ``AWS_DEFAULT_REGION``); the worker used ``AWS_DEFAULT_REGION`` only, so
an operator who set ``S3_REGION`` got uploads that worked and downloads that failed (``PermanentRedirect``). Fake
credentials only.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

# loaded by path: helpers.context's package __init__ pulls in the agent stack, which this module does not need
_PATH = pathlib.Path(__file__).resolve().parents[1] / "helpers" / "context" / "s3_utils.py"
_SPEC = importlib.util.spec_from_file_location("worker_s3_utils_under_test", _PATH)
s3_utils = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(s3_utils)


@pytest.fixture
def captured(monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(s3_utils.boto3, "client", lambda service, **kw: seen.update(service=service, **kw) or object())
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ci-only-dummy")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "ci-only-dummy")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_ENDPOINT_URL_S3", raising=False)
    return seen


def test_worker_client_uses_s3_region(monkeypatch, captured):
    monkeypatch.setenv("S3_REGION", "ap-south-1")
    s3_utils._s3_client()
    assert (captured["service"], captured["region_name"]) == ("s3", "ap-south-1")


def test_worker_client_falls_back_to_the_default_region(monkeypatch, captured):
    monkeypatch.delenv("S3_REGION", raising=False)
    s3_utils._s3_client()
    assert captured["region_name"] == "us-east-1"
