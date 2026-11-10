"""Secrets in scan payloads never appear when a payload model is printed or logged.

Found on the local production stack (round 5, L1): POST /{team}/dast/scan/{id}/estimate_credits printed
`Start scan payload: ... dast=StartDASTScanData(... auth=AuthRequirements(... password='...'))` to the backend log
(routers/scans.py), i.e. the login password of the customer's application under test, in plain text. The secret
fields of the schemas are now excluded from repr/str; model_dump (what reaches the workers) keeps them.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_scan_payload_secrets_not_logged.py -q -p no:cacheprovider
"""
from backend.utilities.db import schemas

SECRET = "s3cr3t-L1-do-not-log"


def test_dast_login_password_is_not_in_the_printed_payload():
    payload = schemas.StartScanPayload(dast=schemas.StartDASTScanData(
        target_url="https://app.example", auth=schemas.AuthRequirements(
            login_url="https://app.example/login", xpath_of_username_field="//a", xpath_of_password_field="//b",
            username="alice", password=SECRET, xpath_of_submit_button="//c")))
    assert SECRET not in f"Start scan payload: {payload}" and SECRET not in repr(payload)
    assert "alice" in str(payload)  # the rest is still printed
    assert payload.model_dump()["dast"]["auth"]["password"] == SECRET  # the worker still gets it


def test_other_secret_fields_are_not_printed():
    for model, field in ((schemas.GithubContextSchema, "PAT"), (schemas.GitlabContextSchema, "PAT"),
                         (schemas.BitbucketContextSchema, "PAT"), (schemas.StartLLMBenchmarkingData, "api_key"),
                         (schemas.JiraTeamSettingsData, "api_token")):
        assert model.model_fields[field].repr is False, f"{model.__name__}.{field}"
