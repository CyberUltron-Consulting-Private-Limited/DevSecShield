"""#84: CBOM_SSHCA_KMS_REGION_OVERRIDE sends calls for a multi-Region KMS key to its replica (DR deployments).

botocore's Stubber stands in for KMS: no network, no AWS account.  Each test checks the region and endpoint of the
client the call went to, and the KeyId it was given, with and without the override."""
from __future__ import annotations

import json
import secrets

import pytest

from backend.utilities.cbom_sources.sshca import keywrap as KW

ACCOUNT = "111122223333"
MRK = "mrk-" + "1234abcd" * 4
PRIMARY = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/{MRK}"
REPLICA = f"arn:aws:kms:ap-south-2:{ACCOUNT}:key/{MRK}"
SINGLE = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
PEM = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
TEAM, FP = 7, "SHA256:test-ca"


class _Kms:
    """A stubbed botocore client per region; ``calls`` records (region, endpoint host, operation, KeyId)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []
        self.plaintext = secrets.token_bytes(32)

    def __call__(self, region: str):
        import boto3
        from botocore.stub import ANY, Stubber

        client = boto3.client("kms", region_name=region, aws_access_key_id="x", aws_secret_access_key="x")
        stub = Stubber(client)
        replies = {"GenerateDataKey": ("generate_data_key", {"Plaintext": self.plaintext, "CiphertextBlob": b"edk"}),
                   "Decrypt": ("decrypt", {"Plaintext": self.plaintext})}
        host = client.meta.endpoint_url.split("//", 1)[1]

        def seen(params, model, **_):  # queue the reply for whichever call comes (wrap and unwrap use new clients)
            name, reply = replies[model.name]
            self.calls.append((region, host, model.name, params["KeyId"]))
            stub.add_response(name, {**reply, "KeyId": params["KeyId"]}, {k: ANY for k in params})

        client.meta.events.register("provide-client-params.kms", seen)
        stub.activate()
        return client


@pytest.fixture
def kms(monkeypatch):
    monkeypatch.setenv(KW.KMS_ENV, f"{PRIMARY},{SINGLE}")
    monkeypatch.delenv(KW.REGION_OVERRIDE_ENV, raising=False)
    fake = _Kms()
    KW.set_kms_client_factory(fake)
    yield fake
    KW.set_kms_client_factory(None)


def _round_trip(key_arn: str) -> str:
    blob = KW.wrap(PEM, team_id=TEAM, ca_fingerprint=FP, key_wrap="aws_kms", kms_key_ref=key_arn)
    assert KW.unwrap(blob, team_id=TEAM, ca_fingerprint=FP) == PEM
    return blob


def test_a_multi_region_key_uses_its_arns_region_without_the_override(kms):
    _round_trip(PRIMARY)
    assert kms.calls == [("us-east-1", "kms.us-east-1.amazonaws.com", "GenerateDataKey", PRIMARY),
                         ("us-east-1", "kms.us-east-1.amazonaws.com", "Decrypt", PRIMARY)]


def test_the_override_sends_a_multi_region_key_to_its_replica_and_stores_the_primary_arn(kms, monkeypatch):
    monkeypatch.setenv(KW.REGION_OVERRIDE_ENV, f"{MRK}=ap-south-2")
    blob = _round_trip(PRIMARY)
    assert kms.calls == [("ap-south-2", "kms.ap-south-2.amazonaws.com", "GenerateDataKey", REPLICA),
                         ("ap-south-2", "kms.ap-south-2.amazonaws.com", "Decrypt", REPLICA)]
    assert json.loads(blob.partition(":")[2])["key_ref"] == PRIMARY  # the CA row keeps the primary ARN
    assert KW.resolve_kms_key(PRIMARY) == PRIMARY and KW.kms_label(PRIMARY) in {c["label"] for c in KW.kms_choices()}


def test_a_key_wrapped_in_the_primary_region_is_unwrapped_at_the_replica(kms, monkeypatch):
    blob = KW.wrap(PEM, team_id=TEAM, ca_fingerprint=FP, key_wrap="aws_kms", kms_key_ref=PRIMARY)
    monkeypatch.setenv(KW.REGION_OVERRIDE_ENV, "*=ap-south-2")  # the DR stack takes over
    assert KW.unwrap(blob, team_id=TEAM, ca_fingerprint=FP) == PEM
    assert kms.calls[-1] == ("ap-south-2", "kms.ap-south-2.amazonaws.com", "Decrypt", REPLICA)


def test_a_named_key_wins_over_the_wildcard(kms, monkeypatch):
    other = "mrk-" + "0" * 32
    monkeypatch.setenv(KW.REGION_OVERRIDE_ENV, f"*=eu-west-1, {other}=us-west-2, {MRK}=ap-south-2")
    assert KW.kms_target(PRIMARY) == ("ap-south-2", REPLICA)
    monkeypatch.setenv(KW.REGION_OVERRIDE_ENV, f"{other}=us-west-2,*=eu-west-1")
    assert KW.kms_target(PRIMARY) == ("eu-west-1", PRIMARY.replace("us-east-1", "eu-west-1"))
    monkeypatch.setenv(KW.REGION_OVERRIDE_ENV, f"{other}=us-west-2")
    assert KW.kms_target(PRIMARY) == ("us-east-1", PRIMARY)  # another key's entry does not apply


@pytest.mark.parametrize("override", ["*=ap-south-2", f"{MRK}=ap-south-2,1234abcd-12ab-34cd-56ef-1234567890ab=x"])
def test_a_single_region_key_ignores_the_override(kms, monkeypatch, override):
    monkeypatch.setenv(KW.REGION_OVERRIDE_ENV, override)
    _round_trip(SINGLE)
    assert [c[:2] for c in kms.calls] == [("us-east-1", "kms.us-east-1.amazonaws.com")] * 2
    assert {c[3] for c in kms.calls} == {SINGLE}
    alias = f"arn:aws:kms:us-east-1:{ACCOUNT}:alias/{MRK}"
    assert KW.kms_target(alias) == ("us-east-1", alias)


@pytest.mark.parametrize("override", ["ap-south-2", f"{MRK}=", f"{MRK}=Mars-1", "key-1=ap-south-2",
                                      f"{MRK}=ap-south-2,oops"])
def test_a_malformed_override_is_refused_by_name_and_never_falls_back_to_the_primary(kms, monkeypatch, override):
    monkeypatch.setenv(KW.REGION_OVERRIDE_ENV, override)
    with pytest.raises(KW.WrapError) as err:
        KW.wrap(PEM, team_id=TEAM, ca_fingerprint=FP, key_wrap="aws_kms", kms_key_ref=PRIMARY)
    assert KW.REGION_OVERRIDE_ENV in str(err.value) and not err.value.transient
    assert "arn:aws" not in str(err.value) and ACCOUNT not in str(err.value)
    assert kms.calls == []  # no KMS call at all, in either region
