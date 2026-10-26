"""Fact properties round-trip as strings."""

from aibom.cbom.posture.codec import decode_fact, encode_fact
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, Linkage, fact_id


def _fact() -> EncryptionFact:
    identity = fact_id("tls_endpoint", "self_hosted", "nginx", "server", "nginx.conf")
    return EncryptionFact(
        id=identity,
        kind="tls_endpoint",
        provider="self_hosted",
        native_type="nginx",
        address="server",
        path="nginx.conf",
        line=4,
        format="server_config",
        layers={"transport": "UNKNOWN"},
        verdict="UNKNOWN",
        basis=(
            BasisEntry(
                "ssl_protocols",
                unknown_reason="provider_version_dependent",
            ),
        ),
        default_row="nginx.ssl_protocols",
        key_management="unspecified",
        unknown_reason="provider_version_dependent",
        path_context="production_like",
        linkage=Linkage(owner_hint="team", source="codeowners"),
        finding_codes=("PLAINTEXT_LISTENER",),
    )


def test_round_trip() -> None:
    fact = _fact()
    props = encode_fact(fact)
    assert all(isinstance(value, str) for value in props.values())
    assert decode_fact(props) == fact
