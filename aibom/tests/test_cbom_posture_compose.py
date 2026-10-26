"""Compose posture extraction. Inline YAML and JSON, no fixture trees."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.extract_compose import (
    extract_compose,
    extract_dockerfile,
    match_datastore_image,
)

_LAYERS = ("database", "volume", "transport")
_QUEUE = (
    ("rabbitmq:3-management", "rabbitmq", "message_queue"),
    ("docker.io/library/kafka", "kafka", "data_stream"),
    ("nats:2.10", "nats", "message_queue"),
    ("apache/activemq:5.18", "activemq", "message_queue"),
    ("docker.redpanda.com/redpandadata/redpanda:v23.2", "redpanda", "data_stream"),
    ("quay.io/minio/minio:latest", "minio", "object_store"),
    ("minio/minio@sha256:deadbeef", "minio", "object_store"),
)


def _service(image: str, *, extra: str = "") -> str:
    return f"services:\n  store:\n    image: {image}\n{extra}"


@pytest.mark.parametrize(
    ("image", "image_id", "kind"),
    [
        ("postgres", "postgres", "relational_db"),
        ("postgres:15", "postgres", "relational_db"),
        ("docker.io/library/postgres:15", "postgres", "relational_db"),
        ("redis", "redis", "cache"),
        ("public.ecr.aws/bitnami/redis:7.2", "redis", "cache"),
        ("mongo", "mongo", "nosql_db"),
        ("mongo:6", "mongo", "nosql_db"),
        ("localhost:5000/library/mongo", "mongo", "nosql_db"),
        ("rabbitmq", "rabbitmq", "message_queue"),
        ("kafka", "kafka", "data_stream"),
        ("minio", "minio", "object_store"),
    ],
)
def test_images_match_without_registry_host_or_tag(
    image: str, image_id: str, kind: str
) -> None:
    assert match_datastore_image(image) == (image_id, kind)
    fact = extract_compose(_service(image), "compose.yaml")[0]
    assert fact.provider == "compose"
    assert fact.kind == kind
    assert fact.native_type == image_id
    assert fact.address == "store"
    assert any(item.name == "image" and item.value == image_id for item in fact.basis)


@pytest.mark.parametrize(("image", "image_id", "kind"), _QUEUE)
def test_queue_stream_and_object_images_keep_three_unknown_layers(
    image: str, image_id: str, kind: str
) -> None:
    facts = extract_compose(_service(image), "compose.yaml")
    assert len(facts) == 1
    fact = facts[0]
    assert fact.kind == kind
    assert fact.native_type == image_id
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "layer_not_observable"
    for layer in _LAYERS:
        assert fact.layers[layer] == "UNKNOWN"
        assert any(
            item.name == layer and item.unknown_reason == "layer_not_observable"
            for item in fact.basis
        )


def test_unlisted_image_is_dropped() -> None:
    assert extract_compose(_service("nginx:1.25"), "compose.yaml") == ()
    assert match_datastore_image("library/nginx:latest") is None


def test_environment_and_command_are_not_stored() -> None:
    extra = (
        "    environment:\n"
        "      POSTGRES_PASSWORD: CANARYPASSWORD\n"
        "    command: [\"postgres\", \"-c\", \"ssl=on\"]\n"
    )
    fact = extract_compose(_service("postgres:15", extra=extra), "compose.yaml")[0]
    assert "CANARYPASSWORD" not in repr(fact)
    assert fact.layers["database"] == "UNKNOWN"


def test_json_compose_matches_a_bare_repository() -> None:
    text = '{"services":{"cache":{"image":"redis"}}}'
    fact = extract_compose(text, "compose.json")[0]
    assert fact.kind == "cache"
    assert fact.native_type == "redis"
    assert fact.format == "compose"
    for layer in _LAYERS:
        assert fact.layers[layer] == "UNKNOWN"


def test_named_volume_stays_unobservable() -> None:
    extra = "    volumes:\n      - pgdata:/var/lib/postgresql/data\n"
    fact = extract_compose(_service("postgres", extra=extra), "compose.yaml")[0]
    assert fact.layers["volume"] == "UNKNOWN"
    assert fact.unknown_reason == "layer_not_observable"


def test_dockerfile_emits_no_fact() -> None:
    text = (
        "FROM postgres:15\n"
        "ENV POSTGRES_PASSWORD=CANARYPASSWORD\n"
        'CMD ["postgres"]\n'
    )
    assert extract_dockerfile(text, "Dockerfile") == ()
