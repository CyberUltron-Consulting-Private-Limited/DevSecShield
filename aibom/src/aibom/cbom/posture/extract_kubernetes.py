"""Kubernetes posture. Unregistered: scan_crypto does not import this."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from aibom.cbom.posture.ciphers import evaluator_for
from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.defaults import load_registry
from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.extract_compose import (
    load_documents,
    match_datastore_image,
    unobserved_basis,
    unobserved_layers,
)
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, path_context
from aibom.cbom.posture.resolve import Absent
from aibom.cbom.posture.verdict import (
    LayerCase,
    assess_layer,
    resource_verdict,
)

_APISERVER_ROW = "k8s.apiserver.encryption_flag"
_COVERS = frozenset({"secrets", "*.", "*.*"})
_LOCAL = frozenset({"aescbc", "aesgcm", "secretbox"})
_WORKLOADS = frozenset(
    {
        "CronJob",
        "DaemonSet",
        "Deployment",
        "Job",
        "Pod",
        "ReplicaSet",
        "StatefulSet",
    }
)
_REF_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@-"
)
_FLAG = "--encryption-provider-config"
READERS = MappingProxyType({"listener": listener_reader})


class _CipherSlot:
    def __init__(self) -> None:
        self.ciphers: object | None = None


_CIPHERS = _CipherSlot()


def extract_kubernetes(
    text: str,
    path: str = "manifest.yaml",
    *,
    files: Mapping[str, str] | None = None,
) -> tuple[EncryptionFact, ...]:
    """Facts for encryption configs, the API server, ingress, and data stores."""
    bundle: dict[str, str] = dict(files or {})
    bundle[path] = text
    parsed: list[tuple[str, Mapping[str, object]]] = []
    for rel in sorted(bundle):
        for doc in load_documents(bundle[rel]):
            parsed.extend((rel, item) for item in _resources(doc))
    configs: list[tuple[str, EncryptionFact]] = []
    rest: list[tuple[str, Mapping[str, object]]] = []
    for rel, doc in parsed:
        if _kind(doc) == "EncryptionConfiguration" and _group(doc) == (
            "apiserver.config.k8s.io"
        ):
            configs.append((rel, _encryption_fact(doc, rel)))
        else:
            rest.append((rel, doc))
    by_path: dict[str, list[EncryptionFact]] = {}
    for rel, fact in configs:
        by_path.setdefault(rel, []).append(fact)
    facts = [fact for _, fact in configs]
    for rel, doc in rest:
        facts.extend(_resource(doc, rel, by_path))
    facts.sort(key=lambda item: (item.path, item.line, item.address, item.kind))
    return tuple(facts)


def _resource(
    doc: Mapping[str, object],
    path: str,
    configs: Mapping[str, list[EncryptionFact]],
) -> list[EncryptionFact]:
    kind = _kind(doc)
    group = _group(doc)
    found: list[EncryptionFact] = []
    if kind in _WORKLOADS:
        if kind == "Pod":
            server = _apiserver(doc, path, configs)
            if server is not None:
                found.append(server)
        found.extend(_images(doc, path, kind))
    elif kind == "Ingress" and group in {"networking.k8s.io", "extensions"}:
        found.append(_ingress(doc, path))
    elif kind == "Secret" and group == "":
        found.append(_secret(doc, path))
    return found


def _encryption_fact(doc: Mapping[str, object], path: str) -> EncryptionFact:
    entry = _secrets_entry(doc.get("resources"))
    if entry is None:
        return _make(
            kind="k8s_secrets_etcd",
            native_type="EncryptionConfiguration",
            address=_address(doc),
            path=path,
            line=_line(doc),
            layers={"database": "NOT_ENCRYPTED"},
            basis=(
                BasisEntry("resources", "no resources entry includes secrets"),
            ),
        )
    provider = _first_provider(entry.get("providers"))
    if provider is None:
        return _make(
            kind="k8s_secrets_etcd",
            native_type="EncryptionConfiguration",
            address=_address(doc),
            path=path,
            line=_line(doc),
            layers={"database": "UNKNOWN"},
            basis=(BasisEntry("provider", None, "attribute_not_modeled"),),
            unknown_reason="attribute_not_modeled",
        )
    name, body = provider
    return _provider_fact(doc, path, name, body)


def _provider_fact(
    doc: Mapping[str, object], path: str, name: str, body: object
) -> EncryptionFact:
    token = name.casefold()
    basis = [BasisEntry("provider", name)]
    verdict = "UNKNOWN"
    reason: str | None = "attribute_not_modeled"
    custody = "unspecified"
    if token == "identity":
        verdict = "NOT_ENCRYPTED"
        reason = None
    elif token == "kms":
        verdict = "ENCRYPTED_DECLARED"
        reason = None
        custody = "customer_managed"
        basis.append(BasisEntry("kms_api", _kms_api(body)))
    elif token in _LOCAL:
        verdict = "ENCRYPTED_DECLARED"
        reason = None
        custody = "local_file"
        basis.append(BasisEntry("custody", "local_file"))
    else:
        basis.append(BasisEntry("provider", name, "attribute_not_modeled"))
    return _make(
        kind="k8s_secrets_etcd",
        native_type="EncryptionConfiguration",
        address=_address(doc),
        path=path,
        line=_line(doc),
        layers={"database": verdict},
        basis=tuple(basis),
        key_management=custody,
        unknown_reason=reason,
    )


def _apiserver(
    doc: Mapping[str, object],
    path: str,
    configs: Mapping[str, list[EncryptionFact]],
) -> EncryptionFact | None:
    for container in _containers(_pod_spec(doc, "Pod")):
        if not _is_apiserver(container):
            continue
        flag = _encryption_flag(container)
        if flag is None:
            verdict, row, reason, basis = _missing_flag()
            return _make(
                kind="k8s_secrets_etcd",
                native_type="Pod",
                address=_address(doc),
                path=path,
                line=_line(doc),
                layers={"database": verdict},
                basis=basis,
                default_row=row,
                unknown_reason=reason,
            )
        linked = _link(flag, configs)
        basis = (BasisEntry("via --encryption-provider-config", flag),)
        if linked is None:
            return _make(
                kind="k8s_secrets_etcd",
                native_type="Pod",
                address=_address(doc),
                path=path,
                line=_line(doc),
                layers={"database": "UNKNOWN"},
                basis=basis,
                unknown_reason="unresolved_reference",
            )
        database = linked.layers.get("database", linked.verdict)
        return _make(
            kind="k8s_secrets_etcd",
            native_type="Pod",
            address=_address(doc),
            path=path,
            line=_line(doc),
            layers={"database": database},
            basis=basis + linked.basis,
            default_row=linked.default_row,
            key_management=linked.key_management,
            unknown_reason=linked.unknown_reason,
        )
    return None


def _missing_flag() -> tuple[str, str | None, str | None, tuple[BasisEntry, ...]]:
    """The flag is absent, so the reviewed default row decides.

    ``self_hosted`` is left false here: the verdict table returns
    ``layer_not_observable`` before a default row when that bit is set, and
    this row is the documented plaintext default.
    """
    row = load_registry().by_id[_APISERVER_ROW]
    result = assess_layer(
        LayerCase(
            sources=(Absent(),),
            effect=row.effect,
            assessable=row.assessable_as_unencrypted,
            row_id=row.id,
            caveat=row.caveat,
        )
    )
    basis = (
        BasisEntry("encryption-provider-config", None),
        BasisEntry("default_row", result.default_row),
        BasisEntry("caveat", result.caveat or None),
    )
    return result.verdict, result.default_row, result.reason, basis


def _images(
    doc: Mapping[str, object], path: str, kind: str
) -> list[EncryptionFact]:
    found: list[EncryptionFact] = []
    owner = _address(doc)
    for container in _containers(_pod_spec(doc, kind)):
        image = container.get("image")
        if not isinstance(image, str):
            continue
        matched = match_datastore_image(image)
        if matched is None:
            continue
        image_id, store_kind = matched
        label = container.get("name")
        suffix = label if isinstance(label, str) and label else image_id
        layers = unobserved_layers()
        found.append(
            _make(
                kind=store_kind,
                provider="kubernetes",
                native_type=image_id,
                address=f"{owner}/{suffix}",
                path=path,
                line=_line(container),
                layers=layers,
                basis=unobserved_basis(image_id),
                unknown_reason="layer_not_observable",
            )
        )
    return found


def _ingress(doc: Mapping[str, object], path: str) -> EncryptionFact:
    spec = _map(doc.get("spec"))
    notes = _map(_map(doc.get("metadata")).get("annotations"))
    refs = _secret_refs(spec)
    has_tls = _tls_present(spec, notes)
    plain, redirect = _listener_inputs(notes, has_tls)
    heard = listener_reader(plaintext=plain, redirect=redirect)
    basis = refs + _cipher_basis(notes)
    if heard.reason:
        basis = basis + (BasisEntry("transport", None, heard.reason),)
    return _make(
        kind="tls_endpoint",
        native_type="Ingress",
        address=_address(doc),
        path=path,
        line=_line(doc),
        layers={"transport": heard.verdict},
        basis=basis,
        unknown_reason=heard.reason,
    )


def _secret(doc: Mapping[str, object], path: str) -> EncryptionFact:
    raw_type = doc.get("type")
    shown = raw_type if isinstance(raw_type, str) and raw_type else "Opaque"
    return _make(
        kind="secret_store",
        native_type="Secret",
        address=_address(doc),
        path=path,
        line=_line(doc),
        layers={"service": "UNKNOWN"},
        basis=(BasisEntry("type", shown), BasisEntry("name", _name(doc))),
        unknown_reason="layer_not_observable",
    )


def _make(
    *,
    kind: str,
    native_type: str,
    address: str,
    path: str,
    line: int,
    layers: Mapping[str, str],
    basis: tuple[BasisEntry, ...] = (),
    provider: str = "k8s",
    default_row: str | None = None,
    key_management: str = "unspecified",
    unknown_reason: str | None = None,
) -> EncryptionFact:
    transport_only = kind in {"tls_endpoint", "ssh_service"}
    rolled = resource_verdict(dict(layers), transport_only=transport_only)
    return EncryptionFact(
        id=make_fact_id(kind, provider, native_type, address, path),
        kind=kind,
        provider=provider,
        native_type=native_type,
        address=address,
        path=path,
        line=line if line > 0 else 1,
        format="kubernetes",
        layers=dict(layers),
        verdict=rolled or "UNKNOWN",
        basis=basis[:40],
        default_row=default_row,
        key_management=key_management,
        unknown_reason=unknown_reason,
        path_context=path_context(path),
    )


def _secrets_entry(raw: object) -> Mapping[str, object] | None:
    if not isinstance(raw, list):
        return None
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        names = item.get("resources")
        if not isinstance(names, list):
            continue
        if any(isinstance(name, str) and name in _COVERS for name in names):
            return item
    return None


def _first_provider(raw: object) -> tuple[str, object] | None:
    if not isinstance(raw, list):
        return None
    for item in raw:
        if not isinstance(item, Mapping) or not item:
            continue
        key = next(iter(item))
        if isinstance(key, str) and key:
            return key, item[key]
    return None


def _kms_api(body: object) -> str:
    if isinstance(body, Mapping):
        raw = body.get("apiVersion")
        if isinstance(raw, str) and "v2" in raw.casefold():
            return "v2"
    return "v1"


def _link(
    flag: str, configs: Mapping[str, list[EncryptionFact]]
) -> EncryptionFact | None:
    wanted = _parts(flag)
    if not wanted:
        return None
    best = 0
    chosen: list[EncryptionFact] = []
    for rel, facts in configs.items():
        if len(facts) != 1:
            continue
        shared = _shared_suffix(wanted, _parts(rel))
        if shared == 0:
            continue
        if shared > best:
            best = shared
            chosen = [facts[0]]
        elif shared == best:
            chosen.append(facts[0])
    if len(chosen) == 1:
        return chosen[0]
    return None


def _shared_suffix(left: tuple[str, ...], right: tuple[str, ...]) -> int:
    count = 0
    for one, two in zip(reversed(left), reversed(right), strict=False):
        if one != two:
            break
        count += 1
    return count


def _parts(path: str) -> tuple[str, ...]:
    return tuple(
        part for part in path.replace("\\", "/").split("/") if part not in {"", "."}
    )


def _is_apiserver(container: Mapping[str, object]) -> bool:
    for key in ("command", "args"):
        words = _words(container.get(key))
        if words and _binary(words[0]) == "kube-apiserver":
            return True
    return False


def _encryption_flag(container: Mapping[str, object]) -> str | None:
    words = _words(container.get("command")) + _words(container.get("args"))
    for index, word in enumerate(words):
        if word.startswith(f"{_FLAG}="):
            return word.split("=", 1)[1]
        if word == _FLAG and index + 1 < len(words):
            return words[index + 1]
    return None


def _words(value: object) -> list[str]:
    if isinstance(value, str):
        return value.split()
    if not isinstance(value, list):
        return []
    found: list[str] = []
    for item in value:
        if isinstance(item, str):
            found.extend(item.split())
    return found


def _binary(token: str) -> str:
    return token.replace("\\", "/").rsplit("/", 1)[-1]


def _pod_spec(doc: Mapping[str, object], kind: str) -> Mapping[str, object]:
    spec = _map(doc.get("spec"))
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job = _map(_map(spec.get("jobTemplate")).get("spec"))
        return _map(_map(job.get("template")).get("spec"))
    return _map(_map(spec.get("template")).get("spec"))


def _containers(spec: Mapping[str, object]) -> list[Mapping[str, object]]:
    found: list[Mapping[str, object]] = []
    for key in ("containers", "initContainers"):
        raw = spec.get(key)
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, Mapping):
                found.append(item)
    return found


def _secret_refs(spec: Mapping[str, object]) -> tuple[BasisEntry, ...]:
    tls = spec.get("tls")
    if not isinstance(tls, list):
        return ()
    found: list[BasisEntry] = []
    for item in tls:
        if not isinstance(item, Mapping):
            continue
        name = _identifier(item.get("secretName"))
        if name is not None:
            found.append(BasisEntry("ref", name))
    return tuple(found)


def _identifier(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 253:
        return None
    if any(char not in _REF_CHARS for char in value):
        return None
    return value


def _tls_present(spec: Mapping[str, object], notes: Mapping[str, object]) -> bool:
    tls = spec.get("tls")
    if isinstance(tls, list) and len(tls) > 0:
        return True
    for key in (
        "alb.ingress.kubernetes.io/certificate-arn",
        "service.beta.kubernetes.io/aws-load-balancer-ssl-cert",
    ):
        if isinstance(notes.get(key), str) and notes.get(key):
            return True
    return False


def _listener_inputs(
    notes: Mapping[str, object], has_tls: bool
) -> tuple[bool, bool]:
    raw = notes.get("nginx.ingress.kubernetes.io/ssl-redirect")
    force = notes.get("nginx.ingress.kubernetes.io/force-ssl-redirect")
    if isinstance(raw, str) and raw == "false" and not _truthy(force):
        return True, False
    if has_tls or _truthy(force) or _truthy(raw) or _alb_redirect(notes):
        return False, True
    return True, False


def _alb_redirect(notes: Mapping[str, object]) -> bool:
    for key in (
        "alb.ingress.kubernetes.io/ssl-redirect",
        "appgw.ingress.kubernetes.io/ssl-redirect",
    ):
        if _truthy(notes.get(key)):
            return True
    return False


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value > 0
    if isinstance(value, str):
        text = value.strip()
        return bool(text) and text != "false"
    return False


def _cipher_basis(notes: Mapping[str, object]) -> tuple[BasisEntry, ...]:
    raw = notes.get("nginx.ingress.kubernetes.io/ssl-ciphers")
    if not isinstance(raw, str) or not raw.strip():
        return ()
    result = evaluator_for(_CIPHERS).cipher_list(raw)  # type: ignore[arg-type]
    rows = [BasisEntry("cipher_suite", name) for name in result.suites[:32]]
    if result.unresolved:
        rows.append(BasisEntry("cipher_suite", None, "unresolved_expression"))
    return tuple(rows)


def _resources(value: object) -> list[Mapping[str, object]]:
    if isinstance(value, list):
        found: list[Mapping[str, object]] = []
        for item in value:
            found.extend(_resources(item))
        return found
    if not isinstance(value, Mapping):
        return []
    kind = value.get("kind")
    api = value.get("apiVersion")
    if isinstance(kind, str) and kind.endswith("List"):
        items = value.get("items")
        if not isinstance(items, list):
            return []
        found = []
        for item in items:
            found.extend(_resources(item))
        return found
    if isinstance(api, str) and "kustomize.config.k8s.io" in api:
        return []
    if kind == "Kustomization":
        return []
    if not isinstance(api, str) or not isinstance(kind, str):
        return []
    return [value]


def _kind(doc: Mapping[str, object]) -> str:
    kind = doc.get("kind")
    return kind if isinstance(kind, str) else ""


def _group(doc: Mapping[str, object]) -> str:
    api = doc.get("apiVersion")
    if not isinstance(api, str) or "/" not in api:
        return ""
    return api.split("/", 1)[0]


def _map(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def _name(doc: Mapping[str, object]) -> str:
    name = _map(doc.get("metadata")).get("name")
    if isinstance(name, str) and name:
        return name
    return "unnamed"


def _namespace(doc: Mapping[str, object]) -> str:
    space = _map(doc.get("metadata")).get("namespace")
    if isinstance(space, str) and space:
        return space
    return "default"


def _address(doc: Mapping[str, object]) -> str:
    return f"{_namespace(doc)}/{_name(doc)}"


def _line(doc: object) -> int:
    line = getattr(doc, "line", 1)
    if isinstance(line, int) and line > 0:
        return line
    return 1
