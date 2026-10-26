"""Path labels do not change a severity."""

from aibom.cbom.posture.extract_common import FactBuilder, listener_reader, path_context


def test_label_only() -> None:
    assert path_context("docs/nginx.conf") == "non_production_hint"
    assert path_context("prod/nginx.conf") == "production_like"


def test_builder_uses_its_own_dict() -> None:
    builder = FactBuilder()
    builder.add("crypto-cfg_a", {"name": "a"})
    assert builder.has("crypto-cfg_a")
    assert builder.by_ref["crypto-cfg_a"]["name"] == "a"


def test_redirect_is_not_plaintext() -> None:
    redirected = listener_reader(plaintext=True, redirect=True)
    assert redirected.verdict == "ENCRYPTED_DECLARED"
    assert listener_reader(plaintext=True, redirect=False).verdict == "NOT_ENCRYPTED"
