"""The credential redaction log filter formats the record first and redacts the finished text; it never raises.

Found in S2 (round 5): "login: password change required before a session user_id=%s" had its TEMPLATE rewritten
to "... user_id=[REDACTED]" while the arg stayed, so formatting raised TypeError in every handler, and under a
handler that re-raises logging errors the sign-in itself failed with a 500.
"""
import logging
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.log_redaction import UNREDACTABLE, CredentialRedactionFilter, redact  # noqa: E402


class Raising(logging.Handler):
    """Like pytest's capture handler: a logging error is raised, not printed."""

    def __init__(self):
        super().__init__()
        self.lines: list[str] = []
        self.addFilter(CredentialRedactionFilter())

    def emit(self, record):
        self.lines.append(self.format(record))

    def handleError(self, record):  # noqa: N802
        raise


@pytest.fixture()
def log():
    logger = logging.getLogger("test.redaction")
    logger.propagate = False
    handler = Raising()
    logger.handlers = [handler]
    logger.setLevel(logging.DEBUG)
    yield logger, handler.lines
    logger.handlers = []


def test_a_password_template_with_args_formats_and_redacts(log):
    logger, lines = log
    logger.info("login: password change required before a session user_id=%s", 5)  # raised TypeError before
    logger.info("password=%s user=%s", "hunter2-secret", "ana")
    logger.info("reset for %s with password: %s", "ana@x.test", "S3cr3t!pw")
    assert lines[0] == "login: password change required before a session user_id=[REDACTED]"
    assert "hunter2" not in lines[1] and lines[1].startswith("password=[REDACTED]")
    assert "S3cr3t" not in lines[2] and "ana@x.test" in lines[2]


def test_a_dict_arg_is_formatted_then_redacted(log):
    logger, lines = log
    logger.info("user %(user)s password=%(pw)s count=%(n)d", {"user": "ana", "pw": "pa55word-x", "n": 3})
    assert "pa55word" not in lines[0] and lines[0].startswith("user ana password=[REDACTED]")


def test_a_str_format_message_is_redacted(log):
    logger, lines = log
    logger.warning("connect postgres://app:pw@db:5432/x token Bearer abc.def secret: {}".format("verysecretvalue"))
    logger.info(f"api_key={'A' * 20} done")
    assert "app:pw" not in lines[0] and "abc.def" not in lines[0] and "verysecretvalue" not in lines[0]
    assert "AAAAAAAAAAAAAAAAAAAA" not in lines[1]


def test_args_that_do_not_match_never_raise(log):
    logger, lines = log
    logger.info("two %s %s", "only-one")
    logger.info("no placeholders password=%s")  # no args: a literal %s stays
    assert lines[0].startswith("two %s %s") and "dropped" in lines[0]
    assert lines[1] == "no placeholders password=[REDACTED]"


def test_the_filter_never_raises_even_when_the_message_cannot_be_turned_into_text():
    class Hostile:
        def __str__(self):
            raise RuntimeError("no")

    record = logging.LogRecord("x", logging.INFO, __file__, 1, Hostile(), None, None)
    assert CredentialRedactionFilter().filter(record) is True
    assert record.getMessage() == UNREDACTABLE


def test_the_app_installs_this_filter():
    import backend.main as main

    assert main.CredentialRedactionFilter is CredentialRedactionFilter
    assert any(isinstance(f, CredentialRedactionFilter) for f in logging.getLogger().filters)
    assert redact("password=abc") == "password=[REDACTED]"
