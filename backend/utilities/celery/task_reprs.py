"""The printable copies of a task's arguments in every Celery message the backend sends are redacted (#44, #88).

A task message carries the real kwargs in its body (the worker needs them: an MCP scan's ``Authorization`` header, a
repository PAT, an LLM api_key) and, in its headers, ``argsrepr`` / ``kwargsrepr``: the text Celery shows for the task
in worker log records, events (``celery events``, Flower) and ``inspect`` replies. Celery fills them with a plain
``repr`` of the arguments, credentials included. This ``before_task_publish`` receiver replaces both with
``log_redaction.safe_repr`` of the same values (header names kept, header values and secret fields replaced) before
the message is published; the body, what the worker runs with, is untouched. (Celery's ``task-sent`` event copies the
reprs before this signal; it is never sent here, ``task_send_sent_event`` being off.)

It is connected when this module is imported, which ``celery_connection`` does: every backend publisher gets its app
from ``get_celery_app`` there.
"""
from __future__ import annotations

from typing import Any

from celery.signals import before_task_publish

from backend.utilities.log_redaction import UNREDACTABLE, safe_repr

# Celery's own bound on these two headers (app.amqp.argsrepr_maxsize / kwargsrepr_maxsize)
MAX_REPR = 1024


def redact_task_reprs(headers: Any = None, body: Any = None, **_signal: Any) -> None:
    """Never raises: a body it cannot read gets the fixed UNREDACTABLE text. A message without these headers (task
    protocol 1) is left alone."""
    if not isinstance(headers, dict) or "kwargsrepr" not in headers:
        return
    try:
        args, kwargs = body[0], body[1]  # protocol 2 body: (args, kwargs, embed)
        headers["argsrepr"] = safe_repr(args)[:MAX_REPR]
        headers["kwargsrepr"] = safe_repr(kwargs)[:MAX_REPR]
    except Exception:
        headers["argsrepr"] = headers["kwargsrepr"] = UNREDACTABLE


before_task_publish.connect(redact_task_reprs, weak=False, dispatch_uid="backend.redact_task_reprs")
