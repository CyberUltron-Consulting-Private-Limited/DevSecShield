"""Verify API polish (staging QA N8), takeover review of PR #500.

* A lone UTF-16 surrogate is judged on the parsed strings, not by a regex over the
  text: ``"C:\\\\uD800x"`` is an escaped backslash followed by the letters ``uD800x``,
  a valid document, and is not refused; a real lone ``\\ud800`` / ``\\udc00`` escape, in
  a value or in a member name, is a clean 400 text.
* A body that is not UTF-8 is refused with words, not Python's codec message
  ("'utf-8' codec can't decode byte ...").
"""

from __future__ import annotations

import io

import pytest

from backend.utilities.cbom_sources import bom_verify as BV


def test_escaped_backslash_before_u_d800_is_valid_json():
    raw = b'{"path": "C:\\\\uD800x", "p2": "\\\\\\ud83d\\udd11"}'
    assert BV.loads_file(io.BytesIO(raw)) == {"path": "C:\\uD800x", "p2": "\\\U0001F511"}
    assert BV.loads(raw)["path"] == "C:\\uD800x"


@pytest.mark.parametrize("raw", [
    b'{"x": "\\ud800"}',
    b'{"x": "a\\udc00b"}',
    b'{"x": ["ok", {"\\udbff": 1}]}',
    b'{"x": "\\ud800\\u0041"}',
])
def test_lone_surrogates_are_refused_cleanly(raw):
    with pytest.raises(BV.InputError) as err:
        BV.loads_file(io.BytesIO(raw))
    text = str(err.value)
    assert "lone UTF-16 surrogate" in text and "codec" not in text


@pytest.mark.parametrize("raw", [b'{"a": "\xff"}', b'\xfe\xff\x00{', b'{"a": "\xc3"}'])
def test_non_utf8_body_is_refused_in_words(raw):
    for parse in (lambda: BV.loads_file(io.BytesIO(raw)), lambda: BV.loads(raw)):
        with pytest.raises(BV.NotJSON) as err:
            parse()
        text = str(err.value)
        assert "codec" not in text and "UTF-8" in text, text
