import json

import pytest

from research_hardening.formats import Invalid, decode


@pytest.mark.parametrize("value", ['a"' + "[" * 70, 'a\\"' + "]" * 70, "end\\", "\\\\", '{"ok"}'])
def test_escaped_text(value):
    assert decode(json.dumps({"x": value}).encode()) == {"x": value}


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":0,"x":1}',
        b"[]",
        b'{"x":truee}',
        b'{"x":NaN}',
        b'{"x":1.5}',
        b'{"x":' + b"0" * 19 + b"}",
        b"\xff",
        b'{"x":"' + b"a" * 4200 + b'"}',
        b'{"x":' + b"[" * 24 + b"]" * 24 + b"}",
    ],
)
def test_decode_rejects_invalid_input(raw):
    with pytest.raises(Invalid):
        decode(raw)
