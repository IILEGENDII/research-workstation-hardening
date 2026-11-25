import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from research_hardening.formats import Invalid
from research_hardening.paths import local_path
from research_hardening.storage import new_workspace, read_file, write_new


@pytest.mark.parametrize(
    "name",
    [
        "https://example.invalid/a",
        "../file",
        r"\\server\x",
        "X:foo",
        "test:a",
        "NUL.txt",
        "data.",
        "a\nb",
    ],
)
def test_refuse_ambiguous_path(name):
    with pytest.raises(Invalid):
        local_path(name)


def test_competing_writers(tmp_path):
    path = tmp_path / "out.json"

    def write(data):
        try:
            write_new(path, data)
            return data
        except (OSError, Invalid):
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        winners = list(pool.map(write, [b"first", b"second"]))
    assert [v for v in winners if v] == [read_file(path)]
    assert list(tmp_path.iterdir()) == [path]


def test_safe_input_and_size(tmp_path):
    path = tmp_path / "snap.json"
    path.write_bytes(b"1234")
    with pytest.raises(Invalid):
        read_file(path, 3)
    with pytest.raises(Invalid):
        write_new(path, b"changed")
    assert path.read_bytes() == b"1234"


def test_parent_symlink(tmp_path):
    a = tmp_path / "private"
    a.mkdir()
    try:
        (tmp_path / "alias").symlink_to(a, target_is_directory=True)
    except OSError:
        pytest.skip("symlink unavailable")
    with pytest.raises(Invalid):
        write_new(tmp_path / "alias" / "x.json", b"x")


def test_linked_input(tmp_path):
    a = tmp_path / "input"
    a.write_bytes(b"fixture")
    try:
        os.link(a, tmp_path / "second")
    except OSError:
        pytest.skip("hard links unavailable")
    with pytest.raises(Invalid):
        read_file(a)


def test_exclusive_workspace(tmp_path):
    path = tmp_path / "demo"
    assert new_workspace(path) == path
    with pytest.raises((OSError, Invalid)):
        new_workspace(path)
