import pytest

from src.product.code_extractor import resolve_snippet


def test_inline_snippet_short_circuits(tmp_path):
    s = resolve_snippet(
        inline="def foo(): pass",
        repo_root=None,
        file_path="any.py",
        line_start=1,
        line_end=1,
    )
    assert s.text == "def foo(): pass"
    assert s.source == "sarif_inline"
    assert s.truncated is False


def test_disk_read_with_context_window(tmp_path):
    src = tmp_path / "demo.py"
    src.write_text("\n".join(f"line {i}" for i in range(1, 21)) + "\n", encoding="utf-8")
    s = resolve_snippet(
        inline=None,
        repo_root=tmp_path,
        file_path="demo.py",
        line_start=10,
        line_end=10,
        context_lines=2,
    )
    assert "line 8" in s.text
    assert "line 12" in s.text
    assert "line 7" not in s.text
    assert s.effective_start == 8 and s.effective_end == 12
    assert s.source == "disk_read"


def test_disk_read_clipped_to_max_chars(tmp_path):
    src = tmp_path / "big.py"
    src.write_text("a" * 20000 + "\n", encoding="utf-8")
    s = resolve_snippet(
        inline=None,
        repo_root=tmp_path,
        file_path="big.py",
        line_start=1,
        line_end=1,
        max_chars=200,
    )
    assert s.truncated is True
    assert "truncated" in s.text


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        resolve_snippet(
            inline=None,
            repo_root=tmp_path,
            file_path="does_not_exist.py",
            line_start=1,
            line_end=1,
        )


def test_missing_repo_and_no_inline_raises():
    with pytest.raises(FileNotFoundError):
        resolve_snippet(
            inline=None,
            repo_root=None,
            file_path="x.py",
            line_start=1,
            line_end=1,
        )
