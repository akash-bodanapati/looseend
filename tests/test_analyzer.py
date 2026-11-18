"""Tests for engine/analyzer.py: inline ignore parsing and the Analyzer base class."""
import pytest

from looseend.engine.analyzer import Analyzer, parse_inline_ignores, should_ignore


def test_parse_single_rule():
    ignores = parse_inline_ignores("x = 1  # looseend: ignore[SEC003]\n")
    assert ignores == {1: {"SEC003"}}


def test_parse_multiple_rules():
    ignores = parse_inline_ignores("x = 1  # looseend: ignore[SEC001, SEC003]\n")
    assert ignores[1] == {"SEC001", "SEC003"}


def test_parse_wildcard_without_brackets():
    ignores = parse_inline_ignores("x = 1  # looseend: ignore\n")
    assert ignores[1] == {"*"}


def test_parse_no_marker_gives_empty():
    assert parse_inline_ignores("x = 1\ny = 2\n") == {}


def test_should_ignore_matching_rule_and_wildcard():
    ignores = {1: {"SEC003"}, 2: {"*"}}
    assert should_ignore(1, "SEC003", ignores)
    assert not should_ignore(1, "SEC001", ignores)
    assert should_ignore(2, "SLOP005", ignores)


def test_should_ignore_other_line_is_false():
    assert not should_ignore(3, "SEC003", {1: {"SEC003"}})


def test_analyzer_is_abstract():
    with pytest.raises(TypeError):
        Analyzer()


def test_concrete_subclass_can_be_instantiated():
    class Dummy(Analyzer):
        def analyze(self, path, source, language, rel_path):
            return iter(())

    assert list(Dummy().analyze(None, "", "python", "a.py")) == []
