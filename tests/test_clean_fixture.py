"""Integration test verifying that a clean repository produces zero findings."""
from looseend.analyzers.gap import GapAnalyzer
from looseend.analyzers.security import SecurityAnalyzer
from looseend.analyzers.slop import SlopAnalyzer
from looseend.engine.runner import run_scan


def test_clean_fixture_zero_findings(tmp_project):
    """The clean fixture must yield zero findings across all analyzers."""
    analyzers = [
        SecurityAnalyzer(),
        SlopAnalyzer(),
        GapAnalyzer(root=tmp_project),
    ]
    result = run_scan(tmp_project, analyzers)
    assert len(result.findings) == 0, [
        (f.rule_id, f.severity.value, f.message, f.file) for f in result.findings
    ]
