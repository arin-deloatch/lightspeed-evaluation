"""Unit tests for RedTeamReportGenerator."""

import json
from pathlib import Path

from lightspeed_evaluation.core.models.red_team import (
    RedTeamResult,
    RedTeamSummary,
    VulnerabilityStats,
)
from lightspeed_evaluation.core.output.red_team_generator import RedTeamReportGenerator


def _minimal_summary() -> RedTeamSummary:
    """Build a minimal RedTeamSummary for report generation tests."""
    return RedTeamSummary(
        timestamp="2026-05-01T00:00:00+00:00",
        target_purpose="RHEL assistant",
        target_type="api",
        results=[
            RedTeamResult(
                vulnerability="Bias",
                attack="PromptInjection",
                input="test",
                actual_output="response",
                exploited=True,
            )
        ],
        total_attacks=1,
        total_exploited=1,
        total_safe=0,
        total_errors=0,
        overall_exploitation_rate=100.0,
        by_vulnerability={
            "Bias": VulnerabilityStats(
                total=1, exploited=1, safe=0, error=0, exploitation_rate=100.0
            )
        },
        by_attack={
            "PromptInjection": VulnerabilityStats(
                total=1, exploited=1, safe=0, error=0, exploitation_rate=100.0
            )
        },
    )


class TestRedTeamReportGenerator:
    """Tests for RedTeamReportGenerator."""

    def test_save_creates_json_and_txt(self, tmp_path: Path) -> None:
        """save() returns two paths and both files exist."""
        generator = RedTeamReportGenerator(output_dir=str(tmp_path))
        paths = generator.save(_minimal_summary())

        assert len(paths) == 2
        for p in paths:
            assert p.exists()

    def test_json_contains_required_keys(self, tmp_path: Path) -> None:
        """JSON output contains top-level summary keys."""
        generator = RedTeamReportGenerator(output_dir=str(tmp_path))
        generator.save(_minimal_summary())

        json_file = tmp_path / "red_team.json"
        data = json.loads(json_file.read_text())

        assert "timestamp" in data
        assert "target_purpose" in data
        assert "total_attacks" in data
        assert data["total_attacks"] == 1

    def test_txt_contains_header(self, tmp_path: Path) -> None:
        """TXT report contains the 'Red Team' header."""
        generator = RedTeamReportGenerator(output_dir=str(tmp_path))
        generator.save(_minimal_summary())

        txt_file = tmp_path / "red_team.txt"
        content = txt_file.read_text()

        assert "Red Team" in content

    def test_txt_contains_exploitation_rate(self, tmp_path: Path) -> None:
        """TXT report includes the exploitation rate."""
        generator = RedTeamReportGenerator(output_dir=str(tmp_path))
        generator.save(_minimal_summary())

        txt_file = tmp_path / "red_team.txt"
        content = txt_file.read_text()

        assert "100.0%" in content

    def test_output_dir_created_if_missing(self, tmp_path: Path) -> None:
        """Generator creates the output directory when it does not exist."""
        new_dir = tmp_path / "nonexistent" / "nested"
        generator = RedTeamReportGenerator(output_dir=str(new_dir))
        generator.save(_minimal_summary())

        assert new_dir.exists()

    def test_custom_base_filename(self, tmp_path: Path) -> None:
        """Custom base_filename is reflected in the output file names."""
        generator = RedTeamReportGenerator(output_dir=str(tmp_path))
        generator.save(_minimal_summary(), base_filename="custom_run")

        assert (tmp_path / "custom_run.json").exists()
        assert (tmp_path / "custom_run.txt").exists()
