"""Report generator for red team evaluation results."""

import json
import logging
from pathlib import Path

from lightspeed_evaluation.core.constants import DEFAULT_RED_TEAM_OUTPUT_DIR
from lightspeed_evaluation.core.models.red_team import RedTeamSummary


class RedTeamReportGenerator:
    """Generates JSON and human-readable text reports from red team results."""

    def __init__(self, output_dir: str = DEFAULT_RED_TEAM_OUTPUT_DIR) -> None:
        """Initialize the report generator."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)

    def save(
        self, summary: RedTeamSummary, base_filename: str = "red_team"
    ) -> list[Path]:
        """Generate JSON and TXT reports. Returns list of created paths."""
        paths = [
            self.generate_json_report(summary, base_filename),
            self.generate_text_report(summary, base_filename),
        ]
        self.logger.info(
            "Red team reports saved to %s (%d files)", self.output_dir, len(paths)
        )
        return paths

    def generate_json_report(
        self, summary: RedTeamSummary, base_filename: str = "red_team"
    ) -> Path:
        """Write summary as indented JSON."""
        path = self.output_dir / f"{base_filename}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(summary.model_dump(), f, indent=2)
        return path

    def generate_text_report(
        self, summary: RedTeamSummary, base_filename: str = "red_team"
    ) -> Path:
        """Write human-readable red team report."""
        path = self.output_dir / f"{base_filename}.txt"
        lines = [
            "=" * 60,
            "Red Team Evaluation Report",
            "=" * 60,
            f"Timestamp:          {summary.timestamp}",
            f"Target purpose:     {summary.target_purpose}",
            f"Target type:        {summary.target_type}",
            f"Total attacks:      {summary.total_attacks}",
            f"Exploited:          {summary.total_exploited}",
            f"Safe:               {summary.total_safe}",
            f"Errors:             {summary.total_errors}",
            f"Exploitation rate:  {summary.overall_exploitation_rate:.1f}%",
            "",
            "By Vulnerability",
            "-" * 40,
        ]
        for vuln, stats in summary.by_vulnerability.items():
            lines.append(
                f"  {vuln:<30} exploited={stats.exploited}/{stats.total - stats.error}"
                f"  ({stats.exploitation_rate:.1f}%)"
            )

        if summary.by_attack:
            lines += ["", "By Attack Method", "-" * 40]
            for attack, stats in summary.by_attack.items():
                lines.append(
                    f"  {attack:<30} exploited={stats.exploited}/{stats.total - stats.error}"
                    f"  ({stats.exploitation_rate:.1f}%)"
                )

        lines += ["", "=" * 60]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        return path
