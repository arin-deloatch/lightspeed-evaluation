"""Unit tests for red team Pydantic models."""

from dataclasses import dataclass, field
from typing import Optional

import pytest
from pydantic import ValidationError
from pytest_mock import MockerFixture

from lightspeed_evaluation.core.models import SystemConfig
from lightspeed_evaluation.core.models.red_team import (
    RedTeamConfig,
    RedTeamSummary,
    RedTeamVulnerabilityConfig,
)


@dataclass
class FakeTestCase:
    """Minimal stand-in for deepteam's RTTestCase."""

    vulnerability: str = "Bias"
    attack_method: Optional[str] = "PromptInjection"
    input: Optional[str] = "test input"
    actual_output: Optional[str] = "test output"
    score: Optional[float] = None
    reason: Optional[str] = ""
    error: Optional[str] = None


@dataclass
class FakeRiskAssessment:
    """Minimal stand-in for deepteam's RiskAssessment."""

    test_cases: list = field(default_factory=list)


class TestRedTeamVulnerabilityConfig:
    """Tests for RedTeamVulnerabilityConfig."""

    def test_name_required(self) -> None:
        """Missing name raises ValidationError."""
        with pytest.raises(ValidationError):
            RedTeamVulnerabilityConfig()  # type: ignore[call-arg]

    def test_extra_params_captured(self) -> None:
        """Extra kwargs (e.g. types=[...]) are captured via extra='allow'."""
        cfg = RedTeamVulnerabilityConfig.model_validate(
            {"name": "Bias", "types": ["race", "gender"]}
        )
        assert cfg.name == "Bias"
        assert cfg.model_extra == {"types": ["race", "gender"]}

    def test_minimal_construction(self) -> None:
        """Name-only construction works without extras."""
        cfg = RedTeamVulnerabilityConfig(name="Toxicity")
        assert cfg.name == "Toxicity"
        assert (cfg.model_extra or {}) == {}


class TestRedTeamConfig:
    """Tests for RedTeamConfig."""

    def test_target_purpose_required(self) -> None:
        """ValidationError raised when target_purpose is missing."""
        with pytest.raises(ValidationError):
            RedTeamConfig()  # type: ignore[call-arg]

    def test_defaults_applied(self, mocker: MockerFixture) -> None:
        """Defaults are applied for optional fields."""
        mock_mod = mocker.MagicMock()
        mocker.patch("importlib.import_module", return_value=mock_mod)

        cfg = RedTeamConfig(target_purpose="test", attacks=["PromptInjection"])

        assert cfg.attacks_per_vulnerability_type == 1
        assert cfg.output_dir == "./red_team_output"
        assert cfg.async_mode is True
        assert cfg.max_concurrent == 10
        assert cfg.simulator_model is None
        assert cfg.evaluation_model is None

    def test_invalid_attack_raises(self, mocker: MockerFixture) -> None:
        """Unknown attack class name raises ValueError."""
        # spec=[] means the mock has no attributes, so hasattr(mod, name) == False
        mocker.patch("importlib.import_module", return_value=mocker.MagicMock(spec=[]))

        with pytest.raises(ValidationError, match="Unknown attack"):
            RedTeamConfig(target_purpose="test", attacks=["BogusAttack"])

    def test_invalid_graph_type_raises(self, mocker: MockerFixture) -> None:
        """Unsupported graph type in enabled_graphs raises ValueError."""
        mock_mod = mocker.MagicMock()
        mocker.patch("importlib.import_module", return_value=mock_mod)

        with pytest.raises(ValidationError, match="Unsupported graph types"):
            RedTeamConfig(
                target_purpose="test",
                attacks=["PromptInjection"],
                enabled_graphs=["bogus_chart"],
            )

    def test_extra_field_forbidden(self, mocker: MockerFixture) -> None:
        """Unknown top-level fields raise ValidationError."""
        mock_mod = mocker.MagicMock()
        mocker.patch("importlib.import_module", return_value=mock_mod)

        with pytest.raises(ValidationError):
            RedTeamConfig(
                target_purpose="test",
                attacks=["PromptInjection"],
                unknown_field="bad",  # type: ignore[call-arg]
            )


class TestRedTeamSummary:
    """Tests for RedTeamSummary.from_deepteam_results."""

    def test_from_deepteam_results_empty(self) -> None:
        """Empty test_cases produces all-zero summary."""
        summary = RedTeamSummary.from_deepteam_results(
            FakeRiskAssessment(test_cases=[]), "test", "api"
        )

        assert summary.total_attacks == 0
        assert summary.total_exploited == 0
        assert summary.total_safe == 0
        assert summary.total_errors == 0
        assert summary.overall_exploitation_rate == 0.0
        assert not summary.by_vulnerability

    def test_from_deepteam_results_safe_case(self) -> None:
        """score > 0 is classified as safe (not exploited)."""
        summary = RedTeamSummary.from_deepteam_results(
            FakeRiskAssessment(test_cases=[FakeTestCase(score=1.0)]), "test", "api"
        )

        assert summary.total_safe == 1
        assert summary.total_exploited == 0
        assert summary.overall_exploitation_rate == 0.0

    def test_from_deepteam_results_exploited_case(self) -> None:
        """score == 0 without error is classified as exploited."""
        summary = RedTeamSummary.from_deepteam_results(
            FakeRiskAssessment(test_cases=[FakeTestCase(score=0.0)]), "test", "api"
        )

        assert summary.total_exploited == 1
        assert summary.total_safe == 0

    def test_from_deepteam_results_mixed_counts(self) -> None:
        """Mixed results produce correct totals and exploitation rate."""
        test_cases = [
            FakeTestCase(score=1.0),  # safe
            FakeTestCase(score=0.0),  # exploited
            FakeTestCase(score=0.0),  # exploited
        ]
        summary = RedTeamSummary.from_deepteam_results(
            FakeRiskAssessment(test_cases=test_cases), "purpose", "llm"
        )

        assert summary.total_attacks == 3
        assert summary.total_safe == 1
        assert summary.total_exploited == 2
        assert summary.total_errors == 0
        assert summary.overall_exploitation_rate == pytest.approx(66.67, abs=0.1)

    def test_from_deepteam_results_error_case(self) -> None:
        """Test cases with error are counted separately, not as exploited."""
        summary = RedTeamSummary.from_deepteam_results(
            FakeRiskAssessment(test_cases=[FakeTestCase(score=None, error="timeout")]),
            "test",
            "api",
        )

        assert summary.total_errors == 1
        assert summary.total_exploited == 0
        assert summary.total_safe == 0
        assert summary.overall_exploitation_rate == 0.0

    def test_from_deepteam_results_by_vulnerability(self) -> None:
        """by_vulnerability dict is populated per vulnerability class."""
        test_cases = [
            FakeTestCase(vulnerability="Bias", score=0.0),
            FakeTestCase(vulnerability="Bias", score=1.0),
            FakeTestCase(vulnerability="Toxicity", score=0.0),
        ]
        summary = RedTeamSummary.from_deepteam_results(
            FakeRiskAssessment(test_cases=test_cases), "test", "api"
        )

        assert "Bias" in summary.by_vulnerability
        assert "Toxicity" in summary.by_vulnerability
        bias = summary.by_vulnerability["Bias"]
        assert bias.exploited == 1
        assert bias.safe == 1
        toxicity = summary.by_vulnerability["Toxicity"]
        assert toxicity.exploited == 1
        assert toxicity.exploitation_rate == pytest.approx(100.0)

    def test_target_type_propagated(self) -> None:
        """target_type and target_purpose are stored on the summary."""
        summary = RedTeamSummary.from_deepteam_results(
            FakeRiskAssessment(), "RHEL assistant", "llm"
        )
        assert summary.target_type == "llm"
        assert summary.target_purpose == "RHEL assistant"


class TestSystemConfigRedTeam:
    """Tests for the red_team field on SystemConfig."""

    def test_red_team_defaults_to_none(self) -> None:
        """SystemConfig() has red_team=None when not provided."""
        config = SystemConfig()
        assert config.red_team is None

    def test_red_team_field_accepted(self, mocker: MockerFixture) -> None:
        """SystemConfig accepts a RedTeamConfig instance without error."""
        mock_mod = mocker.MagicMock()
        mocker.patch("importlib.import_module", return_value=mock_mod)
        rt_cfg = RedTeamConfig(target_purpose="test", attacks=["PromptInjection"])
        config = SystemConfig(red_team=rt_cfg)
        assert config.red_team is rt_cfg
