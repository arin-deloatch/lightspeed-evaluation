"""Unit tests for RedTeamPipeline."""

from typing import Any

import pytest
from pytest_mock import MockerFixture

from lightspeed_evaluation.core.models import SystemConfig
from lightspeed_evaluation.core.models.red_team import (
    RedTeamConfig,
    RedTeamSummary,
    RedTeamVulnerabilityConfig,
)
from lightspeed_evaluation.core.system.exceptions import ConfigurationError
from lightspeed_evaluation.pipeline.red_team.pipeline import RedTeamPipeline

# Patch path for the internal deepteam call
_CALL_RED_TEAM = (
    "lightspeed_evaluation.pipeline.red_team.pipeline.RedTeamPipeline._call_red_team"
)
_TARGET_API = (
    "lightspeed_evaluation.pipeline.red_team.pipeline.TargetBuilder.from_api_client"
)
_TARGET_LLM = (
    "lightspeed_evaluation.pipeline.red_team.pipeline.TargetBuilder.from_llm_config"
)
_API_CLIENT = "lightspeed_evaluation.pipeline.red_team.pipeline.APIClient"
_REPORT_GEN = "lightspeed_evaluation.pipeline.red_team.pipeline.RedTeamReportGenerator"
_GRAPH_GEN = "lightspeed_evaluation.pipeline.red_team.pipeline.GraphGenerator"
_SUMMARY_FROM = (
    "lightspeed_evaluation.pipeline.red_team.pipeline"
    ".RedTeamSummary.from_deepteam_results"
)
_IMPORT_LIB = "lightspeed_evaluation.pipeline.red_team.pipeline.importlib.import_module"


def _make_rt_config(**overrides: Any) -> RedTeamConfig:
    """Build a minimal RedTeamConfig using real deepteam imports for validation."""
    defaults: dict[str, Any] = {
        "target_purpose": "RHEL assistant",
        "attacks": ["PromptInjection"],
    }
    defaults.update(overrides)
    return RedTeamConfig(**defaults)


def _make_summary() -> RedTeamSummary:
    return RedTeamSummary(
        timestamp="2026-05-01T00:00:00+00:00",
        target_purpose="RHEL assistant",
        target_type="api",
        total_attacks=1,
        total_exploited=0,
        total_safe=1,
        total_errors=0,
        overall_exploitation_rate=0.0,
    )


def _patch_run_infra(mocker: MockerFixture) -> tuple:
    """Patch all heavy infra so run() completes without real network calls.

    _IMPORT_LIB is intentionally excluded: mocking importlib.import_module before
    other mocker.patch() calls breaks pkgutil.resolve_name (used by mock internally),
    causing those later patches to silently target throwaway Mock objects instead of
    the real classes.  deepteam is installed, so real imports work here.
    """
    mock_red_team = mocker.patch(
        _CALL_RED_TEAM, return_value=mocker.MagicMock(test_cases=[])
    )
    mocker.patch(_SUMMARY_FROM, return_value=_make_summary())
    mock_report = mocker.patch(_REPORT_GEN)
    mock_graph = mocker.patch(_GRAPH_GEN)
    mocker.patch(_API_CLIENT)
    mock_from_api = mocker.patch(_TARGET_API, return_value=mocker.AsyncMock())
    return mock_red_team, mock_report, mock_graph, mock_from_api


class TestRedTeamPipelineGuards:
    """Configuration validation tests."""

    def test_raises_if_no_red_team_config(self) -> None:
        """run() raises ConfigurationError when red_team is None."""
        config = SystemConfig()
        pipeline = RedTeamPipeline(config)

        with pytest.raises(
            ConfigurationError, match="red_team configuration is required"
        ):
            pipeline.run()

    def test_raises_if_api_disabled_no_model_id(self) -> None:
        """ConfigurationError when api.enabled=False and llm_model_id is not set."""
        rt_cfg = _make_rt_config(llm_model_id=None)
        config = SystemConfig(red_team=rt_cfg)
        config.api.enabled = False  # type: ignore[misc]

        pipeline = RedTeamPipeline(config)

        with pytest.raises(ConfigurationError, match="llm_model_id"):
            pipeline.run()


class TestRedTeamPipelineTarget:
    """Tests for target selection logic."""

    def test_api_target_used_when_api_enabled(self, mocker: MockerFixture) -> None:
        """TargetBuilder.from_api_client is called when api.enabled=True."""
        _, mock_report, mock_graph, mock_from_api = _patch_run_infra(mocker)

        rt_cfg = _make_rt_config()
        config = SystemConfig(red_team=rt_cfg)
        config.api.enabled = True  # type: ignore[misc]

        RedTeamPipeline(config).run()

        mock_from_api.assert_called_once()
        _ = mock_report, mock_graph

    def test_llm_target_used_when_api_disabled(self, mocker: MockerFixture) -> None:
        """TargetBuilder.from_llm_config is called when api.enabled=False."""
        mocker.patch(_CALL_RED_TEAM, return_value=mocker.MagicMock(test_cases=[]))
        mocker.patch(_SUMMARY_FROM, return_value=_make_summary())
        mocker.patch(_REPORT_GEN)
        mocker.patch(_GRAPH_GEN)
        mock_from_llm = mocker.patch(_TARGET_LLM, return_value=mocker.MagicMock())
        mocker.patch.object(
            SystemConfig, "get_llm_config", return_value=mocker.MagicMock()
        )

        rt_cfg = _make_rt_config(llm_model_id="pool_model")
        config = SystemConfig(red_team=rt_cfg)
        config.api.enabled = False  # type: ignore[misc]

        RedTeamPipeline(config).run()

        mock_from_llm.assert_called_once()


class TestRedTeamPipelineCleanup:
    """API client lifecycle tests."""

    def test_api_client_closed_on_success(self, mocker: MockerFixture) -> None:
        """APIClient.close() is called after a successful run."""
        mocker.patch(_CALL_RED_TEAM, return_value=mocker.MagicMock(test_cases=[]))
        mocker.patch(_SUMMARY_FROM, return_value=_make_summary())
        mocker.patch(_REPORT_GEN)
        mocker.patch(_GRAPH_GEN)
        mock_client = mocker.MagicMock()
        mocker.patch(_API_CLIENT, return_value=mock_client)
        mocker.patch(_TARGET_API, return_value=mocker.AsyncMock())

        rt_cfg = _make_rt_config()
        config = SystemConfig(red_team=rt_cfg)
        config.api.enabled = True  # type: ignore[misc]

        RedTeamPipeline(config).run()

        mock_client.close.assert_called_once()

    def test_api_client_closed_on_error(self, mocker: MockerFixture) -> None:
        """APIClient.close() is called even when _call_red_team raises."""
        mocker.patch(_CALL_RED_TEAM, side_effect=RuntimeError("deepteam failure"))
        mock_client = mocker.MagicMock()
        mocker.patch(_API_CLIENT, return_value=mock_client)
        mocker.patch(_TARGET_API, return_value=mocker.AsyncMock())

        rt_cfg = _make_rt_config()
        config = SystemConfig(red_team=rt_cfg)
        config.api.enabled = True  # type: ignore[misc]

        with pytest.raises(RuntimeError, match="deepteam failure"):
            RedTeamPipeline(config).run()

        mock_client.close.assert_called_once()


class TestRedTeamPipelineResolvers:
    """Tests for resolve_model, vulnerabilities, and attacks."""

    def test_resolve_model_none_returns_none(self) -> None:
        """None model_ref returns None (deepteam uses its built-in default)."""
        rt_cfg = _make_rt_config()
        config = SystemConfig(red_team=rt_cfg)
        pipeline = RedTeamPipeline(config)

        assert pipeline.resolve_model(None, "simulator") is None

    def test_resolve_model_direct_string_passthrough(self) -> None:
        """A model name not in llm_pool is returned unchanged."""
        rt_cfg = _make_rt_config()
        config = SystemConfig(red_team=rt_cfg)
        pipeline = RedTeamPipeline(config)

        result = pipeline.resolve_model("gpt-4o-mini", "evaluator")

        assert result == "gpt-4o-mini"

    def test_resolve_model_pool_key_resolved(self, mocker: MockerFixture) -> None:
        """A llm_pool key is resolved to a DeepEvalBaseLLM instance."""
        rt_cfg = _make_rt_config()
        config = SystemConfig(red_team=rt_cfg)
        mock_llm_config = mocker.MagicMock()
        mocker.patch.object(
            SystemConfig, "get_llm_config", return_value=mock_llm_config
        )
        config.llm_pool = mocker.MagicMock()  # type: ignore[misc]
        config.llm_pool.models = {"judge_model": mocker.MagicMock()}
        mock_llm_obj = mocker.MagicMock()
        mocker.patch(
            "lightspeed_evaluation.pipeline.red_team.pipeline.TargetBuilder.from_llm_config",
            return_value=mock_llm_obj,
        )

        pipeline = RedTeamPipeline(config)
        result = pipeline.resolve_model("judge_model", "simulator")

        assert result is mock_llm_obj

    def test_unknown_vulnerability_raises(self, mocker: MockerFixture) -> None:
        """_resolve_vulnerabilities raises ConfigurationError for unknown class."""
        pipeline = RedTeamPipeline(SystemConfig(red_team=_make_rt_config()))

        mocker.patch(_IMPORT_LIB, return_value=mocker.MagicMock(spec=[]))

        with pytest.raises(ConfigurationError, match="Unknown vulnerability"):
            pipeline.resolve_vulnerabilities(
                [RedTeamVulnerabilityConfig(name="NonExistentVuln")]
            )

    def test_unknown_attack_raises(self, mocker: MockerFixture) -> None:
        """_resolve_attacks raises ConfigurationError for unknown attack class."""
        pipeline = RedTeamPipeline(SystemConfig(red_team=_make_rt_config()))

        mocker.patch(_IMPORT_LIB, return_value=mocker.MagicMock(spec=[]))

        with pytest.raises(ConfigurationError, match="Unknown attack"):
            pipeline.resolve_attacks(["NonExistentAttack"])


class TestRedTeamPipelineOutputs:
    """Tests for report and graph generation in run()."""

    def test_report_generator_called_with_summary(self, mocker: MockerFixture) -> None:
        """RedTeamReportGenerator.save() is called with the summary."""
        _, mock_report, mock_graph, _ = _patch_run_infra(mocker)

        rt_cfg = _make_rt_config()
        config = SystemConfig(red_team=rt_cfg)
        config.api.enabled = True  # type: ignore[misc]

        RedTeamPipeline(config).run()

        mock_report.return_value.save.assert_called_once()
        _ = mock_graph

    def test_graphs_generated_when_enabled(self, mocker: MockerFixture) -> None:
        """GraphGenerator.generate_red_team_graphs is called when graphs enabled."""
        _, mock_report, mock_graph, _ = _patch_run_infra(mocker)

        rt_cfg = _make_rt_config(enabled_graphs=["vulnerability_breakdown"])
        config = SystemConfig(red_team=rt_cfg)
        config.api.enabled = True  # type: ignore[misc]

        RedTeamPipeline(config).run()

        mock_graph.return_value.generate_red_team_graphs.assert_called_once()
        _ = mock_report
