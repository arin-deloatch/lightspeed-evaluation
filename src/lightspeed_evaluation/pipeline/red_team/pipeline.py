"""Red team pipeline orchestration."""

import importlib
import logging
import os
from typing import Any, Optional

from lightspeed_evaluation.core.api.client import APIClient
from lightspeed_evaluation.core.models import SystemConfig
from lightspeed_evaluation.core.models.red_team import (
    RedTeamConfig,
    RedTeamSummary,
    RedTeamVulnerabilityConfig,
)
from lightspeed_evaluation.core.output.red_team_generator import RedTeamReportGenerator
from lightspeed_evaluation.core.output.visualization import GraphGenerator
from lightspeed_evaluation.core.system.exceptions import ConfigurationError
from lightspeed_evaluation.pipeline.red_team.target import TargetBuilder

logger = logging.getLogger(__name__)


class RedTeamPipeline:
    """Orchestrates deepteam red teaming against the configured target.

    Completely parallel to EvaluationPipeline — no shared state.
    """

    def __init__(self, system_config: SystemConfig) -> None:
        """Initialize with an already-loaded SystemConfig."""
        self.system_config = system_config
        self._api_client: Optional[APIClient] = None

    def run(self) -> RedTeamSummary:
        """Execute the red team pipeline synchronously."""
        if self.system_config.red_team is None:
            raise ConfigurationError(
                "red_team configuration is required to run RedTeamPipeline. "
                "Add a 'red_team:' section to your system.yaml."
            )

        cfg = self.system_config.red_team
        logger.info(
            "Starting red team run: target=%s, vulnerabilities=%s, attacks=%s",
            cfg.target_purpose,
            [v.name for v in cfg.vulnerabilities],
            cfg.attacks,
        )

        try:
            model_callback, target_type = self._build_target(cfg)
            vulnerabilities = self.resolve_vulnerabilities(cfg.vulnerabilities)
            attacks = self.resolve_attacks(cfg.attacks)
            simulator_name = self.resolve_model(cfg.simulator_model, "simulator")
            evaluator_name = self.resolve_model(cfg.evaluation_model, "evaluator")

            kwargs: dict[str, Any] = {
                "model_callback": model_callback,
                "vulnerabilities": vulnerabilities,
                "attacks": attacks,
                "attacks_per_vulnerability_type": cfg.attacks_per_vulnerability_type,
                "ignore_errors": cfg.ignore_errors,
                "async_mode": cfg.async_mode,
                "max_concurrent": cfg.max_concurrent,
                "target_purpose": cfg.target_purpose,
            }
            if simulator_name is not None:
                kwargs["simulator_model"] = simulator_name
            if evaluator_name is not None:
                kwargs["evaluation_model"] = evaluator_name

            risk_assessment = self._call_red_team(**kwargs)

        finally:
            self.close()

        summary = RedTeamSummary.from_deepteam_results(
            risk_assessment, cfg.target_purpose, target_type
        )

        RedTeamReportGenerator(cfg.output_dir).save(summary)

        if cfg.enabled_graphs:
            GraphGenerator(cfg.output_dir).generate_red_team_graphs(
                summary, "red_team", cfg.enabled_graphs
            )

        logger.info(
            "Red team complete: %d attacks, %.1f%% exploitation rate",
            summary.total_attacks,
            summary.overall_exploitation_rate,
        )
        return summary

    def _build_target(self, cfg: RedTeamConfig) -> tuple[Any, str]:
        """Return (model_callback, target_type) based on api.enabled."""
        if self.system_config.api.enabled:
            client = APIClient(self.system_config.api)
            self._api_client = client
            return TargetBuilder.from_api_client(client), "api"

        if not cfg.llm_model_id:
            raise ConfigurationError(
                "api.enabled is False but red_team.llm_model_id is not set. "
                "Set llm_model_id to a model ID from llm_pool."
            )
        llm_config = self.system_config.get_llm_config(
            cfg.llm_model_id, cache_suffix="redteam"
        )
        return TargetBuilder.from_llm_config(cfg.llm_model_id, llm_config), "llm"

    def resolve_model(self, model_ref: Optional[str], role: str) -> Optional[Any]:
        """Resolve a model reference for use as deepteam simulator or evaluator.

        Resolution order:
        1. None → return None (deepteam uses its built-in default for that role)
        2. Matches a key in llm_pool.models → build a LiteLLMModel instance so
           deepteam routes through LiteLLM rather than its own OpenAI client
        3. Any other string → pass directly to deepteam as a raw model name string
        """
        if model_ref is None:
            return None
        if (
            self.system_config.llm_pool
            and model_ref in self.system_config.llm_pool.models
        ):
            llm_config = self.system_config.get_llm_config(
                model_ref, cache_suffix=f"redteam_{role}"
            )
            return TargetBuilder.from_llm_config(model_ref, llm_config)
        return model_ref

    def close(self) -> None:
        """Close the API client if open. Safe to call multiple times."""
        if self._api_client is not None:
            self._api_client.close()
            self._api_client = None

    def _call_red_team(self, **kwargs: Any) -> Any:
        """Invoke deepteam.red_team(); extracted for testability.

        API_KEY and CONFIDENT_API_KEY are stripped from the environment before
        the call so deepeval's settings does not mistake the Lightspeed API_KEY
        for a Confident AI credential (deepeval falls back to API_KEY when
        CONFIDENT_API_KEY is unset, triggering an unwanted cloud push).
        Both variables are restored in the finally block.
        """
        _MASKED = ("CONFIDENT_API_KEY", "API_KEY")  # pylint: disable=invalid-name
        saved = {k: os.environ.pop(k, None) for k in _MASKED}
        try:
            red_team = importlib.import_module(
                "deepteam"
            ).red_team  # deferred — env vars set by ConfigLoader
            return red_team(**kwargs)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def resolve_vulnerabilities(
        self, cfgs: list[RedTeamVulnerabilityConfig]
    ) -> list[Any]:
        """Dynamically instantiate deepteam vulnerability classes from config."""
        mod = importlib.import_module("deepteam.vulnerabilities")
        result = []
        for vcfg in cfgs:
            cls = getattr(mod, vcfg.name, None)
            if cls is None:
                raise ConfigurationError(
                    f"Unknown vulnerability class: {vcfg.name!r}. "
                    "Must be a class exported from deepteam.vulnerabilities."
                )
            params = vcfg.model_extra or {}
            result.append(cls(**params))
        return result

    def resolve_attacks(self, names: list[str]) -> list[Any]:
        """Dynamically instantiate deepteam attack classes from name strings."""
        result = []
        for name in names:
            cls = None
            for submod_name in (
                "deepteam.attacks.single_turn",
                "deepteam.attacks.multi_turn",
            ):
                mod = importlib.import_module(submod_name)
                cls = getattr(mod, name, None)
                if cls is not None:
                    break
            if cls is None:
                raise ConfigurationError(
                    f"Unknown attack class: {name!r}. "
                    "Must be a class in deepteam.attacks.single_turn or multi_turn."
                )
            result.append(cls())
        return result
