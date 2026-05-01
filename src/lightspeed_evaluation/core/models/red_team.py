"""Pydantic models for red team configuration and results."""

import datetime
import importlib
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from lightspeed_evaluation.core.constants import (
    DEFAULT_RED_TEAM_OUTPUT_DIR,
    SUPPORTED_RED_TEAM_GRAPH_TYPES,
)


class RedTeamVulnerabilityConfig(BaseModel):
    """Configuration for a single deepteam vulnerability class."""

    model_config = ConfigDict(extra="allow")

    name: str = Field(..., min_length=1)


class RedTeamConfig(BaseModel):
    """Configuration for the red team pipeline."""

    model_config = ConfigDict(extra="forbid")

    target_purpose: str = Field(..., min_length=1)
    target_system_prompt: str = Field(default="")
    llm_model_id: Optional[str] = Field(
        default=None,
        description="llm_pool model ID; required when api.enabled is False",
    )

    vulnerabilities: list[RedTeamVulnerabilityConfig] = Field(
        default_factory=lambda: [
            RedTeamVulnerabilityConfig(name="Bias"),
            RedTeamVulnerabilityConfig(name="Toxicity"),
        ],
        min_length=1,
    )
    attacks: list[str] = Field(
        default_factory=lambda: ["PromptInjection"],
        min_length=1,
    )
    attacks_per_vulnerability_type: int = Field(default=1, ge=1, le=100)

    simulator_model: Optional[str] = Field(
        default=None,
        description=(
            "LLM generating adversarial prompts. llm_pool ID, direct model name, "
            "or None (deepteam default)."
        ),
    )
    evaluation_model: Optional[str] = Field(
        default=None,
        description=(
            "LLM scoring vulnerability. llm_pool ID, direct model name, "
            "or None (deepteam default)."
        ),
    )
    ignore_errors: bool = Field(default=False)
    async_mode: bool = Field(default=True)
    max_concurrent: int = Field(default=10, ge=1)

    output_dir: str = Field(default=DEFAULT_RED_TEAM_OUTPUT_DIR)
    enabled_graphs: list[str] = Field(
        default_factory=lambda: ["vulnerability_breakdown"]
    )

    @field_validator("attacks")
    @classmethod
    def validate_attacks(cls, v: list[str]) -> list[str]:
        """Validate all attack names exist in deepteam.attacks submodules."""
        for name in v:
            found = False
            for submod in (
                "deepteam.attacks.single_turn",
                "deepteam.attacks.multi_turn",
            ):
                try:
                    mod = importlib.import_module(submod)
                    if hasattr(mod, name):
                        found = True
                        break
                except ImportError:
                    pass
            if not found:
                raise ValueError(
                    f"Unknown attack '{name}'. Must be a class in "
                    "deepteam.attacks.single_turn or deepteam.attacks.multi_turn."
                )
        return v

    @field_validator("enabled_graphs")
    @classmethod
    def validate_enabled_graphs(cls, v: list[str]) -> list[str]:
        """Validate graph types are supported."""
        invalid = [g for g in v if g not in SUPPORTED_RED_TEAM_GRAPH_TYPES]
        if invalid:
            raise ValueError(f"Unsupported graph types: {invalid}")
        return v


class RedTeamResult(BaseModel):
    """Result for a single red team attack attempt."""

    model_config = ConfigDict(extra="forbid")

    vulnerability: str
    attack: str
    input: str
    actual_output: str
    exploited: bool
    reason: str = Field(default="")
    error: Optional[str] = Field(default=None)


class VulnerabilityStats(BaseModel):
    """Aggregate statistics for a vulnerability class or attack method."""

    model_config = ConfigDict(extra="forbid")

    total: int = 0
    exploited: int = 0
    safe: int = 0
    error: int = 0
    exploitation_rate: float = 0.0


class RedTeamSummary(BaseModel):
    """Summary of a complete red team run."""

    model_config = ConfigDict(extra="forbid")

    timestamp: str
    target_purpose: str
    target_type: str
    results: list[RedTeamResult] = Field(default_factory=list)
    total_attacks: int = 0
    total_exploited: int = 0
    total_safe: int = 0
    total_errors: int = 0
    overall_exploitation_rate: float = 0.0
    by_vulnerability: dict[str, VulnerabilityStats] = Field(default_factory=dict)
    by_attack: dict[str, VulnerabilityStats] = Field(default_factory=dict)

    @staticmethod
    def _build_result(tc: Any) -> "RedTeamResult":
        """Parse a single deepteam test case into a RedTeamResult."""
        vulnerability = getattr(tc, "vulnerability", "unknown")
        attack = getattr(tc, "attack_method", None) or ""
        input_text = getattr(tc, "input", None) or ""
        actual_output = getattr(tc, "actual_output", None) or ""
        score = getattr(tc, "score", None)
        reason = getattr(tc, "reason", None) or ""
        error = getattr(tc, "error", None)
        has_error = error is not None
        is_safe = (score is not None) and (score > 0)
        is_exploited = not is_safe and not has_error
        return RedTeamResult(
            vulnerability=vulnerability,
            attack=attack,
            input=input_text,
            actual_output=actual_output,
            exploited=is_exploited,
            reason=reason,
            error=error,
        )

    @staticmethod
    def _update_stats(
        by_vulnerability: "dict[str, VulnerabilityStats]",
        by_attack: "dict[str, VulnerabilityStats]",
        result: "RedTeamResult",
    ) -> None:
        """Accumulate per-vulnerability and per-attack stats from one result."""
        has_error = result.error is not None
        vuln = result.vulnerability
        if vuln not in by_vulnerability:
            by_vulnerability[vuln] = VulnerabilityStats()
        vstats = by_vulnerability[vuln]
        vstats.total += 1
        if has_error:
            vstats.error += 1
        elif result.exploited:
            vstats.exploited += 1
        else:
            vstats.safe += 1
        if result.attack:
            if result.attack not in by_attack:
                by_attack[result.attack] = VulnerabilityStats()
            astats = by_attack[result.attack]
            astats.total += 1
            if has_error:
                astats.error += 1
            elif result.exploited:
                astats.exploited += 1
            else:
                astats.safe += 1

    @staticmethod
    def _finalize_rates(stats_dict: "dict[str, VulnerabilityStats]") -> None:
        """Compute exploitation_rate in-place for each VulnerabilityStats entry."""
        for stats in stats_dict.values():
            valid = stats.total - stats.error
            stats.exploitation_rate = (
                (stats.exploited / valid * 100) if valid > 0 else 0.0
            )

    @classmethod
    def from_deepteam_results(
        cls,
        risk_assessment: Any,
        target_purpose: str,
        target_type: str,
    ) -> "RedTeamSummary":
        """Build a RedTeamSummary from a deepteam RiskAssessment object.

        score > 0 means the model passed the safety check (was safe).
        score == 0 or None (without error) means it was exploited.
        """
        results: list[RedTeamResult] = []
        by_vulnerability: dict[str, VulnerabilityStats] = {}
        by_attack: dict[str, VulnerabilityStats] = {}

        for tc in getattr(risk_assessment, "test_cases", []):
            result = cls._build_result(tc)
            results.append(result)
            cls._update_stats(by_vulnerability, by_attack, result)

        cls._finalize_rates(by_vulnerability)
        cls._finalize_rates(by_attack)

        total_attacks = len(results)
        total_errors = sum(1 for r in results if r.error is not None)
        total_exploited = sum(1 for r in results if r.exploited)
        total_safe = total_attacks - total_exploited - total_errors
        valid = total_attacks - total_errors
        overall_exploitation_rate = (
            (total_exploited / valid * 100) if valid > 0 else 0.0
        )

        return cls(
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            target_purpose=target_purpose,
            target_type=target_type,
            results=results,
            total_attacks=total_attacks,
            total_exploited=total_exploited,
            total_safe=total_safe,
            total_errors=total_errors,
            overall_exploitation_rate=overall_exploitation_rate,
            by_vulnerability=by_vulnerability,
            by_attack=by_attack,
        )
