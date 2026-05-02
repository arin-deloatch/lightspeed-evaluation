"""Runner/CLI module for LightSpeed Evaluation Framework."""

from lightspeed_evaluation.runner.evaluation import main, run_evaluation
from lightspeed_evaluation.runner.red_team import main as red_team_main
from lightspeed_evaluation.runner.red_team import run_red_team

__all__ = ["main", "run_evaluation", "red_team_main", "run_red_team"]
