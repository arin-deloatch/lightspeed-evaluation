"""LightSpeed Evaluation Framework - Red Team Runner."""

import argparse
import sys
import traceback

from lightspeed_evaluation.core.system import ConfigLoader
from lightspeed_evaluation.core.system.exceptions import ConfigurationError


def run_red_team(eval_args: argparse.Namespace) -> bool:
    """Run the red team pipeline.

    Args:
        eval_args: Parsed command line arguments.

    Returns:
        True if the run completed (even with exploits), False on fatal error.
    """
    print("🔴 LightSpeed Red Team")
    print("=" * 50)

    try:
        print("🔧 Loading Configuration & Setting up environment...")
        loader = ConfigLoader()
        system_config = loader.load_system_config(eval_args.system_config)

        if system_config.red_team is None:
            print(
                "\n❌ No 'red_team:' section found in system config.\n"
                "   Add a 'red_team:' block to your system.yaml to enable red teaming."
            )
            return False

        print("\n📋 Loading Red Team Pipeline...")
        # pylint: disable=import-outside-toplevel
        from lightspeed_evaluation.pipeline.red_team.pipeline import RedTeamPipeline

        # pylint: enable=import-outside-toplevel

        cfg = system_config.red_team
        print(f"🎯 Target purpose : {cfg.target_purpose}")
        print(f"🧪 Vulnerabilities: {[v.name for v in cfg.vulnerabilities]}")
        print(f"⚔️  Attacks        : {cfg.attacks}")
        print(f"🔢 Attacks/vuln   : {cfg.attacks_per_vulnerability_type}")
        print()

        print("🔄 Running Red Team Attacks...")
        pipeline = RedTeamPipeline(system_config)
        summary = pipeline.run()

        print("\n🎉 Red Team Complete!")
        print(f"📊 Total attacks      : {summary.total_attacks}")
        print(f"✅ Safe               : {summary.total_safe}")
        print(f"🚨 Exploited          : {summary.total_exploited}")
        print(f"⚠️  Errors             : {summary.total_errors}")
        print(f"📈 Exploitation rate  : {summary.overall_exploitation_rate:.1f}%")

        if summary.by_vulnerability:
            print("\nBy Vulnerability:")
            for vuln, stats in summary.by_vulnerability.items():
                print(
                    f"  {vuln}: {stats.exploited}/{stats.total} exploited "
                    f"({stats.exploitation_rate:.1f}%)"
                )

        print(f"\n📁 Reports saved to: {cfg.output_dir}")
        return True

    except ConfigurationError as e:
        print(f"\n❌ Configuration error: {e}")
        return False
    except (ValueError, RuntimeError) as e:
        print(f"\n❌ Red team failed: {e}")
        traceback.print_exc()
        return False


def main() -> int:
    """Command line interface."""
    parser = argparse.ArgumentParser(
        description="LightSpeed Red Team Runner — adversarial probing via deepteam",
    )
    parser.add_argument(
        "--system-config",
        default="config/system.yaml",
        help="Path to system configuration file (default: config/system.yaml)",
    )

    eval_args = parser.parse_args()
    return 0 if run_red_team(eval_args) else 1


if __name__ == "__main__":
    sys.exit(main())
