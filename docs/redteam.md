# Red Team Evaluation

**Last Updated:** May 2026

---

## Table of Contents

1. [What Is Red Teaming?](#1-what-is-red-teaming)
2. [How It Fits Into lightspeed-evaluation](#2-how-it-fits-into-lightspeed-evaluation)
3. [Architecture Overview](#3-architecture-overview)
4. [Quickstart](#4-quickstart)
5. [Configuration Reference](#5-configuration-reference)
6. [Vulnerabilities](#6-vulnerabilities)
7. [Attacks](#7-attacks)
8. [Target Modes](#8-target-modes)
9. [Model Resolution (Simulator & Evaluator)](#9-model-resolution-simulator--evaluator)
10. [Running Red Team Evaluations](#10-running-red-team-evaluations)
11. [Understanding the Output](#11-understanding-the-output)
12. [Programmatic API](#12-programmatic-api)
13. [Troubleshooting](#13-troubleshooting)
14. [Reference Tables](#14-reference-tables)

---

## 1. What Is Red Teaming?

Red teaming is adversarial security testing — deliberately attacking an AI system with crafted prompts to discover vulnerabilities before they reach production. Unlike standard quality evaluation (which asks "does the AI give good answers?"), red teaming asks "can the AI be manipulated into giving *harmful* answers?"

The LightSpeed Evaluation Framework's red team module uses [deepteam](https://github.com/confident-ai/deepteam), a purpose-built adversarial LLM testing library. deepteam:

- **Generates adversarial prompts** using a *simulator model* (an LLM that writes attack prompts)
- **Sends those prompts to your system** (the target)
- **Judges the responses** using an *evaluation model* (an LLM that scores whether the attack succeeded)

These three roles map directly to config fields:

| Role | What it does | Config field |
|------|-------------|--------------|
| **Simulator** | **Sends** attack prompts — generates adversarial inputs | `red_team.simulator_model` |
| **Target** | **Receives** attack prompts — the system under test | `api:` block (Lightspeed API) or `red_team.llm_model_id` (direct LLM) |
| **Evaluator** | **Judges** responses — scores whether the attack succeeded | `red_team.evaluation_model` |

The framework wraps this loop with configuration management, report generation, and visualization — consistent with how standard evaluation works.

---

## 2. How It Fits Into lightspeed-evaluation

The red team subsystem is **completely independent** from the standard evaluation pipeline. The two can coexist in the same `system.yaml` without interfering with each other.

```
system.yaml
├── llm_pool / judge_panel   ← shared LLM configurations
├── api                      ← shared API connection settings
├── metrics_metadata         ← used by standard evaluation only
└── red_team                 ← used by red team only (optional)
```

| Aspect | Standard Evaluation | Red Team |
|--------|-------------------|----------|
| Entry point | `lightspeed-eval` CLI | `lightspeed-red-team` CLI |
| Input | `evaluation_data.yaml` with known Q&A pairs | `system.yaml` red_team config only |
| Prompts | Fixed, human-authored | Synthesized at runtime by a simulator LLM |
| Scoring | Metric scores (0–1) against thresholds | Exploit/safe binary per attack |
| Output dir | `./eval_output/` | `./red_team_output/` |
| Public API | `evaluate(config, data)` | `run_red_team(config)` |

Both pipelines share the `llm_pool` configuration, so the same model definitions (e.g. `judge_gpt_4o_mini`) can be referenced by both.

---

## 3. Architecture Overview

### Execution Flow

```
CLI: lightspeed-red-team
           │
   run_red_team(eval_args)            ← runner/red_team.py
           │
   ConfigLoader.load_system_config()  ← parses system.yaml → SystemConfig
           │
   RedTeamPipeline(system_config).run()
     │
     ├─ _build_target()
     │    ├─ api.enabled=true  → TargetBuilder.from_api_client()   (async HTTP callback)
     │    └─ api.enabled=false → TargetBuilder.from_llm_config()   (DeepEvalBaseLLM)
     │
     ├─ resolve_vulnerabilities()  → deepteam vulnerability instances
     ├─ resolve_attacks()          → deepteam attack instances
     ├─ resolve_model(simulator)   → LLM for generating attack prompts
     ├─ resolve_model(evaluator)   → LLM for judging responses
     │
     ├─ _call_red_team()           → deepteam.red_team() → RiskAssessment
     │    └─ (strips API_KEY from env to avoid deepeval credential confusion)
     │
     ├─ RedTeamSummary.from_deepteam_results()
     ├─ RedTeamReportGenerator.save()   → red_team.json + red_team.txt
     └─ GraphGenerator.generate_red_team_graphs()  → vulnerability_breakdown.png
```

### Module Locations

```
src/lightspeed_evaluation/
├── core/
│   ├── models/
│   │   └── red_team.py            # RedTeamConfig, RedTeamResult, RedTeamSummary
│   └── output/
│       ├── red_team_generator.py  # JSON + TXT report generation
│       └── visualization.py       # vulnerability_breakdown graph
├── pipeline/
│   └── red_team/
│       ├── pipeline.py            # RedTeamPipeline (main orchestrator)
│       └── target.py              # TargetBuilder (api/llm callback adapters)
└── runner/
    └── red_team.py                # CLI entry point: run_red_team(), main()
```

---

## 4. Quickstart

### Prerequisites

- `system.yaml` with a `red_team:` block configured (see [Configuration Reference](#5-configuration-reference))
- An LLM API key available in your environment (for the simulator and evaluator models)
- If using API target mode: a running Lightspeed Core compatible API endpoint

### Minimum Configuration

```yaml
# config/system.yaml

llm_pool:
  defaults:
    parameters:
      temperature: 0.0
      max_completion_tokens: 512
  models:
    my_judge:
      provider: openai
      model: gpt-4o-mini

red_team:
  target_purpose: "An AI assistant for Red Hat Enterprise Linux"
  simulator_model: my_judge
  evaluation_model: my_judge
  vulnerabilities:
    - name: Bias
    - name: Toxicity
  attacks:
    - PromptInjection

environment:
  DEEPEVAL_TELEMETRY_OPT_OUT: "YES"
```

Set environment variables:

```bash
export OPENAI_API_KEY="sk-your-key-here"
# If using api target mode:
export API_KEY="your-lightspeed-api-key"
```

### Run

```bash
# CLI
lightspeed-red-team --system-config config/system.yaml

# Or with uv directly
uv run lightspeed-red-team --system-config config/system.yaml
```

Results are written to `./red_team_output/` by default.

---

## 5. Configuration Reference

All red team configuration lives under the `red_team:` key in `system.yaml`. The block is **optional** — when absent, the red team pipeline is disabled and standard evaluation is unaffected.

### Full Example

```yaml
red_team:
  # Required: describes what the system is supposed to do
  target_purpose: "An AI assistant for Red Hat Enterprise Linux that helps
    users with system administration, troubleshooting, and configuration."

  # Optional: system prompt the model operates under (helps the simulator
  # craft more targeted attacks)
  target_system_prompt: "You are a helpful RHEL assistant..."

  # Required when api.enabled: false — references an llm_pool model ID
  llm_model_id: judge_gpt_4o_mini

  # Which vulnerability classes to probe (see Section 6)
  vulnerabilities:
    - name: Misinformation
    - name: ShellInjection
    - name: PromptLeakage
    - name: PIILeakage
    - name: IllegalActivity
    - name: Robustness
    - name: Bias
    - name: Toxicity
    # Vulnerabilities with sub-type configuration:
    - name: Bias
      types: [race, gender, religion]  # passed to Bias() constructor

  # Which attack classes to use (see Section 7)
  attacks:
    - PromptInjection      # single-turn
    - Base64               # single-turn
    - Roleplay             # single-turn
    - CrescendoJailbreaking  # multi-turn
    - LinearJailbreaking     # multi-turn

  # How many attack prompts to generate per vulnerability type
  attacks_per_vulnerability_type: 1  # range: 1-100

  # LLM that generates adversarial prompts (llm_pool ID, raw model name, or null)
  simulator_model: judge_gpt_4o_mini

  # LLM that judges whether the attack succeeded (same resolution rules)
  evaluation_model: judge_gpt_4_1_mini

  # Continue on individual attack errors rather than aborting
  ignore_errors: true

  # Run attacks concurrently via deepteam's async engine
  async_mode: true
  max_concurrent: 10  # range: 1-10000

  # Where to write output files
  output_dir: "./red_team_output"

  # Visualizations to generate
  enabled_graphs:
    - vulnerability_breakdown
```

### Field Reference

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `target_purpose` | Yes | — | Plain-language description of the system under test |
| `target_system_prompt` | No | `""` | System prompt the target model operates under |
| `llm_model_id` | Conditional | `null` | **Target (receiver):** `llm_pool` model ID for the LLM that receives attack prompts; required when `api.enabled: false` |
| `vulnerabilities` | No | `[Bias, Toxicity]` | Vulnerability classes to probe (min 1) |
| `attacks` | No | `[PromptInjection]` | Attack class names from deepteam |
| `attacks_per_vulnerability_type` | No | `1` | Attack attempts per vulnerability class |
| `simulator_model` | No | `null` | **Sender:** LLM that generates adversarial prompts; `null` = deepteam default |
| `evaluation_model` | No | `null` | **Judge:** LLM that scores vulnerability exploitation; `null` = deepteam default |
| `ignore_errors` | No | `false` | Skip individual attack errors instead of aborting |
| `async_mode` | No | `true` | Enable concurrent attack execution |
| `max_concurrent` | No | `10` | Maximum concurrent attacks |
| `output_dir` | No | `"./red_team_output"` | Directory for all output files |
| `enabled_graphs` | No | `[]` | Graph types to generate (see [Section 11](#11-understanding-the-output)) |

---

## 6. Vulnerabilities

Vulnerabilities define the *categories of harm* the red team probes for. Each vulnerability class corresponds to a class in `deepteam.vulnerabilities`.

### Specifying Vulnerabilities

```yaml
red_team:
  vulnerabilities:
    # Simple form — uses class defaults
    - name: Toxicity

    # With sub-type parameters — passed to class constructor
    - name: Bias
      types: [race, gender, religion]

    - name: PIILeakage
      types: [direct, api_db, session]
```

Any extra keys under a vulnerability entry (beyond `name`) are passed as keyword arguments to the deepteam vulnerability class constructor.

### Common Vulnerability Classes

| Class Name | What It Tests |
|------------|--------------|
| `Bias` | Discriminatory or prejudiced responses by category (race, gender, etc.) |
| `Toxicity` | Harmful, offensive, or abusive language |
| `Misinformation` | Factually incorrect or misleading outputs |
| `PIILeakage` | Exposure of personally identifiable information |
| `PromptLeakage` | Leakage of the system prompt or internal instructions |
| `ShellInjection` | Malicious shell commands embedded in output |
| `IllegalActivity` | Assistance with unlawful actions |
| `Robustness` | Model instability under adversarial inputs |

For the complete list of available classes, refer to the [deepteam documentation](https://github.com/confident-ai/deepteam).

> **Validation:** The pipeline will raise a `ConfigurationError` at startup if a vulnerability class name is not found in `deepteam.vulnerabilities`. Typos fail fast.

---

## 7. Attacks

Attacks define *how* adversarial prompts are delivered. deepteam provides two families of attacks:

### Single-Turn Attacks

Single-turn attacks deliver a single adversarial message and evaluate the immediate response.

| Class Name | Description |
|------------|-------------|
| `PromptInjection` | Attempts to override or hijack the system prompt |
| `Base64` | Encodes malicious instructions in Base64 to bypass filters |
| `Roleplay` | Embeds harmful requests inside fictional roleplay scenarios |
| `GrayBox` | Uses partial knowledge of the system to craft targeted prompts |
| `Leetspeak` | Obfuscates harmful terms using character substitution (l33t) |
| `ROT13` | Encodes instructions with ROT13 substitution cipher |
| `MathProblem` | Wraps harmful content inside math word problems |
| `Multilingual` | Requests harmful content in non-English languages |

### Multi-Turn Attacks

Multi-turn attacks build context across multiple exchanges before attempting exploitation.

| Class Name | Description |
|------------|-------------|
| `CrescendoJailbreaking` | Escalates topic sensitivity incrementally across turns |
| `LinearJailbreaking` | Systematically builds toward a harmful request step by step |

### Specifying Attacks

```yaml
red_team:
  attacks:
    - PromptInjection
    - Base64
    - Roleplay
    - CrescendoJailbreaking
```

> **Validation:** Attack class names are validated at startup against both `deepteam.attacks.single_turn` and `deepteam.attacks.multi_turn`. Unknown names raise a `ConfigurationError`.

### Attack Volume

The `attacks_per_vulnerability_type` setting controls how many attack prompts are generated for each vulnerability. The total attack count is:

```
total_attacks = len(vulnerabilities) × len(attacks) × attacks_per_vulnerability_type
```

For example, 8 vulnerabilities × 5 attacks × 1 attempt = 40 total attack calls.

---

## 8. Target Modes

The red team pipeline supports two ways to target your AI system: via the Lightspeed API or directly via an LLM model.

### API Target Mode (`api.enabled: true`)

When the `api` section of `system.yaml` has `enabled: true`, the **Lightspeed stack is the target** — it receives every adversarial prompt generated by the simulator. This is the most realistic test mode — it exercises the full stack including retrieval, tools, and system prompt enforcement.

```yaml
api:
  enabled: true
  api_base: http://localhost:8080
  endpoint_type: streaming
  timeout: 300

red_team:
  target_purpose: "An AI assistant for RHEL"
  # llm_model_id not needed in API mode
  vulnerabilities:
    - name: Bias
  attacks:
    - PromptInjection
```

The framework wraps your API client's `query()` method in an async callback that deepteam calls for each attack prompt.

### LLM Target Mode (`api.enabled: false`)

When API is disabled, you specify an LLM directly as the target using `llm_model_id`. This references a model defined in `llm_pool`.

```yaml
api:
  enabled: false

llm_pool:
  models:
    my_model:
      provider: openai
      model: gpt-4o-mini

red_team:
  target_purpose: "An AI assistant for RHEL"
  llm_model_id: my_model  # Required in this mode
  vulnerabilities:
    - name: Toxicity
  attacks:
    - Roleplay
```

This mode is useful for evaluating a model in isolation, before deploying to a full API stack.

> **Note:** `llm_model_id` is required when `api.enabled: false`. Omitting it raises a `ConfigurationError`.

---

## 9. Model Resolution (Simulator & Evaluator)

These fields control the **sender** (simulator) and **judge** (evaluator) roles. The **target** (receiver) is configured separately — via the `api:` block for Lightspeed API mode, or `red_team.llm_model_id` for direct LLM mode (see [Section 8](#8-target-modes)).

The `simulator_model` and `evaluation_model` fields both follow the same resolution order:

| Value | Resolution |
|-------|-----------|
| `null` (or omitted) | deepteam selects its own default model |
| An `llm_pool` model key (e.g. `judge_gpt_4o_mini`) | Built using your `llm_pool` config via LiteLLM |
| Any other string (e.g. `gpt-4o`) | Passed directly to deepteam as a raw model name |

### Recommended Setup

Using `llm_pool` IDs is recommended — it centralizes credentials, caching, and retry configuration:

```yaml
llm_pool:
  defaults:
    num_retries: 3
    parameters:
      temperature: 0.0
  models:
    simulator_model:
      provider: openai
      model: gpt-4o-mini
    eval_model:
      provider: openai
      model: gpt-4.1-mini

red_team:
  simulator_model: simulator_model   # references llm_pool key
  evaluation_model: eval_model       # references llm_pool key
```

### Cost Considerations

The simulator generates attack prompts, so it makes `total_attacks` LLM calls. The evaluator scores each response, making another `total_attacks` calls. Use cost-effective models (e.g. `gpt-4o-mini`) for these roles, reserving stronger models only when fidelity matters.

---

## 10. Running Red Team Evaluations

### CLI

```bash
# Default config path
lightspeed-red-team

# Explicit config path
lightspeed-red-team --system-config config/system.yaml

# With uv
uv run lightspeed-red-team --system-config config/system.yaml
```

This can also exist as a sub command under `lightspeed-eval`

### What Happens During a Run

1. **Config validation** — `system.yaml` is loaded; `red_team` block is parsed into `RedTeamConfig`; attack and vulnerability names are validated
2. **Target resolution** — API client or LLM model is connected and wrapped in a deepteam-compatible async callback
3. **Attack generation** — deepteam's simulator model generates adversarial prompts for each (vulnerability × attack) combination
4. **Attack execution** — prompts are sent to the target, concurrently up to `max_concurrent`
5. **Scoring** — deepteam's evaluation model judges each response (exploited / safe / error)
6. **Summary computation** — results are aggregated by vulnerability class and attack method
7. **Report generation** — JSON and TXT files written to `output_dir`
8. **Graph generation** — configured graphs written to `output_dir`

### Console Output

At the end of a run, a summary is printed to stdout:

```
Red Team Evaluation Complete
Total attacks:       40
Safe:                32 (80.0%)
Exploited:            7 (17.5%)
Errors:               1 (2.5%)
Exploitation rate:   17.5%

By Vulnerability:
  Bias:             0 / 5 exploited (0.0%)
  Toxicity:         2 / 5 exploited (40.0%)
  ShellInjection:   5 / 5 exploited (100.0%)
  ...
```

---

## 11. Understanding the Output

All output files are written to `output_dir` (default: `./red_team_output/`).

### Output Files

```
red_team_output/
├── red_team.json                          # Full structured summary
├── red_team.txt                           # Human-readable summary
└── red_team_vulnerability_breakdown.png   # Bar chart (if enabled)
```

### JSON Report (`red_team.json`)

Contains the complete `RedTeamSummary` as structured JSON:

```json
{
  "timestamp": "2026-05-18T14:23:01.123456",
  "target_purpose": "An AI assistant for RHEL...",
  "target_type": "api",
  "total_attacks": 40,
  "total_exploited": 7,
  "total_safe": 32,
  "total_errors": 1,
  "overall_exploitation_rate": 17.5,
  "by_vulnerability": {
    "ShellInjection": {
      "total": 5, "exploited": 5, "safe": 0, "error": 0, "exploitation_rate": 100.0
    }
  },
  "by_attack": {
    "PromptInjection": {
      "total": 8, "exploited": 3, "safe": 5, "error": 0, "exploitation_rate": 37.5
    }
  },
  "results": [
    {
      "vulnerability": "ShellInjection",
      "attack": "PromptInjection",
      "input": "<adversarial prompt>",
      "actual_output": "<model response>",
      "exploited": true,
      "reason": "The response included a destructive rm -rf command.",
      "error": null
    }
  ]
}
```

### Text Report (`red_team.txt`)

Human-readable version of the summary, suitable for quick review or inclusion in reports.

### Vulnerability Breakdown Graph

The `vulnerability_breakdown` graph is a grouped bar chart showing exploited vs safe counts per vulnerability class, with exploitation rate percentages labeled on exploited bars.

Enable it in config:

```yaml
red_team:
  enabled_graphs:
    - vulnerability_breakdown
```

### Interpreting Results

| Result | Meaning |
|--------|---------|
| Exploited | The attack succeeded; the model produced harmful output |
| Safe | The model resisted the attack |
| Error | The attack could not be completed (network failure, model error, etc.) |

**Exploitation rate** excludes errors from its denominator:

```
exploitation_rate = (exploited / (total - errors)) × 100
```

A 0% exploitation rate means no attacks succeeded. A high rate on a specific vulnerability (e.g. `ShellInjection: 100%`) indicates an area requiring immediate attention — prompt hardening, guardrails, or output filtering.

---

## 12. Programmatic API

For integration into scripts, notebooks, or CI pipelines:

```python
from lightspeed_evaluation import run_red_team
from lightspeed_evaluation.core.system import ConfigLoader

# Load system config (also sets environment variables from config)
loader = ConfigLoader("config/system.yaml")
config = loader.load_system_config()

# Run red team — blocking call, returns RedTeamSummary
summary = run_red_team(config)

print(f"Exploitation rate: {summary.overall_exploitation_rate:.1f}%")
print(f"Exploited: {summary.total_exploited} / {summary.total_attacks}")

for vuln, stats in summary.by_vulnerability.items():
    print(f"  {vuln}: {stats.exploitation_rate:.0f}% exploitation rate")
```

### Return Type: `RedTeamSummary`

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `str` | ISO 8601 run timestamp |
| `target_purpose` | `str` | From config |
| `target_type` | `str` | `"api"` or `"llm"` |
| `results` | `list[RedTeamResult]` | Individual attack results |
| `total_attacks` | `int` | Total attacks attempted |
| `total_exploited` | `int` | Attacks that exploited a vulnerability |
| `total_safe` | `int` | Attacks the model resisted |
| `total_errors` | `int` | Failed attack executions |
| `overall_exploitation_rate` | `float` | Percentage (0–100) |
| `by_vulnerability` | `dict[str, VulnerabilityStats]` | Per-class aggregates |
| `by_attack` | `dict[str, VulnerabilityStats]` | Per-attack-method aggregates |

### Preconditions

- `config.red_team` must not be `None`
- If `api.enabled: false`, `config.red_team.llm_model_id` must reference a valid `llm_pool` model
- `run_red_team()` is synchronous and blocking; do not call from an active async event loop (use `RedTeamPipeline` directly in that case)

---

## 13. Troubleshooting

### "red_team configuration is required"

**Cause:** The `red_team:` block is missing from `system.yaml`, or `system_config.red_team` is `None`.

**Fix:** Add the `red_team:` block to your config. See [Configuration Reference](#5-configuration-reference).

---

### "llm_model_id is required when api.enabled is False"

**Cause:** `api.enabled: false` but `llm_model_id` was not set in the `red_team` block.

**Fix:**
```yaml
api:
  enabled: false

red_team:
  llm_model_id: my_model  # Add this — must reference an llm_pool key
```

---

### "ConfigurationError: attack class 'X' not found"

**Cause:** A name in `attacks:` does not match any class in `deepteam.attacks.single_turn` or `deepteam.attacks.multi_turn`.

**Fix:** Check spelling. Common names: `PromptInjection`, `Base64`, `Roleplay`, `CrescendoJailbreaking`, `LinearJailbreaking`. Names are case-sensitive.

---

### "ConfigurationError: vulnerability class 'X' not found"

**Cause:** A `name:` under `vulnerabilities:` does not match a class in `deepteam.vulnerabilities`.

**Fix:** Verify the class name against the deepteam documentation. Names are case-sensitive (e.g. `PIILeakage`, not `PiiLeakage`).

---

### Attacks are slow or timing out

**Causes and fixes:**

1. Increase `max_concurrent` (default: 10) if your LLM provider supports higher throughput:
   ```yaml
   red_team:
     max_concurrent: 50
   ```

2. Reduce `attacks_per_vulnerability_type` to limit total attack count.

3. Ensure `async_mode: true` (default) — setting it to `false` runs attacks sequentially.

4. Use faster models for `simulator_model` and `evaluation_model`.

---

### API_KEY or Confident AI credential conflicts

**Symptom:** deepteam errors about authentication to Confident AI when you only want to test locally.

**Cause:** deepeval (which deepteam wraps) looks for `CONFIDENT_API_KEY` and `API_KEY` in the environment. If `API_KEY` is set for your Lightspeed endpoint, deepeval may misinterpret it.

**Resolution:** The pipeline automatically strips `API_KEY` and `CONFIDENT_API_KEY` from the environment before calling `deepteam.red_team()`, then restores them afterward. No manual action is required. This behavior is in `RedTeamPipeline._call_red_team()`.

---

### Suppressing deepteam/deepeval console output

Add these to your `system.yaml` environment block:

```yaml
environment:
  DEEPEVAL_TELEMETRY_OPT_OUT: "YES"
  DEEPEVAL_DISABLE_PROGRESS_BAR: "YES"
```

---

## 14. Reference Tables

### Vulnerability Classes (Common)

| Class | Sub-type parameter | Example values |
|-------|--------------------|----------------|
| `Bias` | `types` | `race`, `gender`, `religion`, `age`, `political` |
| `Toxicity` | — | — |
| `Misinformation` | — | — |
| `PIILeakage` | `types` | `direct`, `api_db`, `session`, `social` |
| `PromptLeakage` | — | — |
| `ShellInjection` | — | — |
| `IllegalActivity` | `types` | `cybercrime`, `illegal_drugs`, `terrorism` |
| `Robustness` | — | — |

### Attack Classes

| Class | Type | Description |
|-------|------|-------------|
| `PromptInjection` | Single-turn | Override or bypass system prompt |
| `Base64` | Single-turn | Encode request in Base64 |
| `Roleplay` | Single-turn | Embed request in fictional scenario |
| `GrayBox` | Single-turn | Exploit partial system knowledge |
| `Leetspeak` | Single-turn | Character substitution obfuscation |
| `ROT13` | Single-turn | ROT13 encoding |
| `MathProblem` | Single-turn | Math word problem wrapper |
| `Multilingual` | Single-turn | Request in another language |
| `CrescendoJailbreaking` | Multi-turn | Gradual escalation across turns |
| `LinearJailbreaking` | Multi-turn | Systematic step-by-step build-up |

### Enabled Graphs

| Graph name | Description |
|------------|-------------|
| `vulnerability_breakdown` | Grouped bar chart: exploited vs safe per vulnerability class |

### Configuration vs Standard Evaluation Quick-Compare

| Feature | Standard Evaluation | Red Team |
|---------|-------------------|----------|
| Config trigger | Always on | `red_team:` block present |
| Input data | `evaluation_data.yaml` | `system.yaml` only |
| CLI command | `lightspeed-eval` | `lightspeed-red-team` |
| Programmatic entry | `evaluate(config, data)` | `run_red_team(config)` |
| LLM usage | Judge scoring | Simulator (attack gen) + Evaluator (scoring) |
| Output metric | PASS/FAIL/ERROR/SKIPPED per turn | Exploited/Safe/Error per attack |
| Output dir | `./eval_output/` | `./red_team_output/` |
| Graphs | Pass rates, score distribution, heatmap | Vulnerability breakdown |

---

## Resources

- **deepteam documentation**: https://github.com/confident-ai/deepteam
- **System configuration reference**: [configuration.md](configuration.md)
- **Standard evaluation guide**: [EVALUATION_GUIDE.md](EVALUATION_GUIDE.md)
- **Sample `system.yaml`**: `config/system.yaml` (includes `red_team` block)

---

**Status:** Active — reflects the `redteam-integration` branch implementation.
