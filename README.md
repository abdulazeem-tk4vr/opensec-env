# OpenSec

[![arXiv](https://img.shields.io/badge/arXiv-2601.21083-b31b1b.svg)](https://arxiv.org/abs/2601.21083)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
[![HF Dataset](https://img.shields.io/badge/HF-Dataset-green)](https://huggingface.co/datasets/Jarrodbarnes/opensec-seeds)

> **[Paper](https://arxiv.org/abs/2601.21083)** | **[Interactive Leaderboard](https://jbarnes850.github.io/opensec/leaderboard/)** | **[Blog Post](https://jbarnes850.github.io/2026/01/23/frontier-security-agents-lack-restraint/)**

Six frontier LLMs correctly identify security threats but act on the wrong targets in 45-97.5% of episodes. Detection is not the problem. The models act before they verify.

OpenSec is a dual-control RL environment that makes this action-calibration gap measurable. The defender investigates evidence from SQLite logs and executes containment actions while a live attacker advances a kill chain. Outcomes are scored by a deterministic oracle: attribution, executed containment, exposure-gated injection violations, and efficiency.

![OpenSec Architecture](assets/opensec-design.jpeg)

## Quickstart

```bash
git clone https://github.com/jbarnes850/opensec-env && cd opensec-env
pip install -e .
export OPENROUTER_API_KEY=your-key
python scripts/eval.py --limit 1
```

Results are written to `outputs/` (gitignored).

## How It Works

The attacker and defender both modify a shared world state each episode. The attacker progresses through a fixed state machine and emits evidence artifacts. The defender queries evidence and takes actions under a step budget. The oracle scores what the agent does (tool calls), not what it says.

Attacker state machine:

```
phish_sent → creds_used → lateral_move → data_access → exfil_attempt
```

Defender tools:

- `query_logs`, `fetch_email`, `fetch_alert`
- `isolate_host`, `block_domain`, `reset_user`
- `submit_report`

## Results

Six frontier models evaluated on 40 standard-tier episodes each. Ranked by EGAR, with FP rate alongside to expose the calibration gap.

| Model | Containment | FP Rate | EGAR | TTFC | Blast Radius | Calibration |
|-------|------------:|--------:|-----:|-----:|-------------:|-------------|
| Opus 4.6 | 100% | 97.5% | 62.6% | 7.8 | 0.79 | Uncalibrated |
| DeepSeek v3.2 | 92.5% | 65.0% | 54.2% | 9.0 | 0.42 | Partially Calibrated |
| Gemini 3 Flash | 75.0% | 57.5% | 42.9% | 8.6 | 0.44 | Partially Calibrated |
| Sonnet 4.5 | 62.5% | 45.0% | 39.2% | 10.6 | 0.44 | Partially Calibrated |
| GPT-5.2 | 100% | 82.5% | 37.5% | 4.1 | 0.45 | Uncalibrated |
| Kimi K2.5 | 52.5% | 45.0% | 26.7% | 10.6 | 0.69 | Partially Calibrated |

**Metrics:**
- **Containment**: fraction of episodes where the model executed at least one containment action
- **FP Rate**: fraction of episodes with at least one incorrect containment action
- **EGAR**: Evidence-Gated Action Rate. Fraction of containment actions preceded by investigation of the target entity
- **TTFC**: time-to-first-containment. Step index of the first containment action (higher = more investigation before acting)
- **Blast Radius**: ratio of false-positive to correct containment actions per episode
- **Calibration**: capability classification based on FP rate and EGAR (see [paper](https://arxiv.org/abs/2601.21083))

Interactive leaderboard: **https://jbarnes850.github.io/opensec/leaderboard/**

GPT-5.2 and Opus 4.6 both achieve 100% containment but at 82.5% and 97.5% FP rates respectively. Sonnet 4.5 and Kimi K2.5 show the strongest restraint with TTFC of 10.6, investigating 70% of the episode before acting.

![Calibration Collapse](assets/calibration.png)

GPT-5.2 acts at step 4, before gathering sufficient evidence. Sonnet 4.5 waits until step 10.6, resulting in significantly fewer false positives.

## Trace Playground

Visualize evaluation traces step-by-step to understand why models over-trigger:

```bash
python -m http.server 8080
open http://localhost:8080/playground/index.html
```

Drag any `outputs/*.jsonl` file onto the page, or use the Watch feature for live updates during evaluation runs.

![Trace Playground](assets/playground-preview.png)

## Published Baselines

Load pre-computed traces from HuggingFace (no API key required):

```python
from datasets import load_dataset

ds = load_dataset("Jarrodbarnes/opensec-seeds")
train_ds = ds["train"]  # 160 scenarios
eval_ds = ds["eval"]    # 60 scenarios

baselines = load_dataset("Jarrodbarnes/opensec-seeds", "baselines", split="train")
print(f"Loaded {len(baselines)} traces across 6 frontier models")

sonnet_traces = [t for t in baselines if t["model_id"] == "sonnet45"]
for trace in sonnet_traces[:3]:
    print(f"{trace['scenario_id']}: reward={trace['reward']:.2f}, fp={trace['false_positive_count']}")
```

## Reproduce and Extend

Run the full evaluation:

```bash
python scripts/eval.py --tier standard --limit 40
python scripts/summarize.py outputs/llm_baselines.jsonl
```

Docker: `docker build -t opensec-env . && docker run --rm -p 8000:8000 opensec-env`

Tiered attacker evals: `python scripts/eval_tiers.py --manifest data/seeds/manifest.json --split eval --limit 5 --defender noop`

Generate new seeds: `python scripts/generate_seeds.py --count 100 --seed 42 --out-dir data/seeds`

See `docs/` for specifications: [Evaluation Protocol](docs/EVAL_PROTOCOL.md), [Taxonomy](docs/TAXONOMY_SPEC.md), [Schema](docs/SCHEMA_SPEC.md), [Attacker Policy](docs/ATTACKER_POLICY_SPEC.md).

## Citation

```bibtex
@article{barnes2026opensec,
  title   = {OpenSec: Measuring Incident Response Agent Calibration Under Adversarial Evidence},
  author  = {Barnes, Jarrod},
  journal = {arXiv preprint arXiv:2601.21083},
  year    = {2026},
  url     = {https://arxiv.org/abs/2601.21083}
}
```
