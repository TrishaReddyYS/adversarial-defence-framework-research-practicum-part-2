# Datasheet — Adversarial Prompt Dataset for LLM Code Generation

Open-source dataset released to enable reproducibility of this research.
Follows the *Datasheets for Datasets* structure (Gebru et al., 2021).

## Motivation
Built to evaluate application-layer defences against prompt-injection attacks on LLM-based code
generation. It pairs benign coding tasks with injected variants spanning the project's threat
taxonomy (see `taxonomy.yaml` and `docs/THREAT_TAXONOMY.md`).

## Composition
- **Records:** 152 labelled prompts — 20 benign controls + 132 adversarial.
- **Adversarial families:** direct injection (60), indirect injection (36), obfuscated (36).
- **Taxonomy coverage:** all 11 vectors (D1–D5, I1–I3, O1–O3), each at two difficulty levels —
  an **overt** variant that states the malicious instruction plainly (66 prompts) and an
  **evasive** variant phrased to avoid explicit override keywords (66 prompts).
- **Benign controls:** 20 legitimate coding tasks, many touching security-sensitive operations
  (database access, shell commands, password hashing, deserialisation) to stress the
  false-positive rate.
- **Format:** JSONL (`adversarial_prompts.jsonl`). Fields: `id`, `text`, `kind`, `language`,
  `adversarial`, `expected_cwes`, `source`, `metadata`. The `source` and `metadata` of an attack
  encode its taxonomy vector and difficulty (e.g. `synthetic:D1:evasive`,
  `{"vector": "D1", "difficulty": "evasive"}`).
- **Language:** Python coding tasks.

## Collection process
**Entirely synthetic and researcher-created** — no human subjects, no scraping, no real-world
attacks harvested. Generated deterministically by `adf.common.datasets.generate_adversarial()` from
a fixed set of benign tasks and taxonomy-derived injection templates, so the dataset is fully
reproducible (`adf make-adversarial`). This matches the submitted Declaration of Ethics
Consideration (researcher-created secondary dataset; no permissions required).

## Uses
Intended for evaluating prompt-injection defences (e.g. Attack Success Rate before/after a defence).
The accompanying framework reproduces its evaluation with `adf evaluate --dataset adversarial`.

## Distribution & licence
Released under **CC BY 4.0** (see `LICENSE`). Free to use with attribution.

## Maintenance
Versioned with the framework (taxonomy `version: 1.0`). Regenerate or extend by editing the
injection templates in `datasets.py` and re-running `adf make-adversarial`.

## Ethical considerations
The attack templates are dual-use; they are published for **defensive** evaluation only, in line
with responsible-disclosure practice. All prompts are synthetic and contain no secrets or personal
data.
