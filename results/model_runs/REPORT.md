# Measured model run — Mistral, 8 September 2026

First evaluation in this repository using real language models. Three Mistral
models, all ten cases, temperature 0, one attempt per case, no execution
failures. Raw responses, prompts and SHA-256 request digests are committed
alongside this file.

| Model | Correct | Unsafe | Broken | Invalid | Execution errors |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `ministral-14b-latest` | 8 | 0 | 0 | 2 | 0 |
| `ministral-8b-latest` | 8 | 0 | 0 | 2 | 0 |
| `ministral-3b-latest` | 8 | 0 | 0 | 2 | 0 |

`mistral-large-latest`, `mistral-medium-latest`, `mistral-small-latest` and both
`magistral` models were unavailable on this API key (HTTP 403/429) and were not
evaluated.

## The aggregate hides the interesting part

All three models score identically, but they do not fail identically. Every one
of the eight AWS cases was graded correct for all three models. Every one of the
two GCP cases failed, for all three, and each failure is a different malformed or
non-existent role identifier:

| Case | `ministral-14b` | `ministral-8b` | `ministral-3b` |
| :--- | :--- | :--- | :--- |
| 09 | `roles/cloudfunctions.functions.viewer` | `roles/cloudfunctions.functions.viewer` | `roles/cloudfunctions.functions.invoker` |
| 10 | `roles/resourcemanager.projectViewer` | duplicate JSON key `role` | `roles/resourcemanager.projectViewer` |

Two observations, stated as observations rather than conclusions:

1. **The invented role names follow GCP's permission namespace, not its role
   namespace.** `cloudfunctions.functions.get` is a real permission;
   `roles/cloudfunctions.viewer` is the real role. The models produced
   `roles/cloudfunctions.functions.viewer`, which is neither. Two independent
   models also produced `roles/resourcemanager.projectViewer`, which does not
   exist — the real equivalents are `roles/viewer` or `roles/browser`.
2. **The oracle flagged these, it did not diagnose them.** `INVALID —
   Unsupported GCP role` is returned both for a hallucinated role and for a real
   role this evaluator does not model. The two above were confirmed non-existent
   by hand against Google's role reference, not by the oracle. Do not read the
   invalid column as proof of hallucination without that manual step.

## Why 8/8 on AWS is a weak result, including for the 3B model

The prompt discloses `must_allow` to the model as structured action/resource
requirements, and the oracle then grades the model on preserving those exact
pairs. On the AWS cases this reduces remediation to transcription: the model is
told which actions to keep and only has to scope them. A 3-billion-parameter
model scoring the same as a 14-billion-parameter one is the expected outcome of
a task that does not require the larger model's knowledge.

The GCP cases are harder for the opposite reason — they require a fact that is
not in the prompt, namely which role identifiers actually exist. That is where
all three models failed and where the scores separate from transcription.

**So this run measures GCP role-identifier knowledge more than it measures
least-privilege reasoning.** Treat the AWS column as a floor, not a capability
estimate.

## What would make the next run informative

- Describe the workload in prose instead of exact action/resource pairs, and
  compare the broken rate. That is the measurement the current design suppresses.
- Hold out `must_allow` from the prompt entirely for a third condition.
- Add GCP cases, which are currently 2 of 10 and are the only cases producing signal.
