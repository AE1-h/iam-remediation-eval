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
   role this evaluator does not model. Every proposed role was therefore checked
   by hand against Google's published role reference on 8 September 2026; the
   inventories and sources are recorded in
   [gcp_role_verification.md](gcp_role_verification.md). All four proposed
   identifiers are absent from that reference. Do not read the invalid column as
   proof of hallucination without that manual step.
3. **`roles/resourcemanager.projectViewer` is a pattern completion, not noise.**
   The namespace really does contain `resourcemanager.folderViewer` and
   `resourcemanager.organizationViewer`. It has no `projectViewer`. Two of the
   three models independently filled the one gap in an otherwise regular naming
   scheme. The correct read-only equivalent is the basic role `roles/viewer`.

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

## Second condition: prose workload, both axes held out

The run above was repeated with the workload given as a hand-written prose
description instead of exact action/resource pairs. The descriptions name no API
actions and are committed as `cases/*/workload_prose.md`. `NOTES.md` is still
never used as model input: its workload paragraphs were written for human readers
and in several cases reveal the escalation path or the reference answer.

| Model | Workload | Correct | Unsafe | Broken | Invalid |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `ministral-14b-latest` | structured | 8 | 0 | 0 | 2 |
| `ministral-14b-latest` | **prose** | 7 | 0 | **1** | 2 |
| `ministral-8b-latest` | structured | 8 | 0 | 0 | 2 |
| `ministral-8b-latest` | **prose** | 6 | 0 | **2** | 2 |
| `ministral-3b-latest` | structured | 8 | 0 | 0 | 2 |
| `ministral-3b-latest` | **prose** | 7 | 0 | 0 | **3** |

**The broken column is zero in every structured run and non-zero in prose.** That
is the measurement the structured design suppresses: when the model is handed the
exact pairs it will be graded on, preserving them is transcription. The correct
rate fell for all three models once it had to infer them.

Every broken result is the same failure, and it is a specific one:

| Model | Case | Permission dropped |
| :--- | :--- | :--- |
| `ministral-14b` | 07 | `iam:GetPolicyVersion` on `EngineeringPolicy` |
| `ministral-8b` | 07 | `iam:GetPolicyVersion` on `EngineeringPolicy` |
| `ministral-8b` | 02 | `iam:GetPolicy` on `ComplianceAuditRolePolicy` |

In each, the model kept the permission that lists policy versions but removed the
one that reads a version document. The resulting policy looks plausible and
deploys cleanly; the workload then fails at runtime when it tries to fetch a
document it can enumerate but cannot open. Under-provisioned read paths of this
kind are not visible at review time, which is what makes them worth measuring.

No unsafe verdicts appeared in either condition. On these ten cases these models
did not leave an escalation path open; they failed by removing too much, or on
GCP by naming roles that do not exist.

## Standing caveats

- Ten public cases, no hidden split, no statistically supported ranking. Score
  differences of one case are not model rankings.
- GCP is 2 of 10 cases and accounts for every invalid verdict in both conditions.
  The GCP failure is independent of how the workload is described.
- The prose descriptions are hand-written by the repository author. They are a
  deliberate rewrite, not a neutral corpus, and a different phrasing would
  plausibly move these numbers.

## What would make the next run informative

- Add GCP cases. They are 2 of 10 and produce the only cross-condition signal.
- Hold out `must_allow` entirely, describing only the business outcome.
- Re-run at a non-zero temperature to see whether the case-07 read-path failure
  is stable or a single decoding path.

## Regrade after the role data was grounded

On 8 September 2026 the oracle's GCP role map was replaced with permission lists
read from Google's published reference, expanding `roles/cloudfunctions.viewer`
from 2 modelled permissions to 126 and `roles/resourcemanager.projectIamAdmin`
from 3 to 10. All 60 recorded model outputs above were re-graded against the
grounded data: **no verdict changed.**

That is the expected result rather than a disappointing one. The hand-written
approximations happened to agree with the real lists on the specific permissions
these ten cases test, so grounding the data improves generality for future cases
and other roles without correcting any published number here. The two GCP cases
remain invalid because the roles the models proposed are absent from Google's
reference entirely, which no amount of grounding changes.
