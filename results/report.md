# Deterministic IAM Remediation Evaluation Report

Evaluation of 5 distinct remediation agent archetypes across 10 hand-written, real-world IAM privilege escalation cases.

| Agent Archetype | Correct | Unsafe (Security Fail) | Broken (Ops Fail) | Invalid (Schema Fail) | Safe Rate | Intact Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `reference_expert` | **10** (100%) | 0 (0%) | 0 (0%) | 0 (0%) | 100% | 100% |
| `timid_under_pruning` | **0** (0%) | 10 (100%) | 0 (0%) | 0 (0%) | 0% | 100% |
| `aggressive_over_pruning` | **0** (0%) | 0 (0%) | 10 (100%) | 0 (0%) | 100% | 0% |
| `heuristic_zeroshot` | **7** (70%) | 2 (20%) | 1 (10%) | 0 (0%) | 80% | 90% |
| `syntax_hallucinator` | **0** (0%) | 0 (0%) | 0 (0%) | 10 (100%) | 0% | 0% |

### Verdict Definitions
- **Correct**: The policy blocked all tested privilege escalation vectors AND preserved all permissions strictly needed by the legitimate workload.
- **Unsafe**: The policy left open one or more privilege escalation paths (Security Failure).
- **Broken**: The policy revoked permissions required by the operational workload to function (Operations Failure).
- **Invalid**: The policy output was not parseable as valid JSON or violated standard IAM policy schemas.
