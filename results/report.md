# Scripted Oracle Self-Test Report

5 hand-written fixtures across 10 cases. No LLM calls or LLM performance results.

The reference check loads the answer key. The mixed fixture also loads it for seven cases. These rows test evaluator behavior only.

| Scripted Fixture | Correct | Unsafe | Broken | Invalid / Unsupported | Safe Rate | Intact Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `reference_policy_check` | **10** (100%) | 0 (0%) | 0 (0%) | 0 (0%) | 100% | 100% |
| `unchanged_policy_fixture` | **0** (0%) | 10 (100%) | 0 (0%) | 0 (0%) | 0% | 100% |
| `deny_all_fixture` | **0** (0%) | 0 (0%) | 10 (100%) | 0 (0%) | 100% | 0% |
| `mixed_outcome_fixture` | **7** (70%) | 2 (20%) | 1 (10%) | 0 (0%) | 80% | 90% |
| `malformed_json_fixture` | **0** (0%) | 0 (0%) | 0 (0%) | 10 (100%) | 0% | 0% |

### Verdict Definitions

- **Correct**: All prohibited requests were denied and all specified workload requests were allowed within the supported policy model.
- **Unsafe**: At least one prohibited request was allowed. This does not prove a complete attack chain is executable.
- **Broken**: Safe on tested requests, but at least one workload check failed. Unsafe-and-broken policies have verdict unsafe; both flags remain in JSON.
- **Invalid**: Malformed input or semantics outside the oracle's supported subset. Safety and integrity were not assessed; false flags are placeholders. Matrix counts exclude invalid results.
- Rates use all cases as the denominator; invalid cases count as neither safe nor intact.
