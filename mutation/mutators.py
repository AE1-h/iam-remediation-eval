"""Single-site mutations compiled in isolated namespaces, without editing files.

A missing/ambiguous mutation site or a crashing mutant is an error, not a kill.
"""
import inspect
from oracle import evaluator


class MutatedOracle:
    mutant_id = "base"
    description = "Unmutated evaluator"
    original = ""
    replacement = ""

    def __init__(self):
        source = inspect.getsource(evaluator)
        if source.count(self.original) != 1:
            raise RuntimeError(f"{self.mutant_id}: expected exactly one mutation site")
        namespace = {"__name__": f"mutation.isolated_{self.mutant_id}"}
        exec(compile(source.replace(self.original, self.replacement, 1),
                     f"<mutant:{self.mutant_id}>", "exec"), namespace)
        self.engine = namespace["DeterministicOracle"]()

    def evaluate(self, policy, case):
        return self.engine.evaluate(policy, case)


def mutant(name, description, original, replacement):
    return type(name, (MutatedOracle,), {
        "mutant_id": name, "description": description,
        "original": original, "replacement": replacement,
    })


ALL_MUTANTS = [
    mutant("invert_deny_precedence", "Earlier Allow defeats explicit Deny",
           'if stmt.effect == "Deny":', 'if stmt.effect == "Deny" and not matched_allow_sid:'),
    mutant("drop_condition_evaluation", "Ignore statement conditions",
           'if not _check_condition(stmt.conditions, check.context):', 'if False:'),
    mutant("drop_default_deny", "Allow unmatched AWS requests",
           'return False, None, "Implicit default deny (no matching Allow statement)"',
           'return True, None, "Mutated default allow"'),
    mutant("invert_must_deny_logic", "Invert the security result",
           'is_safe = (len(unsafe_violations) == 0)', 'is_safe = (len(unsafe_violations) != 0)'),
    mutant("ignore_resource_scoping", "Ignore AWS resource constraints",
           'if not resource_match:', 'if False:'),
    mutant("case_sensitive_action_check", "Make AWS actions case sensitive",
           '_match_wildcard(a, check.action, case_sensitive=False)',
           '_match_wildcard(a, check.action, case_sensitive=True)'),
    mutant("wildcards_are_literal", "Disable wildcard expansion",
           'return re.fullmatch(expression, v, flags=re.DOTALL) is not None', 'return p == v'),
    mutant("shell_character_classes", "Treat literal brackets as shell patterns",
           'return re.fullmatch(expression, v, flags=re.DOTALL) is not None',
           'return __import__("fnmatch").fnmatchcase(v, p)'),
    mutant("unsupported_condition_dispatch", "Silently accept unknown condition operators",
           'raise ValueError(f"Unsupported condition operator: {operator}")', 'continue'),
    mutant("negated_condition_any", "Accept one unequal value instead of NOR",
           'matched = actual_val not in expected_list',
           'matched = any(actual_val != exp for exp in expected_list)'),
    mutant("gcp_role_expansion", "Erase known role permissions",
           'perms = GCP_ROLE_PERMISSIONS.get(role, [])', 'perms = []'),
    mutant("gcp_ignore_member", "Permit unrelated GCP identities",
           'if user_principal not in members:', 'if False:'),
]
