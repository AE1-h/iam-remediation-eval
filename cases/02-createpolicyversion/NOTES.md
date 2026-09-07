# Escalation Vector: iam:CreatePolicyVersion

### Mechanism
AWS customer managed policies support up to 5 versions. An identity with `iam:CreatePolicyVersion` can create a new version of any customer managed policy attached to itself (or other principals) containing an `Effect: Allow, Action: *, Resource: *` statement and automatically set it as the default version via `--set-as-default`. This instantly bypasses existing authorization boundaries without requiring policy attachment permissions.

### Legitimate Workload Purpose
The workload is an internal compliance audit collector. It only requires read-only visibility into policy definitions and versions to inspect configurations for compliance drifts.

### Ground Truth Citation
- Spencer Gietz (Rhino Security Labs), *AWS IAM Privilege Escalation - Methods and Mitigation*, Method 2: `iam:CreatePolicyVersion`.
- Bishop Fox, *Privilege Escalation in the Cloud: From Zero to AWS Administrator*.
