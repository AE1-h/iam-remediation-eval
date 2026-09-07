# Escalation Vector: iam:SetDefaultPolicyVersion

### Mechanism
When an IAM policy is revised to least privilege, older policy versions often remain saved in the policy version history (AWS stores up to 5 versions). An identity with `iam:SetDefaultPolicyVersion` can switch the active default version of a policy back to a prior revision (e.g. `v1`) that was overly permissive or contained full admin rights.

### Legitimate Workload Purpose
The application is a read-only policy inventory collector that monitors the active configuration of IAM policies across the organization.

### Ground Truth Citation
- Spencer Gietzen (Rhino Security Labs), [AWS IAM Privilege Escalation – Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/), Method 2: `iam:SetDefaultPolicyVersion`.
