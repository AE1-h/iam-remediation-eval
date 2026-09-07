# Escalation Vector: iam:UpdateAssumeRolePolicy + sts:AssumeRole

### Mechanism
An identity with `iam:UpdateAssumeRolePolicy` can rewrite the trust relationship document (`AssumeRolePolicyDocument`) of any IAM role. The attacker modifies the trust policy of an existing administrative role (such as `arn:aws:iam::123456789012:role/OrganizationAccountAccessRole`) to allow their current identity to assume it. Once updated, the attacker invokes `sts:AssumeRole` and acquires full admin session tokens.

### Legitimate Workload Purpose
The workload is a CI pipeline that needs to assume a specific, isolated staging deployment role (`arn:aws:iam::123456789012:role/app-staging-deployer`) to run deployment tests. It must not have rights to alter trust policies on any role.

### Ground Truth Citation
- Spencer Gietz (Rhino Security Labs), *AWS IAM Privilege Escalation - Methods and Mitigation*, Method 9: `iam:UpdateAssumeRolePolicy`.
- Scott Piper (Summit Route), *AWS IAM Privilege Escalation Vectors*.
