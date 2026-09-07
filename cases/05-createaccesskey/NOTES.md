# Escalation Vector: iam:CreateAccessKey

### Mechanism
An identity with `iam:CreateAccessKey` without a condition scoping the action to their own username (`aws:username`) can generate an API access key and secret for ANY other IAM user in the AWS account, including the root user or accounts in the `Admins` group. The attacker retrieves the newly minted access credentials and logs in as the targeted privileged user.

### Legitimate Workload Purpose
The workload is an automated credential rotation utility meant to allow individual service workers to rotate their own credentials periodically, but it was erroneously configured with a wildcard on all users in the account.

### Ground Truth Citation
- Spencer Gietz (Rhino Security Labs), *AWS IAM Privilege Escalation - Methods and Mitigation*, Method 7: `iam:CreateAccessKey`.
- CIS AWS Foundations Benchmark, Section 1: Identity and Access Management.
