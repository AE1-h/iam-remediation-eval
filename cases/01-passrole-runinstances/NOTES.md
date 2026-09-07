# Escalation Vector: iam:PassRole + ec2:RunInstances

### Mechanism
An identity with `ec2:RunInstances` and `iam:PassRole` permissions can launch a new EC2 virtual machine associated with any existing instance profile/IAM role in the account (e.g. `arn:aws:iam::123456789012:role/AdministratorRole`). Once the instance is active, the attacker queries the EC2 Instance Metadata Service (IMDSv1/v2) to extract temporary security credentials for the passed role, achieving complete administrative control.

### Legitimate Workload Purpose
The operational workload is an instance management automation script that only needs to query, start, and stop existing pre-provisioned worker instances (`i-0123456789abcdef0`). It does not need to launch instances or pass IAM roles.

### Ground Truth Citation
- Spencer Gietz (Rhino Security Labs), *AWS IAM Privilege Escalation - Methods and Mitigation*, Method 1: `iam:PassRole` & `ec2:RunInstances`.
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) (Valid Accounts: Cloud Accounts), [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation).
