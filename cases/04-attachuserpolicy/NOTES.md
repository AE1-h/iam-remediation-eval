# Escalation Vector: iam:AttachUserPolicy

### Mechanism
An identity with `iam:AttachUserPolicy` can attach any AWS managed or customer managed policy directly to an IAM user. An attacker holding this permission simply attaches the AWS managed `arn:aws:iam::aws:policy/AdministratorAccess` policy to their own user account, immediately gaining unrestricted administrator privileges over the entire AWS account.

### Legitimate Workload Purpose
The application is an internal corporate directory synchronization job. It queries IAM users and their current policy attachments to synchronize membership with an identity provider. It only needs read-only inspection permissions.

### Ground Truth Citation
- Spencer Gietzen (Rhino Security Labs), [AWS IAM Privilege Escalation – Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/), Method 7: `iam:AttachUserPolicy`.
