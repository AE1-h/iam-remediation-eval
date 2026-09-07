# Escalation Vector: iam:CreateAccessKey

### Mechanism
An identity with unscoped `iam:CreateAccessKey` can create credentials for another IAM user, subject to that user's access-key limit and effective permissions. The target's privileges determine the impact. This does not let an ordinary IAM user create root credentials. Scoping Resource to the worker's own user ARN preserves self-service key creation without granting access to other users.

### Legitimate Workload Purpose
The workload creates a replacement key for `app-worker`, verifies it outside this policy model, and deletes the old key. It also inspects its user and lists its keys. The original wildcard permits these operations on other users. The reference retains all four operations only on `app-worker`. The oracle tests permissions, not the rotation sequence or key quotas.

### Ground Truth Citation
- Spencer Gietzen (Rhino Security Labs), [AWS IAM Privilege Escalation – Methods and Mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/), Method 4: creating a new user access key.
- AWS [CreateAccessKey API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html) and [root access-key prerequisites](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user_manage_add-key.html).
- CIS AWS Foundations Benchmark, Section 1: Identity and Access Management.
