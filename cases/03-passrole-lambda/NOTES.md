# Escalation Vector: iam:PassRole + lambda:CreateFunction

### Mechanism
An identity with `iam:PassRole` and `lambda:CreateFunction` can create a serverless Lambda function and assign it a pre-existing IAM execution role with high privileges (such as a VPC admin or account admin role). The attacker invokes the function to execute code within the AWS environment that exports the AWS credentials environment variables or runs arbitrary API calls under the execution role.

### Legitimate Workload Purpose
The operational script is a CI/CD build deployment agent responsible for deploying new code bundles to an existing, pre-registered Lambda function (`arn:aws:lambda:us-east-1:123456789012:function:invoice-processor`). It has no business creating new Lambda functions or passing IAM roles.

### Ground Truth Citation
- Spencer Gietz (Rhino Security Labs), *AWS IAM Privilege Escalation - Methods and Mitigation*, Method 4: `iam:PassRole` & `lambda:CreateFunction`.
- Palo Alto Networks Unit 42, *AWS IAM Privilege Escalation: Cloud Security Risks*.
