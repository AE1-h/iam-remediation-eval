# Escalation Vector: Wildcard s3:* on *

### Mechanism
A blanket `s3:*` on `*` grants unrestricted control over all existing and future Amazon S3 buckets in the AWS account. This allows an attacker to exfiltrate proprietary data from confidential buckets (e.g. `corporate-finance-vault`), delete compliance logs and backups (`s3:DeleteBucket`, `s3:DeleteObject`), and alter bucket access policies to make resources publicly readable.

### Legitimate Workload Purpose
The workload is a web frontend static asset synchronization script. It only requires read and write access to the specific designated production assets bucket: `arn:aws:s3:::app-static-assets-prod/*` and bucket listing on `arn:aws:s3:::app-static-assets-prod`. It should have zero access to corporate databases, finance buckets, or destructive bucket configuration APIs.

### Ground Truth Citation
- AWS Well-Architected Framework: Security Pillar (SEC03: Permissions Management).
- CIS AWS Foundations Benchmark v1.4, Section 2: Storage.
