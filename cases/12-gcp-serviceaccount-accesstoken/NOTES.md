# Escalation Vector: Service account token impersonation

### Mechanism
`roles/iam.serviceAccountTokenCreator` grants `iam.serviceAccounts.getAccessToken`, `signJwt`, `signBlob` and `implicitDelegation` against the service accounts in scope. A principal holding it can request a short-lived OAuth token for a more privileged service account and call any API as that account. No key is downloaded and nothing is written to the project's IAM policy, so the impersonation leaves a thinner audit trail than key creation.

### Legitimate Workload Purpose
The workload builds an inventory and never assumes another identity. Note that `roles/iam.serviceAccountTokenCreator` does not itself grant `iam.serviceAccounts.getIamPolicy`, so binding readership is deliberately outside this case's workload. `roles/iam.serviceAccountViewer` keeps the metadata reads the workload does need while removing every token-minting and signing permission.

### Ground Truth Citation
- Google Cloud, [Service account impersonation](https://docs.cloud.google.com/iam/docs/service-account-impersonation).
- Spencer Gietzen (Rhino Security Labs), [Privilege Escalation in Google Cloud Platform](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/), token generation methods.
- `iam.serviceAccounts.actAs` is denied alongside the token-minting permissions because it is an impersonation primitive in its own right. Without it the case would accept `roles/iam.serviceAccountUser` as a remediation, which removes token minting but leaves the caller able to act as the target account.

- MITRE ATT&CK: [T1548.005](https://attack.mitre.org/techniques/T1548/005/) (Temporary Elevated Cloud Access).
