# Escalation Vector: Service account policy self-binding

### Mechanism
`roles/iam.serviceAccountAdmin` includes `iam.serviceAccounts.setIamPolicy`. A principal holding it can add itself to a service account's own IAM policy with `roles/iam.serviceAccountTokenCreator` or `roles/iam.serviceAccountUser`, then impersonate that account. The grant is written on the service account resource rather than on the project, so a control that only reviews project-level bindings will not see it.

### Legitimate Workload Purpose
The workload reads metadata and bindings to attribute ownership. `roles/iam.serviceAccountViewer` keeps those reads and removes creation, deletion and policy modification.

### Ground Truth Citation
- Google Cloud, [Manage access to service accounts](https://docs.cloud.google.com/iam/docs/manage-access-service-accounts).
- Spencer Gietzen (Rhino Security Labs), [Privilege Escalation in Google Cloud Platform](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/), service account IAM policy modification.
- MITRE ATT&CK: [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation).
