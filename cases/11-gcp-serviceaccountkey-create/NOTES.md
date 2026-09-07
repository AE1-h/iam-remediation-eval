# Escalation Vector: Service account key creation

### Mechanism
`roles/iam.serviceAccountKeyAdmin` includes `iam.serviceAccountKeys.create`, which applies to every service account in the project rather than only the caller's own. A principal holding it can mint a private key for a more privileged service account, authenticate with that key, and act with that account's permissions. Unlike token minting, a downloaded key is long-lived and remains valid until explicitly deleted.

### Legitimate Workload Purpose
The workload only inspects key metadata to find keys past their rotation age. It never creates or deletes a key; a separate approved process performs rotation. `roles/iam.serviceAccountViewer` retains the read permissions and drops key creation and deletion.

### Ground Truth Citation
- Spencer Gietzen (Rhino Security Labs), [Privilege Escalation in Google Cloud Platform](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/), service account key creation.
- Google Cloud, [Service account keys](https://docs.cloud.google.com/iam/docs/keys-create-delete) and [Best practices for managing service account keys](https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys).
- MITRE ATT&CK: [T1098.001](https://attack.mitre.org/techniques/T1098/001/) (Account Manipulation: Additional Cloud Credentials).
