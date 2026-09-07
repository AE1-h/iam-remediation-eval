# Escalation Vector: GCP ActAs + Cloud Function Deployment

### Mechanism
In Google Cloud Platform, the `iam.serviceAccounts.actAs` permission allows a principal to impersonate or run jobs as a service account. When paired with `cloudfunctions.functions.create`, an attacker who possesses minimal project privileges can deploy a new Cloud Function and specify the default App Engine or Compute service account (which by default frequently retains `roles/editor` on the project). The function executes arbitrary attacker payloads with the permissions of that high-privilege service account.

### Legitimate Workload Purpose
The principal is an operations reader account assigned to inspect deployed cloud functions and list project infrastructure. It legitimately requires read/view access (`cloudfunctions.functions.get`, `cloudfunctions.functions.list`), but should never be granted `roles/editor` or `roles/iam.serviceAccountUser`.

### Ground Truth Citation
- Chris Moberly (GitLab Red Team), *Google Cloud Platform Privilege Escalation*.
- Bishop Fox, *Privilege Escalation in Google Cloud Platform (ActAs attack pattern)*.
