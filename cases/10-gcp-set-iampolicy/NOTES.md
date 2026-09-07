# Escalation Vector: GCP resourcemanager.projects.setIamPolicy

### Mechanism
A principal granted `resourcemanager.projects.setIamPolicy` can edit a project's IAM bindings, potentially granting broader access. Actual impact depends on grant restrictions, organization policies and the permissions of the role granted. This case tests whether the policy-editing permission remains; it does not execute a role grant or establish access to every project resource.

### Legitimate Workload Purpose
The principal is a security compliance scanning agent that retrieves the project IAM policy to evaluate it against the CIS Google Cloud Computing Platform Benchmark. It requires `resourcemanager.projects.getIamPolicy` and `resourcemanager.projects.get`, but must never have write access to modify policy bindings.

### Ground Truth Citation
- Google Cloud, [Manage access to projects, folders, and organizations](https://cloud.google.com/iam/docs/granting-changing-revoking-access): required policy read/write permissions and restrictions on Owner grants.
