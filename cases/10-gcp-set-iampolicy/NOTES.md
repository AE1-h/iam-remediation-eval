# Escalation Vector: GCP resourcemanager.projects.setIamPolicy

### Mechanism
A principal granted `resourcemanager.projects.setIamPolicy` (often via `roles/resourcemanager.projectIamAdmin`) possesses permission to edit the IAM policy bindings of the Google Cloud project. An attacker invokes `gcloud projects set-iam-policy` to bind `roles/owner` directly to their own account identity, immediately obtaining full administrative compromise of all project resources, secret manager secrets, and virtual machines.

### Legitimate Workload Purpose
The principal is a security compliance scanning agent that retrieves the project IAM policy to evaluate it against the CIS Google Cloud Computing Platform Benchmark. It requires `resourcemanager.projects.getIamPolicy` and `resourcemanager.projects.get`, but must never have write access to modify policy bindings.

### Ground Truth Citation
- Spencer Gietz (Rhino Security Labs), *GCP Privilege Escalation: `resourcemanager.projects.setIamPolicy`*.
- Palo Alto Networks Unit 42, *Google Cloud Privilege Escalation Techniques*.
