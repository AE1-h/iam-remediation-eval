# Escalation Vector: Custom role redefinition

### Mechanism
`roles/iam.roleAdmin` includes `iam.roles.update`. A principal already bound to a custom role can edit that role's definition to add any permission, including `resourcemanager.projects.setIamPolicy`, and thereby grant itself project-wide control without ever touching the project's IAM policy directly. The escalation is invisible to a review that only watches policy bindings, because the binding does not change; the role behind it does.

### Legitimate Workload Purpose
The workload only reads role definitions and bindings. `roles/iam.roleViewer` provides exactly those reads and removes create, update and delete.

### Ground Truth Citation
- Google Cloud, [Creating and managing custom roles](https://docs.cloud.google.com/iam/docs/creating-custom-roles).
- Spencer Gietzen (Rhino Security Labs), [Privilege Escalation in Google Cloud Platform](https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/), `iam.roles.update`.
- MITRE ATT&CK: [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation).
