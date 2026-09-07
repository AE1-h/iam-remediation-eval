# Verification of the GCP role identifiers produced by the models

Both GCP cases were graded `INVALID` in every run, in both the structured and
prose conditions, because the proposed policy named a role the oracle does not
model. The oracle cannot tell a hallucinated role from a real role it simply does
not know, so the role identifiers were checked by hand against Google's published
role reference on 8 September 2026.

Role inventories below were read from the rendered reference pages, not from
memory:

- Cloud Run functions: <https://docs.cloud.google.com/iam/docs/roles-permissions/cloudfunctions>
- Resource Manager: <https://docs.cloud.google.com/iam/docs/roles-permissions/resourcemanager>

## Cloud Functions

Roles that exist in the `cloudfunctions` namespace:

`roles/cloudfunctions.admin` · `roles/cloudfunctions.developer` ·
`roles/cloudfunctions.editor` · `roles/cloudfunctions.invoker` ·
`roles/cloudfunctions.serviceAgent` · `roles/cloudfunctions.viewer`

Produced by the models, and **absent** from that reference:

| Proposed role | Produced by | Exists |
| :--- | :--- | :--- |
| `roles/cloudfunctions.functions.viewer` | `ministral-14b`, `ministral-8b` | no |
| `roles/cloudfunctions.functions.invoker` | `ministral-3b` | no |

`cloudfunctions.functions.get` and `cloudfunctions.functions.list` are real
*permissions*. The models appear to have promoted a permission-namespace segment
into the role namespace, producing an identifier that is well-formed and wrong.

## Resource Manager

Roles that exist in the `resourcemanager` namespace:

`folderAdmin` · `folderCreator` · `folderEditor` · `folderIamAdmin` ·
`folderMover` · `folderViewer` · `lienModifier` · `organizationAdmin` ·
`organizationViewer` · `projectCreator` · `projectDeleter` · `projectIamAdmin` ·
`projectMover` · `tagAdmin` · `tagHoldAdmin` · `tagUser` · `tagViewer`
(each prefixed `roles/resourcemanager.`)

Produced by the models, and **absent**:

| Proposed role | Produced by | Exists |
| :--- | :--- | :--- |
| `roles/resourcemanager.projectViewer` | `ministral-14b`, `ministral-3b` | no |

This one is worth stating precisely. The namespace contains
`resourcemanager.folderViewer` and `resourcemanager.organizationViewer`, but no
`resourcemanager.projectViewer`. Two of the three models independently completed
a real and internally consistent naming pattern into the one slot Google left
empty. The read-only project equivalent is the basic role `roles/viewer`, or
`roles/browser` for metadata only.

## What this does and does not establish

It establishes that these four identifiers do not exist as predefined roles, so
the policies containing them could not be applied as written.

It does not establish that every `INVALID` verdict in this repository is a
hallucination. The oracle emits the same verdict for a real role outside its
hand-maintained map. Any future invalid result needs the same manual check before
it is described as a model error.
