# Gate and incident handling

## 1 Decision precedence

Coverage gaps take precedence and produce `incomplete`. With complete coverage, confirmed violations produce `block`; unresolved classification produces `review`; an empty unresolved set produces `pass`.

The machine report omits matched values and matched-value hashes. It records the repository, surface, exact object location, rule ID, severity, handling status, coverage gap, tool version, policy fingerprint, and source commit.

## 2 Binary and archive handling

Office Open XML files and Notebook JSON are inspected structurally. PDF files, images, opaque binaries, encrypted archives, oversized objects, and unsupported formats require either supported inspection or an exact digest in `binary_approvals`. Missing coverage produces `incomplete`.

Archive members are checked recursively within fixed expansion, depth, and member-count limits. A limit breach produces `incomplete`.

## 3 Credential incident

If a credential may be valid or was already public, stop publication and notify the credential owner without reproducing the value. Revoke or rotate it first. Repository cleanup follows as a separate approved action because deleting a line or branch does not neutralize a copied credential.

History rewriting, force-pushing, GitHub cache cleanup, fork coordination, and Release asset replacement each require repository-specific approval and a recovery plan.
