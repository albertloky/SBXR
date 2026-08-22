# SBXR

SBXR is a single-owner Installer-Updater for one executable on one Ubuntu Server.

## Language

### Owner
The one person who exclusively controls one SBXR installation.

### Software Lifecycle
The sole product Module. It owns installed status, qualified stable release discovery, update, rollback, forward completion, and recovery.

### Pasteable Install Command
The root-authorized command that finds and installs only the Qualified Stable Release into SBXR's two fixed durable paths.

### Release Identity
The repository, immutable tag, commit SHA, and `release-index.json` SHA-256 that together identify one exact release.

### Release Sequence
The authenticated positive integer that is the only authority for release order.

### Qualified Stable Release
GitHub's canonical immutable Latest release whose four assets, Release Identity, attestations, and Acceptance Record pass Release Qualification.

### Release Qualification
Proof that the exact packaged two-release journey and every required automated, live, identity, SSH, recovery, and secret-safety check passed for unchanged release bytes.

### Acceptance Record
The public, secret-safe record that binds one Release Identity to its qualification stages, evidence, runner facts, and exact asset digests.

### Installed Record
The root-owned schema-1 record that binds the active executable to its Release Identity, Release Sequence, architecture, and executable digest.

### Update Record
The strict root-owned schema-1 transaction record that selects rollback before `Committed` or forward completion at and after `Committed`.

### Ready
The installed lifecycle state in which the active executable and Installed Record agree and no update needs recovery.

### Update in progress
The installed lifecycle state in which one process owns the Software Lifecycle mutation lock.

### Recovery required
The installed lifecycle state in which durable transaction evidence must select safe rollback or forward completion before normal actions can continue.
