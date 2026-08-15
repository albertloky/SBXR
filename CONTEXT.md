# SBXR

SBXR is a single-owner system for managing a fixed set of proxy connection choices on one VPS.

## Language

**Owner**:
The one person who exclusively controls an SBXR installation and its credentials.
_Avoid_: User, account, administrator

**Owner Launch Identity**:
The root or non-root Linux identity through which the Owner starts SBXR. It is distinct from the Owner, who is the person in control.
_Avoid_: Owner, Owner account, User, service identity

**Connection Profile**:
One named connection choice that the Owner can configure, test, export, and use from a client device.
_Avoid_: Protocol, mode, node

**Clean VPS**:
A Not installed Ubuntu host without prior SBXR resources or unrelated infrastructure occupying an SBXR-owned seam; ordinary non-conflicting software may be present.
_Avoid_: Empty VPS, freshly imaged VPS

**Reclaimable VPS**:
A Not installed Ubuntu host where the Owner accepts deletion of every specifically reviewed conflict at SBXR's fixed seams while resources outside those exact conflicts must remain unchanged.
_Avoid_: Clean VPS, disposable VPS, automatically adopted VPS

**Pasteable Install Command**:
One command the Owner can paste on a Clean VPS or Reclaimable VPS to fetch the current qualified stable bootstrap, install or repair only fixed prerequisites, and enter review-first installation without itself authorizing Apply or performing Destructive Reclamation.
_Avoid_: One-line installer, unattended installer

**Installation**:
The review-first process that moves SBXR from a proven Not installed state to proven Managed state through one exact Plan, one Apply attempt, and any required rollback or forward recovery.
_Avoid_: Update, repair, Complete removal, Pasteable Install Command

**Bootstrap Prerequisite Repair**:
The narrow pre-Plan root operation allowed to install or repair SBXR's fixed launch prerequisites; it cannot stop services, remove conflicting packages, change firewall policy, delete identities, inspect Infrastructure Secrets, or mutate Cloudflare.
_Avoid_: Destructive Reclamation, Apply, host cleanup

**Destructive Reclamation**:
An Owner-approved forward-only operation that records durable recovery authority before permanently removing the exact conflicts shown in the reviewed Plan, then continues until SBXR reaches Managed.
_Avoid_: Repair, cleanup, adoption

**Reclamation Boundary**:
The fixed limit on Destructive Reclamation: remove only reviewed conflicting packages without autoremove; stop an exact conflicting process and delete its freshly re-proved exact executable or unambiguous script when both appear in the Plan; preserve unrelated data; delete only exclusive conflicting identities; replace inbound firewall policy while preserving SSH and outbound traffic; and remove Docker while preserving its images, volumes, and application data. An exact package-owned executable may be deleted and its package held only with an explicit damaged-package and missed-security-update warning.
_Avoid_: Clean the server, remove anything suspicious, best-effort cleanup

**Protected Host Foundation**:
The fixed operating-system executables, services, libraries, interpreters, mounts, package tools, current shell, SSH access, and recovery dependencies that Destructive Reclamation must never delete even when they occupy a requested seam.
_Avoid_: Probably safe to delete, replaceable system file

**SSH Preservation Proof**:
The in-memory agreement between the direct SSH session identity captured at launch and fresh observations of its active service, exact listener, and established connection. A listening SSH port or another session is not sufficient.
_Avoid_: SSH port, SSH configuration, session guess

**Irreversible Reclamation Started**:
The durable checkpoint written before the first destructive effect; before it the Owner may leave without change, and after it SBXR offers only exact forward recovery to Managed.
_Avoid_: Apply started, point of no return, partial cleanup

**Acceptance VPS**:
A disposable VPS reserved for explicitly approved live acceptance, where destructive installation, change, rollback, recovery, and Complete removal checks may run without risking Owner data that must be preserved.
_Avoid_: Production VPS, valued VPS

**Acceptance Run**:
One explicitly approved execution of a written acceptance checklist against an exact Acceptance VPS; approval covers every listed step but no unlisted target or action.
_Avoid_: Standing permission, ad hoc live testing

**Acceptance Client**:
An explicitly approved disposable client environment outside the Acceptance VPS that Codex may use with temporary Client Access Values during an Acceptance Run; the values are removed or rotated afterward.
_Avoid_: Owner's personal device, maintained-client acceptance

**Owner Acceptance**:
Albert's live acceptance on maintained client apps, physical devices, real networks, or Owner-operated workflows when the first release or an affected surface requires it; automated checks and Codex observations cannot satisfy it.
_Avoid_: Inferred acceptance, Codex acceptance

**Release Qualification**:
Proof that one exact Release Identity has every required acceptance stage marked Passed or Not required with redacted evidence; only a qualified release may become stable or enter automatic-update discovery.
_Avoid_: Tests passed, release candidate exists, acceptance pending

**Release Identity**:
The exact repository, immutable tag, commit SHA, and release-index SHA-256 that together identify the release artifacts being accepted.
_Avoid_: Version number, tag name alone

**Acceptance Record**:
The single redacted, publishable record of acceptance status, runner, time, software versions, stable check code, secret-safe result, and evidence link or Not required reason; no secret-bearing acceptance archive exists.
_Avoid_: Raw evidence bundle, hidden acceptance logs

**Acceptance Ladder**:
The ordered acceptance stages Module Verification, Seam Verification, Integrated Verification, Codex Live Acceptance, and risk-based Owner Acceptance; a required failed or pending stage blocks every later claim and Release Qualification.
_Avoid_: Tests passed, fully tested

**Module Acceptance**:
Proof that one Module passed its required Module Verification, Seam Verification, and every live check available before integration; its ticket may close with integrated checks explicitly pending, but this is not Release Qualification.
_Avoid_: Release accepted, fully qualified

**Acceptance Baseline**:
A proven Managed revision or proven Not installed state from which an Acceptance Run scenario may safely begin; uncertainty requires stopping and reimaging rather than reusing the VPS.
_Avoid_: VPS is reachable, seems clean

**Client Access Value**:
A credential-bearing value used by a client device, including a Connection Profile credential, share URI, QR code content, or subscription URL.
_Avoid_: Infrastructure credential

**Infrastructure Secret**:
A credential or private key used by SBXR or a managed service to administer infrastructure or prove server identity, rather than by a client device.
_Avoid_: Client credential, Client Access Value

**Desired State**:
The Owner's saved intended SBXR configuration and last successfully committed revision.
_Avoid_: Live state, observed configuration

**Observed State**:
A fresh, read-only inspection of the managed VPS that SBXR compares with Desired State without silently adopting differences.
_Avoid_: Authoritative State, saved configuration

**Recovery Required**:
The fail-safe installation status entered when SBXR cannot prove either the current Desired State lineage or the safe resolution of an unfinished Change Set; normal changes remain blocked.
_Avoid_: Healthy, partially recovered

**Managed**:
The installation status in which Desired State lineage is proven and no Change Set is unfinished, regardless of the separate Health Results reported by individual Modules.
_Avoid_: Healthy, problem-free

**Change Set**:
One approved, revision-bound attempt to move the complete managed installation from one Desired State revision to the next under the global mutation lock.
_Avoid_: Partial update, individual file change

**Rollback Snapshot**:
The single root-only, transaction-scoped copy of the last proven Managed revision, or the proven Not installed baseline, used only to reverse its unfinished Change Set and deleted after durable completion.
_Avoid_: Backup, Recovery Point, restore point

**Correction Flow**:
The navigable Owner Console path that explains a blocked operation and offers an SBXR-owned correction, required Owner input, recheck, or safe return instead of a dead end.
_Avoid_: Continue anyway, error page

**Live Profile Check**:
An optional Owner-started check after SBXR reaches Managed that automatically attributes outside client traffic to each Connection Profile without manual success reporting.
_Avoid_: Installation health gate, manual connectivity report
