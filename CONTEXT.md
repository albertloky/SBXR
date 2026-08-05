# SBXR

SBXR is a single-owner system for managing a fixed set of proxy connection choices on one VPS.

## Language

**Owner**:
The one person who exclusively controls an SBXR installation and its credentials.
_Avoid_: User, account, administrator

**Connection Profile**:
One named connection choice that the Owner can configure, test, export, and use from a client device.
_Avoid_: Protocol, mode, node

**Clean VPS**:
A Not installed Ubuntu host without prior SBXR resources or unrelated infrastructure occupying an SBXR-owned seam; ordinary non-conflicting software may be present.
_Avoid_: Empty VPS, freshly imaged VPS

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
