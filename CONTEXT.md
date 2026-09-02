# SBXR

SBXR is a single-owner proxy product for one Ubuntu Server. Software Lifecycle installs and updates the executable; Proxy Installation owns the installed V3 proxy journey.

## Language

### Owner
The one person who exclusively controls one SBXR installation.

### Software Lifecycle
The Module that owns installed-software status, qualified stable release discovery, update, rollback, forward completion, and recovery.

### Proxy Installation
The review-first V3 journey that adds and manages SBXR proxy capability after Software Lifecycle has installed the executable and safely completes removal of the whole installation.

### Subscription Serving
The private Module that prepares and serves the current Subscription Artifact and reports secret-safe serving facts to Proxy Installation.

### Proxy Installation Status
The separate proxy-capability status: `Not set up`, `Running`, `Change in progress`, `Change incomplete`, `Setup incomplete`, `Removal incomplete`, or `Problem detected`; `Change incomplete` identifies an interrupted Client Identity rotation with a proved recovery direction. It does not describe Software Lifecycle status or Module health, and does not alone prove whether proxy traffic is available.

### Action
One exact Owner intent reviewed and, when legal, executed through Proxy Installation.

### Prepared Action
Opaque, memory-only, single-use authority created by a fresh legal Review and required for Execute. It is invalid after use or when its action, installation, or safety facts no longer match.

### Confirmation
The Owner's explicit decision to approve or decline one Prepared Action. Only the accepted affirmative value authorizes mutation or Client Configuration disclosure; redisclosure of a valid existing Subscription Link through View details is the sole credential-disclosure exception.

### Not installed
The Software Lifecycle result after Complete removal proves that the SBXR executable, Installed Record, Ownership Record, and all proved V3-owned proxy resources are absent. It is distinct from Proxy Installation Status `Not set up`, where SBXR remains installed without proxy capability.

### Proxy Profile
The single managed V3 proxy endpoint and its one authorized Client Identity.

### Client Identity
The single credential-bound identity permitted to use the Proxy Profile from an outside client. Replacement is sequential: old sessions end before revocation selects only the prepared replacement, and revoked access cannot be restored.

### Client Access Values
The Owner-disclosable values required to construct a Client Configuration. They may include a client credential but never an Infrastructure Secret.

### Client Configuration
The secret-bearing outside-client artifact derived from the managed Proxy Profile only when the Owner requests it.

### Subscription Link Credential
The Owner-disclosable bearer credential that authorizes read-only retrieval of the current Subscription Artifact. It is independent from the Client Identity.

### Subscription Link ID
The non-secret identity of one Subscription Link Credential generation, used to correlate secret-safe status, diagnostics, transitions, and acceptance evidence.

### Subscription Link
The stable HTTPS capability URL that carries the Subscription Link Credential and returns the current Subscription Artifact. It remains stable until explicit rotation or Complete removal.

### Subscription Artifact
The secret-bearing representation of exactly one current Proxy Profile returned through the Subscription Link for Karing import and refresh. It owns the imported proxy-node fields but not Karing's profile settings, DNS, routing, TUN, or selector behavior.

### Subscription Capability Status
The separate derived status of the Subscription Link capability: `Not enabled`, `Available`, `Change in progress`, `Change incomplete`, or `Problem detected`. `Available` means fresh local capability checks pass, not that Karing reachability is proved; a subscription problem can coexist with Proxy Installation Status `Running`.

### Renewal Attempt Evidence
The protected diagnostic evidence of a managed certificate-renewal attempt and its known or incomplete outcome. It does not authorize mutation or select a recovery direction.

### Infrastructure Secret
A server-side secret that is never disclosed through a Client Configuration, status, logs, or evidence.

### Ownership Record
The root-owned durable authority that proves which exact resources V3 created and therefore may remove, and which unfinished proxy or subscription change direction is legal.

### Creating Release Identity
The Release Identity that created an installation or an owned resource, retained as provenance across compatible software updates.

### Finishing Release Identity
The exact installed Release Identity selected at Removal committed to finish removal and, if needed, restore only its executable and Installed Record.

### Proxy Package Identity
The official repository, signing-key digest, package name, version, architecture, and package digest that bind one exact proxy package to a qualified SBXR release and one V3 installation.

### Activation committed
The durable V3 setup checkpoint after which only forward completion to `Running` is legal.

### Removal committed
The durable V3 removal checkpoint after which only forward completion to `Not installed` is legal.

### Pasteable Install Command
The root-authorized command that finds and installs only the Qualified Stable Release into SBXR's two fixed durable paths.

### Release Identity
The repository, immutable tag, commit SHA, and `release-index.json` SHA-256 that together identify one exact release.

### Release Sequence
The authenticated positive integer that is the only authority for release order.

### Qualified Stable Release
GitHub's canonical immutable Latest release whose four assets, Release Identity, attestations, and Acceptance Record pass Release Qualification.

### Release Qualification
The single stable-publication gate that binds unchanged release bytes to the required automated, packaged VPS, exact-client, identity, SSH, recovery, and secret-safety evidence. The first V3 release, first subscription-capable release, and explicitly authorized repair have distinct clean-install qualification scopes. Subscription releases require exact Karing macOS evidence; later recurring releases also require each declared source upgrade. A clean-install scope does not prove an upgrade route.

### V3 Packaged Live Qualification
The Codex-driven Release Qualification stage that proves the applicable V3 journey through the exact packaged executable on a real disposable VPS and a genuinely outside network. Its first-V3 baseline and recurring subscription, Client Identity, update, and removal scenarios remain distinct from exact Karing macOS evidence.

### Acceptance Record
The single public, secret-safe record that binds one Release Identity to its qualification stages, including V3 Packaged Live Qualification, evidence, runner facts, and exact asset digests.

### Installed Record
The root-owned schema-1 record that binds the active executable to its Release Identity, Release Sequence, architecture, and executable digest.

### Update Record
The strict root-owned Software Lifecycle transaction authority that selects rollback before `Committed` or forward completion at and after `Committed`, including required runtime completion.

### Ready
The installed lifecycle state in which the active executable and Installed Record agree and no update needs recovery.

### Update in progress
The installed lifecycle state in which one process owns the Software Lifecycle mutation lock.

### Recovery required
The installed lifecycle state in which durable transaction evidence must select safe rollback or forward completion before normal actions can continue.
