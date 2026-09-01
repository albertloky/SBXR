# Supported Ownership Records

Issue #345 implements the subscription-absent compatibility slice of #342.
`Review` and `Execute` remain the Owner Interface. No subscription operation or
resource creation is admitted by this slice.

- Schema 1 retains its original fields and exact resource contracts. An already
  committed schema-1 removal binds its original `release_identity`.
- Schema 2 retains those fields and adds `resource_creating_releases`: one exact
  Creating Release Identity for each ordered `permitted_resources` entry. Its
  Ownership Record entry names `schema-2`. Nested Release Identities retain the
  production field names `Repository`, `Tag`, `Commit`, and `IndexSHA256`. Only idle `Running` or committed
  removal is supported. The optional runtime-only `serving` contract is described
  in [Subscription Serving](subscriptionserving/README.md); other subscription,
  startup, or operation fields refuse until their complete behavior is implemented.
- Schema-2 removal additionally requires `finishing_release_identity`. It is
  forbidden outside removal. Confirmed removal converts schema 1 at commitment,
  preserves original creation identities, resets the setup cleanup checkpoint,
  and selects the verified installed finisher. Reads never convert records.
- Compatibility requires the entire supported record/resource contract and a
  verified active Installed Record/executable pair. Creating identities must be
  the active release or the exact `v3.0.21` identity pinned in the implementation.
  An arbitrary older identity or matching version number is not admitted. This
  is inspection/removal support, not qualification of an update source.
- `Not enabled` requires valid/absent authority, known state-directory contents,
  absence of the dedicated subscription service and certificate paths, and an
  absent TCP 8443 listener. Unknown observations or material block mutation;
  they do not turn an independently verified Running proxy into a proxy fault.
- Removal synchronizes authority before effects and after an uncertain
  publication. Finalization moves all bytes to `/var/lib/.sbxr-removal.json`,
  synchronizes both directories, and keeps exactly one authority until deletion
  completes. Unknown residue is never recursively erased.
- The Pasteable Install Command accepts the complete canonical committed wire
  form, selects the schema-appropriate exact finisher, and restores only its
  verified executable and Installed Record. It does not recreate proxy resources.

Supported checkpoints are 0–11 with a proxy and 0–3 without one. Final authority
outside the state directory is valid only at the final checkpoint. A restored
finishing pair is removed even when its original deletion checkpoint was passed.
Automated checks do not establish packaged VPS or Karing acceptance.

## Client Identity rotation without Subscription Serving

Issue #353 adds reviewed `Rotate Client Identity` and `Finish Client Identity
rotation` actions for a freshly proved Running proxy with subscription absence.
The sing-box Adapter replaces only the VLESS UUID. A protected staged
configuration and one schema-2 operation bind exact source and target
configuration digests without storing credentials in durable authority.

The owned `sing-box.service` drop-in routes every ordinary start through a fixed
private `ExecCondition`. Before cutover it admits only the unchanged source.
During cutover it refuses ordinary starts; one exact `/run` authority can be
consumed only while the Whole-Host Mutation Lock is held by reviewed finishing.
The revocation checkpoint is forward-only. Before it, finishing cleans up and
restores the proved source. After it, finishing can publish and start only the
prepared target. Complete removal removes pending target material and retains
the startup gate until the package service is stopped and disabled. Automated
checks do not prove termination of a real outside session or packaged Karing
refresh.

## Read-only subscription enablement review

Issue #346 adds `Enable subscription` to the existing production menu only after
fresh Running, compatible idle authority, subscription absence, local TCP 80/8443,
clock, package-lock, shared Certbot, dependency, and firewall observations pass.
Unknown or unsupported observations refuse; the existing proxy actions remain
available when their own authority is safe. Schema 1 and subscription-absent
schema 2 remain unchanged by inspection or cancellation.

The Plan describes dependency creation/reuse, two exact owned iptables filter
INPUT rules (recorded IPv4 `/32`, TCP destination 80 or 8443, ACCEPT, comment
`sbxr-subscription`), the dedicated lineage, official renewal, shared-recorder
delay, and local-proof limits. It explicitly states that enablement is unavailable.
No resource contract, certificate, credential, service, or durable operation is
created. Confirmed execution rechecks facts under the existing mutation lock,
opened without file creation, and returns `ACTION-REFUSED`. Missing lock authority
also refuses without creating it. Declining consumes only this Prepared Action;
it does not finish or clear earlier pending work.

## Managed Certbot renewal recording

Issue #348 adds an optional schema-2 `renewal` contract only beside the existing
supported `serving` contract. The fixed private recorder wraps the qualified
official `snap.certbot.renew` service route. It durably publishes a protected,
bounded attempt receipt before launching the official snap app, then records the
exact exit and validated owned-lineage deploy/post-hook outcome. Missing, unsafe,
abandoned, failed, stale, or contradictory evidence remains `Problem detected`;
later no-op or unrelated success does not erase it.

The recorder admission lock and short evidence-writer lock are separate from the
Whole-Host Mutation Lock. Start publication occurs while the caller still owns
whole-host authority. The recorder releases admission before waiting for Certbot,
and hook writers hold only the evidence lock. Complete removal obtains renewal
admission/writer exclusion before Certbot POSIX lockf exclusion, refuses live
work before commitment, removes only the exact owned drop-in and hooks, preserves
unrelated overrides, and resumes partial durable deletion safely.

The private roles are not Owner commands and their arguments or environment do
not create authority. Fresh dispatch requires the exact installed pair, complete
Ownership Record, idle durable gates, official Certbot snap 5.4+, official timer
and service identity, fixed recorder route, protected files, and matching
recorder/lineage/IPv4 authority. This slice does not enable a subscription,
activate a replacement certificate, prove a packaged VPS route, or claim that a
new or renamed external Certbot route was prevented before later drift detection.

The final authority unlink is the terminal deletion. If its directory sync fails,
report uncertain completion without publishing replacement authority. All earlier
removals are already durable: restart sees either the complete final record or
complete installation absence. Neither observation permits restoring proxy resources.
