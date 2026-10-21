# Acceptance documentation

## Current procedure

[HTTP live qualification](http-subscription-live.md) defines the five current
journeys: install, subscription/Karing, credentials, serving restart and removal.
Use `subscription-clean-install-only`, empty incoming sources and `mvp-http-live-v1`
under [ADR-0028](../adr/0028-clean-install-only.md). No source upgrade or subscription
certificate issuance is required. Preparation and local tests do not prove a live pass.

The procedure includes the exact-candidate SSH handoff and incremental observation
recorder. The [temporary log-parent procedure](mvp-protected-log-parent-2026-09-19.md)
applies only to the existing host shape with that prerequisite and requires fresh
host evidence. It adds no journey or general host authorization.

[ADR-0032](../adr/0032-qualified-publication-retry.md) permits publication after
successful exact-candidate qualification and cleanup, without a second publication
approval. Main divergence still needs exact review; publication rechecks authentication
and unchanged bytes. Failed publication preserves qualification for transparent retry.

## Dated evidence and historical contracts

The [report index](reports/README.md) records release attempts and investigations.
Its latest recorded stable publication is [v3.1.81 / 159](reports/v3.1.81-stable-publication-2026-09-25.md),
using the bounded [ADR-0024 exception](../adr/0024-r24-late-confirmation-supplement.md).
Refresh remote state before release work; dated reports do not establish present readiness.

Historical policies and one-target exceptions keep their meanings in the
[ADR index](../adr/README.md) and existing Go readers. Retired V4, HTTPS, recurring,
Installer-Updater and one-time maintenance procedures remain in Git history.
They add no requirements to the current five journeys.

The two versioned checklist paths remain because workflows bind their exact bytes:
[installer-updater-vps.md](installer-updater-vps.md) and
[v3-packaged-live.md](v3-packaged-live.md). Historical checklist links resolve to
the preserved revision; these files do not replace the current HTTP procedure.
