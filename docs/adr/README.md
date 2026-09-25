# Architecture and policy decision index

Read decisions by **scope**, not merely by an `accepted` header. Later explicit
refinements apply only within their stated scope; this index does not adopt,
revoke or rewrite a decision. [CONTEXT.md](../../CONTEXT.md) is the shared glossary.

For current product work, begin with ADR-0016 and its selected resolutions.
For current recurring live qualification, begin with ADR-0025; ADR-0023 defines
the retained five ordinary journeys. ADR-0024 is only the bounded
v3.1.81 / 159 exception; ADR-0017 applies only to v3.1.0 / 83. Neither is a
general publication waiver. See the [acceptance guide](../acceptance/README.md).

## Current V3 and scoped release decisions

- [0016 — Establish the V3 proxy product and Modules](0016-v3-proxy-product-and-modules.md)
- [0018 — Permit a clean-install subscription repair release](0018-clean-install-subscription-repair.md)
- [0023 — Use five product journeys for current MVP live acceptance](0023-mvp-live-acceptance.md)
- [0024 — Validate the approved r24 late-human-confirmation supplement](0024-r24-late-confirmation-supplement.md)
- [0025 — Ordinary recurring live acceptance and an exact packaged upgrade route](0025-ordinary-recurring-live-acceptance.md)
- [0017 — One-release Owner exception for v3.1.0](0017-one-release-owner-exception.md)

## Foundations, read with the V3 refinements

The Installer-Updater-only module/footprint descriptions are historical;
ADR-0016 defines the V3 product extension. Dependency and trust decisions retain
their stated applicability.

- [0001 — Go single-binary implementation stack](0001-go-single-binary-stack.md)
- [0008 — Public release verification dependencies](0008-public-release-verification-dependencies.md)
- [0014 — Reset SBXR to the Installer-Updater](0014-installer-updater-product-reset.md)

## Earlier repair qualification scopes

These explain versioned historical evidence policies. Do not add their
retired scenario matrix to the five-journey MVP procedure.

- [0019 — Bound repair qualification to the production issuance budget](0019-issuance-bounded-repair-qualification.md)
- [0020 — Bind clean-install lifecycle checks to reachable evidence](0020-clean-install-lifecycle-evidence.md)
- [0021 — Qualify Karing without switching the Owner connection](0021-karing-latency-with-current-connection.md)
- [0022 — Run subscription-absent identity qualification before certificate issuance](0022-two-issuance-repair-qualification.md)

## Historical full-product decisions

These belong to the earlier full-product architecture. Use ADR-0014 and
ADR-0016 to understand the product resets before applying any old requirement.

- [0002 — Distributed security ownership and trust boundaries](0002-distributed-security-ownership-and-trust-boundaries.md)
- [0003 — Desired State and migrations](0003-desired-state-and-migrations.md)
- [0004 — Managed lifecycle and recovery](0004-managed-lifecycle-and-recovery.md)
- [0005 — Transaction-only recovery boundary](0005-transaction-only-recovery-boundary.md)
- [0006 — Installation preflight and SSH safety](0006-installation-preflight-and-ssh-safety.md)
- [0007 — Pasteable installation and destructive reclamation](0007-pasteable-install-and-destructive-reclamation.md)
- [0009 — Installation Module](0009-installation-module.md)
- [0010 — Run the Owner Console and managed services as root](0010-root-owner-console-and-services.md)
- [0011 — Add the Cloudflare Profile Setup Module](0011-cloudflare-profile-setup-module.md)
- [0012 — Add a public Package Qualification Command](0012-public-package-qualification-command.md)
- [0013 — Keep Installation conflict seams in Network Policy](0013-network-policy-owns-installation-conflict-seams.md)
