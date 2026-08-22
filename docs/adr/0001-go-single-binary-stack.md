---
status: accepted
---

# Go single-binary implementation stack

SBXR uses pinned Go to build one pure-Go (`CGO_ENABLED=0`) Installer-Updater executable for Ubuntu Server 24.04 on `linux/amd64` and `linux/arm64`. The installed executable opens the standard-library numbered line menu only when called with zero arguments.

Software Lifecycle is the only product Module. The line menu, public GitHub release access, fixed-path local I/O, Pasteable Install Command, and repository release workflows are Adapters. The installed product adds no plugin system, secondary command surface, migration framework, second transaction seam, or unsigned qualification override. During one approved Acceptance VPS run, the same zero-argument executable may consume the signed, root-only, workflow-bound qualification authority defined by ADR-0014.

The standard library is the default dependency boundary. ADR-0008 records the two approved release-verification dependencies.
