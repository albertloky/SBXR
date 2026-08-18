---
status: accepted
---

# Add a public Package Qualification Command

SBXR ships `sbxr acceptance staged-onboarding --components <path-to-sbxr-components-linux-ARCH.tar.gz> --json` as one public, documented, offline Package Qualification Command so the seven fixed controlled procedures can run through the exact packaged executable before Release Qualification. Each Packaged Qualification Run requires the exact matching component archive, refuses a different architecture, build, or manifest, and exercises the real State and System Changes publish, restore, death, restart, and recovery paths against an isolated temporary root. It reuses the production Module Interfaces and transaction paths, adds no hidden test mode or second transaction harness, performs no live VPS or provider mutation, and does not change the Owner Console; this permanent public seam is accepted because source-tree tests cannot prove the exact released artifact. Qualification order is native prepublication Packaged Qualification Runs for both architectures, immutable prerelease publication, public Packaged Qualification Runs for both native architectures, public Acceptance Record verification, stable and `Latest` promotion, stable verification, then ticket closure.
