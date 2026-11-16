# Karing 1.2.26/2932 preservation compatibility — 2026-11-16

Only the exact additional 1.2.26/2932 identity is admitted. Settings, original
profiles, credentials, DNS options and connection checks remain unchanged.
The changed helper and app identity require fresh bindings before dispatch.

The [official release](https://github.com/KaringX/karing/releases/tag/v1.2.26.2932)
provides separately signed PKG and DMG builds. Both downloaded asset digests
matched GitHub metadata:

- PKG: 117639447 bytes, SHA-256
  `e896e08b28e766d669bebe2872cbb8cee185af32ef68fba98bb48d39b6b3b83e`.
  Apple installer signature and Gatekeeper notarization passed for SUPERNOVA
  NEBULA LLC (`TNPM9PFX3W`). Its expanded app passed deep/strict signature
  verification. Executable SHA-256:
  `976f1c86e309b0ab09d54e317f8cb047df5f1b8006a73162365d628ab6265736`.
- DMG: SHA-256
  `3631628da559b802aebb8435431f2f0aa01da132cb2a87985abc636fcb4369fc`.
  The app passed deep/strict signature verification; its executable matched
  the already installed app exactly, SHA-256
  `ae544afd1c4ab2a1a4a94dbf85cea93875dc109e9a8e7826f7bdbc1c5657384e`.
  No app update was performed. The read-only image was detached after inspection.

The [official source comparison](https://github.com/KaringX/karing/compare/v1.2.26.2931...v1.2.26.2932)
reports identical source, zero commits and no changed files. This supports
retaining the 2931 settings/profile contract without new field exceptions.

The 2931-to-2932 regression failed before the allowance. The shared settings
suite now also exercises 2932 and requires a new binding after upgrade; unknown
builds, wrong versions and numeric build identities still refuse. These checks
are isolated preservation tests, not live client qualification.

Local package and test evidence is under `.scratch/acceptance/k2932/`. Fresh
actual baselines and candidate bindings remain necessary for a live test.
