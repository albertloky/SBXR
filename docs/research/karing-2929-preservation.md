# Karing 1.2.26/2929 preservation compatibility — 2026-11-12

The approved change admits only the additional exact 1.2.26/2929 app pair.
All existing settings and original-profile comparison rules remain unchanged;
2928, mixed version/build pairs and unreviewed future builds remain refused.

The official 2929 universal Mac DMG is 116870543 bytes with SHA-256
`3f0529f4eaca98ed4ec29711405e47eacc22d4564f9395576e60b525953bbf9b`.
Downloaded bytes matched the official GitHub asset digest. Read-only inspection
confirmed the bundle version, deep/strict code signature and Gatekeeper acceptance
as Notarized Developer ID, team `TNPM9PFX3W`. No app was executed from the image.

The [official source comparison](https://github.com/KaringX/karing/compare/v1.2.26.2927...v1.2.26.2929)
contains five commits and thirteen changed files. Direct source hashes confirm
settings manager, home screen and window handling are byte-identical. The profile
manager's net change removes an unused import. These observations support the
existing preservation contract; they do not establish network compatibility.
The [release notes](https://github.com/KaringX/karing/releases/tag/v1.2.26.2929)
report a VLESS/uTLS-REALITY conversion fix for a defect introduced in 2928.

The upgrade-binding regression failed before the helper change. Afterward,
99 settings tests, 88 actual-file capture tests and the focused root native
readback, containment and product/two-node contract integrations passed. Tests
retain strict TLS/settings checks and require a fresh binding after an upgrade.

After the separately approved app replacement, installed 2929's signature and
identity passed. Complete settings, subscription profiles and selected-use files
were byte-identical to the protected pre-update baseline. The UI showed the
original selected connection active with TUN enabled. This is update preservation
evidence, not live qualification. Private package/source observations, baseline
and post-update readbacks, and test logs are under `.scratch/acceptance/k2929/`.

Before any live dispatch, refresh the operator bundle and complete native baseline
from the new source/app/helper identities. Existing build 216 preparations remain
historical; neither their binding nor their readiness can be reused as current.
No candidate dispatch, live qualification or stable publication occurred here.
