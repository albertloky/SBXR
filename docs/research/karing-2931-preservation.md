# Karing 1.2.26/2931 preservation compatibility — 2026-11-14

The validator admits only the additional exact 1.2.26/2931 identity. An upgrade
invalidates the previous app/helper binding. Settings and original-profile
preservation rules remain unchanged, including strict DNS and credential fields.

The [official package](https://github.com/KaringX/karing/releases/tag/v1.2.26.2931)
`karing_1.2.26.2931_macos_universal.pkg` is 117640054 bytes, SHA-256
`c54f760ec0f819de35997c6655d02c5ea25c5e9f2313878243e4ef4deb162c05`.
Its digest matched GitHub's asset metadata. Apple installer signature and
Gatekeeper notarization passed for SUPERNOVA NEBULA LLC (`TNPM9PFX3W`). The
expanded app passed deep/strict code-signature verification; bundle identity is
`com.nebula.karing`, version 1.2.26, build 2931. Executable SHA-256:
`7f6508b6dcf457f4739038b23c4b5cf8bf967f2569a847168fa50230854b6996`.

The [official comparison](https://github.com/KaringX/karing/compare/v1.2.26.2930...v1.2.26.2931)
contains one commit. Settings manager remains blob
`30b916bae49d7118d558fb521be579c02de18d27`. Server manager changes from
`f9c06e8ba622ec96f8a4a208e62f13e2026e219f` to
`ded46745731ebdb1d2e84c4fcf70e3d096bf21dd`: automatic subscription updates and
reload-all now forward existing AES/AGE decryption passwords, outbound DNS and
DNS preference into `addRemoteConfig`, matching the existing single-profile
reload call. The callee and settings serialization are unchanged. Previously
these two call sites used default empty/false values. This supports retaining
strict field preservation, not adding an exception for changed options.

The 2930-to-2931 binding regression refused before the allowance. The shared
settings suite exercises 2931, and public profile fixtures require existing
refresh options to survive an allowed timestamp refresh: removal or resetting
any of those fields must fail. These checks validate SBXR's preservation boundary;
they do not execute upstream Dart refresh code or establish a live client pass.

Package/source observations and update evidence belong under
`.scratch/acceptance/k2931/`. Any update must verify actual profiles, settings,
selection and connection afterward, preserve the active extension, and use fresh
operator bindings before the separately approved single live test. No result
here qualifies or publishes a candidate.
