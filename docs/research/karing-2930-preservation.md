# Karing 1.2.26/2930 preservation compatibility — 2026-11-13

The validator admits the additional exact 1.2.26/2930 app pair. Settings and
original-profile comparisons are unchanged. Mixed version/build pairs, numeric
build values and unreviewed future builds remain refused. Upgrading from 2929
invalidates the old settings binding and requires a fresh protected baseline.

The [official release](https://github.com/KaringX/karing/releases/tag/v1.2.26.2930)
provides `karing_1.2.26.2930_macos_universal.pkg`, 117643037 bytes, SHA-256
`7fdfed6bf8b63e77532cdc2055d263b7648a99848341a3818d3d2f58a9a5df2c`.
Read-only package inspection passed Apple installer signature and Gatekeeper
notarization checks for SUPERNOVA NEBULA LLC, team `TNPM9PFX3W`. The expanded
app passed deep/strict code-signature verification; its bundle identifier is
`com.nebula.karing`, version 1.2.26, build 2930. Its executable SHA-256 is
`11d0d38c16132fa6a47abbaaf9cbfc27844428d0cbef27c639fe4c9c7acb1e01`.
The package was expanded for inspection, not installed or executed.

The [official comparison](https://github.com/KaringX/karing/compare/v1.2.26.2929...v1.2.26.2930)
changes tray handling, native project/plugin metadata and dependency versions.
The settings and server manager source blobs are identical across both tags:
`30b916bae49d7118d558fb521be579c02de18d27` and
`f9c06e8ba622ec96f8a4a208e62f13e2026e219f`, respectively. This supports retaining
the preservation contract; it does not prove installed-app preservation or
network compatibility.

The new 2929-to-2930 upgrade regression failed against the previous validator.
After the exact-pair allowance, 123 settings tests, 15 profile tests and 88
actual-file capture tests passed. The settings suite exercises 2930 against the
same preservation and refusal cases as previously supported builds. Review of
capture and containment callers confirmed that fresh app/helper binding checks
remain in place.

Local package and source observations are retained under
`.scratch/acceptance/details-fix/karing2930/`. Installing the app still requires
separate approval, protected pre-update evidence, and verification of existing
profiles, settings, selection and connection afterward. Refresh operator inputs
and native baseline before any separately approved live qualification. This
change does not qualify a candidate or authorize publication.
