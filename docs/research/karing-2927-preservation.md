# Karing 1.2.26/2927 preservation compatibility — 2026-11-11

The installed app advanced from 2923 to 2927 during build 216 preparation.
The canonical settings-v2 helper refused the unreviewed pair before any live
candidate dispatch. This change admits only the additional exact 1.2.26/2927
pair; all settings and original-profile comparison rules remain unchanged.

## Source review

Official [release v1.2.26.2927](https://github.com/KaringX/karing/releases/tag/v1.2.26.2927)
binds commit `a7c1332b939e92571e73c62fecd2b248c1cf37cb`.
The [comparison with 2923](https://github.com/KaringX/karing/compare/v1.2.26.2923...v1.2.26.2927)
contains three commits and fifteen changed files. Direct source reads of both tags
confirm that `lib/screens/home_screen.dart` and `lib/windows_bounds.dart` are
byte-identical. Window serialization and DNS timestamp handling retain the
[2923 review](karing-1.2.26-preservation.md)'s meaning.

`setting_manager.dart` changes the TLS `enable_insecure` default from true to
false. That field is not exempted: its actual captured value and every other
non-permitted setting remain strict. No existing baseline is migrated.

`server_manager.dart` changes profile-refresh handling of decryption passwords,
outbound DNS, DNS preference and duration. Those fields remain strict original
profile data; an automatic refresh that changes them must refuse preservation.
Only the existing bounded updateTime and positive-decimal latency exceptions
remain. The change does not promise that every future refresh will preserve an
original profile, nor that the new release's networking behavior is qualified.

## Verification and limits

The exact-pair and 2923-to-2927 binding regression tests failed on the previous
helper. Settings and real-file capture/consumer suites now exercise all three
supported pairs, including strict TLS settings, unsupported/mixed build refusal,
changed app/helper refusal and M2/M3/M5 capture verification. Focused root native
readback, containment and product/two-node contract integration passed.

Read-only inspection of the installed app verified its deep/strict code signature,
actual version/build, executable and Info.plist binding. Consecutive complete
settings comparisons passed with no differences, retaining all 46 top-level
settings and two original profiles. No settings or profiles were written.
Private upstream source snapshots, hashes, red/focused test logs and actual-file
readbacks are retained under `.scratch/acceptance/k2927/`.

This is compatibility evidence, not a live qualification pass. Existing q216run
preparation and its partial baseline remain historical and unadmitted. Before
any dispatch, refresh the operator bundle from the new source, bind all new
helper/app hashes and acquire a fresh complete baseline and admission evidence.
The original test/cleanup cutoffs are not extended by this repair.
