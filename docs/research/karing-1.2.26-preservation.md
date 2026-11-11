# Karing 1.2.26/2923 preservation compatibility — 2026-11-11

The installed Mac app upgraded from the explicitly supported 1.2.25/2802 to
1.2.26/2923. The existing helper correctly refused its app identity. This change
adds only that reviewed version/build pair and records its actual identity in the
existing settings-v2 binding. It does not broaden the permitted differences or
claim that a candidate passed live qualification.

## Evidence and unchanged contract

Official [release v1.2.26.2923](https://github.com/KaringX/karing/releases/tag/v1.2.26.2923)
binds upstream commit `accbdfc05a999eaa3526aadb0aea994b3eafb7f5`.
The comparison API listed 300 files and was truncated, so it was not used as proof
that preservation source was unchanged. The relevant files were read directly
at both release tags, and the new window helper was read at the new tag.

- [Window serialization](https://github.com/KaringX/karing/blob/accbdfc05a999eaa3526aadb0aea994b3eafb7f5/lib/app/modules/setting_manager.dart#L232)
  still writes x, y, width and height as integers. Window handling moved into
  [WindowBounds](https://github.com/KaringX/karing/blob/accbdfc05a999eaa3526aadb0aea994b3eafb7f5/lib/windows_bounds.dart).
  Only position x/y may differ; dimensions remain strict, including when the app
  adjusts them on restoration. No window operation or app restart was performed.
- [DNS refresh](https://github.com/KaringX/karing/blob/accbdfc05a999eaa3526aadb0aea994b3eafb7f5/lib/screens/home_screen.dart#L850)
  still assigns the timestamp before the HTTP result. The timestamp grants no
  connectivity evidence; the subnet value and all other DNS settings stay strict.
- [Profile refresh](https://github.com/KaringX/karing/blob/accbdfc05a999eaa3526aadb0aea994b3eafb7f5/lib/app/modules/server_manager.dart#L1615)
  continues to save updateTime from Dart DateTime. Profile-v3 rules retain their
  exact identity/content checks, positive-decimal latency restriction and bounded
  timezone-aware refresh audit. No additional cache or schema field is ignored.
- Read-only actual-file inspection found valid types for the three settings-v2
  permitted leaves and two original profiles. All 46 top-level settings, including
  newly introduced fields, remain in the complete normalized comparison. Updated
  upstream TLS defaults are not normalized or exempted from preservation checks.

The binding still includes actual executable, Info.plist and helper hashes.
Unknown releases and cross-paired versions/builds refuse. A supported-to-supported
upgrade or changed helper invalidates an existing binding. Historical v1 remains
byte-strict; historical frozen helper/baseline evidence is not rewritten.

## Verification and limits

New exact-pair and supported-upgrade tests failed before implementation and passed
after it. Existing settings-v2 and real-file capture/consumer suites run for both
pairs, covering permitted changes, strict settings/selection preservation,
malformed data, identity changes and M2/M3/M5 consumers. Root focused native
readback, containment and two-node contract integration passed in 15.050s.
The complete root integration suite passed in 127.538s; `go vet ./...`, changed
documentation links and whitespace checks passed.
Consecutive read-only snapshots of the actual 1.2.26/2923 app passed binding,
settings readback and comparison. No settings/profile file was written.

Private source snapshots, upstream source/hash records, red/focused logs and actual
readbacks are under `.scratch/acceptance/k2923/`. They are readiness evidence,
not a fresh imported candidate, traffic/latency proof or live cleanup result.
Build 216 preparation must copy the new canonical helper, rebind its changed source
and helper hashes, and acquire a fresh baseline before any separately approved live
attempt. Existing unadmitted templates cannot be treated as a frozen current bundle.
