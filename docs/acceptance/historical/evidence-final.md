# Retained evidence inputs for scenarios 19–25

This is historical V4 material. Its producer was retired from the working tree;
the former [final-evidence.py](https://github.com/albertloky/SBXR/blob/0859e964b66d10deb5768a372b09ca5903332553/.github/scripts/v3-operator/final-evidence.py)
is retained in Git for interpreting named records.

The final evidence adapter was `.github/scripts/v3-operator/final-evidence.py`.
It consumes protected mode-0600 files through the common evidence assembler and
adds only the scenario-specific sources below. The assembler supplies the common
`state`, `entry`, and `route` sources. All helper executions must use
`capture-source.py`, which binds the current manifest and request, records actual
stdout with timestamps, and accepts only a named helper from the reviewed bundle.

Scenario 19 runs `19-lifecycle-menu.sh` as helper `19-lifecycle-menu.sh` and
retains its wrapper as `19-lifecycle-menu.json`. It also retains
`19-first-frame.txt`, `19-check.txt`, `19-update.txt`, and `19-recover.txt`.
The helper dynamically resolves the displayed action numbers, runs the installed
zero-argument menu, and emits `sbxr-v4-lifecycle-menu-result-v1` with exact hashes
of those outputs. After the generic action and finish phases,
`scenario-lifecycle-menu-finish.json` is the common
`sbxr-v4-scenario-entry-v1` assembler state.

Scenario 20 captures the interactive `managed-hold.py` session, including its
held and interrupted records, as `20-managed.json`. While the child remains held,
run `removal-refusal.py remove-certbot` through the capture wrapper and retain
`remove-certbot-removal-refusal.json`. Use capture helper identity
`removal-refusal`. Send `interrupt` to the original managed
hold only after the public refusal is captured.

Scenario 21 captures the interactive `recorder-boundary.py writer` session as
`21-writer.json`. While the actual recorder is held before opening its outcome
file, capture `removal-refusal.py remove-writer` as
`remove-writer-removal-refusal.json`. Send `release` only after the public refusal
is captured, so the same wrapper contains both the held and real completed writer
records.

Scenario 22 captures `admission-race-operator.py` as
`22-admission-race.json`. Retain its internally bound
`22-admission-held.json`, `22-removal-refusal.json`, and
`22-admission-final.json` beside the wrapper. The adapter requires the real shared
admission lock, unlocked writer lock, public refusal before commitment, equal
owned inventories, successful recorder completion, and healthy Running result.

Scenario 23 captures the interactive `directory-locks.py` session as
`23-locks.json`. Its stdout must contain the initial three-lock record and the
post-release record for the same PID, paths, device/inodes, contents, metadata,
and created flags. While those POSIX locks remain held, capture
`removal-refusal.py remove-directory-lock` as
`remove-directory-lock-removal-refusal.json`; then send `release` to the holder.

Scenario 24 captures `24-secret-containment.sh` as
`24-secret-containment.json` and retains `24-protection.json`, `24-sandbox.json`,
`24-protected-open.json`, `24-scan.json`, `24-removal.json`, and
`24-cleanup.json`. The helper emits a result that binds every exact receipt hash.
The adapter independently requires the six external surfaces (`runner`, `vps`,
`mac`, `terminal`, `workflow`, and `retained`), nonempty coverage for each,
explicit external-surface and client-cleanup attestations, both unprivileged
permission probes, absent exact secret variants and prohibited patterns, and
completed inventory cleanup. After the generic action and finish phases,
`scenario-secret-containment-finish.json` is the common assembler state.

Scenario 25 is deliberately manual at the Karing UI boundary. Create the
protected canonical input `25-karing-reviewed-input.json` with schema
`sbxr-v4-karing-reviewed-capture-v1`; do not derive it from model rows, fixtures,
source inspection, cached latency, or elapsed time. It must name capture method
`owner-reviewed-manual-karing-ui`, bind the current manifest and request SHA-256,
copy the exact signed Karing package object, hash the initial and final selected
server/settings, hash the one profile and stable nonsecret node fields, and carry
the 19 exact ordered events accepted by `karing-evidence.py`.

Before transferring evidence to the VPS, use the same helper on the Mac to
inventory captures that the Owner already made and to observe the actual package
and installed application identity. This command does not open or control Karing,
request screen-recording or accessibility permission, or install anything:

```sh
python3 karing-evidence.py --capture-native \
  --manifest /absolute/private/qualification-manifest.json \
  --request /absolute/private/karing-final-request.json \
  --package /absolute/path/to/the/signed/Karing.dmg \
  --app /Applications/Karing.app \
  --artifact /absolute/path/to/first-owner-capture.mov \
  --artifact /absolute/path/to/second-owner-capture.png \
  --output-directory /absolute/new/private/karing-native-evidence
```

The new directory is mode 0700. It contains mode-0600 copies of every native
capture and `25-karing-native-capture.json`. Transfer that manifest and every
named artifact through the approved private channel into the scenario-25 source
directory without renaming them. Each reviewed event must contain a nonempty
`native_artifacts` list of those direct filenames, the union of the event lists
must equal the retained inventory, and the reviewed document's
`native_capture_sha256` must equal the native manifest's digest. The native
manifest records the signed package's observed size and SHA-256 plus the installed
bundle identifier, version/build, and executable digest. These records bind the
files the Owner reviewed; the Owner remains responsible for interpreting what the
UI pixels and latency results mean.

Run the VPS validator as:

```sh
python3 /run/sbxr-qualification/capture-source.py \
  --helper karing-evidence \
  --output "$SCENARIO_SOURCE_DIRECTORY/25-karing-evidence.json" -- \
  --input "$SCENARIO_SOURCE_DIRECTORY/25-karing-reviewed-input.json" \
  --native-manifest "$SCENARIO_SOURCE_DIRECTORY/25-karing-native-capture.json" \
  --native-root "$SCENARIO_SOURCE_DIRECTORY"
```

The manual and genuinely due automatic refresh timestamps must differ by at least
300 seconds. The selected server hash must remain constant for every event. The
same profile hash must bind every event. The helper requires the exact signed
package, stable nonsecret fields across UUID replacement, exact outcome enum for
every UI/server observation, and completion within the original 7200-second
request. The adapter uses the actual timestamps for initial latency success,
revoked cached-UUID failure, same-link replacement refresh, and replacement
latency success. Missing input, a stale request, a fixture label, a changed
setting, or any unobserved event is a refusal.

The UI observations and their retained native captures are made on the Mac with
the Owner's existing explicit screen-recording or accessibility permissions. The
Linux `capture-source.py` wrapper does not control Karing and cannot grant those
permissions. The VPS validator stream-hashes every retained artifact and refuses
a missing, renamed, mode-changed, unreferenced, or modified file. A typed document
without the native manifest, actual package receipt, and underlying fresh capture
bytes is incomplete source evidence even when its labels and timestamps are
structurally valid.

Scenarios 20, 21, 22, and 23 remain `Running`. Scenario 24 also preserves
`Running`. Only scenario 25 finishes `Not installed`. The lifecycle automated-only
checks and the four ADR-0021 excluded Karing checks are absent from the live rule
lists and must not appear as observations.
