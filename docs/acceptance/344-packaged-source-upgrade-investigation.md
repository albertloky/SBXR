# #344: Packaged source-upgrade feasibility

Investigation date: 2026-08-31 UTC. **Result: unsatisfied release blocker.**

[Issue #344](https://github.com/albertloky/SBXR/issues/344) requires the actual current qualified stable source's own unchanged packaged updater and recovery route. No supported invocation exists in the verified source below. Keep #344 open; completing this investigation does not satisfy the source-upgrade requirement or authorize a different route.

Authority: [#342, Implementation Decision 11 and Testing Decisions](https://github.com/albertloky/SBXR/issues/342), [#338's selected resolution](https://github.com/albertloky/SBXR/issues/338#issuecomment-5475359350), [#335's selected resolution](https://github.com/albertloky/SBXR/issues/335#issuecomment-5478617632), and [ADR-0016](../adr/0016-v3-proxy-product-and-modules.md). This report records implementation evidence; it changes none of those decisions.

## Revalidation: 2026-09-01 UTC

Repeated the read-only reproduction below from checkout `aa76642d374dbf7f4fb3bb1dab82708b25f9da08`. Both the current checkout's public verifier and the exact released source's verifier accepted the same `v3.0.21` Release Identity and Release Sequence `82` recorded below. Fresh downloads of all four assets and both extracted executables matched every size and digest in the tables; the released-source package verifier accepted both architectures. The released-source focused tests passed.

Rechecked the released entry point and production caller search: the Owner still reaches only the Proxy Installation terminal; no production `.Check(`, `.Update(`, or `.Recover(` call exists in that released source. Its installer still offers the same installation and removal-restoration routes. The retained Update Record and recovery contracts below therefore remain the relevant source constraints.

Current `main` now includes subscription serving, renewal recorder/hook, and proxy-start dispatch in `cmd/sbxr/run.go`. Those changes are absent from the verified immutable source package and do not supply its missing updater/recovery invocation. The original checkout comparison below describes the 2026-08-31 investigation only.

**Disposition unchanged: keep #344 OPEN.** No supported route was established, and no live upgrade or recovery was executed. Candidate changes cannot add a caller to unchanged prior release bytes. Closing this as satisfied still requires proof of the supported source route; an alternative requires an explicit change to #342's authoritative constraint. Revalidate the qualified stable and active installed source again at candidate qualification.

## Verified source and evidence limits

The production public verifier returned:

```json
{"outcome":"accepted","release_identity":{"commit":"989094b9766f02bf17510a71753c6a5c736bf120","release_index_sha256":"90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331","repository":"albertloky/SBXR","tag":"v3.0.21"},"sequence":82}
```

This is the current Qualified Stable Release under its existing first-V3 contract, **not** a qualified source upgrade under #342. The four Release Identity components are all in the result above; sequence `82` is separate ordering authority.

[Release `v3.0.21`](https://github.com/albertloky/SBXR/releases/tag/v3.0.21) has GitHub release ID `378217693`, is immutable, and was published at `2026-08-28T01:55:40Z`. Its Acceptance Record states `Clean-installed V3 release`, result `RELEASE-V3-PACKAGED-LIVE-QUALIFICATION`, and acceptance time `2026-08-28T01:52:24Z`. Its [candidate workflow run `33133751485`](https://github.com/albertloky/SBXR/actions/runs/33133751485) is completed/success at the same commit. These are historical clean-install facts; they do not establish an update route.

Qualification was not inferred from the Latest label or version order. `verify-public-latest` exercised the production GitHub Adapter from both the working checkout and an export of the exact released source. Both returned the identity above. [The Adapter](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/adapter/github/github.go#L111-L187) checks immutable metadata, the exact four-asset set, Acceptance Record, GitHub-initiated signed release attestation, attested digests, and downloaded release index. No qualification gateway or verifier override was used.

All four assets were downloaded separately and their actual sizes and SHA-256 values matched the verified metadata/index. The existing `verify-package` command from the released source accepted both archives and their installer identity bindings. Each archive contains only one regular `0755` file, `sbxr`.

| Asset | Bytes | SHA-256 |
|---|---:|---|
| `install.sh` | 25818 | `7b70ee6a0e0a3c1183d6b71cc4606b247c1660436545ea294dfe0c04c269fcee` |
| `release-index.json` | 501 | `90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331` |
| `sbxr-linux-amd64.tar.gz` | 14049522 | `5d3e5e27abeec1bc06e1bc38f80d052bc61c85f9c626645e7df4fce11c0d3dcd` |
| `sbxr-linux-arm64.tar.gz` | 12963204 | `898e1956c881c643c5c1fbfff2715f9d10d65c23423cb0818b421c6c9f4e11d4` |

| Packaged executable | Bytes | SHA-256 |
|---|---:|---|
| Linux amd64 | 27980084 | `e49c19fa17f456682c188b43a8461d9e64dcf66e586c6ee41b8f6c7f1d37add3` |
| Linux arm64 | 26291155 | `f7d4cb43093b87b2ed086d0d6fdc6daa36863ecfe0c14db6c9ebac858b8eb156` |

The amd64 executable's Go build information identifies `go1.26.6` and `github.com/albertloky/SBXR/cmd/sbxr`. Its symbol table contains `installedInterface.Update`, `installedInterface.Recover`, and their filesystem implementations. Their presence proves code is packaged, not that an authorized caller can reach it. Archive verification for arm64 does not extend V3 live support beyond Ubuntu Server 24.04 amd64.

No packaged executable or installer was run on a VPS. No live upgrade, rollback, recovery, client journey, or new Release Qualification was executed. Existing source tests are automated evidence only. No new helper, patched prior bytes, hidden mode, candidate-only update simulation, protected-configuration change, intermediate release, or release publication was used.

## Actual dispatch and installation routes

Every source link below is pinned to the verified released commit, not current `main`. At investigation start, checkout `1d4354e010a8fa9fdf7f69e22c57c6cbf62afeb5` differed from that commit only in five documentation files; runtime code was unchanged.

| Route inspected | Released behavior and consequence |
|---|---|
| [`cmd/sbxr/main_linux.go`](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/cmd/sbxr/main_linux.go#L17-L30) | Requires effective UID 0, constructs Software Lifecycle with the production GitHub Adapter, creates a signal-cancelled context, and calls `run`. Signals cancel work and close stdin; they do not dispatch lifecycle recovery. |
| [`cmd/sbxr/run.go`](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/cmd/sbxr/run.go#L12-L14) | Calls the Proxy Installation terminal with `proxyinstallation.NewInstalled(lifecycle)`. It does not call the lifecycle menu or `Check`, `Update`, or `Recover`. |
| [Proxy Installation terminal](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/proxyinstallation/adapter/terminal/run.go#L21-L197) | Rejects every argument with `SBXR accepts no arguments.` The zero-argument menu obtains only Proxy Installation Actions through `Review`/`Execute`. Its setup/cleanup/removal finishing Actions are not Software Lifecycle recovery. There is no updater action or private service/hook/environment dispatcher. |
| [Proxy Installation implementation](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/proxyinstallation/proxyinstallation.go) | Uses lifecycle status and the private Complete removal collaboration, not lifecycle `Check`/`Update`/`Recover`. If lifecycle readiness fails, it refuses normal proxy changes; it does not repair an Update Record automatically. |
| [Software Lifecycle Interface](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/status.go#L116-L122) | Declares `Status`, `Check`, `Update`, and `Recover`. Repository-wide inspection found no non-test `.Check(`, `.Update(`, or `.Recover(` calls. The retained implementations are unreachable from a supported packaged invocation. |
| Packaged `install.sh`, lines 79–96 and 248–279 | `successful_finish` releases the lock, then executes `/usr/local/bin/sbxr` with no arguments when a terminal exists. An exact already-current pair returns `SOFTWARE-LIFECYCLE-INSTALL-ALREADY-CURRENT` and reaches the same proxy menu. Downloads are pinned to the script's embedded tag, except removal-bound restoration. Rerunning the old installer does not discover and invoke a newer lifecycle update. |
| Packaged `install.sh`, lines 140–160 and 295–320 | Recognizes a schema-1 `Removal committed` authority and restores its exact selected executable/Installed Record when permitted, returning `SOFTWARE-LIFECYCLE-INSTALL-REMOVAL-RESTORED`. This exists to reach `Finish removal`, not to recover `Prepared`/`Committed` software updates. No Update Record parser is present in the script. |
| Packaged `install.sh`, lines 322 onward | Outside its early-return/restoration cases, its install path can reclaim `/usr/local/bin/sbxr` and `/var/lib/sbxr`. It is not a provenance-preserving transactional source upgrade. Do not execute it as a workaround or assume it always refuses an existing installation. |
| [`cmd/sbxr-release`](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/cmd/sbxr-release/main.go) and qualification gateway | Repository-only release tooling is absent from the application archives. The approved gateway changes release selection; it does not create a product caller for `Update`/`Recover`. Historical Installer-Updater menu instructions cannot create that caller either. |

The only supported Owner entry is still `sudo sbxr`. It cannot initiate the required source update or Software Lifecycle recovery. `sbxr update`, `sbxr recover`, direct execution of a retained rollback binary, or calling the old Module from a newly built program cannot establish the missing supported route.

## What the old transaction and resource contracts understand

These are static findings about retained code, not claims that the packaged Owner can invoke it.

- [Update admission](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/update_transaction.go#L454-L551) takes `/run/lock/sbxr.lock`, requires a verified Ready installed pair with no known lifecycle transaction residue, prepares a qualified archive, and applies Release Identity/Sequence rules. It has no exact supported-source list, Ownership Record compatibility gate, pending proxy-operation/removal check, or subscription/renewal admission collaboration. The shared lock excludes a live cooperating mutation; it does not itself prove idle durable proxy state is safe.
- [Readiness inspection](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/status_local.go#L15-L29) knows the executable, Installed Record, lock, and six lifecycle transaction paths. It does not interpret subscription resources or unfinished proxy authority. The [Installed Record](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/status.go#L359-L361) is schema 1.
- The [Update Record](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/update_transaction.go#L153-L160) has exactly `schema`, `checkpoint`, `prior_executable_sha256`, `prior_installed_record_sha256`, `candidate_executable_sha256`, and `candidate_installed_record_sha256`. It is a root-owned `0600`, one-link file at `/var/lib/sbxr/update.json`, bounded to 4096 bytes. [Reading](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/update_transaction.go#L636-L647) requires schema 1 and `Prepared` or `Committed`; [strict decoding](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/status.go#L363-L370) rejects duplicate/unknown fields and trailing values. A new schema or added admission/runtime-completion fields are not understood by these old bytes, even if `schema` remains 1.
- [Recovery](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/update_transaction.go#L184-L270) proves bound prior/candidate files. `Prepared` restores the prior pair or finishes its cleanup; `Committed` retains the candidate pair and cleans up. It has no Subscription Serving activation, generation/certificate/listener proof, renewal reopening, or runtime-completion checkpoint. Candidate support for old schema 1 would not make the old executable understand an expanded record.
- [Ownership decoding](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/proxyinstallation/proxyinstallation.go#L1506-L1544) accepts only schema 1 and the fixed original proxy resources/package. It rejects unknown fields. [Owned review](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/proxyinstallation/proxyinstallation.go#L397-L407) requires the Ownership Record Release Identity to equal the active installed identity. There is no subscription schema-2 support or separate creating/finishing identity model.
- [Release admission](https://github.com/albertloky/SBXR/blob/989094b9766f02bf17510a71753c6a5c736bf120/internal/softwarelifecycle/adapter/github/github.go#L394-L472) understands the existing Acceptance Record roles, including V3 `Clean-installed V3 release`, fixed package facts, and historical Installer-Updater roles. A future recurring qualification representation must be tested against the actual source parser; new evidence vocabulary cannot be assumed compatible or disguised as historical clean-install evidence.

## Reproduce the read-only investigation

Run from a trusted SBXR checkout with `gh` access and Go `1.26.6`. This creates only local temporary files and downloads public evidence. It does not execute the downloaded installer or Linux binaries. Require each command to succeed; `verify-public-latest` can exit zero while reporting `refused` or `unavailable`, so inspect its JSON outcome.

```sh
evidence_dir=$(mktemp -d)
export evidence_dir
gh api repos/albertloky/SBXR/releases/latest > "$evidence_dir/latest.json"
GOTOOLCHAIN=go1.26.6 go run ./cmd/sbxr-release verify-public-latest > "$evidence_dir/verified.json"
python3 - <<'PY'
import json, os, pathlib
p = pathlib.Path(os.environ['evidence_dir'])
verified = json.loads((p / 'verified.json').read_text())
metadata = json.loads((p / 'latest.json').read_text())
assert verified == {
    'outcome': 'accepted', 'sequence': 82,
    'release_identity': {
        'repository': 'albertloky/SBXR', 'tag': 'v3.0.21',
        'commit': '989094b9766f02bf17510a71753c6a5c736bf120',
        'release_index_sha256': '90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331'}}
assert metadata['immutable'] and not metadata['draft'] and not metadata['prerelease']
assert metadata['tag_name'] == verified['release_identity']['tag']
assert metadata['target_commitish'] == verified['release_identity']['commit']
PY
mkdir "$evidence_dir/source" "$evidence_dir/assets"
git archive 989094b9766f02bf17510a71753c6a5c736bf120 | tar -x -C "$evidence_dir/source"
gh release download v3.0.21 --repo albertloky/SBXR --dir "$evidence_dir/assets"
cd "$evidence_dir/source"
GOTOOLCHAIN=go1.26.6 go run ./cmd/sbxr-release verify-public-latest
GOTOOLCHAIN=go1.26.6 go run ./cmd/sbxr-release verify-package --directory "$evidence_dir/assets" --architecture amd64
GOTOOLCHAIN=go1.26.6 go run ./cmd/sbxr-release verify-package --directory "$evidence_dir/assets" --architecture arm64
python3 - <<'PY'
import hashlib, json, os, pathlib, tarfile
p = pathlib.Path(os.environ['evidence_dir'])
metadata = json.loads((p / 'latest.json').read_text())
assert {a['name'] for a in metadata['assets']} == {
    'install.sh', 'release-index.json', 'sbxr-linux-amd64.tar.gz', 'sbxr-linux-arm64.tar.gz'}
for a in metadata['assets']:
    path = p / 'assets' / a['name']
    body = path.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    assert len(body) == a['size'] and 'sha256:' + digest == a['digest']
    print(a['name'], len(body), digest)
    if a['name'] == 'release-index.json':
        assert digest == '90463aa73a2c81542b44ea833c762bb2cd44d2d585fb7bd322279f678feea331'
    if a['name'].endswith('.tar.gz'):
        with tarfile.open(path) as archive:
            members = archive.getmembers()
            assert len(members) == 1 and members[0].name == 'sbxr'
            assert members[0].isfile() and members[0].mode == 0o755
            body = archive.extractfile(members[0]).read()
            binary = p / a['name'].removesuffix('.tar.gz')
            binary.write_bytes(body)
            print(binary.name, len(body), hashlib.sha256(body).hexdigest())
PY
GOTOOLCHAIN=go1.26.6 go version -m "$evidence_dir/sbxr-linux-amd64"
GOTOOLCHAIN=go1.26.6 go tool nm "$evidence_dir/sbxr-linux-amd64" | rg 'main\.(main|run)|softwarelifecycle\..*(Update|Recover|update|recover)|proxyinstallation/adapter/terminal.Run'
rg -n '\.(Check|Update|Recover)\(' cmd internal --glob '*.go' --glob '!**/*_test.go'
rg -n 'func main|os.Args|Getenv|LookupEnv' cmd/sbxr internal/proxyinstallation --glob '*.go' --glob '!**/*_test.go'
rg -n 'update|recover|RESTORING_REMOVAL|successful_finish|RECLAIMING' "$evidence_dir/assets/install.sh"
GOTOOLCHAIN=go1.26.6 go test ./cmd/sbxr ./internal/softwarelifecycle ./internal/proxyinstallation/adapter/terminal -count=1
```

The `.Check`/`.Update`/`.Recover` search returns no matches (exit 1); inspect the entry and menu sources above as well. Symbol presence is not call reachability. If the identity assertion fails because qualified stable has changed, stop applying this conclusion to the new source and repeat the investigation for its verified identity. Do not select `v3.0.21` merely to avoid the new current-source obligation.

## Remaining qualification obligations and disposition

1. Establish a supported invocation in the actual current qualified stable source's unchanged package for both update and recovery. That capability is missing here. A future candidate-only change cannot retroactively add a caller to these bytes. No workaround is approved by #344.
2. At candidate qualification, reverify current qualified stable, its package provenance, and the installed source executable/Installed Record. Bind its exact Release Identity into the candidate's declared supported sources and signed attempt. Older resource-creation provenance is separate; this report declares no additional supported source.
3. For each declared active source, prove its own packaged updater's actual admission with the applicable record/resource contracts, source-list and incompatible-downgrade refusal, idle/pending-work gates, and unchanged ownership/proxy/credential provenance. Prove exact prior restoration before commitment and candidate-only forward completion afterward, including required subscription activation/cleanup without restarting sing-box or changing either credential. Both sides must understand every Update Record used in their recovery path.
4. Execute the required observable interruption/recovery scenarios through unchanged packaged bytes on the one disposable Acceptance VPS. Preserve #342's signed-attempt, 30-minute scenario, five-minute evidence-validation, secret-containment, and unexpected-failure rules. Complete the remaining recurring V3 and final exact Karing macOS obligations separately. Source inspection and passing tests cannot fill any missing packaged evidence.

**Keep #344 OPEN as an unsatisfied blocker for #342.** No safe supported invocation was established. Resolving this requires new evidence of an existing supported route or an explicit Owner decision that changes the authoritative source-upgrade constraint; this report makes neither decision and grants no mutation or publication authority.
