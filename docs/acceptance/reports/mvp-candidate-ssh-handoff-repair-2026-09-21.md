# MVP candidate identity SSH handoff — local repair, 2026-09-21

**The operator handoff is corrected and locally regression-tested. No product
or release-workflow code changed. No VPS contact, certificate request, candidate
dispatch, release mutation or stable publication occurred in this task.**

This is a local repair report, not candidate readiness or live acceptance.
The [v3.1.76 attempt](https://github.com/albertloky/SBXR/actions/runs/35591785297)
remains failed and burned.

## Confirmed problem and bounded correction

The failed operator command expected
`/run/sbxr-qualification/v3-packaged-live.sh` on the VPS. The current manifest-v3
workflow does not stage that helper. It installed SBXR successfully, then the
missing-helper command returned 127 before setup began.

The [current procedure](../mvp-live-acceptance.md#checking-the-installed-candidate-over-ssh)
now gives one explicit command: stream the reviewed checkout's complete
`v3-packaged-live.sh` over authenticated SSH, source it using `/dev/stdin` in a
fresh Bash process, and invoke only its existing read-only `exact_candidate`
function. The source guard prevents the standalone journey dispatcher from
running. The check still binds the current collector request and manifest to
the Installed Record and actual executable.

The procedure also identifies the local source prerequisite, required stdin
behavior, success/failure handling, and the separate artifact/attestation and
live-acceptance gates. The script map and temporary-menu plan link to that
command. No additional helper is staged on the host; the four-file menu staging,
permission wrapper, identity-check implementation, menu driver, transport,
collector, qualification rules and product code are unchanged.

Historical run-local scripts and reports were preserved rather than rewritten
as current source.

## Regression evidence

Tests live beside the existing boundaries:

- [Candidate handoff tests](../../../release_candidate_handoff_test.go) now run
  the existing fresh-shell identity cases through streamed source as well.
  They retain mismatched manifest/request, tag, sequence, repository, commit,
  index, architecture and executable cases, missing input, and symlink refusal.
  A documentation regression requires the executable SSH example and checks its
  syntax. It failed against the original procedure before the example was added.
- [Real SSH boundary tests](../../../.github/scripts/test_ssh_boundary.py) extract
  and execute the **actual documented command**, using real OpenSSH, Bash, jq,
  files and SHA-256 checks. New namespace-isolated fixtures use the helper's
  unmodified default paths and source bytes. The old `/run` helper is absent.
  The old invocation is required to fail with 127; the corrected invocation
  must succeed without executing the synthetic product or staging a helper.
- The same real-SSH suite proves refusal and no continuation for changed
  manifest bytes, a wrong request binding, a valid but wrong Installed Record
  sequence, changed executable bytes, a missing request, missing local source,
  and an empty source stream. It checks input contents/metadata remain unchanged
  by the check. The original 12 SSH/menu/submission cases also still pass.

As a separate red/green control, the documented command in the disposable test
checkout was temporarily replaced with the original bad helper-path invocation.
The real-SSH regression failed with `unexpected-command-status`. Restoring the
corrected document, with its SHA-256 rechecked, restored the passing result.
The repository document was not mutated for this control.

## Validation and environment

| Check | Result |
|---|---|
| Focused candidate handoff/source/documentation tests on macOS | Passed |
| `GOTOOLCHAIN=go1.26.6 go test ./...` | Passed; unchanged cached results reused where reported |
| `GOTOOLCHAIN=go1.26.6 go vet ./...` | Passed |
| Direct Linux real-SSH suite | `SSH_BOUNDARY_CASES_PASSED count=21` |
| Focused Linux Go tests, including `TestV3RealSSHBoundaries` | Passed |
| Original-command mutation control | Failed as expected; corrected command passed afterward |
| `git diff --check` | Passed |

Linux execution used a new disposable Ubuntu 24.04 **ARM64** QEMU/HVF VM on the
Mac, not the VPS. Its image matched the checksum fetched from Canonical's
official HTTPS endpoint. Provisioning installed test dependencies; the test
launch used restricted egress and a loopback-only SSH forward. An outside TCP
probe was refused. The fixture installation/manifest were synthetic, and no
real SBXR product executable or Certbot was installed.

The final guest audit proved the namespace's product/qualification paths were
absent outside the test, its temporary directory empty, and no fixture process
or listener left running. The VM was then powered off; exact process exit and
loopback-forward absence were verified. Its disks, seed and temporary SSH keys
were removed. Checksums, source receipts, test inputs and logs remain in the
[private local run directory](../../../.scratch/acceptance/h21/), including
`linux-ssh-rehearsal.log`, `linux-old-handoff-red.log`, `linux-focused-go.log`,
`go-test.log`, `go-vet.log`, `guest-final-audit.json` and `cleanup.json`.

## Remaining boundary

This proves the corrected operator identity-check boundary locally. It does not
prove real candidate installation, outside proxy traffic, CA issuance, Karing,
restart/removal after replacement, or any complete MVP journey. The five live
journeys remain pending for a newly reviewed, unused candidate.

At completion of this local repair phase, changes were uncommitted on `main`;
no push or CI dispatch had been performed. Landing and CI are a separate step
before preparing another candidate. That next attempt still needs fresh source,
host, package, network, capacity and concrete signing/live reviews. No further
live attempt is authorized or started by this report.
