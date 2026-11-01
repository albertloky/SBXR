# Build 210: serving readiness and incomplete enablement

Build 210 (v3.1.136), source `00243e0104783ce0b79149b58c29b8e10b5d0e85`,
failed [qualification run 41285797719](https://github.com/albertloky/SBXR/actions/runs/41285797719).
Installation and outside REALITY traffic passed; the collector accepted M1.
The Enable subscription option was present. Its one M2 invocation returned
`PROXY-INSTALLATION-SUBSCRIPTION-CHANGE-INCOMPLETE`. M3–M5 were not run.
Supported Complete removal subsequently succeeded. Neither that cleanup nor
this offline investigation makes the candidate qualified.

## What the saved diagnostic proves

The filtered record is `role=serving stage=ready result=ok first=none
elapsed_ms=14484 stage_ms=0`. In this exact source it is emitted after private
startup admission, start-lock acquisition, protected installed/ownership/material
checks, unit/sandbox/public-IP/configuration checks, listener binding and a final
lock/deadline check. It precedes watcher creation and the HTTP accept loop.
It proves this process reached that point, not continued serving health,
independent Owner acceptance, HTTP response validity or durable enablement commit.

The private process and Owner create different StartContexts. The 14.484 seconds
are private diagnostic elapsed time, not remaining time in the earlier Owner
action's absolute 15-second budget. The saved menu output contains only the
incomplete result, not the underlying HostError, Owner stage or failed checkpoint.
The filtered service capture has no journal timestamp or Owner diagnostics.
Consequently the relative Owner/child timing and exact live failed predicate
cannot be reconstructed. A budget failure, listener-observation race, ownership
refusal or HTTP probe failure remain possible; none is established as the live cause.

## Reproduced race and bounded correction

The concrete Rust activation path previously checked loaded serving authority
once after the fixed `systemctl enable --now` command and descriptor handoff.
The unit is `Type=simple`; neither event guarantees that its HTTP listener has
bound. A composed offline fixture with a real delayed loopback listener reproduced
`SubscriptionChangeIncomplete` where enablement should succeed. The fixture now
holds binding until the first independent listener observation, making this
ordering deterministic rather than depending on a scheduling delay.

Activation now repeats the complete read-only loaded-authority proof only when
the listener is absent but the exact active process, cgroup, routes and material
are proven. Conflicting ownership, listener or HTTP response errors still refuse
immediately. The wait pauses at most 50 ms between pending observations. It uses the original supplied
StartContext and deadline; it does not create another budget, start/restart a
service again, change authentication/ownership checks, accept partial proof or
retry a failed public operation. Cancellation and deadline checks precede each
observation and successful return. Ordinary probes remain one-shot.
The retained Go adapter's waitLoadedServingAuthority also waits for readiness;
this correction does not adopt its separate timeout construction.

The companion negative fixture serves a real authenticated HTTP artifact while
reporting a conflicting listener PID. It still returns incomplete, retains the
pending operation and discloses no link. This demonstrates that ready plus
incomplete can also be a correct refusal. Deadline/cancellation controls verify
bounded refusal without service replay or ownership-record changes.

## Outside rejection limitation

After cleanup, a host read showed no listeners on 443, 8443 or transport 9443.
The Mac's separate TCP connect calls nevertheless returned success. That probe
only connected and closed: it did not exchange HTTP/TLS or authenticate the
remote endpoint. The preserved Karing baseline had TUN enabled. A local or
intermediate proxy can acknowledge such a connect without a successful upstream
application session. That is a plausible explanation, not proof of what happened.
The two observations are retained; outside rejection is not claimed. No new
network probe or TUN change was made during this investigation.

## Offline validation

- Full `cargo test --locked --offline`: 674 passed, zero failed, one existing
  ignored test. This is macOS/local-fixture evidence, not native live qualification.
- After a test-only lint cleanup, the 12 readiness tests and both delayed-listener
  and conflicting-listener regressions passed again.
- `cargo clippy --locked --offline --all-targets -- -D warnings` and formatting
  verification passed. No lint suppression was added.
- Initial run failures are retained: five fixtures required TMPDIR inside the
  authoritative checkout, and one new assertion incorrectly assumed cancellation
  could not precede activation. The latter now checks the actual contract: no
  repeated service start, unchanged deadline, cancellation/deadline refusal and
  unchanged ownership bytes.

## Evidence and limits

Private run evidence: `../SBXR/.scratch/acceptance/q210-full-20261101/OUTCOME.md`.
Offline reproduction and validation: `../SBXR/.scratch/acceptance/q210-diagnosis/`.
The original failure and candidate assets remain unchanged. No new VPS access,
service reset, credential action, cleanup, candidate disposition or trial was
performed for this repair. A future approved observation must distinguish Owner
activation/readiness/probe/commit failures to establish the original live cause;
this fix alone does not do so or justify increasing the startup timeout.
