# Mac executor EPERM: sanitized support diagnostic — 2026-10-18

Automatic Mac client launches and stops previously succeeded. Later, the same
qualification thread encountered runtime EPERM when Python tried to spawn `ps`.
A separate Node/CUA loopback bind also returned EPERM. The effective execution
context causing either failure is unknown. No denied operation was rerun for
this report, and no permanent policy denial or permission change is inferred.

This report is prepared for support correlation, not submitted. It omits
credentials, endpoint identities, private captures and session-file paths.
`<WORKSPACE>` replaces the absolute project directory. Commands below are
historical observations, not instructions to execute.

## Observed events

All times are UTC. Event times come from saved client/failure receipts; they are
not asserted to be command-request start times. Shell command records report
cwd `<WORKSPACE>`; effective sandbox cwd is not separately recorded.

| Event | Receipt time | Runtime and result |
|---|---|---|
| A1 | Oct16 11:10:37 | Codex shell `commandExecution` → `python3` → operator wrapper → client launcher. Exit0, PID4058, port32080 ready; command/start/group checks succeeded. |
| A2 | Oct16 11:27:55.117017 | Same shell/operator route → exact client stopper. Exit0; PID4058 stopped and port32080 absent. Automated execution, not a user terminal command. |
| B1 | Oct17 14:37:21 | Codex shell → direct Python entrypoint. Exit0; PID26369/port32080 identity bound and actual outside HTTPS traffic succeeded. |
| B2 | Oct17 15:01:35 | Same thread/shell route → direct Python entrypoint. Exit0; PID28161/port32081 identity bound and actual outside traffic succeeded. |
| B3 | Oct17 about15:13; failure recorded15:13:29.032930 | Exact stopper, exit1. Python `subprocess.Popen._execute_child` raised `PermissionError: [Errno 1] Operation not permitted: 'ps'` before identity read or signal. |
| B4 | Oct17 15:47 retry turn; exact command start unknown | Explicitly authorized same-route retry, exit1, same spawn EPERM. Also a `DARWIN_USER_TEMP_DIR` lookup warning. No later retry was made for this report. |
| C1 | Oct17 17:19:45.951 | `cua_repl.js`, Node HTTP server `listen`: EPERM on 127.0.0.1; listening=false, address=null, requests=0. |

The launcher/stopper bodies from four retained runs are identical after replacing
only their run-directory literal. Earlier successful launchers performed `ps`
start-time/command checks; the successful stopper performed the same exact
command/start/group checks as the later failing stopper. B2 and B3 occurred in
the same recorded turn. A native reconnect at14:46 preceded B2 success; another
at15:12 preceded B3 failure. Their causal role is unproved.

## Execution arguments

Common shell wrapper: `[/bin/zsh, -lc, <payload>]`. For A1/A2, payload environment
included `PYTHONDONTWRITEBYTECODE=1` and
`TMPDIR=<WORKSPACE>/.scratch/acceptance/hpa1/tmp`; executable argv were:

```text
A1: python3 -B <WORKSPACE>/.scratch/acceptance/hpa1/tree/.github/scripts/mvp-operator-run.py --run-directory <WORKSPACE>/.scratch/acceptance/hpa1 --label m1-traffic-finish -- python3 -B <WORKSPACE>/.scratch/acceptance/hpa1/operator/m1-traffic-finish.py
A2: python3 -B <WORKSPACE>/.scratch/acceptance/hpa1/tree/.github/scripts/mvp-operator-run.py --run-directory <WORKSPACE>/.scratch/acceptance/hpa1 --label stop-m1-client -- python3 -B <WORKSPACE>/.scratch/acceptance/hpa1/operator/stop-outside-client.py m1
```

B1–B4 used `TMPDIR=$PWD/.scratch/acceptance/live106/t`:

```text
B1: python3 -B .scratch/acceptance/live106/operator/m1-traffic-finish.py
B2: python3 -B .scratch/acceptance/live106/operator/m3-prove-identity.py
B3: python3 -B .scratch/acceptance/live106/operator/stop-outside-client.py m1
B4: python3 -B .scratch/acceptance/live106/operator/stop-outside-client.py m1
```

B1–B4 redirected stdout/stderr into distinct run-local envelope files. B4 also
set `umask 077`; B3 and B4 executable arguments were identical. The child argv
failing inside B3/B4 was `['ps', '-p', '26369', '-o', 'command=']`. No signal was
sent. The stack identifies CommandLineTools Python3.9; successful records name
`python3` without pinning its resolved interpreter or patch version.

C1 used MCP server `cua_repl`, tool `js`, Node `node:http`, with
`server.listen({host:'127.0.0.1', port:0, exclusive:true})`. It failed at listen,
not process spawning. Node version/process cwd are unrecorded. That failure does
not establish whether shell-launched sing-box could currently bind; no such
probe was performed.

## Correlation identifiers

| Group | Task/thread ID and recorded title | Turn ID |
|---|---|---|
| A1/A2 | `01a14444-ee25-74fd-b619-7f736264f03a` — Qualify repaired SBXR candidate | `01a14444-f78c-70fe-b12f-09ef4fcee771` |
| B1 | `01a149d8-8b98-75e2-930f-d82dd3a9f01c` — Fix SBXR readiness receipt | `01a14a2a-8631-77ea-8fe4-82b23a0cd745` |
| B2/B3 | same B task | `01a14a5b-b495-700f-a429-12db464ec11a` |
| B4 | same B task | `01a14a8c-1139-7490-a25b-9cdaa56176cb` |
| C1 | `01a14a92-62d7-772a-948d-65285eea301c` — Diagnose Karing edit failure | `01a14ade-b9a9-75fa-989d-49680ed74bfe` |

Recorded item/call IDs:

```text
A1 exec-20cd0321-3098-4ef1-9d1a-58fc97791fe1  exit0  1296ms
A2 exec-2e79d0dd-e918-4add-aa0d-d7c1872fe841  exit0   252ms
B1 exec-3806dafc-03b9-4085-89f5-ab430eafdf59  exit0  1521ms
B2 exec-70ddf2f4-999f-406c-8e2a-7d12b47ffe12  exit0 28137ms
B3 exec-6f1fde94-ab97-4324-8b94-529cc1c1a694  exit1    99ms
B4 exec-f83115c1-03c4-4d06-9b9d-7116de7e6120  exit1    90ms
C1 call_466fb6aa3a8a4f68a85f1e6e49853a05      failed   463ms
```

Turn-start times: A 2026-10-16T10:32:13Z; B1
2026-10-17T14:01:04Z; B2/B3 2026-10-17T14:54:48Z;
B4 2026-10-17T15:47:37Z; C1 2026-10-17T17:17:54Z.
These are turn timestamps, not command timestamps.
All three threads expose logical hostId `durable`; this is not an OS process or
sandbox identity. Distinct backend request IDs are not exposed in these records.

## Unknowns and minimal diagnostic access

App build, app-server/executor build, Node version, full macOS version, resolved
successful Python executable, effective turn `sandboxPolicy`, managed-policy
revision and per-command/device-session inheritance are unrecorded. No evidence
establishes which changed, or whether any changed. No reviewer rejection/rationale
appears in the retained runtime errors; EPERM alone does not establish one.
Official documentation distinguishes reviewer decisions from the continuing
sandbox boundary. [Auto-review](https://learn.chatgpt.com/docs/sandboxing/auto-review)

Minimal missing access is a supported **read-only** correlation of the IDs above
with effective per-turn sandbox/cwd, resolved configuration/admin requirements,
policy revision, app/executor versions and native execution context. The documented
`config/read`, `configRequirements/read` and turn policy/cwd surfaces are not
callable through the current tool set. No new app server, setting change, broader
permission or private session-file access was attempted. [App Server](https://learn.chatgpt.com/docs/app-server)

Feedback/session sharing is a separate documented workflow; this report has not
been submitted and no session was shared. The troubleshooting guidance does not
establish an automatic repair for this incident. [Troubleshooting](https://learn.chatgpt.com/docs/reference/troubleshooting)

Current outcome: cause unresolved; automatic lifecycle access unproved. No live
qualification or process/listener retry follows from this diagnostic. The user
requires automatic operation; no terminal test work is assigned to the user.
