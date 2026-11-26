# One-node Karing diagnostic

## Karing pass criterion

The official SBXR Karing test passes when Karing displays a fresh, successful
latency in milliseconds for the exact temporary Standard VLESS/REALITY node
imported from the disposable RackNerd test VPS. Run the URL-delay test on that
node. An import confirmation or cached result does not count. Record any
RackNerd-side corroboration separately. Direct-route proof and provider-console
availability are outside the Karing pass criterion. Release Qualification has
its own requirements.

## Operational preflight

Use the verified, isolated RackNerd VPS for test work only. Leave production
BandwagonHost untouched. Confirm direct authenticated SSH with the pinned host
key and review the planned setup and rollback against a fresh baseline. Verify
that the approved work preserves administrative access. The provider console
is a recovery option. For an ordinary bounded run whose scope preserves
administrative access, opening the console is optional. If the preflight shows
that a planned action could interrupt administrative access, stop before that
action and confirm a usable, supported independent recovery path and the
authority to use it.

Keep the current VPN selection, TUN settings and both Karing automatic backups
as they are. Record the installed Karing identity for the run without pinning
a version. Add and remove only the single temporary profile. See
[ADR 0021](../adr/0021-karing-latency-with-current-connection.md) for preserving
the selected connection. VMess/Cloudflare, HTTP subscriptions, credential
rotation and stable publication are outside this procedure.

## Declare and bind

Use the existing diagnostic branch of `candidate.yml`. The opt-in is the exact signed value `diagnostic.mode = "karing-one-node"`, with `scenario_limit_seconds = 2700`, `required_scenarios = ["mvp-install"]`, no attended wait and no Owner exception. Keep the existing signed 2-hour test and 3-hour restoration limits from the approved UTC start. The single request allows at most 45 minutes, with 25 minutes reserved for restoration. Earlier signed, protected runtime or Owner cutoffs tighten these limits. Budget up to 14 minutes for server work and disclosure, 5 minutes for the client, 1 minute of coordination margin, 20 minutes for product/client restoration, and 5 minutes for gateway teardown and final checks. These are operator stop allocations. The existing workflow EXIT trap can make up to twelve bounded SSH teardown attempts; it can outlast the final five-minute allocation. At the deadline stop ordinary/operator effects and report incomplete verification. Observe the independent workflow recovery and reconcile the resulting state; its retries cannot extend operator authority or establish restoration by themselves. Actual actions require positive margin for all remaining work. Budget from the request's creation, including staging or coordination after that point. Queue and signing count against the outer window.

The original diagnostic, with no mode field, keeps the disclosure discard, 30-minute request and 15-minute M1 restoration reserve. Build 221 expired without a live VPS step. Use a fresh candidate, declaration and original evidence-preserving collector. The old machine-wide GitHub redirection is a stop condition. Verify the loopback gateway on 127.0.0.1:9443, a separate ordinary process's normal GitHub trust/route and baseline hosts, trust and NAT before product setup, and again on teardown. Keep public TCP 443 available for Standard and TCP 8443 closed.

Obtain separate live approval for the exact signed candidate, RackNerd
host/key, client/build, private file import, single test destination and UTC
deadlines. Confirm root-owned staging identity, expected service/package
effects, outside evidence, installed Karing identity and secret-copy inventory.
Resolve any backup, sync or network route that would send test traffic or data
through an unapproved system before admitting the test. Leave DNS, routing,
TUN, provider firewall, global CA and the selected server as they are. Any
push, signing or dispatch needs its own authority.

The [candidate runner](../../.github/workflows/candidate.yml) requires successful
signing and a separate protected live review. It checks the approved cutoff and
the 20-minute activity and 25-minute restoration budgets before staging over
host-key-pinned SSH, with a second budget check on RackNerd before the request
is created. The runner does not check provider-console availability. Use the
supported installation and guarded removal callers pinned to this request,
with the 1500-second restoration reserve throughout ordinary work.

Inspect the automatic backup destination and inventory before Save. Karing can
archive the full profile store, including the temporary node and credential,
and rotate local backups. Preserve the archives and report retained or
uncertain backup copies separately. The restoration steps verify removal of
the temporary active profile, outside rejection and return to the host and
client baselines.

## Operator sequence

1. Freeze the exact initial host inventory, existing evidence, and current client state, together with the readback caller and native side-file inventory (diversion, cache and other applicable files). Include existing profiles that use the RackNerd address. Confirm that native UI readbacks and cleanup remain available even if an attended reply is lost. Reconcile any earlier pending attempt before creating a fresh request. A disposable Ubuntu environment is optional for offline rehearsal.
   For the firewall comparison, bind the reviewed `firewall_fingerprint` from
   `.github/scripts/diagnostic-restoration.py` into the run-specific caller.
   Use it on the RackNerd baseline, immediately before install, and after
   gateway teardown. Pass the successful byte output of
   `subprocess.check_output(["/usr/sbin/iptables-save"], timeout=7)` and
   compare the returned SHA-256 to the frozen baseline. A failed readback
   or a different fingerprint stops the applicable check. The fingerprint
   excludes generated timestamps and packet/byte counters and preserves
   IPv4 policy, rule order and rule text as reported by iptables-save.
   Capture a fresh baseline for each run.

2. From the active acceptance job, read the one-node readiness notice for this run/attempt. Through the pinned RackNerd SSH session privately read `state.json` and `request.json` in `/root/sbxr-diagnostic-<attempt_id>/` and the protected transport runtime deadline. Verify the exact state bytes against the digest in the running job’s notice, its manifest digest against the independently authenticated signed manifest, the request bytes against its request digest, and the remote directory identity against the state. Do this before the first product effect. The workflow’s final uploaded artifact is for later comparison. If the running notice cannot be observed, stop at admission. The opt-in workflow stages the reviewed recorder at `<diagnostic-directory>/mvp-observe.py`. Verify its ownership, 0600 one-link identity and SHA-256 against the reviewed checkout and the pinned state’s clock digest. Before setup use the authenticated SSH session to run the staged recorder’s ordinary `start --request "$directory/request.json" --draft "$directory/observation-draft.json"` once. An existing draft requires inspection. Use that file, this request and the unsealed draft for each authenticated menu action. Bind the actual runtime deadline and absolute Owner finish. Preserve the prior evidence. The Mac inputs must be canonical, owned 0600 files; the run directory is an existing canonical, owned 0700 local, non-synced directory. The receiver exclusively creates its attempt subdirectory before it starts a producer. A failed attempt cannot be restarted there. Use the same run directory throughout.
3. Bind the pre-Save baseline using the read-only profile helper. Below, shell variables stand for observed, reviewed run inputs. `native` is a Bash array with `--handoff-dir "$run_directory/karing-$attempt_id" --request-sha256 "$request_sha"`, the actually observed `--connected yes|no --tun yes|no`, and any repeated `--side-file` inventoried path. Re-observe the two UI flags each time. Use the same complete side-file inventory for all comparisons. Where a retained original profile can refresh, pass the already frozen original-store and timezone bundle with `--native-inputs` in every call so the existing audited cache exceptions can be applied. Use a freshly retained bundle whose originals match the pre-Save baseline. The default comparison permits the established typed settings and latency-cache exceptions; an unbound refresh timestamp is a refusal. The routing-group file is included by default. Pass other inventoried native files explicitly. Preserve the returned baseline digest independently.

   ```sh
   python3 -B .github/scripts/diagnostic-karing-profile.py baseline "${native[@]}"
   ```

4. Install using the reviewed private-loopback transport’s `install "$TAG"` entry point and apply Standard once under the approved host controls. Retained q221 staging/install scripts expect a global CA and a 900-second reserve. Do not replay those scripts; bind the current private CA, staged recorder and current cutoff in the actual install and removal callers. Run Check once.

   Run the bound remote driver's `action Check SOFTWARE-LIFECYCLE-CHECK-ALREADY-CURRENT`
   with the reviewed executable, timeout, request, clock, exact-candidate check and
   ordinary cutoff. Success requires the expected response, menu return and successful
   process exit. The driver emits menu text on stdout and structured events on stderr.

   In the private Check caller, bind `remote(check_command, check_cap)` to one
   supervised SSH invocation of that command. Discard stdout, pipe stderr in bytes
   and return the completed process even on a nonzero exit (`check=False`). The remote
   command must propagate the driver's exit status. Pass this invocation to the
   reviewed local helper before any generic exception filter or transcript logging.

   <!-- operator-diagnostic-check -->
   ```python
   import runpy

   run_check = runpy.run_path(str(scripts / "v3-menu-session.py"))["run_diagnostic_check"]
   raise SystemExit(run_check(remote, check_command, check_cap))
   ```

   Keep raw stdout, stderr and exception text out of operator logs. The summary
   retains the observed exit and recognized refusal phase. A driver
   `result-accepted` event preserves the expected Check response even if the
   subsequent menu return fails. On a result mismatch it includes only a known
   Check code. Missing evidence is `unavailable`. An unknown result is
   `unrecognized`. A transport exception without a process exit
   reports `exit=unavailable`. Any nonzero caller exit ends ordinary work.

   Do **not** first run the old diagnostic disclosure: the receiver owns the single disclosure and confirms the menu action. Call it through the reviewed operator supervisor. Keep the SSH identity/host-key pins, manifest and request digests independent of the received transcript and ahead of use. The fixed SSH producer starts a clean direct session, checks the installed candidate, signed scope, active recorder, request/manifest and retained runtime on the remote side. Its child stdout flows only to the bounded Mac receiver; the outer supervisor sees a secret-free receipt. Use the reviewed path that operates directly on the installed executable; a host requiring some other wrapper stops here.

   ```sh
   python3 -B .github/scripts/mvp-operator-run.py --run-directory "$run_directory" \
     --label one-node-disclose --cutoff-unix "$ordinary_cutoff" --timeout 130 --reserve 300 -- \
     python3 -B .github/scripts/diagnostic-karing-handoff.py receive \
     --manifest "$manifest" --manifest-sha256 "$manifest_sha" \
     --request "$request" --request-sha256 "$request_sha" \
     --run-directory "$run_directory" --host "$racknerd_ipv4" --port "$ssh_port" \
     --identity "$key" --known-hosts "$known_hosts" \
     --runtime-deadline "$runtime_deadline" --finish-by "$approved_finish"
   ```

   Reserve the full 120-second receiver cap, its 10-second stop allowance and the 300-second client slot before launch. The enclosing supervisor also charges its own 10-second stop allowance. Ordinary cutoff is the earlier of the request’s ordinary cutoff and the earliest cleanup deadline minus 1500 seconds. The receiver checks the producer's final successful exit, exactly one complete frame, and all Standard connection fields, then writes one 0600 `node.txt` plus `receipt.json`. The label is `SBXR-` followed by the first 16 hex characters of the request digest. The resulting node must match the approved RackNerd IP, port 443 and the disclosed identity. Keep the success receipt digest and fixed client deadline in the operator evidence. The receiver emits an independent cleanup-only digest to the private operator stderr before writing any credential bytes. If the final success acknowledgement is lost, that earlier digest can identify a complete file for scoped disposal; it cannot authorize an import. A partially written or mismatched file refuses automated removal. Avoid clipboard, terminal transcript, screen recording and file sync. An uncertain result ends ordinary work; inspect residues without re-running disclosure.

5. Add `--baseline-sha256 "$baseline_sha" --receipt-sha256 "$receipt_sha"` to the native arguments for subsequent calls. Run `before-save` after the receiver succeeds. Require an absent candidate and active client window. Use Karing's local file importer, that exact path and remark, no diversion rules or automatic testing/removal, and **one Save**. Use `inspect` to re-read the native store and full expected node fields even after an error or missing acknowledgement. Never select the new server. Only a fully attributed one-node group after an acknowledged Save may advance. Pin its group UUID from this readback. If Save was uncertain, take the cleanup path regardless of what the subsequent read shows.
6. Run `before-test` with the retained `--group-id "$group_id"`, then initiate one fresh per-node URL-delay request to the already approved destination. Keep selection, connected and TUN state under observation. Stop on tool failure, silence, ambiguity or expiry. Record only the Karing outcome (displayed milliseconds on success), actual time and run binding. Record independently correlated RackNerd evidence separately, or mark RackNerd corroboration unverified if the evidence is missing. A generic connection count is insufficient for unique correlation. The 5-minute client window starts at handoff completion and includes Save, native readback and probe. No manual wait extends it. The readback helpers never click. The operator witnesses and records the single Save, test and Remove; re-running a readback does not license another click.

## Restoration

7. Stop ordinary work. For restoration, follow the **1200-second host-and-client sequence** in the [budget table](bounded-operator-cleanup.md#selected-complete-cleanup-envelopes); leave the final 300 seconds for transport and independent verification. Steps 7–9 describe the client and host checks. Perform the supported product removal in the table’s order, before spending the client UI slot. Use the earlier of the authenticated cleanup deadline, protected runtime and approved finish, minus 300 seconds, as the product/client cutoff. Recheck current ownership and legal direction. The table’s removal row allows one 360-second menu action, 30 seconds of remote supervision and 10 seconds of local supervision. With the ordinary unsealed recorder still bound, the outer runner uses `--timeout 390 --reserve 620` and the maintained menu driver uses `safety-cleanup`, the observed legal action, `--timeout 360 --cleanup-reserve 660` and the same product/client cutoff. The two layers protect the same remaining work. Stop on ambiguity or insufficient margin. For an absent candidate profile, verify baseline and independent side-file checks. For a complete group or an attributed empty shell, use `before-remove --group-id "$group_id" --expected-state "$observed_state"` (the pinned state is `empty` or `complete`) with the same current flags/pins. Only a positive exact-group decision permits one UI Remove. Both before-Save and before-test readbacks require more than 30 seconds left on the receipt’s fixed client clock; timing does not prevent an operator from clicking late, so stop the UI action at that deadline. Follow with `after-remove --group-id "$group_id"`, even for a missing acknowledgement. Wrong path, extra group/node, changed original, changed selection or ambiguous ID means stop client mutations. Preserve the exact unresolved result. No second Remove, store overwrite or app reset. The helper is a readback tool. It does not click, prove a UI click, or delete a native record.
8. After the last required native comparison, use the receiver's `discard` on the **single** verified local URI and retain the nonsecret receipt. The exact file is checked by digest, device/inode, permissions and link count. A refusal, a lost pin or an unidentified partial file is an outstanding cleanup item. Do not reconstruct authority from the file being removed. If removing the URI is independently safe but client restoration is unproved, preserve that outcome in the report.

   ```sh
   python3 -B .github/scripts/diagnostic-karing-handoff.py discard \
     --directory "$run_directory/karing-$attempt_id" --receipt-sha256 "$receipt_sha"
   ```

9. Verify the outcome of the supported host removal. Client ambiguity or silence must not delay independently authorized host restoration. Verify fresh SSH, preserved host files, firewall, packages/services/accounts, test endpoint rejection, absence of test-owned active client, cache and import files, and the original app state. Follow the existing diagnostic operator-finished notification and guarded gateway teardown only when its prerequisites are met. Verify gateway unit/listener/staging removal and the baseline hosts, trust and routing afterward. A notification, passing fixture or zero producer exit does not establish restoration or qualification. Record any residues and retain the diagnostic evidence and draft.

See the [original disclosure procedure](disclosure-diagnostic.md), [guarded removal budgets](bounded-operator-cleanup.md), and [client preservation procedure](http-subscription-live.md).
