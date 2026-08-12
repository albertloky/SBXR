# Network Policy acceptance

This record covers the Network Policy Module only. It is not Release Qualification.

## Stable checks

- `NETWORK-MODULE`: `go test ./internal/networkpolicy`
- `NETWORK-FAMILY-EXPOSURE`: `go test ./internal/networkpolicy -run 'TestEvaluate(SupportedCleanBaseline|PublicFamilyQualification|CleanAndManagedOwnership|ManagedCloudflareRoutes|ManagedPublicListenersMatchQualifiedFamilies|CorrectiveNetworkPolicy)'`
- `NETWORK-PORT-SELECTION`: `go test ./internal/networkpolicy -run 'TestEvaluate(ManagedCommittedPortConflictUsesCorrectionFlow|CorrectiveNetworkPolicy|SelectsReplacementForEveryConfigurableDefault)' && go test ./internal/networkpolicy/adapter/ubuntu -run TestAdapterCollectsTypedFactsWithoutMutation -v`
- `NETWORK-NFTABLES-OWNERSHIP`: `go test ./internal/networkpolicy -run 'TestEvaluate(IsolatedNftablesCandidateAndSSHSafety|NftablesIntervalsAndCompetingPolicy)'`
- `NETWORK-COMPETING-MANAGER`: `go test ./internal/networkpolicy -run TestEvaluateNftablesIntervalsAndCompetingPolicy && go test ./internal/networkpolicy/adapter/ubuntu -run TestAdapterCollectsTypedFactsWithoutMutation`
- `NETWORK-SSH-PRESERVATION`: `go test ./internal/networkpolicy -run TestEvaluateIsolatedNftablesCandidateAndSSHSafety`
- `NETWORK-RETRY`: `go test ./internal/networkpolicy -run TestEvaluateBoundsOutboundAndRenewalFreshness`
- `NETWORK-RECHECK`: `go test ./internal/networkpolicy -run 'TestEvaluate(BoundsOutboundAndRenewalFreshness|HTTP01OutsideFailureStaysExternal)'`
- `NETWORK-PROVIDER-BOUNDARY`: `go test ./internal/networkpolicy -run TestEvaluateKeepsLocalAndOutsideProofDistinct`
- `NETWORK-RENEWAL-STALENESS`: `go test ./internal/networkpolicy -run TestEvaluateBoundsOutboundAndRenewalFreshness`
- `NETWORK-OUTSIDE-PROOF`: `go test ./internal/networkpolicy -run 'TestEvaluate(KeepsLocalAndOutsideProofDistinct|HTTP01OutsideFailureStaysExternal)'`
- `NETWORK-UBUNTU-SEAM`: `go test ./internal/networkpolicy/adapter/ubuntu -run 'TestAdapterCollectsTypedFactsWithoutMutation|TestAdapterUsesRealDNSAndVerifiedHTTPSWithoutCredentials|TestProductionUbuntuSeam' -v`
- `NETWORK-RECLAMATION-REVIEW`: `go test ./internal/networkpolicy -run 'Test(ReclaimableVPSReview|InstallationReviewDistinguishes|ProtectedHostFoundation)' && go test ./internal/ownerconsole -run '^TestRunConfirmsExactReclamationReviewBeforeSeparateApply$'`
- `NETWORK-RECLAMATION-AUTHORITY`: `go test ./internal/networkpolicy ./internal/networkpolicy/adapter/ubuntu -run 'Test(ReclamationAuthority|AdapterRefusesUnsupportedScript)'`
- `NETWORK-REPOSITORY`: `go test ./...`

`NETWORK-UBUNTU-SEAM` always runs the controlled read-only fixture check. `TestProductionUbuntuSeam` additionally collects real facts when the runner is Ubuntu; it is intentionally skipped elsewhere. Neither check applies nftables, changes a service, edits SSH, or writes host configuration.

## Baseline procedure

1. Supply one complete Clean or Managed intent to `Evaluate`.
2. Run pre-approval evaluation. Confirm root-only nftables facts are disclosed as `NETWORK-PRIVILEGED-PENDING`, never guessed.
3. Review the candidate `inet sbxr` exposure policy, findings, staleness digest, disk floor, and pre-/post-Apply gates.
4. After approval and sudo authentication, collect root-only facts and invoke a fresh post-approval `Evaluate` before mutation.
5. Change each bound address, listener, selected port, SSH session, route, firewall fact, owning-Module fact, outbound result, and checksum in turn. Each change must make `Binding.Stale` true; review time alone has no input and cannot expire it.
6. For a Clean VPS, verify unproved SBXR/proxy ownership refuses adoption. For Managed, verify matching Desired State is Healthy, proven drift offers forward repair, and contradictory lineage returns `NETWORK-LINEAGE-RECOVERY`.
7. Verify at least one public family qualifies; the policy contains only qualified selected families; its certificate address is exactly the Owner-selected primary subscription IP; adding or removing a family makes the revision-bound result stale; every enabled Connection Profile has exactly its approved public listener or typed loopback Cloudflare route; every disabled Connection Profile has no exposure; subscription has only public `10443/TCP`; and temporary public `80/TCP` appears only for one requested HTTP-01 interval.
8. Occupy each configurable default in turn and in combination; verify the rebuilt result records every cryptographically selected, bind-proven replacement outside the actual ephemeral range, detected SSH, TCP 80, current listeners, and other selections; identifies the typed downstream artifacts to rebuild; and adds an immediate pre-Apply bind gate for each replacement. Verify a committed replacement and detected SSH never move automatically, exact holder facts appear in their Correction Flows, and occupied TCP 80 returns a typed handoff that keeps the current certificate under Certificate Lifecycle retry ownership.
9. Copy each result and confirm no supplied checksum, Client Access Value, Infrastructure Secret, arbitrary command, raw rule output, or provider credential appears.
10. Confirm the native candidate owns only `inet sbxr`, has no whole-ruleset flush, admits only qualified public exposure, preserves established traffic and the detected SSH port, excludes loopback origins from public rules, and admits TCP 80 only for requested certificate work. Active competing managers and exact unexpected base-chain or legacy-rule identities must block without being disabled; inactive packages must not block.
11. Confirm the typed System Changes handoff requires complete native validation, atomic table Apply, a root-owned rollback watchdog, exact previous-rule restoration, existing-session responsiveness, detected-port admission, and watchdog cancellation only after `NETWORK-SSH-RESPONSIVE`. Complete removal names only `inet sbxr`, and the SSH warning names the future outside-reconnection limit and VPS provider console recovery path.
12. For IP and domain HTTP-01, confirm TCP 80 is one separately marked `sbxr:acme-http-01` policy whose native handles must be recorded and removed after success, failure, interruption, cancellation, or rollback. Confirm unrelated `_acme-challenge` CNAME, NS, and TXT facts do not block; effective CAA must permit `letsencrypt.org` and HTTP-01; and the result never creates CAA or contains a Cloudflare token.
13. Confirm local and outside statuses remain separate: same-VPS facts never become outside success, connected Cloudflare routes prove only the two Tunnel profiles, ACME may prove temporary TCP 80, and direct TCP/UDP stays Pending until a genuine outside client reports. A genuine failure must name the exact address, port, protocol, complete required-port table, SSH warnings, provider firewall/security-group/network-ACL guidance, and `Run Live Profile Check again`, without claiming a provider change.
14. Confirm deterministic checks allow one attempt, temporary DNS or HTTPS allows at most three attempts within 60 seconds, local health allows 60 seconds, Cloudflare and ACME retain their owning-Module bounds, and no retry is infinite. Every finding repeats the affected observation and then the complete preflight. Every result held across global-lock contention is stale and requires a fresh `Evaluate` plus rebuilt one-use Plan.
15. For installation review, distinguish Clean VPS, Reclaimable VPS, contradictory lineage, and unsupported host without adopting anything. A Reclaimable VPS Plan binds exact read-only listener, process, service, package, identity, executable or script digest, firewall, Docker preservation, and Cloudflare conflict facts. Protected Host Foundation version 1 refuses SSH, the current shell, system and package tools, shared interpreters and libraries, mounts, and recovery dependencies. Back and Cancel make no change; only the genuine Owner Console accepts exact `RECLAIM THIS VPS`, returns opaque one-use digest-bound review approval, and still starts no work. A later privileged recheck must match the exact digest and may issue one opaque System Changes authority only for one standalone executable or one direct fixed-interpreter script with the same PID, path, interpreter, and digest.

## Current status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | `NETWORK-MODULE` covers supported/unsupported host facts, address families, Clean/Managed classification, adoption refusal, protocol-aware exposure, stable port selection, isolated nftables ownership, exact temporary HTTP-01 identity, typed DNS/CAA, local-versus-outside proof, provider guidance, retry/recheck bounds, renewal staleness, competing-policy refusal, SSH preservation, the typed watchdog/rollback handoff, Complete-removal scope, stale binding, privilege staging, disk/time gates, Correction Flow material, typed outcomes, and secret safety. |
| Seam Verification — controlled fixture | Passed | `NETWORK-UBUNTU-SEAM` proves the production Adapter parses Ubuntu, memory, systemd, listener ownership, route, virtualization, ephemeral-port, exact nftables base-chain, and legacy-iptables facts; releases real TCP/UDP bind probes; and uses the configured resolver plus verified HTTPS for release, attestation, Cloudflare, ACME, and certificate endpoints without Owner credentials or fixture mutation. |
| Seam Verification — real Ubuntu | Passed | GitHub Actions run `31128326846` ran `TestProductionUbuntuSeam` as root on an isolated Ubuntu 24.04 runner, inspected real host, route, socket, SSH-session, DNS, verified-HTTPS, and nftables facts, and passed native `nft --check` candidate validation without Apply. |
| Integrated Verification | Pending — integrated release | System Changes now covers nftables Apply/watchdog/rollback, recorded-handle TCP 80 cleanup, and global-lock scheduling at Module or controlled-Seam level, but these behaviors have not yet run through the complete executable with all owning Modules. |
| Codex Live Acceptance | Pending — approved Acceptance Run | No Acceptance VPS or Acceptance Client was used. |
| Owner Acceptance | Pending — first v1 release | Provider-console, maintained-client, and maintained-network checks belong to Albert. |
