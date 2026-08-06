# Network Policy acceptance

This record covers the Network Policy Module only. It is not Release Qualification.

## Stable checks

- `NETWORK-MODULE`: `go test ./internal/networkpolicy`
- `NETWORK-FAMILY-EXPOSURE`: `go test ./internal/networkpolicy -run 'TestEvaluate(SupportedCleanBaseline|PublicFamilyQualification|CleanAndManagedOwnership|ManagedCloudflareRoutes|ManagedPublicListenersMatchQualifiedFamilies|CorrectiveNetworkPolicy)'`
- `NETWORK-PORT-SELECTION`: `go test ./internal/networkpolicy -run 'TestEvaluate(ManagedCommittedPortConflictUsesCorrectionFlow|CorrectiveNetworkPolicy|SelectsReplacementForEveryConfigurableDefault)' && go test ./internal/networkpolicy/adapter/ubuntu -run TestAdapterCollectsTypedFactsWithoutMutation -v`
- `NETWORK-UBUNTU-SEAM`: `go test ./internal/networkpolicy/adapter/ubuntu -run 'TestAdapterCollectsTypedFactsWithoutMutation|TestProductionUbuntuSeam' -v`
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

## Current status

| Stage | Status | Evidence |
|---|---|---|
| Module Verification | Passed | `NETWORK-MODULE` covers supported/unsupported host facts, address families, Clean/Managed classification, adoption refusal, protocol-aware exposure, stable port selection, stale binding, privilege staging, disk/time gates, Correction Flow material, typed outcomes, and secret safety. |
| Seam Verification — controlled fixture | Passed | `NETWORK-UBUNTU-SEAM` proves the production Adapter parses Ubuntu, memory, systemd, listener ownership, route, virtualization, and ephemeral-port facts and releases real TCP/UDP bind probes without changing the fixture. |
| Seam Verification — real Ubuntu | Pending | Run `TestProductionUbuntuSeam` on the assigned controlled Ubuntu 24.04 environment; this Mac skips it. |
| Integrated Verification | Pending — integrated release | System Changes, nftables Apply/watchdog, temporary TCP 80 cleanup, and complete executable wiring do not exist yet. |
| Codex Live Acceptance | Pending — approved Acceptance Run | No Acceptance VPS or Acceptance Client was used. |
| Owner Acceptance | Pending — first v1 release | Provider-console, maintained-client, and maintained-network checks belong to Albert. |
