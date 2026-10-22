package proxyinstallation

import (
	"context"
	"slices"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	singboxadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/singbox"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

const VMessConnectionReady ResultCode = "PROXY-INSTALLATION-VMESS-CONNECTION-VERIFIED"
const VMessConnectionPending ResultCode = "PROXY-INSTALLATION-VMESS-CONNECTION-PENDING"

type tunnelHost interface {
	PreflightTunnel(context.Context) (hostadapter.TunnelAuthority, string)
	InstallTunnel(context.Context, hostadapter.TunnelAuthority) bool
	StartTunnel(context.Context, hostadapter.TunnelAuthority) bool
	RemoveTunnel(context.Context, hostadapter.TunnelAuthority) bool
	TunnelRemovalSafe(context.Context, hostadapter.TunnelAuthority) bool
}

func (m *installedInterface) tunnelRemovalSafe(ctx context.Context, record *ownershipRecord) bool {
	if record == nil || record.Tunnel == nil {
		return true
	}
	host, ok := m.host.(tunnelHost)
	return ok && host.TunnelRemovalSafe(ctx, *record.Tunnel)
}

func (m *installedInterface) removeTunnel(ctx context.Context, record ownershipRecord) bool {
	if record.Tunnel == nil {
		return true
	}
	host, ok := m.host.(tunnelHost)
	return ok && host.RemoveTunnel(ctx, *record.Tunnel)
}

func (m *installedInterface) vmessReview(ctx context.Context, review Review, check bool) Review {
	if review.Status != Running {
		if check {
			review.Result = refused(review.Status, "Locally Running VMess profile", "Finish the current proxy operation before checking the connection.")
		}
		return review
	}
	body, err := m.readOwnership()
	record, valid := decodeOwnership(body)
	if err != nil || !valid {
		return review
	}
	if record.Tunnel == nil && !check {
		return review
	}
	if record.Tunnel != nil && review.Result.Code == SetupComplete {
		review.Result = vmessPending("No public connection check was performed in this status view.", true)
		review.Result.SubscriptionStatus, review.Result.SubscriptionServing = review.SubscriptionStatus, review.SubscriptionServing
	}
	config, err := m.host.ReadConfiguration(ctx, hostSetupSpec, record.ConfigurationSHA256)
	facts, factErr := singboxadapter.New().CurrentConnectionFacts(config, record.PublicIPv4)
	if err != nil || factErr != nil || facts.VMessHostname == "" {
		if check {
			review.Result = refused(review.Status, "VMess profile", "This installation has no verified optional VMess configuration.")
		}
		return review
	}
	review.LegalActions = append(review.LegalActions, CheckVMessTunnelAction)
	review.Details = append(review.Details, "VMess hostname: "+facts.VMessHostname+"; origin http://127.0.0.1:10000; WebSocket path /sbxr-vmess.", "VMess public connection: choose Check VMess connection for a fresh server-originated traffic check. Local Running alone does not prove the tunnel, public route, or outside clients.")
	if record.Tunnel != nil {
		review.Details = append(review.Details, "Dedicated connector: sbxr-tunnel.service; selected tunnel ID "+record.Tunnel.TunnelID+". Owner token, cloudflared package, domain, DNS and tunnel are preserved on removal.")
	}
	if check {
		review.Result = m.checkVMessConnection(ctx, record, body)
		review.Result.SubscriptionStatus, review.Result.SubscriptionServing = review.SubscriptionStatus, review.SubscriptionServing
	}
	return review
}

func vmessPending(correction string, localVerified bool) Result {
	result := Result{Status: ProblemDetected, Code: VMessConnectionPending, ProxyTraffic: CannotBeVerified, Message: "VMess connection check could not verify the local runtime or public connection.", FailedCheck: "VMess public connection", Correction: correction + " Inspect View details, correct the dedicated connector or Cloudflare route, then choose Check VMess connection. Reinstalling SBXR is not needed. See docs/setup-vmess-tunnel.md."}
	if localVerified {
		result.Status, result.ProxyTraffic, result.Message = Running, ProvedWorking, "Local proxy setup is complete; VMess public connection is not verified."
	}
	return result
}

func (m *installedInterface) checkVMessConnection(ctx context.Context, record ownershipRecord, body []byte) Result {
	lock, busy, err := m.host.AcquireMutationLock(hostSetupSpec.LockPath)
	if err != nil || busy || lock == nil {
		return vmessPending("Wait for the current SBXR operation to finish.", false)
	}
	defer lock.Release()
	installed := m.statusUnderMutationLock(ctx, lock)
	current, err := m.readOwnership()
	if err != nil || !slices.Equal(body, current) || record.Phase != runningPhase || record.Direction != noDirection || record.ClientRotation != nil || installed.State != softwarelifecycle.Ready || installed.Installed == nil || !compatibleOwnership(record, *installed.Installed) || !runningAccepted(m.host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)) {
		return vmessPending("The protected proxy configuration or local runtime changed; inspect View details first.", false)
	}
	config, err := m.host.ReadConfiguration(ctx, hostSetupSpec, record.ConfigurationSHA256)
	host, ok := m.host.(interface {
		ProbeVMess(context.Context, []byte, string) string
	})
	if err != nil || !ok {
		return vmessPending("The protected VMess configuration or probe is unavailable.", true)
	}
	if problem := host.ProbeVMess(ctx, config, record.PublicIPv4); problem != "" {
		return vmessPending(problem, true)
	}
	return Result{Status: Running, ProxyTraffic: ProvedWorking, Code: VMessConnectionReady, Message: "VMess public connection verified from this server: TLS/WebSocket and authenticated VMess-only HTTPS traffic returned the expected server egress. Outside-client and Karing acceptance remain unverified."}
}
