package host

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SoftwareUpdateContracts observes the actual resources while the caller holds
// package and renewal exclusion. Diagnostic evidence is read, never cleared.
func (a Adapter) SoftwareUpdateContracts(ctx context.Context, serving *ServingAuthority, renewal *RenewalAuthority, resources *SubscriptionResourceAuthority, startup *ProxyStartupAuthority) bool {
	if ctx.Err() != nil || !a.ClientIdentityPreparationIdle().Accepted || !a.safelyAbsent(ClientIdentityTargetPath+".sbxr-next") || !a.safelyAbsent(ClientIdentityConfigurationNextPath) {
		return false
	}
	if startup != nil && !a.VerifyProxyStartupIntegration(ctx, *startup) {
		return false
	}
	if serving == nil {
		return renewal == nil && resources == nil && a.InspectSubscriptionAbsence(ctx).Accepted
	}
	dependencies := a.subscriptionDependencies(ctx, SubscriptionPreflight{})
	if !dependencies.Dependencies.Accepted || !dependencies.CertbotInstalled || !dependencies.SnapdInstalled {
		return false
	}
	if renewal == nil || resources == nil || !a.InspectServingFiles(*serving, false).Accepted || !a.renewalFiles(*renewal) || !a.renewalRoute() || !a.renewalHooksSafe() || !a.VerifyClientIdentityServingStartup(ctx) {
		return false
	}
	if _, _, err := a.readRenewalEvidence(*renewal); err != nil {
		return false
	}
	published, ok := a.publishedServingAuthority(*renewal, *serving)
	if !ok || published != *serving || !a.exactSubscriptionFirewall(resources.PublicIPv4) {
		return false
	}
	unit, err := a.protectedServingFile(SubscriptionFirewallUnitPath, 0644, resources.FirewallSHA256)
	if err != nil || string(unit) != subscriptionFirewallUnit(resources.PublicIPv4) {
		return false
	}
	for _, path := range []string{SubscriptionCandidateStatePath, ClientIdentityArtifactPath, ServingUnitPath + ".sbxr-next"} {
		if !a.safelyAbsent(path) {
			return false
		}
	}
	return true
}

// servingExecutable observes whether the selected service process uses the
// exact installed executable. A failed observation never authorizes restart.
func (a Adapter) servingExecutable(ctx context.Context) Observation {
	run := a.subscriptionCommand
	if run == nil {
		run = commandOutput
	}
	state, code, known := run(ctx, "systemctl", "show", "--property=ActiveState", "--value", "sbxr-subscription.service")
	if !known || code != 0 {
		return Observation{}
	}
	switch strings.TrimSpace(state) {
	case "inactive", "failed":
		return observation(false, true)
	case "active":
	default:
		return Observation{}
	}
	output, code, known := run(ctx, "systemctl", "show", "--property=MainPID", "--value", "sbxr-subscription.service")
	pid, err := strconv.Atoi(strings.TrimSpace(output))
	if !known || code != 0 || err != nil || pid < 1 {
		return Observation{}
	}
	file, err := os.Open(a.path("/proc/" + strconv.Itoa(pid) + "/exe"))
	if err != nil {
		return Observation{}
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 256<<20+1))
	installed, installedErr := a.readInstalledUpdateExecutable()
	if err != nil || len(body) == 0 || len(body) > 256<<20 || installedErr != nil {
		return Observation{}
	}
	return observation(digest(body) == digest(installed), true)
}

func (a Adapter) CompleteSoftwareUpdateServing(ctx context.Context, serving ServingAuthority, renewal RenewalAuthority) bool {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	executable := a.servingExecutable(ctx)
	if !executable.Observed {
		return false
	}
	if !executable.Accepted && !a.ActivateServing(ctx, renewal, serving) {
		return false
	}
	return a.servingExecutable(ctx).Accepted && a.InspectPreparedSubscription(ctx, serving, renewal).Accepted
}

func (a Adapter) readInstalledUpdateExecutable() ([]byte, error) {
	path := "/usr/local/bin/sbxr"
	if err := a.safeParents(path); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(a.path(path), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0755 || stat.Uid != a.ownerUID() || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > 256<<20 {
		return nil, errors.New("installed executable refused")
	}
	return io.ReadAll(io.LimitReader(file, 256<<20+1))
}
