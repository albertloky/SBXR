package proxyinstallation

import (
	"bytes"
	"context"
	"errors"
	"os"

	hostadapter "github.com/albertloky/SBXR/internal/proxyinstallation/adapter/host"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
)

type httpMigrationHost interface {
	hostInterface
	AcquireServingExclusion() (*hostadapter.ServingExclusion, bool)
	AcquireRenewalExclusion(hostadapter.RenewalAuthority) (*hostadapter.RenewalExclusion, bool)
	AcquireHTTPSRetirementExclusion(hostadapter.HTTPSRetirementAuthority, bool) (*hostadapter.RenewalExclusion, bool)
	SnapshotHTTPSRetirement(hostadapter.ServingAuthority, hostadapter.RenewalAuthority, hostadapter.SubscriptionResourceAuthority, *hostadapter.RenewalExclusion) (hostadapter.HTTPSRetirementAuthority, bool)
	MigrateHTTPSRetirement(context.Context, hostadapter.HTTPSRetirementAuthority, hostadapter.ServingAuthority, *hostadapter.RenewalExclusion) bool
	InspectHTTPSRetirement(hostadapter.HTTPSRetirementAuthority, bool) bool
	HTTPMigrationExecutable() bool
	DiscardHTTPMigrationPublication([]byte, []byte) bool
}

// Retained historical migration machinery has no current production entrypoint.
// Clean-install-only releases do not initiate or automatically resume migration.
func completeHTTPSubscriptionHandoff(ctx context.Context, lifecycle softwarelifecycle.Interface, host httpMigrationHost) (string, bool) {
	body, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", true
	}
	record, valid := decodeOwnership(body)
	if err != nil || !valid {
		// The ordinary menu retains its existing problem/removal reporting.
		return "", true
	}
	if record.Serving == nil || record.Serving.HTTP && !record.TransportMigrating {
		return "", true
	}
	// Existing unfinished proxy directions must keep their ordinary recovery
	// menu. Only this handoff's own journal may resume before that menu.
	if !record.TransportMigrating && (record.Phase != runningPhase || record.Direction != noDirection || record.FinishingRelease != nil || record.Activation != nil || record.Enablement != nil || record.Rotation != nil || record.Repair != nil || record.ClientRotation != nil) {
		return "", true
	}
	if lifecycle.Status(ctx).State != softwarelifecycle.Ready {
		// Update/Recover owns a pending binary transaction; do not change the
		// ownership hash or transport it is still proving.
		return "", true
	}
	lock, busy, err := host.AcquireSubscriptionReviewLock(hostSetupSpec.LockPath)
	if err != nil || busy || lock == nil {
		return "Subscription HTTP migration is busy or unsafe. Run sudo sbxr again after the current writer finishes.", false
	}
	defer lock.Release()
	lc, ok := lifecycle.(mutationLifecycle)
	if !ok {
		return "Subscription HTTP migration cannot verify the installed release.", false
	}
	installed := lc.StatusUnderMutationLock(ctx, lock)
	if installed.State != softwarelifecycle.Ready || installed.Installed == nil {
		return "Subscription HTTP migration waits for Software Lifecycle recovery.", false
	}
	return migrateLegacyHTTPSubscription(ctx, host, *installed.Installed, lock)
}

func migrateLegacyHTTPSubscription(ctx context.Context, host httpMigrationHost, installed softwarelifecycle.ReleaseIdentity, lock *softwarelifecycle.MutationLockAuthority) (string, bool) {
	failed := "Subscription HTTP migration is incomplete. The recorded token, proxy identity and certificate files are retained. Run sudo sbxr again to finish forward; do not edit protected state or reinstall."
	if ctx.Err() != nil || lock == nil {
		return failed, false
	}
	for _, path := range []string{"/var/lib/sbxr/update.json", "/var/lib/sbxr/.update.json.next", finalOwnershipPath} {
		if _, err := host.ReadOwnership(path); !errors.Is(err, os.ErrNotExist) {
			return failed, false
		}
	}
	body, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", true
	}
	record, valid := decodeOwnership(body)
	if err != nil || !valid || record.Phase != runningPhase || record.Direction != noDirection || !compatibleOwnership(record, installed) || record.FinishingRelease != nil || record.Activation != nil || record.Enablement != nil || record.Rotation != nil || record.Repair != nil || record.ClientRotation != nil {
		return failed, false
	}
	if record.Serving == nil || record.Serving.HTTP && !record.TransportMigrating {
		return "", true
	}
	if !host.HTTPMigrationExecutable() {
		return failed, false
	}
	packages, busy, err := host.AcquirePackageLocks()
	if err != nil || busy || packages == nil {
		return failed, false
	}
	defer packages.Release()
	var renewal *hostadapter.RenewalExclusion
	if record.TransportMigrating {
		renewal, valid = host.AcquireHTTPSRetirementExclusion(*record.HTTPSRetirement, false)
	} else if record.Renewal != nil && record.SubscriptionResources != nil {
		renewal, valid = host.AcquireRenewalExclusion(*record.Renewal)
	} else {
		valid = false
	}
	if !valid || renewal == nil {
		return failed, false
	}
	defer renewal.Release()
	certbot, valid := host.AcquireServingExclusion()
	if !valid || certbot == nil {
		return failed, false
	}
	defer certbot.Release()
	// A crash before ownership rename can leave a complete or truncated
	// deterministic publication. Preserve current authority and discard only
	// that protected expected prefix before replaying the ordinary writer.
	nextRecord := record
	if record.TransportMigrating {
		nextRecord.TransportMigrating = false
	} else {
		retired, ok := host.SnapshotHTTPSRetirement(*record.Serving, *record.Renewal, *record.SubscriptionResources, renewal)
		if !ok {
			return failed, false
		}
		serving := hostadapter.ServingAuthority{HTTP: true, LinkID: record.Serving.LinkID, CredentialSHA256: record.Serving.CredentialSHA256}
		resources := hostadapter.SubscriptionResourcesForEnablement(record.PublicIPv4, hostadapter.SubscriptionPreflight{HTTP: true})
		nextRecord.Serving, nextRecord.Renewal, nextRecord.SubscriptionResources = &serving, nil, &resources
		nextRecord.HTTPSRetirement, nextRecord.TransportMigrating = &retired, true
	}
	updateSubscriptionResources(&nextRecord, installed)
	if !host.DiscardHTTPMigrationPublication(body, ownershipBytes(nextRecord)) {
		return failed, false
	}
	if host.SyncOwnership(hostSetupSpec.OwnershipPath, body) != nil {
		return failed, false
	}
	facts := host.InspectRunning(ctx, hostSetupSpec, aptSourceBody, body, record.ConfigurationSHA256, record.PublicIPv4)
	if !ownedFactsAccepted(facts) || !all(facts.Host, facts.PublicIPv4Matches).Accepted {
		return failed, false
	}
	if !record.TransportMigrating {
		retired, ok := host.SnapshotHTTPSRetirement(*record.Serving, *record.Renewal, *record.SubscriptionResources, renewal)
		if !ok {
			return failed, false
		}
		serving := hostadapter.ServingAuthority{HTTP: true, LinkID: record.Serving.LinkID, CredentialSHA256: record.Serving.CredentialSHA256}
		resources := hostadapter.SubscriptionResourcesForEnablement(record.PublicIPv4, hostadapter.SubscriptionPreflight{HTTP: true})
		record.Serving, record.Renewal, record.SubscriptionResources = &serving, nil, &resources
		record.HTTPSRetirement, record.TransportMigrating = &retired, true
		updateSubscriptionResources(&record, installed)
		next := ownershipBytes(record)
		if _, valid := decodeOwnership(next); !valid || host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next) != nil {
			return failed, false
		}
		body = next
	}
	current, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
	if err != nil || !bytes.Equal(current, body) || !host.MigrateHTTPSRetirement(hostadapter.RuntimeStartContext(ctx, lock), *record.HTTPSRetirement, *record.Serving, renewal) || !host.InspectHTTPSRetirement(*record.HTTPSRetirement, false) {
		return failed, false
	}
	record.TransportMigrating = false
	updateSubscriptionResources(&record, installed)
	next := ownershipBytes(record)
	if host.PublishOwnership(hostSetupSpec.OwnershipPath, hostSetupSpec.OwnershipNextPath, body, next) != nil {
		published, err := host.ReadOwnership(hostSetupSpec.OwnershipPath)
		if err != nil || !bytes.Equal(published, next) || host.SyncOwnership(hostSetupSpec.OwnershipPath, published) != nil {
			return failed, false
		}
	}
	return "Subscription migrated to HTTP; token and proxy settings are unchanged. Use confirmed View details to display the replacement Subscription Link, then update the existing client profile URL and refresh it while preserving client settings. HTTP exposes the subscription token and proxy credentials to interception and permits response tampering.", true
}
