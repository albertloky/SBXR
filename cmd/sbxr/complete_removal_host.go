package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/systemchanges"
	systemubuntu "github.com/albertloky/SBXR/internal/systemchanges/adapter/ubuntu"
)

var removalPublicUnits = []string{"cloudflared.service", "sbxr-subscription.service", "sing-box.service", "xray.service"}

type completeRemovalHost struct {
	base     systemubuntu.InstallHost
	root     string
	desired  state.DesiredState
	api      cloudflaretunnel.MutationAPI
	token    cloudflaretunnel.ManagementToken
	recovery cloudflaretunnel.RemovalRecoveryAuthority
	run      func(context.Context, []byte, string, ...string) ([]byte, error)
}

type completeRemovalRollback struct {
	Resource systemchanges.RemovalResource `json:"resource"`
	Firewall []byte                        `json:"firewall,omitempty"`
	Routes   []cloudflaretunnel.Route      `json:"routes,omitempty"`
}

func newCompleteRemovalHost(base systemubuntu.InstallHost, desired state.DesiredState, api cloudflaretunnel.MutationAPI, token cloudflaretunnel.ManagementToken) *completeRemovalHost {
	return &completeRemovalHost{base: base, root: "/", desired: desired, api: api, token: token, run: runCompleteRemovalCommand}
}

func runCompleteRemovalCommand(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Stdin = bytes.NewReader(input)
	return command.CombinedOutput()
}

func (host completeRemovalHost) CaptureRollback(step systemchanges.Step, write func(io.Reader) error) error {
	change, ok := step.RemovalChange()
	if !ok {
		return host.base.CaptureRollback(step, write)
	}
	if write == nil || irreversibleProviderResource(change.Resource) {
		return errors.New("Complete removal rollback capture unavailable")
	}
	snapshot := completeRemovalRollback{Resource: change.Resource}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	switch change.Resource {
	case systemchanges.FirewallTableResource:
		body, err := host.run(ctx, nil, "nft", "-j", "list", "table", "inet", "sbxr")
		if err != nil || !json.Valid(body) {
			return errors.New("owned firewall rollback unavailable")
		}
		snapshot.Firewall = body
	case systemchanges.PublicListenerResource:
		if !host.allUnits(ctx, "is-active") {
			return errors.New("owned listener rollback unavailable")
		}
	case systemchanges.PublicServiceResource:
		if !host.allUnits(ctx, "is-enabled") {
			return errors.New("owned service rollback unavailable")
		}
	case systemchanges.CloudflareRouteResource:
		observed, err := host.observeTunnel(ctx)
		if err != nil || !reflect.DeepEqual(observed.Routes, host.managedRoutes()) {
			return errors.New("owned Tunnel route rollback unavailable")
		}
		return cloudflaretunnel.WriteRemovalRecovery(host.token, host.removalRecoveryAuthority(observed.Routes), write)
	default:
		return errors.New("Complete removal rollback resource unavailable")
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	return write(bytes.NewReader(body))
}

func (host completeRemovalHost) Execute(step systemchanges.Step, timeout time.Duration, cancellation *systemchanges.Cancellation) (systemchanges.StepEvidence, error) {
	change, ok := step.RemovalChange()
	if !ok {
		return host.base.Execute(step, timeout, cancellation)
	}
	if timeout <= 0 || cancellation == nil || cancellation.Requested() {
		return systemchanges.StepEvidence{}, errors.New("Complete removal step refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var err error
	switch change.Resource {
	case systemchanges.FirewallTableResource:
		_, err = host.run(ctx, nil, "nft", "delete", "table", "inet", "sbxr")
	case systemchanges.PublicListenerResource:
		_, err = host.run(ctx, nil, "systemctl", append([]string{"stop"}, removalPublicUnits...)...)
	case systemchanges.PublicServiceResource:
		_, err = host.run(ctx, nil, "systemctl", append([]string{"disable"}, removalPublicUnits...)...)
	case systemchanges.CloudflareRouteResource:
		_, err = host.api.PutConfiguration(ctx, cloudflaretunnel.PutConfigurationRequest{AccountID: host.desired.Cloudflare.AccountID, TunnelID: host.desired.Cloudflare.TunnelID, Routes: removedTunnelRoutes(), Token: host.token})
	case systemchanges.CloudflareDNSRecordResource:
		err = host.api.DeleteDNSRecord(ctx, cloudflaretunnel.DeleteDNSRecordRequest{ZoneID: host.desired.Cloudflare.ZoneID, ID: change.ImmutableID, Token: host.token})
		if err == nil {
			_, observedErr := host.api.GetDNSRecord(ctx, cloudflaretunnel.GetDNSRecordRequest{ZoneID: host.desired.Cloudflare.ZoneID, ID: change.ImmutableID, Token: host.token})
			if !cloudflaretunnel.IsNotFound(observedErr) {
				err = errors.New("owned DNS record absence is unproved")
			}
		}
	case systemchanges.CloudflareTunnelResource:
		err = host.api.DeleteTunnel(ctx, cloudflaretunnel.DeleteTunnelRequest{AccountID: host.desired.Cloudflare.AccountID, ID: change.ImmutableID, Token: host.token})
		if err == nil {
			_, observedErr := host.observeTunnel(ctx)
			if !cloudflaretunnel.IsNotFound(observedErr) {
				err = errors.New("owned Tunnel absence is unproved")
			}
		}
	default:
		err = errors.New("unsupported Complete removal resource")
	}
	if err != nil || cancellation.Requested() && !irreversibleProviderResource(change.Resource) {
		return systemchanges.StepEvidence{}, errors.New("Complete removal effect failed")
	}
	digest := sha256.Sum256([]byte(string(change.Resource) + "\x00" + change.ImmutableID))
	return systemchanges.StepEvidence{Code: "owned-removal-verified", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (host completeRemovalHost) Reverse(step systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEvidence, error) {
	change, ok := step.RemovalChange()
	if !ok {
		return host.base.Reverse(step, snapshot, timeout)
	}
	if irreversibleProviderResource(change.Resource) {
		return systemchanges.StepEvidence{}, errors.New("irreversible provider deletion cannot roll back")
	}
	var prior completeRemovalRollback
	if change.Resource == systemchanges.CloudflareRouteResource {
		authority, token, err := cloudflaretunnel.ReadRemovalRecovery(snapshot)
		if err != nil || authority.TunnelID != change.ImmutableID {
			return systemchanges.StepEvidence{}, errors.New("Complete removal rollback snapshot unavailable")
		}
		host.applyRemovalRecovery(authority, token)
		prior.Resource, prior.Routes = change.Resource, authority.Routes
	} else if json.NewDecoder(io.LimitReader(snapshot, 1<<20)).Decode(&prior) != nil || prior.Resource != change.Resource {
		return systemchanges.StepEvidence{}, errors.New("Complete removal rollback snapshot unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var err error
	switch change.Resource {
	case systemchanges.FirewallTableResource:
		if !json.Valid(prior.Firewall) {
			return systemchanges.StepEvidence{}, errors.New("owned firewall rollback unavailable")
		}
		_, err = host.run(ctx, prior.Firewall, "nft", "-j", "-f", "-")
	case systemchanges.PublicListenerResource:
		_, err = host.run(ctx, nil, "systemctl", append([]string{"start"}, removalPublicUnits...)...)
	case systemchanges.PublicServiceResource:
		_, err = host.run(ctx, nil, "systemctl", append([]string{"enable"}, removalPublicUnits...)...)
	case systemchanges.CloudflareRouteResource:
		if !reflect.DeepEqual(prior.Routes, host.managedRoutes()) {
			return systemchanges.StepEvidence{}, errors.New("owned Tunnel route rollback changed")
		}
		_, err = host.api.PutConfiguration(ctx, cloudflaretunnel.PutConfigurationRequest{AccountID: host.desired.Cloudflare.AccountID, TunnelID: host.desired.Cloudflare.TunnelID, Routes: prior.Routes, Token: host.token})
	}
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	digest := sha256.Sum256([]byte("restored\x00" + change.ImmutableID))
	return systemchanges.StepEvidence{Code: "owned-removal-restored", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (host completeRemovalHost) HoldServices() error { return host.base.HoldServices() }
func (host completeRemovalHost) AllowProvenServices(recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	return host.base.AllowProvenServices(recovery, timeout)
}
func (host completeRemovalHost) VerifyStartingServices(recovery systemchanges.RecoveryTransaction, timeout time.Duration) error {
	return host.base.VerifyStartingServices(recovery, timeout)
}
func (host completeRemovalHost) VerifyAgreement(agreement systemchanges.Agreement, timeout time.Duration) error {
	return host.base.VerifyAgreement(agreement, timeout)
}
func (host completeRemovalHost) VerifyRollback(agreement systemchanges.RollbackAgreement, timeout time.Duration) error {
	return host.base.VerifyRollback(agreement, timeout)
}

func (host completeRemovalHost) InspectStep(step systemchanges.Step, snapshot io.Reader, timeout time.Duration) (systemchanges.StepEffect, error) {
	change, ok := step.RemovalChange()
	if !ok {
		return host.base.InspectStep(step, snapshot, timeout)
	}
	if irreversibleProviderResource(change.Resource) {
		return "", errors.New("irreversible provider step is not rollback-inspected")
	}
	var prior completeRemovalRollback
	if change.Resource == systemchanges.CloudflareRouteResource {
		authority, token, err := cloudflaretunnel.ReadRemovalRecovery(snapshot)
		if err != nil || authority.TunnelID != change.ImmutableID {
			return "", errors.New("Complete removal inspection snapshot unavailable")
		}
		host.applyRemovalRecovery(authority, token)
		prior.Resource, prior.Routes = change.Resource, authority.Routes
	} else if json.NewDecoder(io.LimitReader(snapshot, 1<<20)).Decode(&prior) != nil || prior.Resource != change.Resource {
		return "", errors.New("Complete removal inspection snapshot unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	switch change.Resource {
	case systemchanges.FirewallTableResource:
		_, err := host.run(ctx, nil, "nft", "list", "table", "inet", "sbxr")
		if err != nil {
			return systemchanges.StepEffectPresent, nil
		}
		return systemchanges.StepEffectAbsent, nil
	case systemchanges.PublicListenerResource:
		return host.unitEffect(ctx, "is-active")
	case systemchanges.PublicServiceResource:
		return host.unitEffect(ctx, "is-enabled")
	case systemchanges.CloudflareRouteResource:
		observed, err := host.observeTunnel(ctx)
		if err != nil {
			return "", err
		}
		if reflect.DeepEqual(observed.Routes, removedTunnelRoutes()) {
			return systemchanges.StepEffectPresent, nil
		}
		if reflect.DeepEqual(observed.Routes, prior.Routes) {
			return systemchanges.StepEffectAbsent, nil
		}
	}
	return "", errors.New("Complete removal effect is contradictory")
}

func (host completeRemovalHost) Check(check systemchanges.Check, phase systemchanges.GatePhase, timeout time.Duration) (systemchanges.HealthStatus, error) {
	if check.Code != "SOFTWARE-LIFECYCLE-REMOVAL-EXTERNAL-ABSENT" || phase != systemchanges.PrePublication {
		return host.base.Check(check, phase, timeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if host.anyUnit(ctx, "is-active") || host.anyUnit(ctx, "is-enabled") {
		return systemchanges.Failed, nil
	}
	if _, err := host.run(ctx, nil, "nft", "list", "table", "inet", "sbxr"); err == nil {
		return systemchanges.Failed, nil
	}
	observed, err := host.observeTunnel(ctx)
	if err != nil || !reflect.DeepEqual(observed.Routes, removedTunnelRoutes()) {
		return systemchanges.Failed, err
	}
	return systemchanges.Healthy, nil
}

func (host completeRemovalHost) VerifyIrreversibleRemovalReady(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, name := range []string{"var/lib/sbxr/state/state.json", "etc/systemd/system/sbxr-recovery.service", "usr/local/bin/sbxr"} {
		if _, err := os.Lstat(host.path(name)); err != nil {
			return errors.New("final removal prerequisites unavailable")
		}
	}
	observed, err := host.observeTunnel(ctx)
	if err != nil || !reflect.DeepEqual(observed.Routes, removedTunnelRoutes()) {
		return errors.New("rollback-capable exposure removal is unproved")
	}
	return nil
}

func (host completeRemovalHost) VerifyCloudflareTokenRevoked(timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return cloudflaretunnel.New(host.api, cloudflaretunnel.SystemClock{}).VerifyManagementTokenRevoked(ctx, cloudflaretunnel.ObservationRequest{AccountID: host.desired.Cloudflare.AccountID, ZoneID: host.desired.Cloudflare.ZoneID, ZoneName: host.desired.Cloudflare.ZoneName, Token: host.token})
}

func (host completeRemovalHost) DeleteIrreversibleRemovalPhase(phase systemchanges.IrreversibleRemovalPhase, timeout time.Duration) (systemchanges.StepEvidence, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var err error
	switch phase {
	case systemchanges.LocalStatePhase:
		err = host.removeTree("var/lib/sbxr/state")
	case systemchanges.SecretsPhase:
		err = host.removeTree("etc/sbxr")
	case systemchanges.CertificatesPhase:
		if err = host.removeTree("var/lib/sbxr/certificates"); err == nil {
			err = host.removeTree("var/lib/sbxr/certbot")
		}
	case systemchanges.TransactionMaterialDeletionAuthorizedPhase:
		// The durable authorization makes a crash during the following protected-file deletion resumable.
	case systemchanges.ReleasesPhase:
		err = host.removeTree("opt/sbxr/releases")
	case systemchanges.UnitsPhase:
		units := removalManagedUnits()
		_, _ = host.run(ctx, nil, "systemctl", append([]string{"disable", "--now"}, units...)...)
		if err = host.proveUnitsStoppedAndDisabled(ctx, units); err != nil {
			break
		}
		for _, unit := range units {
			if removeErr := os.Remove(host.path(filepath.Join("etc/systemd/system", unit))); removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
				err = removeErr
				break
			}
		}
		if err == nil {
			_, err = host.run(ctx, nil, "systemctl", "daemon-reload")
		}
	case systemchanges.IdentitiesPhase:
		for index := len(softwarelifecycle.ManagedIdentityNames()) - 1; index >= 0 && err == nil; index-- {
			name := softwarelifecycle.ManagedIdentityNames()[index]
			if !managedIdentityAbsent(name) {
				_, _ = host.run(ctx, nil, "/usr/sbin/userdel", name)
				_, _ = host.run(ctx, nil, "/usr/sbin/groupdel", name)
			}
			if !managedIdentityAbsent(name) {
				err = errors.New("managed service identity remains")
			}
		}
	case systemchanges.ListenersPhase:
		if _, commandErr := host.run(ctx, nil, "systemctl", append([]string{"disable", "--now"}, removalPublicUnits...)...); commandErr != nil && (host.anyUnit(ctx, "is-active") || host.anyUnit(ctx, "is-enabled")) {
			err = commandErr
		}
	case systemchanges.PreparedArtifactsPhase:
		for _, name := range []string{"var/lib/sbxr/subscriptions", "var/lib/sbxr/software-lifecycle", "var/lib/sbxr/diagnostics"} {
			if err = host.removeTree(name); err != nil {
				break
			}
		}
	case systemchanges.OwnedFirewallStatePhase:
		if _, commandErr := host.run(ctx, nil, "nft", "delete", "table", "inet", "sbxr"); commandErr != nil {
			if _, inspectErr := host.run(ctx, nil, "nft", "list", "table", "inet", "sbxr"); inspectErr == nil {
				err = commandErr
			}
		}
	default:
		err = errors.New("unsupported irreversible removal phase")
	}
	if err != nil {
		return systemchanges.StepEvidence{}, err
	}
	digest := sha256.Sum256([]byte(phase))
	return systemchanges.StepEvidence{Code: "removal-phase-absent", SHA256: hex.EncodeToString(digest[:])}, nil
}

func (host completeRemovalHost) VerifyFinalRemovalAbsence(timeout time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for _, name := range []string{"var/lib/sbxr/state", "etc/sbxr", "var/lib/sbxr/certificates", "var/lib/sbxr/certbot", "var/lib/sbxr/subscriptions", "var/lib/sbxr/software-lifecycle", "var/lib/sbxr/diagnostics", "opt/sbxr/releases"} {
		if _, err := os.Lstat(host.path(name)); !errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
	}
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		if unit == "sbxr-recovery.service" {
			continue
		}
		if _, err := os.Lstat(host.path(filepath.Join("etc/systemd/system", unit))); !errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
	}
	for _, identity := range softwarelifecycle.ManagedIdentityNames() {
		if !managedIdentityAbsent(identity) {
			return false, nil
		}
	}
	if err := host.proveUnitsStoppedAndDisabled(ctx, removalManagedUnits()); err != nil {
		return false, err
	}
	if _, err := host.run(ctx, nil, "nft", "list", "table", "inet", "sbxr"); err == nil {
		return false, nil
	}
	return true, nil
}

func (host completeRemovalHost) PrepareRemovalFinalization(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Do not stop the recovery service: this code may be running inside it after reboot.
	_, _ = host.run(ctx, nil, "systemctl", "disable", "sbxr-recovery.service")
	if err := host.proveUnitsDisabled(ctx, []string{"sbxr-recovery.service"}); err != nil {
		return err
	}
	if err := os.Remove(host.path("etc/systemd/system/sbxr-recovery.service")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if _, err := host.run(ctx, nil, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return host.proveUnitsDisabled(ctx, []string{"sbxr-recovery.service"})
}

func (host completeRemovalHost) FinalizeRemoval(time.Duration) error {
	err := os.Remove(host.path("usr/local/bin/sbxr"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (host completeRemovalHost) observeTunnel(ctx context.Context) (cloudflaretunnel.WholeTunnelObservation, error) {
	return host.api.ObserveWholeTunnel(ctx, cloudflaretunnel.WholeTunnelRequest{AccountID: host.desired.Cloudflare.AccountID, ZoneID: host.desired.Cloudflare.ZoneID, TunnelID: host.desired.Cloudflare.TunnelID, DNSRecords: host.dnsReferences(), Token: host.token})
}

func (host completeRemovalHost) dnsReferences() []cloudflaretunnel.DNSRecordReference {
	ids := []string{host.desired.Cloudflare.XHTTPDNSRecordID, host.desired.Cloudflare.WebSocketDNSRecordID, host.desired.Cloudflare.DirectIPv4RecordID, host.desired.Cloudflare.DirectIPv6RecordID}
	result := make([]cloudflaretunnel.DNSRecordReference, 0, len(ids))
	for _, id := range ids {
		if id != "" {
			result = append(result, cloudflaretunnel.DNSRecordReference{ID: id})
		}
	}
	return result
}

func (host completeRemovalHost) managedRoutes() []cloudflaretunnel.Route {
	if len(host.recovery.Routes) != 0 {
		return append([]cloudflaretunnel.Route(nil), host.recovery.Routes...)
	}
	return managedTunnelExpected(host.desired).Routes
}

func (host completeRemovalHost) removalRecoveryAuthority(routes []cloudflaretunnel.Route) cloudflaretunnel.RemovalRecoveryAuthority {
	cloudflare := host.desired.Cloudflare
	ids := []string{cloudflare.XHTTPDNSRecordID, cloudflare.WebSocketDNSRecordID}
	if cloudflare.DirectIPv4RecordID != "" {
		ids = append(ids, cloudflare.DirectIPv4RecordID)
	}
	if cloudflare.DirectIPv6RecordID != "" {
		ids = append(ids, cloudflare.DirectIPv6RecordID)
	}
	return cloudflaretunnel.RemovalRecoveryAuthority{AccountID: cloudflare.AccountID, ZoneID: cloudflare.ZoneID, ZoneName: cloudflare.ZoneName, TunnelID: cloudflare.TunnelID, DNSRecordIDs: ids, Routes: append([]cloudflaretunnel.Route(nil), routes...)}
}

func (host *completeRemovalHost) applyRemovalRecovery(authority cloudflaretunnel.RemovalRecoveryAuthority, token cloudflaretunnel.ManagementToken) {
	host.recovery, host.token = authority, token
	host.desired.Cloudflare.AccountID, host.desired.Cloudflare.ZoneID = authority.AccountID, authority.ZoneID
	host.desired.Cloudflare.ZoneName, host.desired.Cloudflare.TunnelID = authority.ZoneName, authority.TunnelID
	ids := authority.DNSRecordIDs
	host.desired.Cloudflare.XHTTPDNSRecordID, host.desired.Cloudflare.WebSocketDNSRecordID = ids[0], ids[1]
	if len(ids) > 2 {
		host.desired.Cloudflare.DirectIPv4RecordID = ids[2]
	}
	if len(ids) > 3 {
		host.desired.Cloudflare.DirectIPv6RecordID = ids[3]
	}
}

func (host *completeRemovalHost) LoadRemovalRecovery(source io.Reader) error {
	authority, token, err := cloudflaretunnel.ReadRemovalRecovery(source)
	if err == nil {
		host.applyRemovalRecovery(authority, token)
	}
	return err
}

func removedTunnelRoutes() []cloudflaretunnel.Route {
	return []cloudflaretunnel.Route{{Service: "http_status:404"}}
}

func irreversibleProviderResource(resource systemchanges.RemovalResource) bool {
	return resource == systemchanges.CloudflareDNSRecordResource || resource == systemchanges.CloudflareTunnelResource
}

func (host completeRemovalHost) allUnits(ctx context.Context, action string) bool {
	for _, unit := range removalPublicUnits {
		if _, err := host.run(ctx, nil, "systemctl", action, unit); err != nil {
			return false
		}
	}
	return true
}

func (host completeRemovalHost) anyUnit(ctx context.Context, action string) bool {
	for _, unit := range removalPublicUnits {
		if _, err := host.run(ctx, nil, "systemctl", action, unit); err == nil {
			return true
		}
	}
	return false
}

func removalManagedUnits() []string {
	units := make([]string, 0, len(softwarelifecycle.ManagedUnitNames())-1)
	for _, unit := range softwarelifecycle.ManagedUnitNames() {
		if unit != "sbxr-recovery.service" {
			units = append(units, unit)
		}
	}
	return units
}

func (host completeRemovalHost) proveUnitsStoppedAndDisabled(ctx context.Context, units []string) error {
	allowed := func(body []byte, values ...string) bool {
		value := strings.TrimSpace(string(body))
		return slices.Contains(values, value)
	}
	for _, unit := range units {
		active, activeErr := host.run(ctx, nil, "systemctl", "is-active", unit)
		if activeErr == nil || !allowed(active, "inactive", "failed", "unknown") {
			return errors.New("managed unit activity is unproved")
		}
		enabled, enabledErr := host.run(ctx, nil, "systemctl", "is-enabled", unit)
		if enabledErr == nil || !allowed(enabled, "disabled", "static", "masked", "not-found") {
			return errors.New("managed unit enablement is unproved")
		}
	}
	return nil
}

func (host completeRemovalHost) proveUnitsDisabled(ctx context.Context, units []string) error {
	for _, unit := range units {
		enabled, err := host.run(ctx, nil, "systemctl", "is-enabled", unit)
		if err == nil || !slices.Contains([]string{"disabled", "static", "masked", "not-found"}, strings.TrimSpace(string(enabled))) {
			return errors.New("managed unit enablement is unproved")
		}
	}
	return nil
}

func (host completeRemovalHost) unitEffect(ctx context.Context, action string) (systemchanges.StepEffect, error) {
	present := 0
	for _, unit := range removalPublicUnits {
		if _, err := host.run(ctx, nil, "systemctl", action, unit); err == nil {
			present++
		}
	}
	if present == len(removalPublicUnits) {
		return systemchanges.StepEffectAbsent, nil
	}
	if present == 0 {
		return systemchanges.StepEffectPresent, nil
	}
	return "", errors.New("partial Complete removal service effect")
}

func (host completeRemovalHost) removeTree(name string) error {
	path := host.path(name)
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := host.removeTree(filepath.Join(name, entry.Name())); err != nil {
			return err
		}
	}
	return os.Remove(path)
}

func (host completeRemovalHost) path(name string) string {
	return filepath.Join(host.root, filepath.FromSlash(strings.TrimPrefix(name, "/")))
}

func managedIdentityAbsent(name string) bool {
	_, userErr := user.Lookup(name)
	_, groupErr := user.LookupGroup(name)
	_, userMissing := userErr.(user.UnknownUserError)
	_, groupMissing := groupErr.(user.UnknownGroupError)
	return userMissing && groupMissing
}
