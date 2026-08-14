package softwarelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/albertloky/SBXR/internal/networkpolicy"
	lifecyclecontract "github.com/albertloky/SBXR/internal/softwarelifecycle/contract"
	"github.com/albertloky/SBXR/internal/systemchanges"
)

type InstallContributionName string

const (
	NetworkInstallContribution      InstallContributionName = "Network Policy"
	ProfilesInstallContribution     InstallContributionName = "Connection Profiles"
	CloudflareInstallContribution   InstallContributionName = "Cloudflare Tunnel"
	CertificateInstallContribution  InstallContributionName = "Certificate Lifecycle"
	SubscriptionInstallContribution InstallContributionName = "Subscription Publication"
	InstallPlanRefused              RefusalCode             = "SOFTWARE-LIFECYCLE-INSTALL-PLAN-REFUSED"
)

var installIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type installCandidateCell struct {
	verified   VerifiedRelease
	staged     StagedRelease
	archive    []byte
	components []byte
}

// InstallCandidate is the opaque handoff from authenticated staging to Plan.
type InstallCandidate struct{ cell *installCandidateCell }

func (InstallCandidate) String() string   { return "verified install candidate: protected" }
func (InstallCandidate) GoString() string { return "verified install candidate: protected" }
func (InstallCandidate) MarshalJSON() ([]byte, error) {
	return nil, fmt.Errorf("verified install candidate cannot be rendered")
}
func (candidate InstallCandidate) SoftwareLifecyclePreparedArchive() (StagedRelease, []byte, []byte, bool) {
	if !validInstallCandidate(candidate) {
		return StagedRelease{}, nil, nil, false
	}
	return candidate.cell.staged, append([]byte(nil), candidate.cell.archive...), append([]byte(nil), candidate.cell.components...), true
}

// CertificateLifecycleQualification exposes only the Certbot capability
// already authenticated by candidate staging, never candidate bytes or paths.
func (candidate InstallCandidate) CertificateLifecycleQualification() (string, bool) {
	if !validInstallCandidate(candidate) {
		return "", false
	}
	manifest, err := ValidateComponentArchive(candidate.cell.components, candidate.cell.staged.Architecture)
	return manifest.Certbot, err == nil
}

func (candidate InstallCandidate) ManagedComponentVersions() (xray, singBox, cloudflared, certbot string, valid bool) {
	if !validInstallCandidate(candidate) {
		return "", "", "", "", false
	}
	manifest, err := ValidateComponentArchive(candidate.cell.components, candidate.cell.staged.Architecture)
	if err != nil {
		return "", "", "", "", false
	}
	return manifest.Xray, manifest.SingBox, manifest.Cloudflared, manifest.Certbot, true
}

func (candidate InstallCandidate) QualifiedComponent(name string) ([]byte, string, bool) {
	if !validInstallCandidate(candidate) {
		return nil, "", false
	}
	return qualifiedComponent(candidate.cell.components, candidate.cell.staged.Architecture, name)
}

// ManagedUnit returns one fixed unit rendered from the authenticated candidate
// payload. Callers cannot supply a path or template.
func (candidate InstallCandidate) ManagedUnit(name string) ([]byte, bool) {
	if !validInstallCandidate(candidate) {
		return nil, false
	}
	executable, ok := executableArchiveBytes(candidate.cell.archive)
	if !ok {
		return nil, false
	}
	metadata, _, err := ReadPayloadMetadata(bytes.NewReader(executable), int64(len(executable)))
	units, renderErr := RenderManagedUnits(metadata, candidate.cell.staged.Identity)
	unit, exists := units[name]
	return append([]byte(nil), unit...), err == nil && renderErr == nil && exists
}

func (candidate InstallCandidate) SoftwareLifecyclePreparedUpdate() (VerifiedRelease, StagedRelease, []byte, []byte, bool) {
	if !validInstallCandidate(candidate) || !validInstalled(candidate.cell.verified) || candidate.cell.verified.Identity != candidate.cell.staged.Identity {
		return VerifiedRelease{}, StagedRelease{}, nil, nil, false
	}
	return candidate.cell.verified, candidate.cell.staged, append([]byte(nil), candidate.cell.archive...), append([]byte(nil), candidate.cell.components...), true
}

type InstallContributionProof = lifecyclecontract.InstallContribution

type InstallContribution interface {
	SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution
}

type networkInstallContribution struct{ proof InstallContributionProof }

func (value networkInstallContribution) SoftwareLifecycleInstallContribution() lifecyclecontract.InstallContribution {
	return value.proof
}

func NewNetworkInstallContribution(result networkpolicy.Result, changeSet, desiredStateSHA256 string) InstallContribution {
	return newNetworkInstallContribution(result, changeSet, desiredStateSHA256, result.Outcome != networkpolicy.Unknown)
}

// NewReviewedNetworkInstallContribution records a complete read-only Plan.
// Privileged authority remains unavailable until the later fresh recheck.
func NewReviewedNetworkInstallContribution(result networkpolicy.Result, changeSet, desiredStateSHA256 string) InstallContribution {
	return newNetworkInstallContribution(result, changeSet, desiredStateSHA256, false)
}

func newNetworkInstallContribution(result networkpolicy.Result, changeSet, desiredStateSHA256 string, privileged bool) InstallContribution {
	if result.Baseline != networkpolicy.Clean || (result.Outcome != networkpolicy.Healthy && result.Outcome != networkpolicy.NeedsAttention && result.Outcome != networkpolicy.Unknown) || !hashPattern.MatchString(result.Binding.Digest) || result.Policy.Table != "inet sbxr" || result.Policy.Nftables == "" || !installIdentityPattern.MatchString(changeSet) || !hashPattern.MatchString(desiredStateSHA256) {
		return networkInstallContribution{}
	}
	var advisoryChecks []systemchanges.Check
	for _, finding := range result.Findings {
		if finding.Code == "NETWORK-PRIVILEGED-PENDING" && finding.Outcome == networkpolicy.Unknown {
			continue
		}
		if finding.Classification == networkpolicy.Advisory && finding.Outcome == networkpolicy.NeedsAttention {
			advisoryChecks = append(advisoryChecks, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Advisory, Status: systemchanges.NeedsAttention, Code: finding.Code, Disclosed: true})
			continue
		}
		{
			return networkInstallContribution{}
		}
	}
	var sshPort uint16
	ports := make([]string, 0, len(result.Policy.Exposures))
	for _, exposure := range result.Policy.Exposures {
		ports = append(ports, fmt.Sprintf("%s: %s %d/%s", exposure.Purpose, exposure.Address, exposure.Port, exposure.Protocol))
		if exposure.Purpose == "SSH preservation" && exposure.Protocol == networkpolicy.TCP {
			sshPort = exposure.Port
		}
	}
	step, err := systemchanges.NewFirewallPolicyStep(result.Policy.Nftables, sshPort)
	if err != nil || len(ports) == 0 {
		return networkInstallContribution{}
	}
	checks := []systemchanges.Check{
		{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-INSTALL-PREFLIGHT"},
		{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "NETWORK-INSTALL-AGREEMENT"},
	}
	for _, gate := range result.PostApplyGates {
		if gate.Code == "NETWORK-DOCKER-ABSENT" {
			checks = append(checks, systemchanges.Check{Owner: systemchanges.NetworkPolicyModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: gate.Code})
		}
	}
	checks = append(checks, advisoryChecks...)
	digest := sha256.Sum256([]byte(result.Binding.Digest + result.Policy.Nftables))
	stableBody, _ := json.Marshal(struct {
		Baseline networkpolicy.Baseline
		Ports    []string
		Firewall string
	}{result.Baseline, ports, result.Policy.Nftables})
	stableDigest := sha256.Sum256(stableBody)
	proof := InstallContributionProof{Name: string(NetworkInstallContribution), Owner: systemchanges.NetworkPolicyModule, Identity: "network-install-" + hex.EncodeToString(digest[:6]), SHA256: hex.EncodeToString(digest[:]), StableSHA256: hex.EncodeToString(stableDigest[:]), ChangeSet: changeSet, DesiredStateSHA256: desiredStateSHA256, Steps: []systemchanges.Step{step}, Checks: checks, Ports: ports, Firewall: result.Policy.Nftables, Details: []string{"Clean VPS admission and exact SBXR-owned nftables policy; no adoption or bypass"}, Privileged: privileged}
	return networkInstallContribution{proof: proof}
}

type InstallPlanRequest struct {
	Candidate                 InstallCandidate
	ChangeSet                 string
	DesiredStateSHA256        string
	Contributions             []InstallContribution
	Disk                      systemchanges.DiskRequirement
	ReviewedReclamationSHA256 string
}

type InstallSummary struct {
	ReleaseIdentity             ReleaseIdentity
	Revision                    uint64
	InstallationStatus, Result  InstallationStatus
	RollbackResult              InstallationStatus
	Files, Ownership            []string
	Units, Profiles             []string
	SubscriptionRepresentations []string
	Cloudflare, Certificates    []string
	Ports                       []string
	Firewall                    string
	Interruption                string
	Cancellation                string
	Rollback                    string
	Disk                        systemchanges.DiskRequirement
	Checks                      []string
	SudoAfterApproval           bool
	OneUse                      bool
	SecretsMemoryOnly           bool
}

type InstallFinding struct {
	Code       RefusalCode
	Problem    string
	NextAction string
}

type InstallPlan struct {
	identity, sha256, volatileSHA256 string
	changeSet, desiredStateSHA256    string
	candidate                        InstallCandidate
	summary                          InstallSummary
	steps                            []systemchanges.Step
	checks                           []systemchanges.Check
	proofs                           []InstallContributionProof
	disk                             systemchanges.DiskRequirement
	used                             *atomic.Bool
	reclamation                      string
}

func PlanInstall(request InstallPlanRequest) (*InstallPlan, *InstallFinding) {
	refuse := func() (*InstallPlan, *InstallFinding) {
		return nil, &InstallFinding{Code: InstallPlanRefused, Problem: "The reviewed fresh-install Plan is incomplete or stale", NextAction: "Check the Clean VPS and build a fresh Plan"}
	}
	if !validInstallCandidate(request.Candidate) || !installIdentityPattern.MatchString(request.ChangeSet) || !hashPattern.MatchString(request.DesiredStateSHA256) || request.ReviewedReclamationSHA256 != "" && !hashPattern.MatchString(request.ReviewedReclamationSHA256) || !validInstallDisk(request.Disk) {
		return refuse()
	}
	want := map[InstallContributionName]systemchanges.Module{
		NetworkInstallContribution: systemchanges.NetworkPolicyModule, ProfilesInstallContribution: systemchanges.ConnectionProfilesModule,
		CloudflareInstallContribution: systemchanges.CloudflareModule, CertificateInstallContribution: systemchanges.CertificateModule,
		SubscriptionInstallContribution: systemchanges.SubscriptionModule,
	}
	proofs := make([]InstallContributionProof, 0, len(request.Contributions))
	seen := map[InstallContributionName]bool{}
	var steps []systemchanges.Step
	var cloudflarePrelude []systemchanges.Step
	var checks []systemchanges.Check
	var ports []string
	var firewall string
	stable := ""
	var cloudflare, certificates []string
	for _, contribution := range request.Contributions {
		if contribution == nil {
			return refuse()
		}
		proof := contribution.SoftwareLifecycleInstallContribution()
		name := InstallContributionName(proof.Name)
		owner, known := want[name]
		if !known || seen[name] || proof.Owner != owner || proof.ChangeSet != request.ChangeSet || proof.DesiredStateSHA256 != request.DesiredStateSHA256 || !validInstallProof(proof) || proof.Privileged {
			return refuse()
		}
		seen[name] = true
		proofs = append(proofs, proof)
		if name == CloudflareInstallContribution {
			for _, step := range proof.Steps {
				if step.Forward() == systemchanges.ActivatePreparedConfiguration {
					steps = append(steps, step)
				} else {
					cloudflarePrelude = append(cloudflarePrelude, step)
				}
			}
		} else {
			steps = append(steps, proof.Steps...)
		}
		checks = append(checks, proof.Checks...)
		stable += proof.StableSHA256
		if name == NetworkInstallContribution {
			ports, firewall = append([]string(nil), proof.Ports...), proof.Firewall
		}
		if name == CloudflareInstallContribution {
			cloudflare = append(cloudflare, proof.Details...)
		}
		if name == CertificateInstallContribution {
			certificates = append(certificates, proof.Details...)
		}
	}
	if len(seen) != len(want) || len(ports) == 0 || firewall == "" {
		return refuse()
	}
	softwareStep, err := systemchanges.NewStep(systemchanges.SoftwareModule, systemchanges.ActivatePreparedConfiguration, systemchanges.RestorePriorConfiguration)
	if err != nil {
		return refuse()
	}
	steps = append(cloudflarePrelude, append([]systemchanges.Step{softwareStep}, steps...)...)
	softwareChecks := []systemchanges.Check{
		{Owner: systemchanges.SoftwareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PrePublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SOFTWARE-LIFECYCLE-INSTALL-STAGED"},
		{Owner: systemchanges.SoftwareModule, Scope: systemchanges.ServerSideCheck, Phase: systemchanges.PostPublication, Classification: systemchanges.Required, Status: systemchanges.Healthy, Code: "SOFTWARE-LIFECYCLE-INSTALL-AGREEMENT"},
	}
	checks = append(softwareChecks, checks...)
	bound := struct {
		Release      StagedRelease
		ChangeSet    string
		DesiredState string
		Proofs       []InstallContributionProof
		Disk         systemchanges.DiskRequirement
		Reclamation  string
	}{request.Candidate.cell.staged, request.ChangeSet, request.DesiredStateSHA256, proofs, request.Disk, request.ReviewedReclamationSHA256}
	encoded, err := json.Marshal(bound)
	if err != nil {
		return refuse()
	}
	digest := sha256.Sum256(encoded)
	checksum := hex.EncodeToString(digest[:])
	volatileDigest := sha256.Sum256([]byte(stable))
	identity := request.ChangeSet + "-plan-" + checksum[:12]
	unitNames := ManagedUnitNames()
	sort.Strings(unitNames)
	checkNames := make([]string, len(checks))
	for index, check := range checks {
		checkNames[index] = check.Code
	}
	staged := request.Candidate.cell.staged
	summary := InstallSummary{
		ReleaseIdentity: staged.Identity, Revision: 1, InstallationStatus: NotInstalled, Result: Managed, RollbackResult: NotInstalled,
		Files: []string{staged.InstallPath, "/usr/local/bin/sbxr", "/var/lib/sbxr", "/etc/sbxr", "/etc/systemd/system"}, Units: unitNames,
		Ownership:                   []string{"release executable and systemd units: root:root", "generated State: root-only", "runtime service material: root:root 0644"},
		Profiles:                    []string{"VLESS REALITY Vision", "VLESS XHTTP", "VLESS WebSocket", "Hysteria2", "TUIC", "AnyTLS"},
		SubscriptionRepresentations: []string{"raw", "base64", "v2rayN", "Shadowrocket", "Karing", "Mihomo", "sing-box"},
		Cloudflare:                  cloudflare, Certificates: certificates, Ports: ports, Firewall: firewall, Disk: request.Disk, Checks: checkNames,
		Interruption:      "no managed service exists before Apply; failed Apply rolls back all SBXR-owned additions",
		Cancellation:      "Back before Apply changes nothing; cancellation after start waits for a safe checkpoint and rolls back",
		Rollback:          "remove only additions recorded by this Change Set and prove Not installed",
		SudoAfterApproval: false, OneUse: true, SecretsMemoryOnly: true,
	}
	return &InstallPlan{identity: identity, sha256: checksum, volatileSHA256: hex.EncodeToString(volatileDigest[:]), changeSet: request.ChangeSet, desiredStateSHA256: request.DesiredStateSHA256, candidate: request.Candidate, summary: summary, steps: steps, checks: checks, proofs: proofs, disk: request.Disk, used: &atomic.Bool{}, reclamation: request.ReviewedReclamationSHA256}, nil
}

type InstallRecheck struct {
	Candidate                InstallCandidate
	Contributions            []InstallContribution
	PrivilegedNetworkHealthy bool
	Reclamation              systemchanges.ReclamationAuthority
}

type InstallApproval interface {
	// AuthorizeAndRecheck runs only inside the verified root Apply process.
	AuthorizeAndRecheck(context.Context) (InstallRecheck, error)
}

type InstallApplyRequest struct {
	Approval      InstallApproval
	PreparedState systemchanges.PreparedStateCommit
	SystemChanges systemchanges.Interface
	Cancellation  *systemchanges.Cancellation
}

func (plan *InstallPlan) Apply(ctx context.Context, request InstallApplyRequest) systemchanges.ApplyResult {
	if plan == nil || plan.used == nil || !plan.used.CompareAndSwap(false, true) {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-PLAN-USED", "The reviewed install Plan was already consumed")
	}
	if request.Approval == nil || reflect.ValueOf(request.Approval).Kind() == reflect.Pointer && reflect.ValueOf(request.Approval).IsNil() {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-APPROVAL", "The verified privileged install handoff is unavailable")
	}
	rechecked, err := request.Approval.AuthorizeAndRecheck(ctx)
	if err != nil {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-APPROVAL", "The verified privileged install handoff was denied, cancelled, or expired")
	}
	freshSHA256, stableSHA256, contributionsMatch := sameInstallContributions(plan.proofs, rechecked.Contributions)
	if !rechecked.PrivilegedNetworkHealthy || !sameInstallCandidate(plan.candidate, rechecked.Candidate) || !contributionsMatch || stableSHA256 != plan.volatileSHA256 {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-STALE", "A privileged or volatile install fact changed after approval")
	}
	if (plan.reclamation == "") != (rechecked.Reclamation == nil) {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-STALE", "The privileged reclamation authority changed after approval")
	}
	preparedRelease, ok := request.PreparedState.(interface {
		SoftwareLifecyclePreparedRelease() (repository, tag, commit, releaseIndexSHA256 string, valid bool)
	})
	if !ok {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-PREPARED", "The prepared revision 1 State has no verified release binding")
	}
	repository, tag, commit, indexSHA256, valid := preparedRelease.SoftwareLifecyclePreparedRelease()
	if identity := plan.summary.ReleaseIdentity; !valid || repository != identity.Repository || tag != identity.Tag || commit != identity.Commit || indexSHA256 != identity.IndexSHA256 {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-PREPARED", "The prepared revision 1 State does not match the verified release")
	}
	changeSet, err := systemchanges.NewChangeSet(systemchanges.ChangeSetSpec{
		Identity: plan.changeSet, Mutation: systemchanges.InstallationMutation, OutcomeOwner: systemchanges.SoftwareModule,
		StartingState: systemchanges.StateLineage{Status: systemchanges.NotInstalled}, TargetStateSHA256: plan.desiredStateSHA256,
		Plan: systemchanges.PlanBinding{Identity: plan.identity, SHA256: plan.sha256, VolatileSHA256: freshSHA256}, PreparedState: request.PreparedState,
		Steps: plan.steps, Checks: plan.checks, Timeouts: systemchanges.Timeouts{Step: 10 * time.Minute, Check: 5 * time.Minute}, Disk: plan.disk, Reclamation: rechecked.Reclamation,
	})
	if err != nil {
		return installRefused("SOFTWARE-LIFECYCLE-INSTALL-PREPARED", "The prepared revision 1 State does not match the reviewed install Plan")
	}
	if request.Cancellation != nil {
		return request.SystemChanges.ApplyWithCancellation(changeSet, request.Cancellation)
	}
	return request.SystemChanges.Apply(changeSet)
}

func installRefused(code, problem string) systemchanges.ApplyResult {
	return systemchanges.ApplyResult{Outcome: systemchanges.Refused, NothingChanged: true, PlanConsumed: true, UsesMonotonicDurations: true, Evidence: systemchanges.EvidenceRules{SecretSafeOnly: true}, Finding: &systemchanges.Finding{Code: code, Owner: systemchanges.SoftwareModule, Problem: problem, Found: "the reviewed install authority is unavailable or changed", Required: "one fresh exact review followed by a complete root recheck", WhyStopped: "stale or incomplete approval cannot authorize host mutation", NextAction: "Return to review and create a fresh install Plan."}}
}

func sameInstallCandidate(left, right InstallCandidate) bool {
	return validInstallCandidate(left) && validInstallCandidate(right) && reflect.DeepEqual(left.cell.verified, right.cell.verified) && left.cell.staged == right.cell.staged && bytes.Equal(left.cell.archive, right.cell.archive) && bytes.Equal(left.cell.components, right.cell.components)
}

func sameInstallContributions(want []InstallContributionProof, got []InstallContribution) (string, string, bool) {
	if len(want) != len(got) {
		return "", "", false
	}
	byName := make(map[InstallContributionName]InstallContributionProof, len(want))
	for _, proof := range want {
		byName[InstallContributionName(proof.Name)] = proof
	}
	seen := map[InstallContributionName]bool{}
	var fresh, stable string
	for _, contribution := range got {
		if contribution == nil {
			return "", "", false
		}
		proof := contribution.SoftwareLifecycleInstallContribution()
		name := InstallContributionName(proof.Name)
		expected, ok := byName[name]
		if !ok || seen[name] {
			return "", "", false
		}
		seen[name] = true
		fresh += proof.SHA256
		stable += proof.StableSHA256
		if name == NetworkInstallContribution {
			if !proof.Privileged || proof.StableSHA256 != expected.StableSHA256 || !hashPattern.MatchString(proof.SHA256) || proof.Identity != "network-install-"+proof.SHA256[:12] {
				return "", "", false
			}
			proof.Identity, proof.SHA256, proof.Privileged = expected.Identity, expected.SHA256, expected.Privileged
		}
		if !reflect.DeepEqual(proof, expected) {
			return "", "", false
		}
	}
	if len(seen) != len(byName) {
		return "", "", false
	}
	freshDigest, stableDigest := sha256.Sum256([]byte(fresh)), sha256.Sum256([]byte(stable))
	return hex.EncodeToString(freshDigest[:]), hex.EncodeToString(stableDigest[:]), true
}

func (plan *InstallPlan) Identity() string {
	if plan == nil {
		return ""
	}
	return plan.identity
}
func (plan *InstallPlan) SHA256() string {
	if plan == nil {
		return ""
	}
	return plan.sha256
}
func (plan *InstallPlan) VolatileSHA256() string {
	if plan == nil {
		return ""
	}
	return plan.volatileSHA256
}
func (plan *InstallPlan) Summary() InstallSummary {
	if plan == nil {
		return InstallSummary{}
	}
	result := plan.summary
	result.Files = append([]string(nil), result.Files...)
	result.Ownership = append([]string(nil), result.Ownership...)
	result.Units = append([]string(nil), result.Units...)
	result.Profiles = append([]string(nil), result.Profiles...)
	result.SubscriptionRepresentations = append([]string(nil), result.SubscriptionRepresentations...)
	result.Ports = append([]string(nil), result.Ports...)
	result.Checks = append([]string(nil), result.Checks...)
	result.Cloudflare = append([]string(nil), result.Cloudflare...)
	result.Certificates = append([]string(nil), result.Certificates...)
	return result
}

func (plan *InstallPlan) MatchesDesiredState(xray, singBox, cloudflared, certbot string) bool {
	if plan == nil {
		return false
	}
	wXray, wSingBox, wCloudflared, wCertbot, valid := plan.candidate.ManagedComponentVersions()
	return valid && xray == wXray && singBox == wSingBox && cloudflared == wCloudflared && certbot == wCertbot
}
func (plan *InstallPlan) String() string {
	if plan == nil {
		return "Software Lifecycle install Plan: unavailable"
	}
	return fmt.Sprintf("Software Lifecycle install Plan %s: revision 1, %s, %d files/categories, %d units, 6 Connection Profiles, 7 subscription representations, root Apply after approval, rollback to Not installed", plan.identity, plan.summary.ReleaseIdentity.Tag, len(plan.summary.Files), len(plan.summary.Units))
}
func (plan *InstallPlan) GoString() string { return plan.String() }

func validInstallCandidate(candidate InstallCandidate) bool {
	if candidate.cell == nil || len(candidate.cell.archive) == 0 || len(candidate.cell.components) == 0 {
		return false
	}
	staged := candidate.cell.staged
	return staged.Identity.Repository == Repository && safeTag(staged.Identity.Tag) && commitPattern.MatchString(staged.Identity.Commit) && hashPattern.MatchString(staged.Identity.IndexSHA256) && staged.Build.Repository == staged.Identity.Repository && staged.Build.Tag == staged.Identity.Tag && staged.Build.Commit == staged.Identity.Commit && hashPattern.MatchString(staged.Build.PayloadSHA256) && (staged.Architecture == AMD64 || staged.Architecture == ARM64) && hashPattern.MatchString(staged.ExecutableSHA256) && hashPattern.MatchString(staged.ComponentsSHA256) && staged.InstallPath == ReleaseInstallPath(staged.Identity) && staged.StateSchema > 0 && staged.StateSchema <= 64
}

func validInstallProof(proof InstallContributionProof) bool {
	if !installIdentityPattern.MatchString(proof.Identity) || !hashPattern.MatchString(proof.SHA256) || !hashPattern.MatchString(proof.StableSHA256) || len(proof.Steps) == 0 || len(proof.Checks) == 0 || strings.Contains(strings.ToUpper(proof.Identity), "SECRET") {
		return false
	}
	var pre, post bool
	for _, step := range proof.Steps {
		if !validInstallContributionOwner(InstallContributionName(proof.Name), proof.Owner, step.Owner()) {
			return false
		}
	}
	for _, check := range proof.Checks {
		validOutcome := check.Classification == systemchanges.Required && check.Status == systemchanges.Healthy || check.Classification == systemchanges.Advisory && (check.Status == systemchanges.Healthy || check.Status == systemchanges.NeedsAttention && check.Disclosed)
		if !validInstallContributionOwner(InstallContributionName(proof.Name), proof.Owner, check.Owner) || !validOutcome || check.Scope != systemchanges.ServerSideCheck {
			return false
		}
		pre = pre || check.Phase == systemchanges.PrePublication
		post = post || check.Phase == systemchanges.PostPublication
	}
	if InstallContributionName(proof.Name) == NetworkInstallContribution {
		if len(proof.Ports) == 0 || proof.Firewall == "" || len(proof.Details) == 0 {
			return false
		}
		for _, port := range proof.Ports {
			if port == "" || strings.ContainsAny(port, "\r\n") {
				return false
			}
		}
	} else if len(proof.Ports) != 0 || proof.Firewall != "" {
		return false
	}
	return pre && post
}

func validInstallContributionOwner(name InstallContributionName, owner, effectOwner systemchanges.Module) bool {
	if effectOwner == owner {
		return true
	}
	if name == CertificateInstallContribution {
		return owner == systemchanges.CertificateModule && (effectOwner == systemchanges.NetworkPolicyModule || effectOwner == systemchanges.ConnectionProfilesModule)
	}
	return false
}

func validInstallDisk(disk systemchanges.DiskRequirement) bool {
	return disk.PreparationBytes > 0 && disk.TemporaryBytes > 0 && disk.SnapshotBytes > 0 && disk.JournalBytes > 0 && disk.RollbackBytes > 0 && disk.OverheadBytes > 0
}
