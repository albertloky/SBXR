package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareCommitValidatesCandidateAndSerializesLeastPrivilegeMaterial(t *testing.T) {
	candidate := completeDesiredState()
	validators := &validatingSeams{want: candidate, calls: map[string]int{}}
	preparation, err := New(intentStorage{}).PrepareCommit(PrepareRequest{
		CandidateRevision:        8,
		CandidateReleaseIdentity: testRelease,
		ChangeSet:                "change-0008",
		Candidate:                candidate,
		SemanticValidators:       validatorsFor(validators),
		ServiceMaterials:         serviceMaterialsFor(candidate),
	})
	if err != nil {
		t.Fatal(err)
	}
	if preparation.ReleaseIdentity != testRelease || !reflect.DeepEqual(preparation.Candidate, candidate) {
		t.Fatal("PrepareCommit did not preserve the complete candidate")
	}
	for _, module := range []string{"connectionprofiles", "subscriptionpublication", "cloudflaretunnel", "certificatelifecycle", "networkpolicy", "softwarelifecycle"} {
		if validators.calls[module] != 1 {
			t.Fatalf("%s validation calls = %d, want 1", module, validators.calls[module])
		}
	}
	if validators.connectionSecrets.ReadClientAccessValue(candidate.ConnectionProfiles.VLESSRealityVision.UUID) != "" || validators.subscriptionSecrets.ReadClientAccessValue(candidate.Subscription.Token) != "" || validators.cloudflareSecrets.ReadInfrastructureSecret(candidate.Cloudflare.ManagementToken) != "" {
		t.Fatal("an owning validator retained secret-reading authority after validation")
	}

	checks := []struct {
		copy        *PreparedServiceCopy
		service     string
		module      string
		group       string
		want        any
		mustHave    []string
		mustNotHave []string
	}{
		{copy: preparation.ServiceCopies.Xray, service: "xray.service", module: "connectionprofiles", group: "xray", want: serviceMaterialsFor(candidate).Xray, mustHave: []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, mustNotHave: []string{"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "xhttp.example.com", "ws.example.com", "HYSTERIA2-SECRET-MARKER-00000001", "CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "CLOUDFLARE-RUN-SECRET-MARKER-00001", "6666666666666666666666666666666666666666666666666666666666666666"}},
		{copy: preparation.ServiceCopies.SingBox, service: "sing-box.service", module: "connectionprofiles", group: "sing-box", want: serviceMaterialsFor(candidate).SingBox, mustHave: []string{"HYSTERIA2-SECRET-MARKER-00000001", "TUIC-PASSWORD-SECRET-MARKER-00001", "ANYTLS-PASSWORD-SECRET-MARKER-01", "/var/lib/sbxr/certificates/domain/current"}, mustNotHave: []string{"domain-certificate", "11111111-1111-4111-8111-111111111111", "CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "CLOUDFLARE-RUN-SECRET-MARKER-00001", "6666666666666666666666666666666666666666666666666666666666666666"}},
		{copy: preparation.ServiceCopies.Cloudflared, service: "cloudflared.service", module: "cloudflaretunnel", group: "cloudflared", want: serviceMaterialsFor(candidate).Cloudflared, mustHave: []string{"CLOUDFLARE-RUN-SECRET-MARKER-00001"}, mustNotHave: []string{"CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "11111111-1111-4111-8111-111111111111", "HYSTERIA2-SECRET-MARKER-00000001", "6666666666666666666666666666666666666666666666666666666666666666"}},
		{copy: preparation.ServiceCopies.Subscription, service: "sbxr-subscription.service", module: "subscriptionserving", group: "sbxr-subscription", want: serviceMaterialsFor(candidate).Subscription, mustHave: []string{"6666666666666666666666666666666666666666666666666666666666666666", "/var/lib/sbxr/certificates/ip/current"}, mustNotHave: []string{"ip-certificate", "CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "CLOUDFLARE-RUN-SECRET-MARKER-00001", "11111111-1111-4111-8111-111111111111", "HYSTERIA2-SECRET-MARKER-00000001"}},
	}

	for _, check := range checks {
		t.Run(check.service, func(t *testing.T) {
			if check.copy == nil {
				t.Fatal("required service copy was omitted")
			}
			manifest := check.copy.manifest
			if manifest.Service != check.service || manifest.OwningModule != check.module || manifest.CandidateRevision != 8 || manifest.ChangeSet != "change-0008" || manifest.Owner != "root" || manifest.Group != check.group || manifest.DirectoryMode != 0o750 || manifest.FileMode != 0o640 {
				t.Fatalf("manifest = %+v", manifest)
			}
			digest := sha256.Sum256(check.copy.bytes)
			if manifest.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("manifest checksum does not bind the prepared bytes")
			}
			decoded := reflect.New(reflect.TypeOf(check.want))
			if err := json.Unmarshal(check.copy.bytes, decoded.Interface()); err != nil || !reflect.DeepEqual(decoded.Elem().Interface(), check.want) {
				t.Fatalf("serialized material did not round-trip: %v", err)
			}
			text := string(check.copy.bytes)
			for _, marker := range check.mustHave {
				if !strings.Contains(text, marker) {
					t.Fatalf("prepared copy omitted its required value %q", marker)
				}
			}
			for _, marker := range check.mustNotHave {
				if strings.Contains(text, marker) {
					t.Fatalf("prepared copy exposed unrelated value %q", marker)
				}
			}
			if strings.Contains(text, `"enabled"`) || strings.Contains(text, "comment") || strings.Contains(text, "provenance") || strings.Contains(text, "release_identity") {
				t.Fatal("prepared copy contains comments or provenance")
			}
		})
	}
}

func TestPreparedServiceCopiesCannotBeRendered(t *testing.T) {
	candidate := completeDesiredState()
	validator := &validatingSeams{want: candidate, calls: map[string]int{}}
	request := PrepareRequest{CandidateRevision: 8, CandidateReleaseIdentity: testRelease, ChangeSet: "change-0008", Candidate: candidate, SemanticValidators: validatorsFor(validator), ServiceMaterials: serviceMaterialsFor(candidate)}
	preparation, err := New(intentStorage{}).PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, copy := range []*PreparedServiceCopy{preparation.ServiceCopies.Xray, preparation.ServiceCopies.SingBox, preparation.ServiceCopies.Cloudflared, preparation.ServiceCopies.Subscription} {
		if copy == nil {
			t.Fatal("required service copy was omitted")
		}
		rendered, renderErr := json.Marshal(copy)
		formatted := fmt.Sprintf("%+v %#v", copy, copy)
		if renderErr == nil || strings.Contains(string(rendered), "SECRET-MARKER") || !strings.Contains(formatted, "redacted prepared service copy") || len(formatted) > 100 {
			t.Fatal("prepared service copy exposed protected bytes through general rendering")
		}
	}
}

func TestPrepareCommitRefusesInvalidCandidateFactsAndMaterial(t *testing.T) {
	valid := completeDesiredState()
	tests := []struct {
		name   string
		change func(*PrepareRequest)
		code   string
	}{
		{name: "partial candidate", change: func(r *PrepareRequest) { r.Candidate.Subscription.Token = ClientAccessValue{} }, code: "STATE-INTENT-INCOMPLETE"},
		{name: "missing semantic validator", change: func(r *PrepareRequest) { r.SemanticValidators.NetworkPolicy = nil }, code: "STATE-CANDIDATE-SEMANTIC"},
		{name: "owning validator refusal", change: func(r *PrepareRequest) {
			validator := &validatingSeams{want: valid, reject: "cloudflaretunnel", calls: map[string]int{}}
			r.SemanticValidators = validatorsFor(validator)
		}, code: "STATE-CANDIDATE-SEMANTIC"},
		{name: "unrelated service value", change: func(r *PrepareRequest) {
			r.ServiceMaterials.Xray.VLESSRealityVision.UUID = r.Candidate.ConnectionProfiles.Hysteria2.Password
		}, code: "STATE-SERVICE-MATERIAL-UNRELATED"},
		{name: "omitted service material", change: func(r *PrepareRequest) { r.ServiceMaterials.Cloudflared = nil }, code: "STATE-SERVICE-MATERIAL-UNRELATED"},
		{name: "missing candidate revision", change: func(r *PrepareRequest) { r.CandidateRevision = 0 }, code: "STATE-SERVICE-MANIFEST"},
		{name: "missing Release Identity", change: func(r *PrepareRequest) { r.CandidateReleaseIdentity = ReleaseIdentity{} }, code: "STATE-SERVICE-MANIFEST"},
		{name: "invalid later Change Set", change: func(r *PrepareRequest) { r.ChangeSet = "invalid\nchange" }, code: "STATE-SERVICE-MANIFEST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &validatingSeams{want: valid, calls: map[string]int{}}
			request := PrepareRequest{CandidateRevision: 8, CandidateReleaseIdentity: testRelease, ChangeSet: "change-0008", Candidate: valid, SemanticValidators: validatorsFor(validator), ServiceMaterials: serviceMaterialsFor(valid)}
			tt.change(&request)
			preparation, err := New(intentStorage{}).PrepareCommit(request)
			var finding *Finding
			if !errors.As(err, &finding) || finding.Code != tt.code || !reflect.DeepEqual(preparation, Preparation{}) {
				t.Fatalf("PrepareCommit() = (%+v, %#v), want %s refusal", preparation, err, tt.code)
			}
			for _, marker := range []string{"CLOUDFLARE-MANAGEMENT-SECRET-MARKER", "HYSTERIA2-SECRET-MARKER-00000001", "6666666666666666666666666666666666666666666666666666666666666666"} {
				if strings.Contains(err.Error(), marker) {
					t.Fatal("refusal exposed a protected value")
				}
			}
		})
	}
}

func TestPrepareCommitRequiresOwningSemanticValidationForEverySection(t *testing.T) {
	valid := completeDesiredState()
	tests := []struct {
		name   string
		change func(*DesiredState)
	}{
		{name: "installation identity", change: func(candidate *DesiredState) { candidate.Installation.ID = "not-a-uuid" }},
		{name: "Connection Profiles", change: func(candidate *DesiredState) { candidate.ConnectionProfiles.VLESSXHTTP.OriginAddress = "0.0.0.0" }},
		{name: "subscription", change: func(candidate *DesiredState) { candidate.Subscription.ListenPort = 10444 }},
		{name: "Cloudflare", change: func(candidate *DesiredState) { candidate.Cloudflare.TunnelName = "invalid tunnel name" }},
		{name: "certificates", change: func(candidate *DesiredState) { candidate.Certificates.RenewalPolicy = false }},
		{name: "Network Policy", change: func(candidate *DesiredState) {
			candidate.NetworkPolicy.PublicIPv4 = "not-an-ip"
			candidate.NetworkPolicy.PrimarySubscriptionAddress = "not-an-ip"
		}},
		{name: "software", change: func(candidate *DesiredState) { candidate.Software.XrayVersion = "invalid version" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			tt.change(&candidate)
			validator := &validatingSeams{want: valid, calls: map[string]int{}}
			request := PrepareRequest{CandidateRevision: 8, CandidateReleaseIdentity: testRelease, ChangeSet: "change-0008", Candidate: candidate, SemanticValidators: validatorsFor(validator), ServiceMaterials: serviceMaterialsFor(candidate)}
			_, err := New(intentStorage{}).PrepareCommit(request)
			var finding *Finding
			if !errors.As(err, &finding) || finding.Code != "STATE-CANDIDATE-SEMANTIC" {
				t.Fatalf("PrepareCommit() error = %#v, want STATE-CANDIDATE-SEMANTIC", err)
			}
		})
	}
}

func TestPrepareCommitRevokesSecretReaderAfterValidatorPanic(t *testing.T) {
	candidate := completeDesiredState()
	validator := &validatingSeams{want: candidate, panicModule: "subscriptionpublication", calls: map[string]int{}}
	request := PrepareRequest{CandidateRevision: 8, CandidateReleaseIdentity: testRelease, ChangeSet: "change-0008", Candidate: candidate, SemanticValidators: validatorsFor(validator), ServiceMaterials: serviceMaterialsFor(candidate)}
	_, err := New(intentStorage{}).PrepareCommit(request)
	var finding *Finding
	if !errors.As(err, &finding) || finding.Code != "STATE-CANDIDATE-SEMANTIC" {
		t.Fatalf("PrepareCommit() error = %#v, want secret-safe semantic refusal", err)
	}
	if validator.subscriptionSecrets == nil || validator.subscriptionSecrets.ReadClientAccessValue(candidate.Subscription.Token) != "" {
		t.Fatal("panicking validator retained secret-reading authority")
	}
}

func TestPrepareCommitOmitsDisabledProfileCredentials(t *testing.T) {
	candidate := completeDesiredState()
	candidate.ConnectionProfiles.VLESSWebSocket.Enabled = false
	validator := &validatingSeams{want: candidate, calls: map[string]int{}}
	request := PrepareRequest{CandidateRevision: 8, CandidateReleaseIdentity: testRelease, ChangeSet: "change-0008", Candidate: candidate, SemanticValidators: validatorsFor(validator), ServiceMaterials: serviceMaterialsFor(candidate)}
	preparation, err := New(intentStorage{}).PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.ServiceCopies.Xray == nil || strings.Contains(string(preparation.ServiceCopies.Xray.bytes), "33333333-3333-4333-8333-333333333333") || strings.Contains(string(preparation.ServiceCopies.Xray.bytes), "4444444444444444444444444444444444444444444444444444444444444444") {
		t.Fatal("disabled Connection Profile credentials entered runtime service material")
	}
}

func TestPrepareCommitOmitsUnusedServices(t *testing.T) {
	candidate := completeDesiredState()
	candidate.ConnectionProfiles.VLESSRealityVision.Enabled = false
	candidate.ConnectionProfiles.VLESSXHTTP.Enabled = false
	candidate.ConnectionProfiles.VLESSWebSocket.Enabled = false
	candidate.NetworkPolicy.SSHPort = 443
	validator := &validatingSeams{want: candidate, calls: map[string]int{}}
	request := PrepareRequest{CandidateRevision: 8, CandidateReleaseIdentity: testRelease, ChangeSet: "change-0008", Candidate: candidate, SemanticValidators: validatorsFor(validator), ServiceMaterials: serviceMaterialsFor(candidate)}
	preparation, err := New(intentStorage{}).PrepareCommit(request)
	if err != nil {
		t.Fatal(err)
	}
	if preparation.ServiceCopies.Xray != nil || preparation.ServiceCopies.Cloudflared != nil {
		t.Fatal("disabled Xray and Cloudflare-backed profiles produced unused service copies")
	}
}

type validatingSeams struct {
	want                DesiredState
	reject              string
	panicModule         string
	calls               map[string]int
	connectionSecrets   ConnectionProfileSecretReader
	subscriptionSecrets ClientAccessReader
	cloudflareSecrets   InfrastructureSecretReader
}

func (v *validatingSeams) validate(module string, got, want any) error {
	v.calls[module]++
	if v.reject == module || !reflect.DeepEqual(got, want) {
		return errors.New("semantic refusal")
	}
	return nil
}

func (v *validatingSeams) ValidateConnectionProfiles(got ConnectionProfiles, secrets ConnectionProfileSecretReader) error {
	v.connectionSecrets = secrets
	if v.panicModule == "connectionprofiles" {
		panic("validator panic")
	}
	if secrets.ReadClientAccessValue(got.VLESSRealityVision.UUID) == "" || secrets.ReadInfrastructureSecret(got.VLESSRealityVision.PrivateKey) == "" {
		return errors.New("protected Connection Profile value unavailable")
	}
	return v.validate("connectionprofiles", got, v.want.ConnectionProfiles)
}

func (v *validatingSeams) ValidateSubscription(got SubscriptionSettings, secrets ClientAccessReader) error {
	v.subscriptionSecrets = secrets
	if _, broad := secrets.(InfrastructureSecretReader); broad {
		return errors.New("subscription reader exposed Infrastructure Secrets")
	}
	if v.panicModule == "subscriptionpublication" {
		panic("validator panic")
	}
	if secrets.ReadClientAccessValue(got.Token) == "" {
		return errors.New("protected subscription value unavailable")
	}
	return v.validate("subscriptionpublication", got, v.want.Subscription)
}

func (v *validatingSeams) ValidateCloudflare(got CloudflareSettings, secrets InfrastructureSecretReader) error {
	v.cloudflareSecrets = secrets
	if _, broad := secrets.(ClientAccessReader); broad {
		return errors.New("Cloudflare reader exposed Client Access Values")
	}
	if v.panicModule == "cloudflaretunnel" {
		panic("validator panic")
	}
	if secrets.ReadInfrastructureSecret(got.ManagementToken) == "" || secrets.ReadInfrastructureSecret(got.TunnelRunToken) == "" {
		return errors.New("protected Cloudflare value unavailable")
	}
	return v.validate("cloudflaretunnel", got, v.want.Cloudflare)
}

func (v *validatingSeams) ValidateCertificates(got CertificateSettings) error {
	return v.validate("certificatelifecycle", got, v.want.Certificates)
}

func (v *validatingSeams) ValidateNetworkPolicy(got NetworkPolicyInputs) error {
	return v.validate("networkpolicy", got, v.want.NetworkPolicy)
}

func (v *validatingSeams) ValidateSoftwareLifecycle(got SoftwareLifecycleIntent) error {
	want := SoftwareLifecycleIntent{Installation: v.want.Installation, Software: v.want.Software}
	return v.validate("softwarelifecycle", got, want)
}

func validatorsFor(validator *validatingSeams) SemanticValidators {
	return SemanticValidators{ConnectionProfiles: validator, Subscription: validator, Cloudflare: validator, Certificates: validator, NetworkPolicy: validator, SoftwareLifecycle: validator}
}

func serviceMaterialsFor(candidate DesiredState) ServiceMaterials {
	return expectedServiceMaterials(candidate)
}
