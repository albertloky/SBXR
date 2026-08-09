package softwarelifecycle_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
	"github.com/albertloky/SBXR/internal/softwarelifecycle"
	"github.com/albertloky/SBXR/internal/state"
	"github.com/albertloky/SBXR/internal/subscriptionpublication"
)

func TestPayloadMetadataBindsTheUnmodifiedExecutableAndCompleteEmbeddedDocuments(t *testing.T) {
	executable := []byte("qualified executable bytes")
	stamped, err := softwarelifecycle.StampPayload(executable, payloadMetadata())
	if err != nil {
		t.Fatal(err)
	}
	got, payloadBytes, err := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(stamped), int64(len(stamped)))
	if err != nil || !bytes.Equal(payloadBytes, executable) || got.Build.Repository != softwarelifecycle.Repository || got.Build.Tag != "v1.0.0" || got.Build.PayloadSHA256 == "" || len(got.Schemas) != 1 || len(got.Migrations) != 0 || len(got.Units) != 10 || len(got.Artifacts) != 10 {
		t.Fatalf("ReadPayloadMetadata() = %#v, payload=%q, err=%v", got, payloadBytes, err)
	}
}

func TestManagedUnitsBindOnlyToTheAuthenticatedVersionedRelease(t *testing.T) {
	metadata := payloadMetadata()
	metadata.Build.PayloadSHA256 = strings.Repeat("a", 64)
	identity := softwarelifecycle.ReleaseIdentity{Repository: softwarelifecycle.Repository, Tag: metadata.Build.Tag, Commit: metadata.Build.Commit, IndexSHA256: strings.Repeat("b", 64)}
	units, err := softwarelifecycle.RenderManagedUnits(metadata, identity)
	directory := "/opt/sbxr/releases/" + identity.Tag + "-" + identity.Commit + "-" + identity.IndexSHA256
	if err != nil || !bytes.Contains(units["xray.service"], []byte("ExecStart="+directory+"/xray ")) || bytes.Contains(units["xray.service"], []byte("/usr/bin/xray")) {
		t.Fatalf("RenderManagedUnits() = %q, %v", units["xray.service"], err)
	}
	identity.IndexSHA256 = strings.Repeat("B", 64)
	if _, err := softwarelifecycle.RenderManagedUnits(metadata, identity); err == nil {
		t.Fatal("caller-selected release directory accepted")
	}
}

func TestPayloadMetadataRejectsTamperingAmbiguityAndIncompleteReleaseMaterial(t *testing.T) {
	tests := []struct {
		name   string
		change func(*softwarelifecycle.PayloadMetadata)
	}{
		{"repository", func(value *softwarelifecycle.PayloadMetadata) { value.Build.Repository = "attacker/SBXR" }},
		{"tag", func(value *softwarelifecycle.PayloadMetadata) { value.Build.Tag = "../v1" }},
		{"commit", func(value *softwarelifecycle.PayloadMetadata) { value.Build.Commit = strings.Repeat("x", 40) }},
		{"architecture", func(value *softwarelifecycle.PayloadMetadata) { value.Architecture = "riscv64" }},
		{"schema missing", func(value *softwarelifecycle.PayloadMetadata) { delete(value.Schemas, "desired-state-v1.schema.json") }},
		{"invented migration", func(value *softwarelifecycle.PayloadMetadata) {
			value.Migrations = []softwarelifecycle.EmbeddedMigration{{Name: "invented"}}
		}},
		{"unit missing", func(value *softwarelifecycle.PayloadMetadata) { delete(value.Units, "xray.service") }},
		{"timer behavior", func(value *softwarelifecycle.PayloadMetadata) {
			value.Units["sbxr-update-check.timer"] = append(value.Units["sbxr-update-check.timer"], []byte("ExecStart=/bin/unsafe\n")...)
		}},
		{"artifact missing", func(value *softwarelifecycle.PayloadMetadata) { delete(value.Artifacts, "subscription-raw.txt") }},
		{"artifact semantics changed", func(value *softwarelifecycle.PayloadMetadata) { value.Artifacts["subscription-raw.txt"][0] = 'x' }},
		{"baseline changed", func(value *softwarelifecycle.PayloadMetadata) { value.Baselines.SingBox = "v1.13.17" }},
		{"Owner path changed", func(value *softwarelifecycle.PayloadMetadata) { value.Paths.OwnerState = "/etc/sbxr/" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := payloadMetadata()
			test.change(&metadata)
			if _, err := softwarelifecycle.StampPayload([]byte("executable"), metadata); err == nil {
				t.Fatal("invalid release material accepted")
			}
		})
	}
	valid, err := softwarelifecycle.StampPayload([]byte("executable"), payloadMetadata())
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{append(append([]byte(nil), valid...), 'x'), append([]byte(nil), valid...)} {
		if len(changed) == len(valid) {
			changed[0] ^= 1
		}
		if _, _, err := softwarelifecycle.ReadPayloadMetadata(bytes.NewReader(changed), int64(len(changed))); err == nil {
			t.Fatal("tampered or trailing payload accepted")
		}
	}
}

func payloadMetadata() softwarelifecycle.PayloadMetadata {
	definitions, _ := state.ReleaseDefinitions()
	units := map[string][]byte{}
	commands := map[string]string{
		"cloudflared.service": "@SBXR_RELEASE_DIR@/cloudflared tunnel --no-autoupdate run --token-file /etc/sbxr/cloudflared/token", "sbxr-cert-renew.service": "/usr/local/bin/sbxr private certificate-renewal", "sbxr-health-check.service": "/usr/local/bin/sbxr private health-check", "sbxr-subscription.service": "/usr/local/bin/sbxr __subscription-serve", "sbxr-update-check.service": "/usr/local/bin/sbxr private update-check", "sing-box.service": "@SBXR_RELEASE_DIR@/sing-box run -c /etc/sbxr/sing-box/config.json", "xray.service": "@SBXR_RELEASE_DIR@/xray run -config /etc/sbxr/xray/config.json",
	}
	for _, name := range softwarelifecycle.ManagedUnitNames() {
		if strings.HasSuffix(name, ".timer") {
			units[name] = []byte("[Timer]\nUnit=" + strings.TrimSuffix(name, ".timer") + ".service\n")
		} else {
			units[name] = []byte("[Service]\nExecStart=" + commands[name] + "\n")
		}
	}
	artifacts, _ := subscriptionpublication.QualificationArtifacts()
	artifacts["cloudflared.yml"] = cloudflaretunnel.QualificationConfiguration()
	return softwarelifecycle.PayloadMetadata{
		Schema: 1, Build: softwarelifecycle.EmbeddedBuildIdentity{Repository: softwarelifecycle.Repository, Tag: "v1.0.0", Commit: strings.Repeat("a", 40)}, Architecture: softwarelifecycle.AMD64,
		StateSchema: 1, MinimumUpdaterSchema: 1, Schemas: definitions,
		Migrations: []softwarelifecycle.EmbeddedMigration{},
		Units:      units, Artifacts: artifacts, Baselines: softwarelifecycle.QualifiedComponentBaselines(), Paths: softwarelifecycle.QualifiedPaths(),
	}
}
